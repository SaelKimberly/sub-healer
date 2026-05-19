use crate::urlx::{HostSpec, PortSpec, RawUrlX, SchemeX, TinyText, UrlX, UserInfo};

pub struct VmessProto;

impl super::ProtoVisitor for VmessProto {
    fn parse(raw: &super::Input<'_>) -> Result<UrlX, super::ParseError> {
        // 1: Verify, that the raw url contains only userinfo (and optional fragment)
        let RawUrlX {
            schema: _,
            userinfo,
            hostport: None,
            path: None,
            query: None,
            fragment: _,
        } = raw
        else {
            return Err(super::ParseError::InvalidStructure(SchemeX::Vmess));
        };

        // 2: Verify, that userinfo is base64 encoded
        let Ok(mut userinfo) = UserInfo::new_from_b64(userinfo) else {
            return Err(super::ParseError::InvalidStructure(SchemeX::Vmess));
        };
        // 3: Verify, that userinfo is json (and decode it, permissive)
        let Ok(json) = userinfo.as_json_decoded(true) else {
            return Err(super::ParseError::InvalidStructure(SchemeX::Vmess));
        };

        // Extract and validate host
        let host: HostSpec = {
            let host = json
                .get("add")
                .ok_or(super::ParseError::MissingHost)
                .and_then(|v| {
                    v.as_str().ok_or_else(|| {
                        super::ParseError::InvalidHost(format!("cannot parse: {v}").into())
                    })
                })?;
            let host = if let Some(new_host) = host.strip_prefix('[') {
                new_host.strip_suffix(']').ok_or_else(|| {
                    super::ParseError::InvalidHost(format!("cannot parse: {host}").into())
                })?
            } else {
                host
            };

            rustls::pki_types::ServerName::try_from(host)
                .map_err(|e| {
                    super::ParseError::InvalidHost(format!("cannot parse: {host} {e}").into())
                })?
                .to_owned()
        };

        // Extract and validate port
        let port = {
            let port = json
                .get("port")
                .ok_or(super::ParseError::MissingPort)
                .and_then(|v| {
                    v.as_u64()
                        .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
                        .ok_or_else(|| {
                            super::ParseError::InvalidPort(format!("cannot parse: {v}").into())
                        })
                })?;

            u16::try_from(port)
                .map_err(|e| {
                    super::ParseError::InvalidPort(format!("cannot parse: {port} {e}").into())
                })
                .map(PortSpec::new_with)?
        };

        // Extract and validate security
        let security: TinyText = json
            .get("scy")
            .map(|v| {
                if v.is_null() {
                    return Ok(None);
                }
                v.as_str().ok_or_else(|| {
                    super::ParseError::InvalidConf("scy".into(), v.to_string().into())
                })
                .map(Some)
            })
            .transpose()?
            .flatten()
            .unwrap_or("auto")
            .into();

        // Extract and validate transport
        let transport: TinyText = json
            .get("net")
            .map(|v| {
                if v.is_null() {
                    return Ok(None);
                }
                v.as_str().ok_or_else(|| {
                    super::ParseError::InvalidConf("net".into(), v.to_string().into())
                })
                .map(Some)
            })
            .transpose()?
            .flatten()
            .unwrap_or("tcp")
            .into();

        // Extract remarks
        let remarks = json
            .as_object_mut()
            .and_then(|o| o.remove("ps"))
            .map(|v| {
                if v.is_null() {
                    return Ok(None);
                }
                v.as_str()
                    .map(|s| s.trim_matches(['"', '\'']))
                    .map(TinyText::from)
                    .ok_or(super::ParseError::InvalidConf(
                        "ps".into(),
                        v.to_string().into(),
                    ))
                    .map(Some)
            })
            .transpose()?
            .flatten();

        // Extract user (UUID)
        let user = json
            .get("id")
            .map(|v| {
                v.as_str()
                    .map(TinyText::from)
                    .ok_or(super::ParseError::InvalidConf(
                        "id".into(),
                        v.to_string().into(),
                    ))
            })
            .transpose()?
            .ok_or_else(|| super::ParseError::MissingConf("id".into()))?;

        Ok(UrlX {
            uid: 0,
            sig: 0,
            schema: SchemeX::Vmess,
            host: Some(host),
            port: Some(port),
            transport: transport.into(),
            security: security.into(),
            username: userinfo,
            password: Some(user),
            path: None,
            query: vec![],
            fragment: remarks,
        })
    }

    fn build(url: &UrlX) -> Result<String, super::ParseError> {
        // VMess embeds connection parameters in a JSON userinfo field.
        // Reconstruct by re-encoding the stored userinfo to base64.
        let username = url
            .username
            .as_url_safe()
            .map_err(|e| super::ParseError::InvalidUserInfo(e.to_string().into()))?;
        Ok(format!("{}://{}", url.schema.as_str(), username))
    }

    fn visit(url: &mut UrlX) -> Result<(), super::ParseError> {
        let UserInfo::Json(json) = &url.username else {
            return Ok(());
        };

        let mut sig_parts: Vec<String> = vec![url.schema.as_str().to_string()];

        if let Some(scy) = json.get("scy").and_then(|v| v.as_str()) {
            sig_parts.push(scy.to_string());
        }
        if let Some(net) = json.get("net").and_then(|v| v.as_str()) {
            sig_parts.push(net.to_string());
        }
        if let Some(aid) = json.get("aid").and_then(|v| v.as_str()) {
            sig_parts.push(aid.to_string());
        }
        if let Some(sni) = json.get("sni").and_then(|v| v.as_str()) {
            sig_parts.push(sni.to_string());
        }
        if let Some(ves) = json.get("ves").and_then(|v| v.as_str()) {
            sig_parts.push(ves.to_string());
        }
        if let Some(seq) = json.get("seq").and_then(serde_json::Value::as_u64) {
            sig_parts.push(seq.to_string());
        }

        let sig_data = sig_parts.join(":");
        url.sig = rapidhash::v3::rapidhash_v3(sig_data.as_bytes());

        let (uid, _) = super::_compute_uid(url);
        url.uid = uid;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::try_accept_raw as visit_basic;
    use crate::urlx::SchemeX;

    #[test]
    fn test_vmess() {
        let url = "vmess://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTozMTM0NzA1Ny03YWY1LTQ1NjItYjkxMi1mMWMyMTdjNGMxNjA@hnt.cndns.shop:27761#%F0%9F%87%A8%F0%9F%87%B3_CN_%E4%B8%AD%E5%9B%BD-%3E%F0%9F%87%B7%F0%9F%87%BA_RU_%E4%BF%84%E7%BD%97%E6%96%AF%E8%81%94%E9%82%A6";

        let raw = crate::urlx::RawUrlX::from(url);
        let url = visit_basic(&raw).expect("failed");

        assert_eq!(url.schema, SchemeX::Vmess);
    }

    #[test]
    fn test_reconstruct_vmess_roundtrip() {
        let input = "vmess://eyJhZGQiOiIxOTIuMjAwLjE2MC4xNiIsImFpZCI6IjAiLCJhbHBuIjoiIiwiZnAiOiIiLCJob3N0IjoiIiwiaWQiOiI5YjRjMmVkYS0zNDFlLTQ4OGYtYTNiMi0xZGM3MTZiOWYzNmEiLCJpbnNlY3VyZSI6IjEiLCJuZXQiOiJ3cyIsInBhdGgiOiIvIiwicG9ydCI6Ijg0NDMiLCJwcyI6IkBDbG91ZENpdHl5Iiwic2N5IjoiYXV0byIsInNuaSI6InN0ZWFtLmF2YWFhYWwuaXIiLCJ0bHMiOiJ0bHMiLCJ0eXBlIjoiLS0tIiwidiI6IjIifQ==";

        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = visit_basic(&raw).expect("failed to parse");

        assert_eq!(parsed.schema, SchemeX::Vmess, "schema should be Vmess");

        let reconstructed = parsed.reconstruct();

        assert!(
            reconstructed.starts_with("vmess://"),
            "should start with vmess://"
        );

        let raw2 = crate::urlx::RawUrlX::from(reconstructed.as_str());
        let reparsed = visit_basic(&raw2).expect("failed to re-parse");

        assert_eq!(
            parsed.schema, reparsed.schema,
            "schema mismatch after re-parse"
        );
    }
}
