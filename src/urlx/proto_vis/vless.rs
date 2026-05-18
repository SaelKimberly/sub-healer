use crate::urlx::{SchemeX, TinyText, UrlX, UserInfo};

pub struct VlessProto;

impl super::ProtoVisitor for VlessProto {
    fn parse(raw: &super::Input<'_>) -> Result<UrlX, super::ParseError> {
        let (username, hostport) = if let Some(hostport) = raw.hostport {
            let username = raw.userinfo;
            (username, hostport)
        } else {
            let userinfo = raw.userinfo;
            let (userinfo, hostport) = userinfo.split_once('@').ok_or_else(|| {
                super::ParseError::InvalidUserInfo(format!("{userinfo}: missing hostport").into())
            })?;
            (userinfo, hostport)
        };

        let (host, port) = super::_parse_hostport(hostport)?;

        let uuid = uuid::Uuid::parse_str(username).map_err(|_| {
            super::ParseError::InvalidUserInfo(format!("invalid UUID: {username}").into())
        })?;

        let query_string = raw.query.unwrap_or("");
        let query_pairs: Vec<(TinyText, Option<TinyText>)> = if query_string.is_empty() {
            vec![]
        } else {
            query_string
                .split('&')
                .filter_map(|s| {
                    if let Some((k, v)) = s.split_once('=') {
                        if v.is_empty() {
                            Some((TinyText::from(k), None))
                        } else {
                            Some((TinyText::from(k), Some(TinyText::from(v))))
                        }
                    } else if !s.is_empty() {
                        Some((TinyText::from(s), None))
                    } else {
                        None
                    }
                })
                .collect()
        };

        let security = query_pairs
            .iter()
            .find(|(k, _)| k.as_str() == "security")
            .and_then(|(_, v)| v.as_ref())
            .map_or_else(|| "none".into(), |v| TinyText::from(v.as_str()));
        let transport = query_pairs
            .iter()
            .find(|(k, _)| k.as_str() == "type")
            .and_then(|(_, v)| v.as_ref())
            .map_or_else(|| "tcp".into(), |v| TinyText::from(v.as_str()));
        let path = query_pairs
            .iter()
            .find(|(k, _)| k.as_str() == "path")
            .and_then(|(_, v)| v.as_ref())
            .cloned();

        let remarks = raw
            .fragment
            .map(urlencoding::decode)
            .transpose()
            .map_err(|e| super::ParseError::InvalidConf("remarks".into(), e.to_string().into()))?
            .map(TinyText::from);

        Ok(UrlX {
            uid: 0,
            sig: 0,
            schema: SchemeX::Vless,
            username: UserInfo::Text(username.into(), UserInfoEncoding::URL),
            password: Some(uuid.to_string().into()),
            host: Some(host),
            port: Some(port),
            path,
            query: query_pairs,
            transport: Some(transport),
            security: Some(security),
            fragment: remarks,
        })
    }

    fn build(url: &UrlX) -> Result<String, super::ParseError> {
        let mut base = url::Url::parse(
            format!(
                "{}://{}@{}",
                url.schema.as_str(),
                url._safe_userinfo()?,
                url._safe_hostport(None)?,
            )
            .as_str(),
        )
        .map_err(|e| super::ParseError::Unknown(e.into()))?;

        if let Some(ref path) = url.path {
            base.set_path(path.as_str());
        }

        if !url.query.is_empty() {
            let mut filtered_query: Vec<_> = url
                .query
                .iter()
                .filter(|(k, v)| {
                    !matches!(
                        (k.as_str(), v.as_deref()),
                        (
                            "security" | "type" | "encryption",
                            Some("none" | "tcp") | None
                        )
                    )
                })
                .collect();
            filtered_query.sort_by(|a, b| a.0.cmp(&b.0));

            let mut q = base.query_pairs_mut();
            for (k, v) in &filtered_query {
                if let Some(v) = v {
                    q.append_pair(k, v);
                } else {
                    q.append_key_only(k);
                }
            }
            drop(q);
        }

        if let Some(ref frag) = url.fragment {
            let frag = crate::Unescaper::default()
                .enc_pct()
                .enc_uni(true)
                .chardet(true, true)
                .do_unescape(frag.as_bytes())
                .unwrap();
            let frag = frag.trim();
            let frag = frag.split_whitespace().collect::<Vec<_>>().join(" ");
            if !frag.is_empty() {
                base.set_fragment(Some(frag.as_str()));
            }
        }

        base.set_username(
            url.username
                .as_url_safe()
                .map_err(|e| {
                    super::ParseError::InvalidConf("username".into(), e.to_string().into())
                })?
                .as_str(),
        )
        .expect("username should be always present");

        Ok(base.to_string())
    }

    fn visit(url: &mut UrlX) -> Result<(), super::ParseError> {
        let mut sig_parts = Vec::new();
        sig_parts.push(url.schema.as_str().as_bytes());

        if let Some(ref security) = url.security {
            sig_parts.push(security.as_bytes());
        }
        if let Some(ref transport) = url.transport {
            sig_parts.push(transport.as_bytes());
        }
        if let Some(ref path) = url.path {
            sig_parts.push(path.as_bytes());
        }

        for (key, value) in &url.query {
            let key_str = key.as_str();
            if matches!(
                key_str,
                "encryption" | "sni" | "flow" | "alpn" | "fp" | "pbk" | "sid" | "splice"
            ) {
                sig_parts.push(key_str.as_bytes());
                if let Some(v) = value {
                    sig_parts.push(v.as_bytes());
                }
            }
        }

        let sig_data = sig_parts.concat();
        url.sig = rapidhash::v3::rapidhash_v3(&sig_data);

        let (uid, _) = super::_compute_uid(url);
        url.uid = uid;

        Ok(())
    }
}

use crate::urlx::user_info::UserInfoEncoding;

#[cfg(test)]
mod tests {
    use super::super::super::try_accept_raw as visit_basic;
    use crate::urlx::SchemeX;

    #[test]
    fn test_vless() {
        let url = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@159.223.24.65:443?path=/?ed=2560&security=tls&encryption=none&sni=test.ir&type=ws";

        let raw = crate::urlx::RawUrlX::from(url);
        let url = visit_basic(&raw).expect("failed");

        assert_eq!(url.schema, SchemeX::Vless);
    }

    #[test]
    fn test_vless_reality() {
        let url = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@159.223.24.65:443?security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision&pbk=abc123";

        let raw = crate::urlx::RawUrlX::from(url);
        let url = visit_basic(&raw).expect("failed");

        assert_eq!(url.schema, SchemeX::Vless);
    }

    #[test]
    fn test_reconstruct_vless_roundtrip() {
        let input = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@159.223.24.65:443?path=/?ed=2560&security=tls&encryption=none&sni=test.ir&type=ws";

        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = visit_basic(&raw).expect("failed to parse");

        let reconstructed = parsed.reconstruct();

        let raw2 = crate::urlx::RawUrlX::from(reconstructed.as_str());
        let reparsed = visit_basic(&raw2).expect("failed to re-parse");

        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
        assert_eq!(parsed.schema, reparsed.schema, "schema mismatch");
    }
}
