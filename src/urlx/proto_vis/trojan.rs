use crate::urlx::{HostSpec, PortSpec, RawUrlX, SchemeX, TinyText, UrlX, UserInfo};

pub struct TrojanProto;

impl super::ProtoVisitor for TrojanProto {
    fn parse(raw: &super::Input<'_>) -> Result<UrlX, super::ParseError> {
        let (username, hostport) = if let Some(hostport) = raw.hostport {
            (raw.userinfo, hostport)
        } else {
            let userinfo = raw.userinfo;
            let (username, hostport) = userinfo.split_once('@').ok_or_else(|| {
                super::ParseError::InvalidUserInfo(format!("{}: missing hostport", userinfo).into())
            })?;
            (username, hostport)
        };

        let (host, port) = super::_parse_hostport(hostport)?;

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

        let security: TinyText = query_pairs
            .iter()
            .find(|(k, _)| k.as_str() == "security")
            .and_then(|(_, v)| v.as_deref())
            .unwrap_or("tls")
            .into();
        let transport: TinyText = query_pairs
            .iter()
            .find(|(k, _)| k.as_str() == "type")
            .and_then(|(_, v)| v.as_deref())
            .unwrap_or("tcp")
            .into();
        let path = query_pairs.iter().find_map(|(k, v)| {
            if k.as_str() == "path"
                && let Some(v) = v
            {
                Some(v.to_owned())
            } else {
                None
            }
        });

        let remarks = raw
            .fragment
            .map(urlencoding::decode)
            .transpose()
            .map_err(|e| super::ParseError::InvalidConf("remarks".into(), e.to_string().into()))?
            .map(TinyText::from);

        Ok(UrlX {
            uid: 0,
            sig: 0,
            schema: SchemeX::Trojan,
            username: UserInfo::Text(username.into(), UserInfoEncoding::URL),
            password: Some(username.into()),
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
        let hostport = url._safe_hostport(None)?;

        let query_string = if !url.query.is_empty() {
            let filtered: Vec<_> = url
                .query
                .iter()
                .filter(|(k, v)| {
                    !matches!((k.as_str(), v.as_deref()), ("security", Some("tls") | None))
                })
                .collect();
            if filtered.is_empty() {
                String::new()
            } else {
                let parts: Vec<String> = filtered
                    .iter()
                    .map(|(k, v)| {
                        v.as_ref().map_or_else(
                            || format!("{}=", k),
                            |v| format!("{}={}", k, urlencoding::encode(v)),
                        )
                    })
                    .collect();
                format!("?{}", parts.join("&"))
            }
        } else {
            String::new()
        };

        let fragment = url
            .fragment
            .as_ref()
            .map(|f| format!("#{}", urlencoding::encode(f)))
            .unwrap_or_default();

        let username = url
            .username
            .as_url_safe()
            .map_err(|e| super::ParseError::InvalidUserInfo(e.to_string().into()))?;

        Ok(format!(
            "trojan://{}@{}{}{}",
            username, hostport, query_string, fragment
        ))
    }

    fn visit(_url: &mut UrlX) -> Result<(), super::ParseError> {
        // TODO: implement sig/uid computation
        Ok(())
    }
}

use crate::urlx::user_info::UserInfoEncoding;

#[cfg(test)]
mod tests {
    use super::super::super::try_accept_raw as visit_basic;
    use crate::urlx::SchemeX;

    #[test]
    fn test_trojan() {
        let url = "trojan://humanity@172.64.152.23:443?security=tls&type=ws&path=/assignment&sni=www.creationlong.org";

        let raw = crate::urlx::RawUrlX::from(url);
        let url = visit_basic(raw).expect("failed");

        assert_eq!(url.schema, SchemeX::Trojan);
    }

    #[test]
    fn test_reconstruct_trojan_roundtrip() {
        let input = "trojan://humanity@172.64.152.23:443?security=tls&type=ws&path=/assignment&sni=www.creationlong.org";

        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = visit_basic(raw).expect("failed to parse");
        let reconstructed = parsed.reconstruct();

        let raw2 = crate::urlx::RawUrlX::from(reconstructed.as_str());
        let reparsed = visit_basic(raw2).expect("failed to re-parse");

        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
    }
}
