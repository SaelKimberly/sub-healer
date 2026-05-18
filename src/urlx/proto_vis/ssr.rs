use base64::Engine;

use crate::urlx::{HostSpec, PortSpec, RawUrlX, SchemeX, TinyText, UrlX, UserInfo};

use std::collections::BTreeMap;

pub struct SsrProto;

impl super::ProtoVisitor for SsrProto {
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
            return Err(super::ParseError::InvalidStructure(super::SchemeX::SSR));
        };

        // 2: Verify, that userinfo is base64
        let Ok(userinfo) = UserInfo::new_from_b64(userinfo) else {
            return Err(super::ParseError::InvalidStructure(super::SchemeX::SSR));
        };
        let Some(text) = userinfo.as_text().cloned() else {
            unreachable!();
        };

        // 3: Verify, that userinfo is in the correct format
        let &[raw_host, raw_port, protocol, method, obfs, raw_password] =
            text.split(':').collect::<Vec<_>>().as_slice()
        else {
            return Err(super::ParseError::InvalidStructure(super::SchemeX::SSR));
        };

        // Parse host
        let host: HostSpec = rustls::pki_types::ServerName::try_from(raw_host)
            .map_err(|_| super::ParseError::InvalidHost(raw_host.to_owned().into()))?
            .to_owned();

        // Parse port
        let port = raw_port
            .parse::<u16>()
            .map(PortSpec::new_with)
            .map_err(|_| super::ParseError::InvalidPort(raw_port.to_owned().into()))?;

        // Make security and transport
        let security: TinyText = TinyText::from(method);
        let transport: TinyText = "tcp".into();

        // Extract password and query-like params
        let Some((password, query)) = raw_password
            .split_once("/?")
            .or_else(|| raw_password.split_once('?'))
        else {
            return Err(super::ParseError::InvalidStructure(super::SchemeX::SSR));
        };

        // Construct params
        let mut query_pairs = if query.is_empty() {
            BTreeMap::new()
        } else {
            query
                .split('&')
                .map(|s| {
                    if let Some((k, v)) = s.split_once('=') {
                        if v.is_empty() {
                            (k, Option::<TinyText>::None)
                        } else {
                            (k, Some(v.into()))
                        }
                    } else {
                        (s, None)
                    }
                })
                .collect::<BTreeMap<_, _>>()
        };

        // Extract remarks
        let remarks = if let Some(e) = query_pairs.remove("remarks") {
            let Some(remarks) = e else {
                return Err(super::ParseError::InvalidConf(
                    "remarks (should be base64)".into(),
                    "".into(),
                ));
            };
            let decoded = base64::prelude::BASE64_URL_SAFE_NO_PAD
                .decode(remarks.trim_end_matches('='))
                .map_err(|_| {
                    super::ParseError::InvalidConf(
                        "remarks (should be base64)".into(),
                        remarks.to_string().into(),
                    )
                })?;
            let decoded = urlencoding::decode_binary(decoded.as_ref());
            let decoded = str::from_utf8(decoded.as_ref()).map_err(|_| {
                super::ParseError::InvalidConf(
                    "remarks (should be utf8)".into(),
                    remarks.to_string().into(),
                )
            })?;
            Some(decoded.into())
        } else {
            None
        };

        // Build username for identification
        let username = UserInfo::Text(
            format!(
                "{}:{}:{}:{}:{}:{}/?{}",
                raw_host,
                raw_port,
                protocol,
                method,
                obfs,
                password,
                query_pairs
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v.as_deref().unwrap_or_default()))
                    .collect::<Vec<_>>()
                    .join("&")
            )
            .into(),
            UserInfoEncoding::B64,
        );

        Ok(UrlX {
            uid: 0,
            sig: 0,
            schema: SchemeX::SSR,
            username,
            password: Some(password.into()),
            host: Some(host),
            port: Some(port),
            path: None,
            query: [
                (TinyText::from("protocol"), Some(protocol.into())),
                (TinyText::from("obfs"), Some(obfs.into())),
            ]
            .into_iter()
            .chain(query_pairs.into_iter().map(|(k, v)| (k.into(), v)))
            .collect(),
            transport: Some(transport),
            security: Some(security),
            fragment: remarks,
        })
    }

    fn build(url: &UrlX) -> Result<String, super::ParseError> {
        // SSR embeds connection parameters in the username field.
        // Reconstruct by re-encoding the stored userinfo to base64.
        let username = url
            .username
            .as_url_safe()
            .map_err(|e| super::ParseError::InvalidUserInfo(e.to_string().into()))?;
        Ok(format!("{}://{}", url.schema.as_str(), username))
    }

    fn visit(url: &mut UrlX) -> Result<(), super::ParseError> {
        let mut sig_parts = Vec::new();
        sig_parts.push(url.schema.as_str().as_bytes());

        for (key, value) in &url.query {
            if key.as_str() == "remarks" {
                continue;
            }
            sig_parts.push(key.as_bytes());
            if let Some(v) = value {
                sig_parts.push(v.as_bytes());
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

    const SSR_URL: &str = "ssr://MTA3LjE1MS4xODIuMjUzOjgwODA6b3JpZ2luOnJjNC1tZDU6cGxhaW46TVRSbVJsQnlZbVY2UlROSVJGcDZjMDFQY2pZLz9ncm91cD1VMU5TVUhKdmRtbGtaWEkmcmVtYXJrcz04Si1IdXZDZmg3Z2dVMU5TTGVlLWp1V2J2UzFPUnVpbm8tbVVnZWlIcXVXSXR1V0pweTFEYUdGMFIxQlVMVlJwYTFSdmF5MVpiM1ZVZFdKbExURXdOeTR4TlRFdU1UZ3lMkkxTXpvNE1EZ3cmb2Jmc3BhcmFtPSZwcm90b3BhcmFtPQ";

    #[test]
    fn test_ssr() {
        let raw = crate::urlx::RawUrlX::from(SSR_URL);
        let url = visit_basic(&raw).expect("failed");
        assert_eq!(url.schema, SchemeX::SSR);
    }

    #[test]
    fn test_reconstruct_ssr_roundtrip() {
        let raw = crate::urlx::RawUrlX::from(SSR_URL);
        let parsed = visit_basic(&raw).expect("failed to parse");
        let reconstructed = parsed.reconstruct();

        assert!(
            reconstructed.starts_with("ssr://"),
            "should start with ssr://"
        );

        let raw2 = crate::urlx::RawUrlX::from(reconstructed.as_str());
        let reparsed = visit_basic(&raw2).expect("failed to re-parse");

        assert_eq!(parsed.schema, reparsed.schema, "schema mismatch");
        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
    }
}
