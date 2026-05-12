use base64::Engine;

use crate::urlx::{HostSpec, ParseError, PortSpec, RawUrlX, SchemeX, TinyText, UrlX, UserInfo};

pub struct SlipnetProto;

impl super::ProtoVisitor for SlipnetProto {
    fn parse(raw: &super::Input<'_>) -> Result<UrlX, super::ParseError> {
        let encrypted = matches!(raw.schema, SchemeX::SlipnetEnc);
        let config_data = UserInfo::new_from_b64(raw.userinfo)
            .map_err(|_| ParseError::InvalidUserInfo("Expected valid Base64".into()))?;

        if encrypted {
            return Ok(UrlX {
                uid: 0,
                sig: 0,
                schema: SchemeX::SlipnetEnc,
                username: config_data,
                password: None,
                host: None,
                port: None,
                path: None,
                query: vec![],
                transport: None,
                security: None,
                fragment: None,
            });
        }

        let Some(text) = config_data.as_text() else {
            return Err(super::ParseError::InvalidStructure(super::SchemeX::Slipnet));
        };

        let fields: Vec<&str> = text.split('|').collect();

        if fields.len() < 12 {
            return Err(super::ParseError::InvalidStructure(super::SchemeX::Slipnet));
        }

        let domain = fields
            .get(3)
            .copied()
            .filter(|s| !s.is_empty())
            .map(TinyText::from);
        let public_key = fields
            .get(11)
            .copied()
            .filter(|s| !s.is_empty())
            .map(TinyText::from);
        let tunnel_type = fields
            .get(1)
            .copied()
            .filter(|s| !s.is_empty())
            .map(TinyText::from);
        let local_port = fields.get(8).and_then(|s| s.parse::<u16>().ok());

        let host = domain
            .as_ref()
            .and_then(|d| rustls::pki_types::ServerName::try_from(d.as_str()).ok())
            .map(|s| s.to_owned());

        let query: Vec<(TinyText, Option<TinyText>)> = std::iter::empty()
            .chain(
                public_key
                    .as_ref()
                    .map(|pk| (TinyText::from("pk"), Some(pk.clone()))),
            )
            .chain(
                tunnel_type
                    .as_ref()
                    .map(|tt| (TinyText::from("type"), Some(tt.clone()))),
            )
            .collect();

        let port = local_port.map(PortSpec::new_with);

        let remarks = raw
            .fragment
            .map(urlencoding::decode)
            .transpose()
            .map_err(|e| super::ParseError::InvalidConf("remarks".into(), e.to_string().into()))?
            .map(TinyText::from);

        Ok(UrlX {
            uid: 0,
            sig: 0,
            schema: SchemeX::Slipnet,
            username: config_data,
            password: None,
            host,
            port,
            path: None,
            query,
            transport: tunnel_type,
            security: None,
            fragment: remarks,
        })
    }

    fn build(url: &UrlX) -> Result<String, super::ParseError> {
        let config_data = url
            .username
            .as_url_safe()
            .map_err(|e| ParseError::InvalidUserInfo(e.to_string().into()))?;
        let schema_str = url.schema.as_str();
        Ok(format!("{}://{}", schema_str, config_data))
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

    const SLIPNET_URL: &str = "slipnet://MjJ8ZG5zdHR8ZG5zdHQtc29ja3N8dC5zaGFtbG91Lm9ubGluZXw4LjguOC44OjUzOjB8MHw1MDAwfGJicnwxMDgwfDEyNy4wLjAuMXwwfDg0ZTcxMjU3ZjRjZDkyZThmZjFiZDFlNTFjOWE5NGY3MjRlOWU5MTM2MzgxNDliN2FlNDJmNjhiNjljNTRkMjd8aXJhbnV4fglyYW51eHwwfHx8MjJ8MHw0NS4xNDguMjguMTE1fDB8fHVkcHxwYXNzd29yZHx8fHwwfDQ0M3x8fDB8fDB8MHx8MHx8MHwwfDEwODB8MHx0eHR8MTAxfDB8MHwwfDB8MHwwfDB8fHw4MDgwfHwwfC98MXx8";

    #[test]
    fn test_slipnet() {
        let raw = crate::urlx::RawUrlX::from(SLIPNET_URL);
        let url = visit_basic(raw).expect("failed");
        assert_eq!(url.schema, SchemeX::Slipnet);
    }

    #[test]
    fn test_reconstruct_slipnet_roundtrip() {
        let raw = crate::urlx::RawUrlX::from(SLIPNET_URL);
        let parsed = visit_basic(raw).expect("failed to parse");
        let reconstructed = parsed.reconstruct();

        assert_eq!(
            SLIPNET_URL, reconstructed,
            "slipnet:// URLs must be exactly equal after reconstruction"
        );

        let raw2 = crate::urlx::RawUrlX::from(reconstructed.as_str());
        let reparsed = visit_basic(raw2).expect("failed to re-parse");

        assert_eq!(parsed.schema, reparsed.schema, "schema mismatch");
        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
    }

    #[test]
    fn test_slipnet_enc() {
        let input = "slipnet-enc://Ac3GD6rpCy53w/nMNSrt/pGttnE/aagWaQyqTM+rr1LJgl5T8xRs+5IWD/pe+tKPpz2eUHYXEza8roniezFp25RM6iHo902gfJYZFg5lGVaQMjwQPu6BlBBFSCjVehs70Kgf1Fx56ha566VkTPsJDu37in+EKjaHxijwEJydn4o8n6YgSoyOsxd9OzQufIXRkPM3K5FGFUG9nYSV4oBe2hUmtJVRT+q8CONfij91e9dn3FnbQfvkst08zfah4WaAHkJEIPw28CwzExsPOjRexMTmrRsZZZuliTRmncnM0gI6WmGGKe2jdizCZN6TnDM2efkWLjfWk3+d26O+xTgJZ+lUqI/h7swa11p2OzsAdNpNnNSCMECvM8TbTuwfFeY6X668AebOi8SVHTLe5S31+ZXObdlQYQFC57aU1XXmYjI6pPFbfWjPgvtmO9mR+GQ0yp0Gg+yM6ufxra4qDhmIQWbcTfqHCc1bxCMjyYdC9d+9TGapCM41IJwnoDl7zer2G+3NkEZ0E2edw4/lXxS3D95GN0PEudoi+ic/hnFeeMPUWFoAyApi9F/KwBItcjkSKqvkluNgQdzL0UmcLWkyVuhBJ8rWSdMU5ZKUqccpeiNKlKRhQ6a2b9Buiz4YxfQ4LRbVUVllZaX84hxJgMeaMg9Jp+CJmSyUD0QkN+si6pd6+31yRIZpFHGk0UnYJ9hZQuqeczecc88d0oRDMGf/rDBt198/caUJpKo=";

        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = visit_basic(raw).expect("failed");
        let reconstructed = parsed.reconstruct();

        assert_eq!(
            input, reconstructed,
            "slipnet-enc:// URLs must be exactly equal after reconstruction"
        );
    }
}
