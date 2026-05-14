use crate::urlx::{HostSpec, PortSpec, RawUrlX, SchemeX, TinyText, UrlX, UserInfo};

pub struct TgProto;

impl super::ProtoVisitor for TgProto {
    fn parse(raw: &super::Input<'_>) -> Result<UrlX, super::ParseError> {
        let is_socks = if raw.schema == SchemeX::Https && raw.userinfo == "t.me" {
            match raw.path {
                Some("/socks") => true,
                Some("/proxy") => false,
                _ => return Err(super::ParseError::InvalidStructure(SchemeX::Tg)),
            }
        } else if raw.schema == SchemeX::Tg {
            match raw.userinfo {
                "socks" => true,
                "proxy" => false,
                _ => return Err(super::ParseError::InvalidStructure(SchemeX::Tg)),
            }
        } else {
            return Err(super::ParseError::InvalidStructure(raw.schema.clone()));
        };

        let query = raw
            .query()
            .map_err(|e| super::ParseError::InvalidConf("query".into(), e.to_string().into()))?;

        let host: HostSpec = {
            let host_raw = query
                .iter()
                .find_map(|(k, v)| if k == "server" { v.as_ref() } else { None })
                .ok_or(super::ParseError::MissingHost)?;
            rustls::pki_types::ServerName::try_from(host_raw.as_str())
                .map_err(|e| super::ParseError::InvalidConf("server".into(), e.to_string().into()))?
                .to_owned()
        };

        let port: PortSpec = {
            let port_raw = query
                .iter()
                .find_map(|(k, v)| if k == "port" { v.as_ref() } else { None })
                .ok_or(super::ParseError::MissingPort)?;

            port_raw
                .parse::<u16>()
                .map(PortSpec::new_with)
                .map_err(|e| super::ParseError::InvalidConf("port".into(), e.to_string().into()))?
        };

        let secret = query
            .iter()
            .find_map(|(k, v)| if k == "secret" { v.as_ref() } else { None })
            .ok_or(super::ParseError::MissingConf("secret".into()))?;

        let remarks = raw
            .fragment
            .map(urlencoding::decode)
            .transpose()
            .map_err(|e| super::ParseError::InvalidConf("remarks".into(), e.to_string().into()))?
            .map(TinyText::from);

        Ok(UrlX {
            uid: 0,
            sig: 0,
            schema: SchemeX::Tg,
            username: UserInfo::Text(secret.to_owned(), UserInfoEncoding::URL),
            password: Some(secret.to_owned()),
            host: Some(host),
            port: Some(port),
            path: None,
            query: vec![],
            transport: Some(if is_socks { "socks" } else { "mtproto" }.into()),
            security: Some("tls".into()),
            fragment: remarks,
        })
    }

    fn build(url: &UrlX) -> Result<String, super::ParseError> {
        let userinfo = url
            .transport
            .as_ref()
            .and_then(|t| (t.as_str() == "socks").then_some("socks"))
            .unwrap_or("proxy");

        let secret = url
            .password
            .as_ref()
            .ok_or_else(|| super::ParseError::MissingConf("password".into()))?;

        let host_str = url
            .host
            .as_ref()
            .map(|h| h.to_str().into_owned())
            .unwrap_or_default();

        let port_str = url.port.as_ref().map(|p| p.to_string()).unwrap_or_default();

        let tg_url = url::Url::parse(
            format!(
                "tg://{}?server={}&port={}&secret={}",
                userinfo, host_str, port_str, secret
            )
            .as_str(),
        )
        .map_err(|e| super::ParseError::Unknown(e.into()))?;

        Ok(tg_url.to_string())
    }

    fn visit(url: &mut UrlX) -> Result<(), super::ParseError> {
        let mut sig_parts = Vec::new();
        sig_parts.push(url.schema.as_str().as_bytes());

        if let Some(ref transport) = url.transport {
            sig_parts.push(transport.as_bytes());
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
    fn test_tg() {
        let url = "https://t.me/proxy?server=146.185.211.126&port=443&secret=ee1e36377253a29133d290f3d14ae0163873756e342d32302e757365726170692e636f6d";

        let raw = crate::urlx::RawUrlX::from(url);
        let url = visit_basic(raw).expect("failed");

        assert_eq!(url.schema, SchemeX::Tg);
    }

    #[test]
    fn test_tg_hostname() {
        let url = "https://t.me/proxy?server=proxium.rest&port=888&secret=a669r5a45920422f9d417e4867efdc4fb8jllllloo9w88220wpwoow9";

        let raw = crate::urlx::RawUrlX::from(url);
        let url = visit_basic(raw).expect("failed");

        assert_eq!(url.schema, SchemeX::Tg);
    }

    #[test]
    fn test_reconstruct_tg_roundtrip() {
        let input = "https://t.me/proxy?server=146.185.211.126&port=443&secret=ee1e36377253a29133d290f3d14ae0163873756e342d32302e757365726170692e636f6d";

        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = visit_basic(raw).expect("failed to parse");
        let reconstructed = parsed.reconstruct();

        assert!(
            reconstructed.contains("server="),
            "should contain server param"
        );
        assert!(reconstructed.contains("port="), "should contain port param");
        assert!(
            reconstructed.contains("secret="),
            "should contain secret param"
        );
    }
}
