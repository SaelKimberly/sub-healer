use base64::Engine;

use crate::urlx::{HostSpec, ParseError, PortSpec, RawUrlX, SchemeX, TinyText, UrlX, UserInfo};

pub struct SsProto;

impl super::ProtoVisitor for SsProto {
    fn parse(raw: &super::Input<'_>) -> Result<UrlX, super::ParseError> {
        let (userinfo, hostport) = if let Some(hostport) = raw.hostport {
            // Scenario 1: separate userinfo and hostport
            let userinfo = UserInfo::new_from_b64(raw.userinfo).map_err(|e| {
                super::ParseError::InvalidUserInfo(format!("{}: {}", raw.userinfo, e).into())
            })?;
            (
                userinfo.as_text().expect("should be text").clone(),
                TinyText::from(hostport),
            )
        } else {
            // Scenario 2: encoded userinfo contains hostport
            let userinfo = UserInfo::new_from_b64(raw.userinfo).map_err(|e| {
                super::ParseError::InvalidUserInfo(format!("{}: {}", raw.userinfo, e).into())
            })?;

            let userinfo = userinfo.as_text().expect("should be text");

            let (userinfo, hostport) = userinfo.split_once('@').ok_or_else(|| {
                super::ParseError::InvalidUserInfo(
                    format!("{}: missing hostport", raw.userinfo).into(),
                )
            })?;

            (userinfo.into(), TinyText::from(hostport))
        };

        // Parse hostport
        let (host, port) = super::_parse_hostport(hostport.as_str())?;

        // Parse userinfo as method:password
        let Some((method, password)) = userinfo.split_once(':') else {
            return Err(super::ParseError::InvalidUserInfo(
                format!("{}: missing password", raw.userinfo).into(),
            ));
        };

        // Extract fragment
        let fragment = raw
            .fragment
            .map(urlencoding::decode)
            .transpose()
            .map_err(|e| super::ParseError::InvalidConf("remarks".into(), e.to_string().into()))?
            .map(TinyText::from);

        Ok(UrlX {
            uid: 0,
            sig: 0,
            schema: SchemeX::SS,
            username: UserInfo::Text(format!("{method}:{password}").into(), UserInfoEncoding::B64),
            password: Some(password.into()),
            host: Some(host),
            port: Some(port),
            path: None,
            query: vec![],
            transport: Some("tcp".into()),
            security: Some(method.into()),
            fragment,
        })
    }

    fn build(url: &UrlX) -> Result<String, super::ParseError> {
        let encoded = url
            .username
            .as_url_safe()
            .map_err(|e| ParseError::InvalidUserInfo(format!("{}: {}", url.username, e).into()))?;
        let hostport = url._safe_hostport(None)?;
        Ok(format!("ss://{}@{}", encoded, hostport))
    }

    fn visit(url: &mut UrlX) -> Result<(), super::ParseError> {
        let mut sig_parts = Vec::new();
        sig_parts.push(url.schema.as_str().as_bytes());

        if let Some(ref security) = url.security {
            sig_parts.push(security.as_bytes());
        }

        let sig_data = sig_parts.concat();
        url.sig = rapidhash::v3::rapidhash_v3(&sig_data);

        let (uid, _) = super::_compute_uid(url);
        url.uid = uid;

        Ok(())
    }
}

// Need UserInfoEncoding for the parse method
use crate::urlx::user_info::UserInfoEncoding;

#[cfg(test)]
mod tests {
    use super::super::super::try_accept_raw as visit_basic;
    use crate::urlx::SchemeX;

    #[test]
    fn test_ss() {
        let url = "ss://Y2xlb2Y6cGFzc3dvcmRAMTwzMC4wLjE2MDo4MDgw@127.0.0.1:8080";
        let raw = crate::urlx::RawUrlX::from(url);
        let url = visit_basic(raw).expect("failed");
        assert_eq!(url.schema, SchemeX::SS);
    }

    #[test]
    fn test_reconstruct_ss_roundtrip() {
        let input = "ss://Y2xlb2Y6cGFzc3dvcmRAMTwzMC4wLjE2MDo4MDgw@127.0.0.1:8080";
        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = visit_basic(raw).expect("failed to parse");
        let reconstructed = parsed.reconstruct();
        eprintln!("input:        {}", input);
        eprintln!("reconstructed: {}", reconstructed);

        let raw2 = crate::urlx::RawUrlX::from(reconstructed.as_str());
        let reparsed = visit_basic(raw2).expect("failed to re-parse");

        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
    }
}
