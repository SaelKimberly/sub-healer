use crate::urlx::{HostSpec, PortSpec, ParseError, SchemeX, TinyText, UrlX, UserInfo};

pub struct StormdnsProto;

impl super::ProtoVisitor for StormdnsProto {
    fn parse(raw: &super::Input<'_>) -> Result<UrlX, ParseError> {
        let raw_userinfo = raw.userinfo;
        let mut userinfo = UserInfo::new_from_b64(raw_userinfo)
            .map_err(|_| ParseError::InvalidStructure(SchemeX::Stormdns))?;
        let json = userinfo
            .as_json_decoded(true)
            .map_err(|_| ParseError::InvalidStructure(SchemeX::Stormdns))?
            .clone();

        let schema = json
            .get("schema")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ParseError::InvalidStructure(SchemeX::Stormdns))?;
        if schema != "whitedns.profile" {
            tracing::warn!(target: "visit", "Unknown stormdns schema: {schema}");
            return Err(ParseError::InvalidStructure(SchemeX::Stormdns));
        }

        let version = json
            .get("version")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| ParseError::InvalidStructure(SchemeX::Stormdns))?;
        if version != 1 {
            tracing::warn!(target: "visit", "Unknown stormdns version: {version}");
            return Err(ParseError::InvalidStructure(SchemeX::Stormdns));
        }

        let profile = json
            .get("profile")
            .ok_or_else(|| ParseError::MissingConf("profile".into()))?;

        let name = profile
            .get("name")
            .and_then(|v| v.as_str())
            .map(TinyText::from);

        let server = profile
            .get("server")
            .ok_or_else(|| ParseError::MissingConf("profile.server".into()))?;

        let domain = server
            .get("domain")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ParseError::MissingConf("profile.server.domain".into()))?
            .to_owned();

        let host: HostSpec = rustls::pki_types::ServerName::try_from(domain.as_str())
            .map_err(|e| ParseError::InvalidHost(format!("{domain}: {e}").into()))?
            .to_owned();

        let encryption_key = server
            .get("encryption_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ParseError::MissingConf("profile.server.encryption_key".into()))?
            .to_owned();

        let encryption_method = server
            .get("encryption_method")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| ParseError::MissingConf("profile.server.encryption_method".into()))?;

        Ok(UrlX {
            uid: 0,
            sig: 0,
            schema: SchemeX::Stormdns,
            host: Some(host),
            port: Some(PortSpec::new_with(53)),
            transport: Some(TinyText::from(format!("enc{}", encryption_method))),
            security: None,
            username: userinfo,
            password: Some(TinyText::from(encryption_key)),
            path: None,
            query: vec![],
            fragment: name,
        })
    }

    fn build(url: &UrlX) -> Result<String, ParseError> {
        let username = url
            .username
            .as_url_safe()
            .map_err(|e| ParseError::InvalidUserInfo(e.to_string().into()))?;
        Ok(format!("{}://{}", url.schema.as_str(), username))
    }

    fn visit(url: &mut UrlX) -> Result<(), ParseError> {
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
