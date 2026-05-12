use crate::urlx::{SchemeX, UrlX};

pub struct WireguardProto;

impl super::ProtoVisitor for WireguardProto {
    fn parse(_raw: &super::Input<'_>) -> Result<UrlX, super::ParseError> {
        // WireGuard currently falls through to the fallback in the dispatcher
        Err(super::ParseError::InvalidStructure(SchemeX::WireGuard))
    }

    fn build(_url: &UrlX) -> Result<String, super::ParseError> {
        Err(super::ParseError::InvalidStructure(SchemeX::WireGuard))
    }

    fn visit(_url: &mut UrlX) -> Result<(), super::ParseError> {
        // TODO: implement sig/uid computation
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::try_accept_raw as visit_basic;
    use crate::urlx::SchemeX;

    #[test]
    fn test_reconstruct_wireguard() {
        // WireGuard currently delegates to fallback reconstruction.
        // This test validates roundtripping through the fallback path.
        let input = "wireguard://MHlIYW5kYWNlZToxMjcuMC4wLjE6ODQ4Mw==";

        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = visit_basic(raw).expect("failed to parse");

        assert_eq!(parsed.schema, SchemeX::WireGuard);

        let reconstructed = parsed.reconstruct();

        let raw2 = crate::urlx::RawUrlX::from(reconstructed.as_str());
        let reparsed = visit_basic(raw2).expect("failed to re-parse");

        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
    }
}
