use std::borrow::Cow;

/// This function is used to normalize the `extra` query part of V2ray URL.
///
/// It will try to recover JSON with a very permissive parser, and reencode it to urlencoded.
///
/// This fixes following issues:
/// - not encoded extras (raw JSON)
/// - python dicts: str(dict(...) instead of json.dumps(dict(...))
/// - multiline JSON / python dict
/// - JSON with missing quotes
/// - truncated JSON (if you have a good luck, there may be just missing brackets at the end)
///
/// After this normalizing step, all V2ray URLs should be valid on a single line
/// When no extras found, no data copy will be performed
pub fn normalize_extras<'a>(span: &'a [u8]) -> Cow<'a, [u8]> {
    const EXTRA_PREFIX: &str = "extra=";
    const EXTRA_PREFIX_LEN: usize = 6;
    let finder = bstr::Finder::new(EXTRA_PREFIX);

    let mut result = Vec::<Cow<'a, [u8]>>::new();

    let mut chunk = span;
    let mut found = false;
    while let Some(pos) = finder.find(chunk) {
        let (prefix, potential_area) = chunk.split_at(pos + EXTRA_PREFIX_LEN);

        result.push(Cow::Borrowed(prefix));

        if let Ok((tail, res)) = super::permissive_json::permissive_json_core(potential_area.into()) {
            let Ok(res) = serde_json::to_string(&res) else {
                unreachable!("Should never fail");
            };
            let encoded = urlencoding::encode(res.as_str()).into_owned();

            let original_area = &potential_area[..potential_area.len() - tail.len()];

            found = original_area != encoded.as_bytes();
            if found {
                result.push(Cow::Owned(encoded.as_bytes().to_owned()));
            } else {
                result.push(Cow::Borrowed(original_area));
            }

            chunk = tail.into_fragment();
        } else {
            chunk = potential_area;
        }
    }
    if found {
        Cow::Owned(result.join(&b""[..]))
    } else {
        Cow::Borrowed(span)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_encode_not_encoded() {
        let s = "extra={'a':'b'}";
        let n = super::normalize_extras(s.as_bytes());
        let x = unsafe { str::from_utf8_unchecked(n.as_ref()) };
        // -> valid json, urlencoded: extra={"a":"b"}
        assert_eq!(x, "extra=%7B%22a%22%3A%22b%22%7D");
    }

    #[test]
    fn test_not_valid_encoded() {
        // -> invalid json, urlencoded: extra={'a':'b'}
        let s = "extra=%7B%27a%27%3A%27b%27%7D";
        let n = super::normalize_extras(s.as_bytes());
        let x = unsafe { str::from_utf8_unchecked(n.as_ref()) };
        // -> valid json, urlencoded: extra={"a":"b"}
        assert_eq!(x, "extra=%7B%22a%22%3A%22b%22%7D");
    }

    #[test]
    fn test_not_valid_not_encoded() {
        // -> invalid json, multiline, not encoded
        let s = "extra={
            'a': True
        }";
        let n = super::normalize_extras(s.as_bytes());
        let x = unsafe { str::from_utf8_unchecked(n.as_ref()) };
        // -> valid json, urlencoded: extra={"a":true}
        assert_eq!(x, "extra=%7B%22a%22%3Atrue%7D");
    }
}
