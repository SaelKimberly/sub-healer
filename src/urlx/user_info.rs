#![allow(dead_code)]
use std::string::FromUtf8Error;

use base64::Engine;
use serde_json::Value;

use crate::{permissive_json, urlx::TinyText};

#[derive(Debug, thiserror::Error)]
pub enum UserInfoError {
    #[error("invalid base64: {0}")]
    InvalidBase64(#[from] base64::DecodeError),
    #[error("invalid utf8: {0}")]
    InvalidUtf8(#[from] FromUtf8Error),
    #[error("invalid json: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("broken json")]
    BrokenJson,
}

impl From<crate::utils::NomError<'_>> for UserInfoError {
    fn from(_e: crate::utils::NomError) -> Self {
        Self::BrokenJson
    }
}

/// Label, which says, how the raw underlying data should be encoded, when added to URL.
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UserInfoEncoding {
    /// Into Base64 (urlsafe)
    B64,
    /// Just urlencode (default)
    #[default]
    URL,
}

/// Contains decoded user info, with information about how it should be stored in URL.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UserInfo {
    /// Arbitrary text with encoding label
    Text(TinyText, UserInfoEncoding),
    /// Json value (parsed). Will always be encoded to Base64 (urlsafe)
    Json(Value),
}

fn decode_from_b64(data: &[u8]) -> Result<String, UserInfoError> {
    let data = 'block: {
        let e = match base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(data) {
            Ok(r) => break 'block r,
            Err(e) => e,
        };
        if let Ok(r) = base64::prelude::BASE64_STANDARD_NO_PAD.decode(data) {
            break 'block r;
        }
        // return error from url-safe version
        return Err(UserInfoError::InvalidBase64(e));
    };
    // 4: Then UTF-8 decoding
    let data = String::from_utf8(data)?;
    Ok(data)
}

impl UserInfo {
    /// data should be already decoded here. b64 will be used on serialization
    pub const fn new_from_json(data: Value) -> Self {
        Self::Json(data)
    }

    pub fn new_from_b64<S: AsRef<str>>(data: S) -> Result<Self, UserInfoError> {
        // 1: First, percent decoding (only %XX, no '+' -> ' ')
        let data = percent_encoding::percent_decode_str(data.as_ref())
            .collect::<Vec<_>>();
        let data = String::from_utf8(data).map_err(UserInfoError::InvalidUtf8)?;
        // 2: Trim optional '=' at the end
        let data = data.trim_end_matches(|c: char| c == '=' || c.is_whitespace());
        // 3: Then base64 decoding
        let data = decode_from_b64(data.as_bytes())?;
        Ok(Self::Text(data.into(), UserInfoEncoding::B64))
    }

    pub fn new_from<S: AsRef<str>>(data: S) -> Result<Self, UserInfoError> {
        // 1: First, percent decoding
        let data = urlencoding::decode(data.as_ref())?;
        Ok(Self::Text(data.as_ref().into(), UserInfoEncoding::URL))
    }

    /// Change encoding to base64
    pub const fn with_b64_encoding(&mut self) {
        if let Self::Text(_, e @ UserInfoEncoding::URL) = self {
            *e = UserInfoEncoding::B64;
        }
    }
    /// Change encoding to percent
    pub const fn with_pct_encoding(&mut self) {
        if let Self::Text(_, e @ UserInfoEncoding::B64) = self {
            *e = UserInfoEncoding::URL;
        }
    }

    pub fn is_text_and(&self, f: impl FnOnce(&TinyText) -> bool) -> Option<&TinyText> {
        match self {
            Self::Text(t, _) if f(t) => Some(t),
            _ => None,
        }
    }

    pub const fn as_json_mut(&mut self) -> Option<&mut Value> {
        match self {
            Self::Text(_, _) => None,
            Self::Json(v) => Some(v),
        }
    }

    pub const fn as_json(&self) -> Option<&Value> {
        match self {
            Self::Text(_, _) => None,
            Self::Json(v) => Some(v),
        }
    }
    pub const fn as_text(&self) -> Option<&TinyText> {
        match self {
            Self::Text(t, _) => Some(t),
            Self::Json(_) => None,
        }
    }

    /// Convert to string, using stored label.
    pub fn as_url_safe(&self) -> Result<String, UserInfoError> {
        match self {
            Self::Text(t, UserInfoEncoding::B64) => {
                Ok(base64::prelude::BASE64_URL_SAFE.encode(t.as_bytes()))
            }
            Self::Text(t, UserInfoEncoding::URL) => {
                Ok(urlencoding::encode(t.as_ref()).into_owned())
            }
            Self::Json(v) => {
                let encoded =
                    serde_json::to_string(v).map(|s| base64::prelude::BASE64_URL_SAFE.encode(s))?;
                Ok(encoded)
            }
        }
    }

    /// Change the encoding label (if not already), to Base64 (urlsafe)
    pub fn as_base64_decoded(&mut self) -> Result<&mut Self, UserInfoError> {
        if let Self::Text(t, e @ UserInfoEncoding::URL) = self {
            *t = decode_from_b64(t.as_bytes())?.into();
            *e = UserInfoEncoding::B64;
        }

        Ok(self)
    }

    /// Try to change internal representation of data into parsed Json.
    pub fn as_json_decoded(&mut self, permissive: bool) -> Result<&mut Value, std::io::Error> {
        let text = match self {
            Self::Text(t, _) => t,
            Self::Json(v) => return Ok(v),
        };
        let value = if permissive {
            let (_, value) = permissive_json(text.as_bytes().into()).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Cannot parse JSON: {e}"),
                )
            })?;
            value
        } else {
            serde_json::from_slice(text.as_bytes()).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Cannot parse JSON: {e}"),
                )
            })?
        };
        *self = Self::Json(value);
        match self {
            Self::Json(v) => Ok(v),
            Self::Text(_, _) => unreachable!(),
        }
    }
}

impl std::fmt::Display for UserInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text(t, _) => f.write_str(t.as_ref()),
            Self::Json(v) => f.write_str(
                serde_json::to_string(v)
                    .map_err(|_| std::fmt::Error {})?
                    .as_str(),
            ),
        }
    }
}

impl From<Value> for UserInfo {
    fn from(v: Value) -> Self {
        Self::Json(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::literal_string_with_formatting_args)]
    #[test]
    fn test_url_safe() {
        let expected = "some useful text";
        let userinfo = urlencoding::encode(expected);
        let userinfo = UserInfo::new_from(userinfo).unwrap();

        if userinfo.as_text().map(TinyText::as_str) == Some("some useful text") {
        } else {
            panic!()
        }

        let raw_json = "{a:b}";
        let expected = serde_json::json!({"a":"b"});

        let userinfo = base64::prelude::BASE64_URL_SAFE.encode(raw_json);

        let mut userinfo = UserInfo::new_from_b64(userinfo).unwrap();
        _ = userinfo.as_json_decoded(true).unwrap();

        if userinfo.as_json().unwrap() == &expected {
        } else {
            panic!()
        }

        let userinfo = base64::prelude::BASE64_STANDARD_NO_PAD.encode(raw_json);

        let mut userinfo = UserInfo::new_from_b64(userinfo).unwrap();
        _ = userinfo.as_json_decoded(true).unwrap();

        if userinfo.as_json().unwrap() == &expected {
        } else {
            panic!()
        }

        eprintln!("{userinfo} => {}", userinfo.as_url_safe().unwrap());
    }
}
