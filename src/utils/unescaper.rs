#[derive(thiserror::Error, Debug)]
pub enum UnescapeError {
    #[error("Invalid UTF-8: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),
    #[error("Encoding \"{0}\" was detected, but some characters were replaced")]
    EncodingFlaw(&'static str),
    #[error("Invalid JSON escape sequence: {0}")]
    InvalidJsonEscape(#[from] escape8259::UnescapeError),
    #[error("Invalid Unicode escape sequence: {0}")]
    InvalidUnicodeEscape(#[from] unescaper::Error),
}

#[derive(Default)]
pub struct Unescaper {
    chardet: (bool, bool),
    enc_pct: bool,
    enc8259: Option<bool>,
    enc_uni: Option<bool>,
}

impl Unescaper {
    #[inline]
    pub const fn enc_pct(mut self) -> Self {
        self.enc_pct = true;
        self
    }
    #[inline]
    pub const fn enc8259(mut self, bypass: bool) -> Self {
        self.enc8259 = Some(bypass);
        self
    }
    #[inline]
    pub const fn enc_uni(mut self, bypass: bool) -> Self {
        self.enc_uni = Some(bypass);
        self
    }
    #[inline]
    pub const fn chardet(mut self, enable: bool, bypass: bool) -> Self {
        self.chardet = (enable, bypass);
        self
    }

    pub fn do_unescape<'a>(self, span: &'a [u8]) -> core::result::Result<String, UnescapeError> {
        let s: std::borrow::Cow<'a, [u8]> = if self.enc_pct {
            percent_encoding::percent_decode(span).into()
        } else {
            std::borrow::Cow::Borrowed(span)
        };

        let mut s: String = match self.chardet {
            (true, bypass) => {
                let enc = {
                    let mut enc =
                        chardetng::EncodingDetector::new(chardetng::Iso2022JpDetection::Allow);
                    enc.feed(s.as_ref(), true);
                    enc.guess(None, chardetng::Utf8Detection::Allow)
                };

                let (s, e, replaced) = enc.decode(s.as_ref());
                if replaced && !bypass {
                    return Err(UnescapeError::EncodingFlaw(e.name()));
                }
                s.into_owned()
            }
            (false, bypass) => {
                if bypass {
                    String::from_utf8_lossy(s.as_ref()).into_owned()
                } else {
                    str::from_utf8(s.as_ref())?.to_owned()
                }
            }
        };

        if let Some(bypass) = self.enc8259 {
            match escape8259::unescape(s.as_str()) {
                Ok(unescaped) => {
                    s = unescaped;
                }
                Err(e) => {
                    if !bypass {
                        return Err(UnescapeError::from(e));
                    }
                }
            }
        }

        if let Some(bypass) = self.enc_uni {
            match unescaper::unescape(s.as_str()) {
                Ok(unescaped) => {
                    s = unescaped;
                }
                Err(e) => {
                    if !bypass {
                        return Err(UnescapeError::from(e));
                    }
                }
            }
        }

        Ok(s)
    }
}
