use crate::{CutResult, Span};

#[derive(Default)]
pub struct Unescaper {
    chardet: (bool, bool),
    enc_pct: bool,
    enc8259: Option<bool>,
    enc_uni: Option<bool>,
}

impl Unescaper {
    #[inline]
    pub fn enc_pct(mut self) -> Self {
        self.enc_pct = true;
        self
    }
    #[inline]
    pub fn enc8259(mut self, bypass: bool) -> Self {
        self.enc8259 = Some(bypass);
        self
    }
    #[inline]
    pub fn enc_uni(mut self, bypass: bool) -> Self {
        self.enc_uni = Some(bypass);
        self
    }
    #[inline]
    pub fn chardet(mut self, enable: bool, bypass: bool) -> Self {
        self.chardet = (enable, bypass);
        self
    }

    pub fn do_unescape<'a>(self, span: Span<'a>) -> CutResult<'a, String> {
        let s: std::borrow::Cow<'a, [u8]> = if self.enc_pct {
            percent_encoding::percent_decode(span.as_ref()).into()
        } else {
            std::borrow::Cow::Borrowed(span.as_ref())
        };

        let mut s: String = match self.chardet {
            (true, bypass) => {
                let enc = {
                    let mut enc =
                        chardetng::EncodingDetector::new(chardetng::Iso2022JpDetection::Allow);
                    enc.feed(s.as_ref(), true);
                    enc.guess(None, chardetng::Utf8Detection::Allow)
                };

                let (s, _, replaced) = enc.decode(s.as_ref());
                if replaced && !bypass {
                    return Err(crate::InputError::at(span));
                } else {
                    s.into_owned()
                }
            }
            (false, bypass) => {
                if bypass {
                    String::from_utf8_lossy(s.as_ref()).into_owned()
                } else {
                    str::from_utf8(s.as_ref())
                        .map_err(|_| crate::InputError::at(span))?
                        .to_owned()
                }
            }
        };

        if let Some(bypass) = self.enc8259 {
            if let Ok(unescaped) = escape8259::unescape(s.as_str()) {
                s = unescaped
            } else if !bypass {
                return Err(crate::InputError::at(span));
            }
        };

        if let Some(bypass) = self.enc_uni {
            if let Ok(unescaped) = unescaper::unescape(s.as_str()) {
                s = unescaped
            } else if !bypass {
                return Err(crate::InputError::at(span));
            }
        };

        Ok(s)
    }
}
