use std::num::NonZeroUsize;

use bstr::ByteSlice;
use nom::{
    AsBytes, Input, Offset,
    error::{Error, ErrorKind},
};

use super::{CutResult, NomError, Span};

pub struct PercentDecode<'a> {
    pub(super) span: Span<'a>,
    iter: bstr::CharIndices<'a>,
    decode: bool,
}

impl<'a> PercentDecode<'a> {
    pub(super) fn new(span: Span<'a>) -> Self {
        Self {
            span,
            iter: (*span.fragment()).char_indices(),
            decode: true,
        }
    }

    pub(super) fn error(&self, kind: ErrorKind) -> NomError<'a> {
        nom::Err::Error(Error::new(self.span, kind))
    }

    pub(super) const fn with_decoding(mut self, decoding: bool) -> Self {
        self.decode = decoding;
        self
    }

    fn current_offset(&self) -> usize {
        self.span.as_bytes().offset(self.iter.as_bytes())
    }

    fn next_impl(&mut self) -> CutResult<'a, Option<(usize, usize, char)>> {
        const NEED1: nom::Needed = nom::Needed::Size(NonZeroUsize::new(1).unwrap());
        const NEED2: nom::Needed = nom::Needed::Size(NonZeroUsize::new(2).unwrap());

        let offset = self.current_offset();

        match self.iter.next() {
            Some((c_s, _, '%')) if self.decode => {
                let Some((_, _, h)) = self.iter.next() else {
                    return Err(nom::Err::Incomplete(NEED2));
                };
                let Some(h) = h.to_digit(16) else {
                    return Err(nom::Err::Error(nom::error::make_error(
                        self.span.take_from(offset),
                        nom::error::ErrorKind::HexDigit,
                    )));
                };
                let Some((_, c_e, l)) = self.iter.next() else {
                    return Err(nom::Err::Incomplete(NEED1));
                };
                let Some(l) = l.to_digit(16) else {
                    return Err(nom::Err::Error(nom::error::make_error(
                        self.span.take_from(offset),
                        nom::error::ErrorKind::HexDigit,
                    )));
                };
                #[allow(clippy::cast_possible_truncation)]
                Ok(Some((c_s, c_e, ((h << 4 | l) as u8) as char)))
            }
            Some((c_s, c_e, c)) => Ok(Some((c_s, c_e, c))),
            None => Ok(None),
        }
    }
}

impl<'a> Iterator for PercentDecode<'a> {
    type Item = CutResult<'a, (usize, usize, char)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_impl().transpose()
    }
}
