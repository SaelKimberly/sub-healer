use std::num::NonZeroUsize;

use bstr::ByteSlice;
use winnow::{
    ModalResult, Parser,
    combinator::fail,
    error::{ContextError, ErrMode, Needed, ParserError, StrContext, StrContextValue},
};

use crate::Span;

pub(crate) struct PercentDecode<'a> {
    pub(super) span: Span<'a>,
    iter: bstr::CharIndices<'a>,
    decode: bool,
}

impl<'a> PercentDecode<'a> {
    pub(super) fn new(span: Span<'a>) -> Self {
        Self {
            span,
            iter: (*span.as_ref()).char_indices(),
            decode: true,
        }
    }

    

    pub(super) fn error<T>(&mut self, context: &'static str) -> ModalResult<T> {
        Parser::context(
            fail,
            StrContext::Expected(StrContextValue::Description(context)),
        )
        .parse_next(&mut self.span)
    }

    pub(super) fn with_decoding(mut self, decoding: bool) -> Self {
        self.decode = decoding;
        self
    }

    fn next_impl(&mut self) -> ModalResult<Option<(usize, usize, char)>> {
        match self.iter.next() {
            Some((c_s, _, '%')) if self.decode => {
                let (_, _, h) = self.iter.next().ok_or_else(|| {
                    ErrMode::Incomplete(Needed::Size(unsafe { NonZeroUsize::new_unchecked(2) }))
                })?;
                let h = h
                    .to_digit(16)
                    .ok_or_else(|| ErrMode::Cut(ContextError::from_input(&self.span)))?;

                let (_, c_e, l) = self.iter.next().ok_or_else(|| {
                    ErrMode::Incomplete(Needed::Size(unsafe { NonZeroUsize::new_unchecked(1) }))
                })?;
                let l = l
                    .to_digit(16)
                    .ok_or_else(|| ErrMode::Cut(ContextError::from_input(&self.span)))?;

                Ok(Some((c_s, c_e, ((h << 4 | l) as u8) as char)))
            }
            Some((c_s, c_e, c)) => Ok(Some((c_s, c_e, c))),
            None => Ok(None),
        }
    }
}

impl<'a> Iterator for PercentDecode<'a> {
    type Item = ModalResult<(usize, usize, char)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_impl().transpose()
    }
}
