#![allow(dead_code)]
mod utils;

pub type Span<'a> = winnow::LocatingSlice<&'a [u8]>;

pub type CutResult<'a, T> = core::result::Result<T, winnow::error::InputError<Span<'a>>>;

pub use winnow::{Result, error::InputError};
