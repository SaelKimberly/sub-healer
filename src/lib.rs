#![warn(clippy::nursery, clippy::pedantic)]
#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
pub mod db;
pub mod decoder;
pub mod mining;
pub mod proto_spec;
mod utils;

pub mod urlx;
pub mod whitelist;

use std::borrow::Cow;

use base64::Engine;
use bstr::ByteSlice;

pub use utils::norm_extras::normalize_extras;
pub use utils::permissive_json::{permissive_json, permissive_json_core};
pub(crate) use utils::unescaper::Unescaper;
// exported

pub use urlx::SchemeX;

pub(crate) use urlx::PortSpec;

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod macros {
    #![allow(unused_macros)]

    macro_rules! nom_bail {
        ($input: expr, $code: ident) => {{
            return Err(nom::Err::Error(nom::error::Error::new(
                $input,
                nom::error::ErrorKind::$code,
            )));
        }};

        ($input: expr, $code: ident, $context: expr) => {{
            return Err(::nom::Err::Error(crate::Error {
                row: $input.location_line(),
                col: $input.get_utf8_column() as u32,
                offset: $input.location_offset(),
                length: $input.len(),
                // XXX: Default value for errors without a tag
                errtag: $code,
                errctx: $context,
            }));
        }};
    }

    pub(crate) use nom_bail;
}

pub(crate) use macros::nom_bail;
/// Pre-process raw subscription data: trim padding, base64 decode, normalize
/// extras, and lossily convert to UTF-8.
///
/// Returns an owned `String` of decoded-and-normalized text suitable for
/// line splitting and URL extraction.
#[must_use]
pub fn preprocess_sub_data(data: &[u8]) -> String {
    let data = data.trim_end_with(|c| c.is_whitespace() || c == '=');
    let data = base64::prelude::BASE64_STANDARD_NO_PAD
        .decode(data)
        .map_err(|_| tracing::info!("Not a Standard Base64"))
        .or_else(|()| {
            base64::prelude::BASE64_URL_SAFE_NO_PAD
                .decode(data)
                .map_err(|_| tracing::info!("Not a URL Safe Base64"))
        })
        .map_or_else(|()| Cow::Borrowed(data), Cow::Owned);
    tracing::info!("Total length of incoming data: {}", data.len());
    let data = normalize_extras(data.as_ref());
    if let Cow::Owned(_) = data {
        tracing::info!("Some extras was fixed");
    }

    simdutf8::basic::from_utf8(data.as_ref()).map_or_else(
        |_| String::from_utf8_lossy(data.as_ref()).into_owned(),
        ToOwned::to_owned,
    )
}
