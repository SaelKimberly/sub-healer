#![warn(clippy::nursery, clippy::pedantic)]
pub mod db;
pub mod mining;
pub mod proto_spec;
mod utils;

pub mod urlx;

use std::borrow::Cow;

use base64::Engine;
use bstr::ByteSlice;

pub use utils::norm_extras::normalize_extras;
pub(crate) use utils::{permissive_json::permissive_json, unescaper::Unescaper};
// exported

pub use urlx::{SchemeX, UrlX};
pub use utils::line::{Line, Lines};

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

pub fn parse_sub(url: &url::Url, sub: &[u8]) -> Lines<'static> {
    let sub = sub.trim_end_with(|c| c.is_whitespace() || c == '=');
    let sub = base64::prelude::BASE64_STANDARD_NO_PAD
        .decode(sub)
        .map_err(|_| tracing::info!("Not a Standard Base64"))
        .or_else(|()| {
            base64::prelude::BASE64_URL_SAFE_NO_PAD
                .decode(sub)
                .map_err(|_| tracing::info!("Not a URL Safe Base64"))
        })
        .map_or_else(|()| Cow::Borrowed(sub), Cow::Owned);

    tracing::info!("Total length of incoming data: {}", sub.len());

    let sub = normalize_extras(sub.as_ref());
    if let Cow::Owned(_) = sub {
        tracing::info!("Some extras was fixed");
    }
    let sub = String::from_utf8_lossy(sub.as_ref());
    if let Cow::Owned(_) = sub {
        tracing::info!("Some characters was replaced");
    }

    Lines::new_raw(url, sub.as_ref()).processed()
}
