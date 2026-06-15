mod fast_perc;
pub mod host_port;
pub mod norm_extras;
pub mod permissive_json;
pub mod unescaper;

pub use host_port::host_port_spec;

// restrict to crate internal usage
type Span<'a> = &'a [u8];
/// Type alias for nom error
pub type NomError<'a, E = nom::error::Error<Span<'a>>> = nom::Err<E>;
/// Type alias for nom result with tail
type RawResult<'a, T = Span<'a>> = ::std::result::Result<(Span<'a>, T), NomError<'a>>;
