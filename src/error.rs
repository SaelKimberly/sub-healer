pub(crate) type Span<'a> = nom_locate::LocatedSpan<&'a [u8]>;
/// Type alias for nom error
pub(crate) type NomError<'a, E = nom::error::Error<Span<'a>>> = nom::Err<E>;
/// Type alias for nom result without tail
pub(crate) type CutResult<'a, T> = ::std::result::Result<T, NomError<'a>>;
/// Type alias for nom result with tail
pub(crate) type RawResult<'a, T = Span<'a>> = ::std::result::Result<(Span<'a>, T), NomError<'a>>;
