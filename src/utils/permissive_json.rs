//! Very permissive nom-based parser for JSON area in raw data

use super::percent_encoding::PercentDecode;
use super::unescaper::Unescaper;
use super::{CutResult, NomError, RawResult, Span};
use bstr::ByteSlice;
use nom::{
    Input,
    error::{Error, ErrorKind},
};

/// JSON token
#[derive(Debug)]
enum JsonToken {
    Comma,
    Colon,
    Key(String),
    Val(serde_json::Value),
    ArrStart,
    ObjStart,
    ArrClose,
    ObjClose,
}

/// JSON container traverse path item
enum Path {
    Key(String),
    Index(usize),
}

/// JSON object cursor for reconstructing JSON from tokens.
struct Cursor<'a> {
    span: Span<'a>,
    base: Option<serde_json::Value>,
    path: Vec<Path>,
}

impl<'a> Cursor<'a> {
    const fn new(span: Span<'a>) -> Self {
        Self {
            span,
            base: None,
            path: Vec::new(),
        }
    }

    /// Traverse current JSON object, based on path, to the map.
    /// Returns [`nom::error::ErrorKind::Tag`] error, if traversed destination is not a map
    fn traverse_map<'b>(
        &'b mut self,
    ) -> CutResult<'a, &'b mut serde_json::Map<String, serde_json::Value>> {
        let mut container_ref: &'b mut _ = self
            .base
            .get_or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));

        for elem in &self.path {
            container_ref = match elem {
                Path::Key(k) => {
                    let serde_json::Value::Object(o) = container_ref else {
                        return Err(nom::Err::Error(Error::new(self.span, ErrorKind::Tag)));
                    };
                    o.get_mut(k)
                        .ok_or_else(|| nom::Err::Error(Error::new(self.span, ErrorKind::Tag)))?
                }
                Path::Index(i) => {
                    let serde_json::Value::Array(a) = container_ref else {
                        return Err(nom::Err::Error(Error::new(self.span, ErrorKind::Tag)));
                    };
                    a.get_mut(*i)
                        .ok_or_else(|| nom::Err::Error(Error::new(self.span, ErrorKind::Tag)))?
                }
            };
        }

        let serde_json::Value::Object(o) = container_ref else {
            return Err(nom::Err::Error(Error::new(self.span, ErrorKind::Tag)));
        };

        Ok(o)
    }

    /// Traverse current JSON object, based on path, to the array.
    /// Returns [`nom::error::ErrorKind::Tag`] error, if traversed destination is not an array
    fn traverse_arr<'b>(&'b mut self) -> CutResult<'a, &'b mut Vec<serde_json::Value>> {
        let mut container_ref: &'b mut _ = self
            .base
            .get_or_insert_with(|| serde_json::Value::Array(vec![]));

        for elem in &self.path {
            container_ref = match elem {
                Path::Key(k) => {
                    let serde_json::Value::Object(o) = container_ref else {
                        return Err(nom::Err::Error(Error::new(self.span, ErrorKind::Tag)));
                    };
                    o.get_mut(k)
                        .ok_or_else(|| nom::Err::Error(Error::new(self.span, ErrorKind::Tag)))?
                }
                Path::Index(i) => {
                    let serde_json::Value::Array(a) = container_ref else {
                        return Err(nom::Err::Error(Error::new(self.span, ErrorKind::Tag)));
                    };
                    a.get_mut(*i)
                        .ok_or_else(|| nom::Err::Error(Error::new(self.span, ErrorKind::Tag)))?
                }
            };
        }

        let serde_json::Value::Array(o) = container_ref else {
            return Err(nom::Err::Error(Error::new(self.span, ErrorKind::Tag)));
        };

        Ok(o)
    }

    fn add_new_container(&mut self, key: Option<String>, is_array: bool) -> CutResult<'a, ()> {
        if self.base.is_none() {
            if is_array {
                self.base = Some(serde_json::Value::Array(Vec::new()));
            } else {
                self.base = Some(serde_json::Value::Object(serde_json::Map::new()));
            }
            return Ok(());
        }

        if let Some(k) = key {
            let o = self.traverse_map()?;
            o.insert(
                k.clone(),
                if is_array {
                    serde_json::Value::Array(Vec::new())
                } else {
                    serde_json::Value::Object(serde_json::Map::new())
                },
            );
            self.path.push(Path::Key(k));
        } else {
            let new_index = {
                let a = self.traverse_arr()?;

                a.push(if is_array {
                    serde_json::Value::Array(Vec::new())
                } else {
                    serde_json::Value::Object(serde_json::Map::new())
                });
                a.len() - 1
            };
            self.path.push(Path::Index(new_index));
        }

        Ok(())
    }

    /// Move cursor one level up
    fn move_up(&mut self) {
        _ = self.path.pop();
    }

    fn push_kv(&mut self, key: Option<String>, value: serde_json::Value) -> CutResult<'a, ()> {
        if let Some(key) = key {
            let o = self.traverse_map()?;

            o.insert(key, value);
        } else {
            let a = self.traverse_arr()?;

            a.push(value);
        }
        Ok(())
    }

    /// Get final JSON value. When no root container is set, return [`nom::error::ErrorKind::NonEmpty`]
    fn finalize(self) -> CutResult<'a, serde_json::Value> {
        self.base
            .ok_or_else(|| nom::Err::Error(Error::new(self.span, ErrorKind::NonEmpty)))
    }
}

fn tokens_to_new_json(span: Span<'_>, tokens: Vec<JsonToken>) -> CutResult<'_, serde_json::Value> {
    let mut cursor = Cursor::new(span);
    let mut key = Option::<String>::None;

    for t in tokens {
        match t {
            JsonToken::Key(s) => {
                let None = key.replace(s) else {
                    return Err(nom::Err::Error(Error::new(span, ErrorKind::Tag)));
                };
            }
            JsonToken::ArrStart => {
                cursor.add_new_container(key.take(), true)?;
            }
            JsonToken::ArrClose | JsonToken::ObjClose => {
                cursor.move_up();
            }
            JsonToken::ObjStart => {
                cursor.add_new_container(key.take(), false)?;
            }
            JsonToken::Colon | JsonToken::Comma => {}
            JsonToken::Val(v) => match v {
                serde_json::Value::String(s) => {
                    let s = Unescaper::default()
                        .enc_uni(true)
                        .do_unescape(s.as_bytes())
                        .expect("As all unescape should be ok");
                    cursor.push_kv(key.take(), serde_json::Value::String(s))?;
                }
                other => {
                    cursor.push_kv(key.take(), other)?;
                }
            },
        }
    }
    cursor.finalize()
}

/// Character source: either percent-decoded or raw
enum CharSource<'a> {
    Decode(PercentDecode<'a>),
    Raw(bstr::CharIndices<'a>, Span<'a>),
}

impl<'a> CharSource<'a> {
    fn next(&mut self) -> Option<CutResult<'a, (usize, usize, char)>> {
        match self {
            Self::Decode(d) => d.next(),
            Self::Raw(iter, _) => {
                let (c_s, c_e, c) = iter.next()?;
                Some(Ok((c_s, c_e, c)))
            }
        }
    }

    fn error(&self, kind: ErrorKind) -> NomError<'a> {
        match self {
            Self::Decode(d) => d.error(kind),
            Self::Raw(_, span) => nom::Err::Error(Error::new(*span, kind)),
        }
    }

    const fn span(&self) -> Span<'a> {
        match self {
            Self::Decode(d) => d.span,
            Self::Raw(_, span) => *span,
        }
    }
}

/// JSON tokenizer
struct Tokenizer<'a> {
    /// Input (auto percent decode)
    iter: CharSource<'a>,
    /// Byte offset of the last character end (for percent encoded, it is percent sequence end)
    last_e: usize,
    /// Last character
    last_c: char,
    /// Collected tokens
    tokens: Vec<JsonToken>,
}

impl<'a> Tokenizer<'a> {
    /// Construct a new tokenizer
    /// If we are not able to read a character, return None.
    fn new(span: Span<'a>) -> Option<Self> {
        let mut chars = span.fragment().char_indices();
        let (_, last_e, last_c) = chars.next()?;

        if last_c == '%' {
            // PercentDecode creates its own char_indices from span start
            let mut decoded = PercentDecode::new(span).with_decoding(true);
            let (_, last_e, last_c) = decoded.next()?.ok()?;
            Some(Self {
                iter: CharSource::Decode(decoded),
                last_e,
                last_c,
                tokens: Vec::new(),
            })
        } else {
            // Fast path: raw char_indices, first char already read
            Some(Self {
                iter: CharSource::Raw(chars, span),
                last_e,
                last_c,
                tokens: Vec::new(),
            })
        }
    }

    /// Get the next character (returns a Eof error if there are no more characters)
    fn next_char(&mut self) -> CutResult<'a, char> {
        if let Some((_, c_e, c)) = self.iter.next().transpose()? {
            self.last_e = c_e;
            self.last_c = c;
            Ok(c)
        } else {
            Err(self.iter.error(ErrorKind::Eof))
        }
    }

    /// Skip whitespace (free '+' sign is considered whitespace too)
    fn skip_ws(&mut self) -> CutResult<'a, ()> {
        while self.last_c.is_whitespace() || self.last_c == '+' {
            self.next_char()?;
        }
        Ok(())
    }

    /// Test for a control character (returns `None` if it's not a control character)
    const fn test_ctrl(&self) -> Option<JsonToken> {
        match self.last_c {
            '{' => Some(JsonToken::ObjStart),
            '}' => Some(JsonToken::ObjClose),
            '[' => Some(JsonToken::ArrStart),
            ']' => Some(JsonToken::ArrClose),
            ':' => Some(JsonToken::Colon),
            ',' => Some(JsonToken::Comma),
            _ => None,
        }
    }

    /// Test for a text (perform encoding detection if `is_value` is true. keys should be ascii)
    fn test_text(&mut self, is_value: bool) -> CutResult<'a, Option<String>> {
        // eof char must be the same as beginning
        if let eof @ ('"' | '\'') = self.last_c {
            let bos = self.last_e;

            let mut esc = false;

            let mut txt = String::new();

            let txt: String = loop {
                let Ok(c) = self.next_char() else {
                    // If we reached eof immediately after opening quote, return error
                    if self.last_e == bos {
                        return Err(self.iter.error(ErrorKind::Eof));
                    }
                    // If we reached eof before closing quote,
                    //  return available data
                    break txt;
                };
                if esc {
                    esc = false;
                } else if c == '\\' {
                    esc = true;
                    txt.push('\\');
                    continue;
                } else if c == eof {
                    // ignore eof error if no next character is available
                    // for handling unclosed JSON string
                    // If we reached closing quote
                    _ = self.next_char();
                    break txt;
                }
                txt.push(c);
            };

            let txt = Unescaper::default()
                .chardet(is_value, true)
                .enc8259(true)
                .do_unescape(txt.as_bytes())
                .expect("As all unescape should be ok");

            Ok(Some(txt))
        } else {
            Ok(None)
        }
    }

    /// Test for an unquoted key
    ///
    /// As parser is highly permissive about JSON errors, there is just several constraints:
    /// - key must contains only alphanumeric characters, '-' and '_' characters
    /// - only colon control character is allowed after key
    /// - whitespace characters will be considered as end of key
    /// - quote character will be considered as end of key (as if we just missed the opening quote)
    fn test_ukey(&mut self) -> CutResult<'a, String> {
        self.skip_ws()?;

        let mut key = String::new();

        loop {
            match self.last_c {
                ':' => break,
                '{' | '}' | '[' | ']' | ',' => return Err(self.iter.error(ErrorKind::Tag)),
                _ => {}
            }

            if self.last_c.is_alphanumeric() || matches!(self.last_c, '_' | '-') {
                key.push(self.last_c);
            } else if matches!(self.last_c, '"' | '\'') {
                // detected mismatched closing bracket
                // no action required, as it shouldn't be added to the key
            } else {
                return Err(self.iter.error(ErrorKind::Tag));
            }

            self.next_char()?;

            if self.last_c.is_whitespace() {
                break;
            }
        }
        Ok(key)
    }

    /// Test for an unquoted value
    ///
    /// As parser is highly permissive about JSON errors, there is just several constraints:
    /// - value must contains only alphanumeric characters, '-' and '_' characters
    /// - only comma or closing brackets control characters are allowed after value
    /// - whitespace characters will be considered as end of value
    /// - quote character will be considered as end of value (as if we just missed the opening quote)
    fn test_uval(&mut self, in_object: bool) -> CutResult<'a, serde_json::Value> {
        // If value starts with a dash, it may represent a negative number
        let positive = if self.last_c == '-' {
            self.next_char()?;
            false
        } else {
            true
        };
        // If first char (after possible dash) is a digit, it may represent a number
        let mut maybe_num = self.last_c.is_ascii_digit();
        // Does the value contain a scientific notation 'e' or 'E' marker
        let mut e_appeared = false;
        // Does the value contain a decimal notation '.' marker
        let mut p_appeared = false;

        let mut value_repr = String::new();
        loop {
            // If we have found a whitespace, we are done
            if self.last_c.is_whitespace() {
                break;
            }
            // If we have found a mismatched closing quote, we are done
            //  it means, that value should not be numeric
            if matches!(self.last_c, '"' | '\'') {
                maybe_num = false;
                break;
            }
            // If there is a control character, that usually closes or separates something, we are done
            // Otherwise, when we are not found any control character, we should proceed.
            // If we found a not supported control characters (opening brackets, quotes, etc), this is an error
            match self.last_c {
                ',' => break,
                '}' if in_object => break,
                ']' if !in_object => break,
                '{' | '[' | ':' => return Err(self.iter.error(ErrorKind::Tag)),
                _ => {}
            }

            match self.last_c {
                '0'..='9' => value_repr.push(self.last_c),
                'e' | 'E' => {
                    if maybe_num && e_appeared {
                        // number cannot have two 'e'/'E' in scientific notation
                        maybe_num = false;
                    } else {
                        e_appeared = true;
                    }
                    value_repr.push('e');
                }
                '.' => {
                    if maybe_num && (p_appeared || e_appeared) {
                        // number cannot have two '.' in decimal notation
                        // number cannot have '.' after 'e'/'E'
                        maybe_num = false;
                    } else {
                        p_appeared = true;
                    }
                    value_repr.push(self.last_c);
                }
                _ => {
                    maybe_num = false;
                    value_repr.push(self.last_c);
                }
            }

            self.next_char()?;
        }

        let v = if maybe_num {
            if p_appeared || e_appeared {
                value_repr
                    .parse::<f64>()
                    .map_or(serde_json::Value::String(value_repr), |v| {
                        let Some(v) = serde_json::Number::from_f64(if positive { v } else { -v })
                        else {
                            unreachable!()
                        };
                        serde_json::Value::Number(v)
                    })
            } else if let Ok(v) = value_repr.parse::<i64>() {
                serde_json::Value::Number(serde_json::Number::from(if positive { v } else { -v }))
            } else {
                serde_json::Value::String(value_repr)
            }
        } else {
            match value_repr.as_str().trim() {
                // python | json literals
                "None" | "null" => serde_json::Value::Null,
                "True" | "true" => serde_json::Value::Bool(true),
                "False" | "false" => serde_json::Value::Bool(false),
                _ => serde_json::Value::String(value_repr),
            }
        };
        Ok(v)
    }

    /// Returns key or an error
    fn expect_key(&mut self) -> CutResult<'a, String> {
        // first try to get valid JSON key (single quotes allowed)
        self.test_text(false)?.map_or_else(|| self.test_ukey(), Ok)
    }

    /// Returns value or an error
    fn expect_val(&mut self, in_object: bool) -> CutResult<'a, serde_json::Value> {
        // first try to get valid JSON value
        self.test_text(true)?.map_or_else(
            || self.test_uval(in_object),
            |v| Ok(serde_json::Value::String(v)),
        )
    }

    pub fn tokenize(&mut self) -> RawResult<'a, serde_json::Value> {
        // Stack of opening brackets (true: object, false: array)
        let mut opens: Vec<bool> = Vec::new();

        if self.test_ctrl().is_none() {
            // When no control character is found, it means that the input is not a valid JSON
            // or the input contains 'None' or 'null' value
            return if 'n'.eq_ignore_ascii_case(&self.last_c)
                && ('o'.eq_ignore_ascii_case(&self.next_char()?)
                    && 'n'.eq_ignore_ascii_case(&self.next_char()?)
                    && 'e'.eq_ignore_ascii_case(&self.next_char()?))
                || ('u'.eq_ignore_ascii_case(&self.last_c)
                    && 'l'.eq_ignore_ascii_case(&self.next_char()?)
                    && 'l'.eq_ignore_ascii_case(&self.next_char()?))
            {
                let tail = self.iter.span().take_from(self.last_e);
                Ok((tail, serde_json::Value::Null))
            } else {
                Err(self.iter.error(ErrorKind::Tag))
            };
        }

        let mut allow_comma: bool = false;
        let mut allow_colon: bool = false;

        let mut in_object = false;

        'tokenize: loop {
            // Consume all control characters before next token
            // When inappropriate control character sequence is appeared,
            //  it will fail later on composition of JSON.

            'ctrl: loop {
                // Skip whitespace characters before control character
                self.skip_ws()?;

                // When there are no more control characters, break.
                let Some(t) = self.test_ctrl() else {
                    break 'ctrl;
                };

                match t {
                    // Add opening brackets to the stack
                    JsonToken::ArrStart => {
                        opens.push(false);

                        allow_comma = false;
                        allow_colon = false;
                    }
                    JsonToken::ObjStart => {
                        opens.push(true);

                        allow_comma = false;
                        allow_colon = false;
                    }
                    // Only allow array closing bracket after array opening
                    JsonToken::ArrClose if opens.pop() == Some(false) => {
                        // after closing bracket, comma is allowed
                        // on last closing, loop will break anyway
                        allow_comma = true;
                    }
                    // Only allow object closing bracket after object opening
                    JsonToken::ObjClose if opens.pop() == Some(true) => {
                        // after closing bracket, comma is allowed
                        // on last closing, loop will break anyway
                        allow_comma = true;
                    }
                    // Add comma if it is allowed
                    JsonToken::Comma if allow_comma => {}
                    // Add colon if it is allowed
                    JsonToken::Colon if allow_colon => {}
                    // Key or Val tokens should never stay with no control character between them
                    _ => return Err(self.iter.error(ErrorKind::Tag)),
                }

                // remove trailing comma before closing brackets
                if let JsonToken::ArrClose | JsonToken::ObjClose = t
                    && matches!(self.tokens.last(), Some(JsonToken::Comma))
                {
                    _ = self.tokens.pop();
                }
                // Add token
                self.tokens.push(t);

                // If stack is empty, break main loop
                let Some(is_in_object) = opens.last() else {
                    break 'tokenize;
                };
                in_object = *is_in_object;

                // Move to the next character
                self.next_char()?;
            }

            if in_object {
                // when in an object, after a comma or opening bracket, expect key
                if let Some(JsonToken::ObjStart | JsonToken::Comma) = self.tokens.last() {
                    let key = self.expect_key()?;
                    self.tokens.push(JsonToken::Key(key));

                    // colons are allowed after key
                    allow_colon = true;
                    // commas are not allowed after key
                    allow_comma = false;
                } else
                // after a colon, expect value
                if matches!(self.tokens.last(), Some(JsonToken::Colon)) {
                    let val = self.expect_val(true)?;
                    self.tokens.push(JsonToken::Val(val));

                    // colons are not allowed after value
                    allow_colon = false;
                    // commas are allowed after value
                    allow_comma = true;
                } else {
                    return Err(self.iter.error(ErrorKind::Tag));
                }
            } else {
                // when in an array, after a comma or opening bracket, expect value
                if let Some(JsonToken::ArrStart | JsonToken::Comma) = self.tokens.last() {
                    let val = self.expect_val(false)?;
                    self.tokens.push(JsonToken::Val(val));

                    // colons are not allowed in array
                    allow_colon = false;
                    // commas are allowed in array
                    allow_comma = true;
                } else {
                    return Err(self.iter.error(ErrorKind::Tag));
                }
            }
        }

        // Note, that missing closing brackets will be recovered automatically
        //  as the tokenizer will not check their presense, only the order, if any.

        let (tail, span) = self.iter.span().take_split(self.last_e);
        let json = tokens_to_new_json(span, core::mem::take(&mut self.tokens))?;
        Ok((tail, json))
    }
}

/// # Errors
///
/// Returns `Error` if the input is not valid and not recoverable JSON.
pub fn permissive_json_core(span: Span<'_>) -> RawResult<'_, serde_json::Value> {
    // Fast path: try serde_json first for well-formed input
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(span.fragment()) {
        return Ok((Span::new(b""), value));
    }

    // Fallback: full permissive parser for malformed input
    Tokenizer::new(span)
        .ok_or_else(|| nom::Err::Error(Error::new(span, ErrorKind::Eof)))?
        .tokenize()
}

/// Parse JSON permissively, with recovery for bare `[` in values (e.g. `"ps": [emoji]...`).
/// On success, guarantees empty tail. Falls back to original error if recovery fails.
///
/// # Errors
///
/// Returns `Error` if the input is not valid and not recoverable JSON.
pub fn permissive_json(span: Span<'_>) -> RawResult<'_, serde_json::Value> {
    let first = permissive_json_core(span);
    if let Ok((tail, _)) = &first
        && tail.fragment().is_empty()
    {
        return first;
    }

    let frag = span.fragment();
    if let Some(pos) = frag.iter().position(|&b| b == b'[') {
        let mut m = frag.to_vec();
        m.insert(pos, b'"');
        if let Ok((_, value)) = permissive_json_core(Span::new(&m)) {
            return Ok((Span::new(b""), value));
        }
    }

    first
}

#[cfg(test)]
mod tests {
    use super::{Span, Tokenizer};

    #[test]
    fn test_tokenizer() {
        let data = &b"None"[..];
        let Ok((tail, res)) = Tokenizer::new(Span::new(data)).unwrap().tokenize() else {
            panic!("Should have succeeded");
        };
        eprintln!("{tail:?}");
        eprintln!("{res:?}");

        let data = &b"{}"[..];
        let Ok((tail, res)) = Tokenizer::new(Span::new(data)).unwrap().tokenize() else {
            panic!("Should have succeeded");
        };
        eprintln!("{tail:?}");
        eprintln!("{res:?}");

        let data = &b"{'key':'val'}"[..];
        let mut tokenizer = Tokenizer::new(Span::new(data)).unwrap();
        let Ok((tail, res)) = tokenizer.tokenize() else {
            panic!("Should have succeeded");
        };
        eprintln!("{tail:?}");
        eprintln!("{res:?}");

        let data = &b"{'key':[['val',],],}"[..];
        let mut tokenizer = Tokenizer::new(Span::new(data)).unwrap();
        let Ok((tail, res)) = tokenizer.tokenize() else {
            panic!("Should have succeeded");
        };
        eprintln!("{tail:?}");
        eprintln!("{res:?}");

        let data = &b"{'key':[[{'val':null}]]}"[..];
        let mut tokenizer = Tokenizer::new(Span::new(data)).unwrap();
        let Ok((tail, res)) = tokenizer.tokenize() else {
            panic!("Should have succeeded");
        };
        eprintln!("{tail:?}");
        eprintln!("{res:?}");

        let data = &b"{key:[[{'val':null}]]}"[..];
        let mut tokenizer = Tokenizer::new(Span::new(data)).unwrap();
        let Ok((tail, res)) = tokenizer.tokenize() else {
            panic!("Should have succeeded");
        };
        eprintln!("{tail:?}");
        eprintln!("{res:?}");

        let data = &b"{var-length-key:[[{'some val':null}]]}"[..];
        let mut tokenizer = Tokenizer::new(Span::new(data)).unwrap();
        let Ok((tail, res)) = tokenizer.tokenize() else {
            panic!("Should have succeeded");
        };
        eprintln!("{tail:?}");
        eprintln!("{res:?}");

        let data = &b"%7B%22key%22%3A%22value%22%7D"[..];
        let mut tokenizer = Tokenizer::new(Span::new(data)).unwrap();
        let Ok((tail, res)) = tokenizer.tokenize() else {
            panic!("Should have succeeded");
        };
        eprintln!("{tail:?}");
        eprintln!("{res:?}");
    }
}
