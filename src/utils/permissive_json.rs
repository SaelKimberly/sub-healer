//! Very permissive parser for JSON-ish data in raw subscriptions.
//! Uses hand-rolled UTF-8/percent-decoding character source.

use super::fast_perc::AutoChars;
use super::unescaper::Unescaper;

type PResult<T> = Result<T, PermissiveJsonError>;

#[derive(Debug)]
pub enum PermissiveJsonError {
    EmptyInput,
    Eof,
    InvalidEncoding,
    InvalidSyntax,
}

impl core::fmt::Display for PermissiveJsonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "empty input"),
            Self::Eof => write!(f, "unexpected end of input"),
            Self::InvalidEncoding => write!(f, "invalid byte encoding"),
            Self::InvalidSyntax => write!(f, "invalid JSON syntax"),
        }
    }
}

impl std::error::Error for PermissiveJsonError {}

#[repr(transparent)]
struct Opens(u64);

const OBJ: u64 = 0b01;
const ARR: u64 = 0b10;
const MOV: usize = 2;

impl Opens {
    #[inline]
    const fn push_obj(&mut self) {
        self.0 = (self.0 << MOV) | OBJ;
    }
    #[inline]
    const fn push_arr(&mut self) {
        self.0 = (self.0 << MOV) | ARR;
    }
    #[inline]
    const fn pop(&mut self) -> Option<bool> {
        let Some(result) = self.last() else {
            return None;
        };
        self.0 >>= MOV;
        Some(result)
    }
    #[inline]
    const fn last(&self) -> Option<bool> {
        match self.0 & 0b11 {
            OBJ => Some(true),
            ARR => Some(false),
            _ => None,
        }
    }
}

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

enum Path {
    Key(String),
    Index(usize),
}

struct Cursor {
    base: Option<serde_json::Value>,
    path: Vec<Path>,
}

impl Cursor {
    const fn new() -> Self {
        Self {
            base: None,
            path: Vec::new(),
        }
    }

    fn traverse_map<'b>(
        &'b mut self,
    ) -> PResult<&'b mut serde_json::Map<String, serde_json::Value>> {
        let mut container_ref: &'b mut _ = self
            .base
            .get_or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));

        for elem in &self.path {
            container_ref = match elem {
                Path::Key(k) => {
                    let serde_json::Value::Object(o) = container_ref else {
                        return Err(PermissiveJsonError::InvalidSyntax);
                    };
                    o.get_mut(k).ok_or(PermissiveJsonError::InvalidSyntax)?
                }
                Path::Index(i) => {
                    let serde_json::Value::Array(a) = container_ref else {
                        return Err(PermissiveJsonError::InvalidSyntax);
                    };
                    a.get_mut(*i).ok_or(PermissiveJsonError::InvalidSyntax)?
                }
            };
        }

        let serde_json::Value::Object(o) = container_ref else {
            return Err(PermissiveJsonError::InvalidSyntax);
        };

        Ok(o)
    }

    fn traverse_arr<'b>(&'b mut self) -> PResult<&'b mut Vec<serde_json::Value>> {
        let mut container_ref: &'b mut _ = self
            .base
            .get_or_insert_with(|| serde_json::Value::Array(vec![]));

        for elem in &self.path {
            container_ref = match elem {
                Path::Key(k) => {
                    let serde_json::Value::Object(o) = container_ref else {
                        return Err(PermissiveJsonError::InvalidSyntax);
                    };
                    o.get_mut(k).ok_or(PermissiveJsonError::InvalidSyntax)?
                }
                Path::Index(i) => {
                    let serde_json::Value::Array(a) = container_ref else {
                        return Err(PermissiveJsonError::InvalidSyntax);
                    };
                    a.get_mut(*i).ok_or(PermissiveJsonError::InvalidSyntax)?
                }
            };
        }

        let serde_json::Value::Array(o) = container_ref else {
            return Err(PermissiveJsonError::InvalidSyntax);
        };

        Ok(o)
    }

    fn add_new_container(&mut self, key: Option<String>, is_array: bool) -> PResult<()> {
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

    fn move_up(&mut self) {
        _ = self.path.pop();
    }

    fn push_kv(&mut self, key: Option<String>, value: serde_json::Value) -> PResult<()> {
        if let Some(key) = key {
            let o = self.traverse_map()?;
            o.insert(key, value);
        } else {
            let a = self.traverse_arr()?;
            a.push(value);
        }
        Ok(())
    }

    fn finalize(self) -> PResult<serde_json::Value> {
        self.base.ok_or(PermissiveJsonError::EmptyInput)
    }
}

fn tokens_to_new_json(tokens: Vec<JsonToken>) -> PResult<serde_json::Value> {
    let mut cursor = Cursor::new();
    let mut key = Option::<String>::None;

    for t in tokens {
        match t {
            JsonToken::Key(s) => {
                let None = key.replace(s) else {
                    return Err(PermissiveJsonError::InvalidSyntax);
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

struct Tokenizer<'a> {
    iter: AutoChars<'a>,
    last_c: char,
    tokens: Vec<JsonToken>,
}

impl<'a> Tokenizer<'a> {
    fn new(input: &'a [u8]) -> PResult<Self> {
        let mut iter = AutoChars::new(input);
        let last_c = iter.next().ok_or(PermissiveJsonError::EmptyInput)?;
        Ok(Self {
            iter,
            last_c,
            tokens: Vec::new(),
        })
    }

    const fn next_char(&mut self) -> PResult<char> {
        match self.iter.next() {
            Some(c) => {
                self.last_c = c;
                Ok(c)
            }
            None if self.iter.remaining().is_empty() => Err(PermissiveJsonError::Eof),
            None => Err(PermissiveJsonError::InvalidEncoding),
        }
    }

    fn skip_ws(&mut self) -> PResult<()> {
        while self.last_c.is_whitespace() || self.last_c == '+' {
            self.next_char()?;
        }
        Ok(())
    }

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

    fn test_text(&mut self, is_value: bool) -> PResult<Option<String>> {
        if let eof @ ('"' | '\'') = self.last_c {
            let bos = self.iter.bytes_read();

            let mut esc = false;
            let mut txt = String::new();

            let txt: String = loop {
                match self.next_char() {
                    Ok(c) => {
                        if esc {
                            esc = false;
                        } else if c == '\\' {
                            esc = true;
                            txt.push('\\');
                            continue;
                        } else if c == eof {
                            _ = self.next_char();
                            break txt;
                        }
                        txt.push(c);
                    }
                    Err(PermissiveJsonError::Eof) => {
                        if self.iter.bytes_read() == bos {
                            return Err(PermissiveJsonError::Eof);
                        }
                        break txt;
                    }
                    Err(e) => return Err(e),
                }
            };

            let txt = Unescaper::default()
                .chardet(is_value, true)
                .enc8259(true)
                .enc_uni(true)
                .do_unescape(txt.as_bytes())
                .expect("As all unescape should be ok");

            Ok(Some(txt))
        } else {
            Ok(None)
        }
    }

    fn test_ukey(&mut self) -> PResult<String> {
        self.skip_ws()?;
        let mut key = String::new();

        loop {
            match self.last_c {
                ':' => break,
                c @ ('A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-') => {
                    key.push(c);
                }
                '"' | '\'' => {
                    // detected mismatched closing bracket — skip it
                }
                _ => return Err(PermissiveJsonError::InvalidSyntax),
            }

            self.next_char()?;

            if self.last_c.is_whitespace() {
                break;
            }
        }
        Ok(key)
    }

    fn test_uval(&mut self, in_object: bool) -> PResult<serde_json::Value> {
        let positive = if self.last_c == '-' {
            self.next_char()?;
            false
        } else {
            true
        };
        let mut maybe_num = self.last_c.is_ascii_digit();
        let mut e_appeared = false;
        let mut p_appeared = false;
        let mut value_repr = String::new();

        loop {
            if self.last_c.is_whitespace() {
                break;
            }
            if matches!(self.last_c, '"' | '\'') {
                maybe_num = false;
                break;
            }
            match self.last_c {
                ',' => break,
                '}' if in_object => break,
                ']' if !in_object => break,
                '{' | '[' | ':' => return Err(PermissiveJsonError::InvalidSyntax),
                _ => {}
            }

            match self.last_c {
                '0'..='9' => value_repr.push(self.last_c),
                'e' | 'E' => {
                    if maybe_num && e_appeared {
                        maybe_num = false;
                    } else {
                        e_appeared = true;
                    }
                    value_repr.push('e');
                }
                '.' => {
                    if maybe_num && (p_appeared || e_appeared) {
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
                "None" | "null" => serde_json::Value::Null,
                "True" | "true" => serde_json::Value::Bool(true),
                "False" | "false" => serde_json::Value::Bool(false),
                _ => serde_json::Value::String(value_repr),
            }
        };
        Ok(v)
    }

    fn expect_key(&mut self) -> PResult<String> {
        self.test_text(false)?.map_or_else(|| self.test_ukey(), Ok)
    }

    fn expect_val(&mut self, in_object: bool) -> PResult<serde_json::Value> {
        self.test_text(true)?.map_or_else(
            || self.test_uval(in_object),
            |v| Ok(serde_json::Value::String(v)),
        )
    }

    fn tokenize(&mut self) -> PResult<(&'a [u8], serde_json::Value)> {
        let mut opens = Opens(0);

        if self.test_ctrl().is_none() {
            return match (self.last_c, self.iter.remaining()) {
                (
                    'N' | 'n',
                    [b'O' | b'o', b'N' | b'n', b'E' | b'e', tail @ ..]
                    | [b'U' | b'u', b'L' | b'l', b'L' | b'l', tail @ ..],
                ) => Ok((tail, serde_json::Value::Null)),
                _ => Err(PermissiveJsonError::InvalidSyntax),
            };
        }

        let mut allow_comma = false;
        let mut allow_colon = false;
        let mut in_object = false;

        'tokenize: loop {
            'ctrl: loop {
                self.skip_ws()?;

                let Some(t) = self.test_ctrl() else {
                    break 'ctrl;
                };

                match t {
                    JsonToken::ArrStart => {
                        opens.push_arr();
                        allow_comma = false;
                        allow_colon = false;
                    }
                    JsonToken::ObjStart => {
                        opens.push_obj();
                        allow_comma = false;
                        allow_colon = false;
                    }
                    JsonToken::ArrClose if opens.pop() == Some(false) => {
                        allow_comma = true;
                    }
                    JsonToken::ObjClose if opens.pop() == Some(true) => {
                        allow_comma = true;
                    }
                    JsonToken::Comma if allow_comma => {}
                    JsonToken::Colon if allow_colon => {}
                    _ => return Err(PermissiveJsonError::InvalidSyntax),
                }

                if let JsonToken::ArrClose | JsonToken::ObjClose = t
                    && matches!(self.tokens.last(), Some(JsonToken::Comma))
                {
                    _ = self.tokens.pop();
                }
                self.tokens.push(t);

                let Some(is_in_object) = opens.last() else {
                    break 'tokenize;
                };
                in_object = is_in_object;

                self.next_char()?;
            }

            if in_object {
                if let Some(JsonToken::ObjStart | JsonToken::Comma) = self.tokens.last() {
                    let key = self.expect_key()?;
                    self.tokens.push(JsonToken::Key(key));
                    allow_colon = true;
                    allow_comma = false;
                } else if matches!(self.tokens.last(), Some(JsonToken::Colon)) {
                    let val = self.expect_val(true)?;
                    self.tokens.push(JsonToken::Val(val));
                    allow_colon = false;
                    allow_comma = true;
                } else {
                    return Err(PermissiveJsonError::InvalidSyntax);
                }
            } else if let Some(JsonToken::ArrStart | JsonToken::Comma) = self.tokens.last() {
                let val = self.expect_val(false)?;
                self.tokens.push(JsonToken::Val(val));
                allow_colon = false;
                allow_comma = true;
            } else {
                return Err(PermissiveJsonError::InvalidSyntax);
            }
        }

        let remaining = self.iter.remaining();
        let json = tokens_to_new_json(core::mem::take(&mut self.tokens))?;
        Ok((remaining, json))
    }
}

/// Parse a JSON value from a byte slice, with some leniency.
///
/// # Errors
///
/// Returns an error if the input is not valid or recoverable JSON.
pub fn permissive_json_core(input: &[u8]) -> PResult<(&[u8], serde_json::Value)> {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(input) {
        return Ok((b"", value));
    }
    Tokenizer::new(input)?.tokenize()
}

/// Parse a JSON value from a byte slice, with some leniency.
///
/// # Errors
///
/// Returns an error if the input is not valid or recoverable JSON.
pub fn permissive_json(input: &[u8]) -> PResult<serde_json::Value> {
    let first = permissive_json_core(input);

    let done = matches!(&first, Ok((rem, _)) if rem.is_empty());
    if done {
        return first.map(|(_, v)| v);
    }

    if let Some(pos) = input.iter().position(|&b| b == b'[') {
        let mut m = input.to_vec();
        m.insert(pos, b'"');
        if let Ok((_, value)) = permissive_json_core(&m) {
            return Ok(value);
        }
    }

    first.map(|(_, v)| v)
}

#[cfg(test)]
mod tests {
    use super::Tokenizer;

    #[test]
    fn test_tokenizer() {
        let data = b"None";
        let mut t = Tokenizer::new(data.as_slice()).expect("new failed");
        let (tail, res) = t.tokenize().expect("tokenize failed");
        eprintln!("{tail:?}");
        eprintln!("{res:?}");

        let data = b"{}";
        let mut t = Tokenizer::new(data.as_slice()).expect("new failed");
        let (tail, res) = t.tokenize().expect("tokenize failed");
        eprintln!("{tail:?}");
        eprintln!("{res:?}");

        let data = b"{'key':'val'}";
        let mut t = Tokenizer::new(data.as_slice()).expect("new failed");
        let (tail, res) = t.tokenize().expect("tokenize failed");
        eprintln!("{tail:?}");
        eprintln!("{res:?}");

        let data = b"{'key':[['val',],],}";
        let mut t = Tokenizer::new(data.as_slice()).expect("new failed");
        let (tail, res) = t.tokenize().expect("tokenize failed");
        eprintln!("{tail:?}");
        eprintln!("{res:?}");

        let data = b"{'key':[[{'val':null}]]}";
        let mut t = Tokenizer::new(data.as_slice()).expect("new failed");
        let (tail, res) = t.tokenize().expect("tokenize failed");
        eprintln!("{tail:?}");
        eprintln!("{res:?}");

        let data = b"{key:[[{'val':null}]]}";
        let mut t = Tokenizer::new(data.as_slice()).expect("new failed");
        let (tail, res) = t.tokenize().expect("tokenize failed");
        eprintln!("{tail:?}");
        eprintln!("{res:?}");

        let data = b"{var-length-key:[[{'some val':null}]]}";
        let mut t = Tokenizer::new(data.as_slice()).expect("new failed");
        let (tail, res) = t.tokenize().expect("tokenize failed");
        eprintln!("{tail:?}");
        eprintln!("{res:?}");

        let data = b"%7B%22key%22%3A%22value%22%7D";
        let mut t = Tokenizer::new(data.as_slice()).expect("new failed");
        let (tail, res) = t.tokenize().expect("tokenize failed");
        eprintln!("{tail:?}");
        eprintln!("{res:?}");
    }
}
