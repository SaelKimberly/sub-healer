//! Very permissive parser for JSON-ish data in raw subscriptions.
//! Uses hand-rolled UTF-8/percent-decoding character source.

use std::str::FromStr;

use serde_json::{Map, Number, Value};

use super::fast_perc::AutoChars;

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

#[cfg_attr(test, derive(Debug))]
enum Container {
    Arr(Vec<Value>),
    Obj(Map<String, Value>, Option<String>),
}
#[derive(Default)]
#[cfg_attr(test, derive(Debug))]
struct JsonBuilder {
    stack: Vec<Container>,
    root: Option<Value>,
}
impl JsonBuilder {
    pub const fn object(&self) -> bool {
        matches!(self.stack.as_slice(), &[.., Container::Obj(_, _)])
    }
    pub fn begin_obj(&mut self) {
        self.stack.push(Container::Obj(Map::default(), None));
    }
    pub fn begin_arr(&mut self) {
        self.stack.push(Container::Arr(Vec::default()));
    }
    pub fn set_pending_key(&mut self, key: String) -> Result<(), PermissiveJsonError> {
        match self.stack.last_mut() {
            Some(Container::Obj(_, pending)) => {
                *pending = Some(key);
                Ok(())
            }
            _ => Err(PermissiveJsonError::InvalidSyntax),
        }
    }
    pub fn end_obj(&mut self) -> Result<(), PermissiveJsonError> {
        let Some(Container::Obj(map, _)) = self.stack.pop() else {
            return Err(PermissiveJsonError::InvalidSyntax);
        };
        self.insert_completed_value(Value::Object(map))
    }
    pub fn end_arr(&mut self) -> Result<(), PermissiveJsonError> {
        let Some(Container::Arr(arr)) = self.stack.pop() else {
            return Err(PermissiveJsonError::InvalidSyntax);
        };
        self.insert_completed_value(Value::Array(arr))
    }
    pub fn insert_completed_value(&mut self, value: Value) -> Result<(), PermissiveJsonError> {
        match self.stack.last_mut() {
            None => {
                self.root = Some(value);
                Ok(())
            }
            Some(Container::Obj(map, pending)) => {
                pending
                    .take()
                    .map_or(Err(PermissiveJsonError::InvalidSyntax), |key| {
                        map.insert(key, value);
                        Ok(())
                    })
            }
            Some(Container::Arr(arr)) => {
                arr.push(value);
                Ok(())
            }
        }
    }
}
#[cfg_attr(test, derive(Debug))]
struct JsonReader<'a> {
    char_iter: AutoChars<'a>,
    last_char: char,
    json: JsonBuilder,
}

const fn next_char_impl(char_iter: &mut AutoChars) -> PResult<char> {
    match char_iter.next() {
        Some(c) => Ok(c),
        None if char_iter.remaining().is_empty() => Err(PermissiveJsonError::Eof),
        None => Err(PermissiveJsonError::InvalidEncoding),
    }
}

impl<'a> JsonReader<'a> {
    const fn create(input: &'a [u8]) -> PResult<Self> {
        let mut char_iter = AutoChars::new(input);
        match next_char_impl(&mut char_iter) {
            Ok(last_char) => Ok(Self {
                char_iter,
                last_char,
                json: JsonBuilder {
                    stack: Vec::new(),
                    root: None,
                },
            }),
            Err(e) => Err(e),
        }
    }

    fn try_consume(mut self) -> PResult<(Value, &'a [u8])> {
        loop {
            // #[cfg(test)]
            // eprintln!("{:#?}", &self);
            if let Some(root) = self.json.root.take() {
                return Ok((root, self.char_iter.remaining()));
            }

            if self.json.object() {
                if let Err(e) = self.read_key() {
                    match self.last_char {
                        '}' | ']' => {}
                        _ => return Err(e),
                    }
                } else {
                    _ = self.next_char()?;
                }
            }
            self.read_val()?;

            while self.skip_while_whitespace(None)? == ',' {
                _ = self.next_char()?;
            }
        }
    }
}
impl JsonReader<'_> {
    const fn next_char(&mut self) -> PResult<char> {
        match next_char_impl(&mut self.char_iter) {
            Ok(c) => {
                self.last_char = c;
                Ok(c)
            }
            Err(e) => Err(e),
        }
    }
    fn skip_while_whitespace(&mut self, mut opt_out: Option<&mut String>) -> PResult<char> {
        loop {
            if self.last_char.is_whitespace() || matches!(self.last_char, '+') {
                if let Some(out) = opt_out.as_mut() {
                    out.push(self.last_char);
                }
                _ = self.next_char()?;
            } else {
                break Ok(self.last_char);
            }
        }
    }

    fn take_text(
        &mut self,
        out: &mut String,
        predicate: impl Fn(char) -> bool,
        esc_char: Option<char>,
    ) -> PResult<()> {
        loop {
            if let Some(esc_char) = esc_char
                && self.last_char == esc_char
            {
                let ch = self.next_char()?;
                out.push(esc_char);
                out.push(ch);
            } else if predicate(self.last_char) {
                out.push(self.last_char);
            } else {
                return Ok(());
            }
            match self.next_char() {
                Ok(_) => {}
                Err(PermissiveJsonError::Eof) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }

    #[inline]
    fn read_key(&mut self) -> PResult<()> {
        let key = self.read_any_data_and_verify(&[':'])?;
        self.json.set_pending_key(key)
    }
    fn read_val_raw(&mut self) -> PResult<String> {
        self.read_any_data_and_verify(&[',', ']', '}'])
    }

    fn read_val(&mut self) -> PResult<()> {
        match self.skip_while_whitespace(None)? {
            '{' => {
                self.json.begin_obj();
                self.next_char()?;
            }
            '[' => {
                self.json.begin_arr();
                self.next_char()?;
            }
            '}' => {
                self.json.end_obj()?;
                if self.json.root.is_none() {
                    self.next_char()?;
                }
            }
            ']' => {
                self.json.end_arr()?;
                if self.json.root.is_none() {
                    self.next_char()?;
                }
            }
            _ => {
                let val_raw = self.read_val_raw()?;

                let v = match val_raw.as_bytes() {
                    [c @ (b'0'..=b'9')] => Value::Number(Number::from(c - b'0')),
                    n @ [b'1'..=b'9', ..]
                        if let Ok(s) = str::from_utf8(n)
                            && s.chars().all(|c| c.is_ascii_digit()) =>
                    {
                        <i64 as FromStr>::from_str(val_raw.as_str()).map_or_else(
                            |_| Value::String(val_raw),
                            |v| Value::Number(Number::from(v)),
                        )
                    }
                    [b't' | b'T', b'r', b'u', b'e'] => Value::Bool(true),
                    [b'F' | b'f', b'a', b'l', b's', b'e'] => Value::Bool(false),
                    [b'N', b'o', b'n', b'e'] | [b'n', b'u', b'l', b'l'] => Value::Null,
                    _ => <i64 as FromStr>::from_str(val_raw.as_str())
                        .map_or_else(
                            |_| {
                                <f64 as FromStr>::from_str(val_raw.as_str()).map_or_else(
                                    |_| None,
                                    |v| Number::from_f64(v).map(Value::Number),
                                )
                            },
                            |v| Some(Value::Number(Number::from(v))),
                        )
                        .unwrap_or(Value::String(val_raw)),
                };
                return self.json.insert_completed_value(v);
            }
        }
        Ok(())
    }

    // Read all characters from current (last_char):
    // If current char is a quote, then read to the next not escaped quote.
    // If current char is not a quote, read with restrictive allowlist
    // When reading done, verify, that next non-whitespace character is in verification asset.

    fn apply_unescape(val: &str, is_value: bool) -> String {
        if is_value {
            super::unescaper::Unescaper::default()
                .chardet(true, true)
                .enc8259(true)
                .enc_uni(true)
                .do_unescape(val.as_bytes())
                .expect("unescape ok")
        } else {
            super::unescaper::Unescaper::default()
                .enc8259(true)
                .do_unescape(val.as_bytes())
                .expect("unescape ok")
        }
    }

    fn read_any_data_and_verify(&mut self, verification_asset: &'static [char]) -> PResult<String> {
        if verification_asset.is_empty() {
            unreachable!("should never be used if empty")
        }
        let c = self.skip_while_whitespace(None)?;

        let mut key = String::new();
        if let eof @ ('"' | '\'') = c {
            _ = self.next_char()?;
            let is_value = verification_asset.len() > 1 || verification_asset[0] != ':';
            loop {
                self.take_text(&mut key, |c| c != eof, Some('\\'))?;
                let mut key_length = key.len();
                key.push('\\');
                key.push(eof);

                let check = loop {
                    match self.next_char() {
                        Err(PermissiveJsonError::Eof) => {
                            key.truncate(key_length);
                            let raw = core::mem::take(&mut key);
                            return Ok(Self::apply_unescape(&raw, is_value));
                        }
                        Err(e) => return Err(e),
                        Ok(_) => {}
                    }
                    match self.skip_while_whitespace(Some(&mut key)) {
                        Err(PermissiveJsonError::Eof) => {
                            key.truncate(key_length);
                            let raw = core::mem::take(&mut key);
                            return Ok(Self::apply_unescape(&raw, is_value));
                        }
                        Err(e) => return Err(e),
                        Ok(c) if c == eof => {
                            key_length = key.len();
                            key.push('\\');
                            key.push(eof);
                        }
                        Ok(c) => break c,
                    }
                };

                if verification_asset.contains(&check) {
                    key.truncate(key_length);
                    let raw = core::mem::take(&mut key);
                    return Ok(Self::apply_unescape(&raw, is_value));
                }

                // check is not a delimiter — it's part of the value text
                // It was consumed from iterator by next_char above.
                // Push it to key and advance past it so take_text doesn't
                // double-process it (which would mess up \ escape handling).
                key.push(check);
                match self.next_char() {
                    Err(PermissiveJsonError::Eof) => {
                        key.push('\\');
                        key.push(eof);
                        let raw = core::mem::take(&mut key);
                        return Ok(Self::apply_unescape(&raw, is_value));
                    }
                    Err(e) => return Err(e),
                    Ok(_) => {}
                }
                match self.skip_while_whitespace(Some(&mut key)) {
                    Err(PermissiveJsonError::Eof) => {
                        key.push('\\');
                        key.push(eof);
                        let raw = core::mem::take(&mut key);
                        return Ok(Self::apply_unescape(&raw, is_value));
                    }
                    Err(e) => return Err(e),
                    Ok(_) => {}
                }
            }
        } else {
            self.take_text(
                &mut key,
                |c| matches!(c,'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-' | '.'),
                None,
            )?;
            if verification_asset.contains(&self.last_char) {
                return Ok(key);
            }
            if self.char_iter.remaining().is_empty() && !key.is_empty() {
                return Ok(key);
            }
        }
        if matches!(self.last_char, '"' | '\'') {
            _ = self.next_char()?;
            if verification_asset.contains(&self.skip_while_whitespace(None)?) {
                return Ok(key);
            }
            return Err(PermissiveJsonError::InvalidSyntax);
        }
        if !verification_asset.contains(&self.skip_while_whitespace(None)?) {
            return Err(PermissiveJsonError::InvalidSyntax);
        }
        Ok(key)
    }
}

/// Parse a JSON value from a byte slice, with some leniency.
///
/// # Errors
///
/// Returns an error if the input is not valid or recoverable JSON.
pub fn permissive_json_core(input: &[u8]) -> PResult<(&[u8], serde_json::Value)> {
    let (value, remaining) = JsonReader::create(input)?.try_consume()?;
    Ok((remaining, value))
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
    use super::permissive_json_core;
    use super::{PResult, permissive_json};

    #[test]
    fn test_tokenizer() -> PResult<()> {
        let (tail, res) = permissive_json_core(b"None")?;
        assert_eq!(res, serde_json::Value::Null);
        assert!(tail.is_empty(), "tail: {tail:?}");

        let (tail, res) = permissive_json_core(b"{}")?;
        assert_eq!(res, serde_json::json!({}));
        assert!(tail.is_empty(), "tail: {tail:?}");

        let (tail, res) = permissive_json_core(b"{'key':'val'}")?;
        assert_eq!(res, serde_json::json!({"key": "val"}));
        assert!(tail.is_empty(), "tail: {tail:?}");

        let (tail, res) = permissive_json_core(b"{'key':[['val',],],}")?;
        assert_eq!(res, serde_json::json!({"key": [["val"]]}));
        assert!(tail.is_empty(), "tail: {tail:?}");

        let (tail, res) = permissive_json_core(b"{'key':[[{'val':null}]]}")?;
        assert_eq!(res, serde_json::json!({"key": [[{"val": null}]]}));
        assert!(tail.is_empty(), "tail: {tail:?}");

        let (tail, res) = permissive_json_core(b"{key:[[{'val':null}]]}")?;
        assert_eq!(res, serde_json::json!({"key": [[{"val": null}]]}));
        assert!(tail.is_empty(), "tail: {tail:?}");

        let (tail, res) = permissive_json_core(b"{var-length-key:[[{'some val':null}]]}")?;
        assert_eq!(
            res,
            serde_json::json!({"var-length-key": [[{"some val": null}]]})
        );
        assert!(tail.is_empty(), "tail: {tail:?}");

        let (tail, res) = permissive_json_core(b"%7B%22key%22%3A%22value%22%7D")?;
        assert_eq!(res, serde_json::json!({"key": "value"}));
        assert!(tail.is_empty(), "tail: {tail:?}");

        Ok(())
    }

    #[test]
    fn test_corrupted_vmess_ps() {
        let input: &[u8] = &[
            0x7b, 0x22, 0x61, 0x64, 0x64, 0x22, 0x3a, 0x20, 0x22, 0x32, 0x31, 0x36, 0x2e, 0x32,
            0x33, 0x38, 0x2e, 0x38, 0x36, 0x2e, 0x31, 0x35, 0x38, 0x22, 0x2c, 0x20, 0x22, 0x69,
            0x64, 0x22, 0x3a, 0x20, 0x22, 0x39, 0x30, 0x62, 0x65, 0x32, 0x31, 0x34, 0x64, 0x2d,
            0x30, 0x34, 0x38, 0x63, 0x2d, 0x34, 0x65, 0x61, 0x32, 0x2d, 0x61, 0x36, 0x30, 0x32,
            0x2d, 0x62, 0x38, 0x65, 0x34, 0x64, 0x34, 0x65, 0x35, 0x31, 0x65, 0x33, 0x36, 0x22,
            0x2c, 0x20, 0x22, 0x6e, 0x65, 0x74, 0x22, 0x3a, 0x20, 0x22, 0x74, 0x63, 0x70, 0x22,
            0x2c, 0x20, 0x22, 0x70, 0x6f, 0x72, 0x74, 0x22, 0x3a, 0x20, 0x33, 0x34, 0x34, 0x36,
            0x30, 0x2c, 0x20, 0x22, 0x74, 0x79, 0x70, 0x65, 0x22, 0x3a, 0x20, 0x22, 0x6e, 0x6f,
            0x6e, 0x65, 0x22, 0x2c, 0x20, 0x22, 0x76, 0x22, 0x3a, 0x20, 0x22, 0x32, 0x22, 0x2c,
            0x20, 0x22, 0x73, 0x6b, 0x69, 0x70, 0x2d, 0x63, 0x65, 0x72, 0x74, 0x2d, 0x76, 0x65,
            0x72, 0x69, 0x66, 0x79, 0x22, 0x3a, 0x20, 0x74, 0x72, 0x75, 0x65, 0x2c, 0x20, 0x22,
            0x70, 0x73, 0x22, 0x3a, 0x20, 0x5b, 0xf0, 0x9f, 0x8f, 0x81, 0x5d, 0x74, 0x2e, 0x6d,
            0x65, 0x2f, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x48, 0x75, 0x62, 0x3a, 0x20,
            0x22, 0x5c, 0x75, 0x64, 0x38, 0x33, 0x64, 0x5c, 0x75, 0x64, 0x63, 0x34, 0x39, 0x5c,
            0x75, 0x64, 0x38, 0x33, 0x63, 0x5c, 0x75, 0x64, 0x64, 0x39, 0x34, 0x40, 0x76, 0x32,
            0x72, 0x61, 0x79, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x5f, 0x70, 0x6f,
            0x6f, 0x6c, 0x5c, 0x75, 0x64, 0x38, 0x33, 0x64, 0x5c, 0x75, 0x64, 0x63, 0x65, 0x31,
            0x5c, 0x75, 0x64, 0x38, 0x33, 0x63, 0x5c, 0x75, 0x64, 0x64, 0x66, 0x32, 0x5c, 0x75,
            0x64, 0x38, 0x33, 0x63, 0x5c, 0x75, 0x64, 0x64, 0x66, 0x64, 0x5c, 0x75, 0x30, 0x30,
            0x61, 0x65, 0x5c, 0x75, 0x66, 0x65, 0x30, 0x66, 0x4d, 0x65, 0x78, 0x69, 0x63, 0x6f,
            0x5c, 0x75, 0x30, 0x30, 0x61, 0x39, 0x5c, 0x75, 0x66, 0x65, 0x30, 0x66, 0x51, 0x75,
            0x65, 0x72, 0x5c, 0x75, 0x30, 0x30, 0x65, 0x39, 0x74, 0x61, 0x72, 0x6f, 0x20, 0x43,
            0x69, 0x74, 0x79, 0x5c, 0x75, 0x64, 0x38, 0x33, 0x63, 0x5c, 0x75, 0x64, 0x64, 0x37,
            0x66, 0x5c, 0x75, 0x66, 0x65, 0x30, 0x66, 0x70, 0x69, 0x6e, 0x67, 0x3a, 0x31, 0x36,
            0x31, 0x2e, 0x36, 0x38, 0x6d, 0x73, 0x22, 0x7d,
        ];
        let result = permissive_json(input);
        assert!(result.is_ok(), "Should parse corrupted VMess: {result:?}");
        let value = result.unwrap();
        let ps = value.get("ps").and_then(|v| v.as_str());
        assert!(ps.is_some(), "Should have 'ps' field: {value}");
        let ps = ps.unwrap();
        assert!(ps.contains("ConfigsHub"), "Should contain channel name");
        assert!(ps.contains("v2ray"), "Should contain description");
        eprintln!("OK: ps={:?}", ps);
    }
}
