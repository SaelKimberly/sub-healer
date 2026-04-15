//! Very permissive nom-based parser for JSON area in raw data

use bstr::ByteSlice;
use winnow::ModalResult;
use winnow::error::{ContextError, ErrMode, ParserError};

use crate::utils::PercentDecode;
use crate::{Span, utils::Unescaper};

use super::cursor::{JsonToken, tokens_to_new_json};

pub(super) struct Tokenizer<'a> {
    iter: PercentDecode<'a>,
    last_e: usize,
    last_c: char,
    tokens: Vec<JsonToken>,
}

impl<'a> Tokenizer<'a> {
    pub(super) fn new(span: Span<'a>) -> Option<Self> {
        let mut chars = span.as_ref().char_indices();
        let (_, _, last_c) = chars.next()?;

        let mut chars = PercentDecode::new(span).with_decoding(last_c == '%');
        let (_, last_e, last_c) = chars.next()?.ok()?;

        Some(Self {
            iter: chars,
            last_e,
            last_c,
            tokens: Vec::new(),
        })
    }

    /// Get the next character (returns a Eof error if there are no more characters)
    fn _next_char(&mut self) -> ModalResult<char> {
        if let Some((_, c_e, c)) = self.iter.next().transpose()? {
            self.last_e = c_e;
            self.last_c = c;
            Ok(c)
        } else {
            self.iter.error("Expected character")
        }
    }

    /// Skip whitespace (free '+' sign is considered whitespace too)
    fn _skip_ws(&mut self) -> ModalResult<bool> {
        let mut skipped = false;
        while self.last_c.is_whitespace() || self.last_c == '+' {
            self._next_char()?;
            skipped = true;
        }
        Ok(skipped)
    }

    /// Test for a control character (returns a Tag error if it's not a control character)
    fn _test_ctrl(&mut self, require: bool) -> ModalResult<Option<JsonToken>> {
        let ctrl = match self.last_c {
            '{' => JsonToken::ObjStart,
            '}' => JsonToken::ObjClose,
            '[' => JsonToken::ArrStart,
            ']' => JsonToken::ArrClose,
            ':' => JsonToken::Colon,
            ',' => JsonToken::Comma,
            _ if !require => return Ok(None),
            _ => return self.iter.error("Expected control character"),
        };
        Ok(Some(ctrl))
    }

    fn _test_text(&mut self, is_value: bool) -> ModalResult<Option<String>> {
        if let eof @ ('"' | '\'') = self.last_c {
            let bos = self.last_e;

            let mut esc = false;

            let span: Span<'a> = loop {
                let Ok(c) = self._next_char() else {
                    // If we reached eof immediately after opening quote, return error
                    if self.last_e == bos {
                        return self.iter.error("Expected closing quote");
                    } else {
                        // If we reached eof before closing quote,
                        //  return available data

                        break Span::new(&self.iter.span.as_ref()[bos..self.last_e]);
                    }
                };
                if esc {
                    esc = false;
                } else if c == '\\' {
                    esc = true;
                    continue;
                } else if c == eof {
                    // ignore eof error if no next character is available
                    // for handling unclosed JSON string
                    let moved = self._next_char().is_ok();
                    // If we reached closing quote
                    break Span::new(
                        &self.iter.span.as_ref()[bos..if moved {
                            self.last_e - 2
                        } else {
                            self.last_e - 1
                        }],
                    );
                }
            };

            let text = Unescaper::default()
                .chardet(is_value, true)
                .enc8259(true)
                .do_unescape(span)
                .expect("As all unescape should be ok");

            Ok(Some(text))
        } else {
            Ok(None)
        }
    }

    /// Test for an unquoted key
    fn _test_ukey(&mut self) -> ModalResult<String> {
        self._skip_ws()?;

        let mut key = String::new();

        loop {
            match self._test_ctrl(false).expect("Infallible") {
                Some(JsonToken::Colon) => break,
                Some(_) => return self.iter.error("Unexpected control character"),
                // not a control character
                None => {}
            }

            if self.last_c.is_alphanumeric() || matches!(self.last_c, '_' | '-') {
                key.push(self.last_c);
            } else if matches!(self.last_c, '"' | '\'') {
                // detected mismatched closing bracket
                // no action required, as it shouldn't be added to the key
            } else {
                return self.iter.error("Expected key character");
            }

            self._next_char()?;

            if self.last_c.is_whitespace() {
                break;
            }
        }
        Ok(key)
    }

    /// Test for an unquoted value
    fn _test_uval(&mut self, in_object: bool) -> ModalResult<serde_json::Value> {
        // If value starts with a dash, it may represent a negative number
        let positive = if self.last_c == '-' {
            self._next_char()?;
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
            // Also, EOF should be provided to upstream as an error
            match self._test_ctrl(false).expect("Infallible") {
                Some(JsonToken::Comma) => break,
                Some(JsonToken::ObjClose) if in_object => break,
                Some(JsonToken::ArrClose) if !in_object => break,
                Some(_) => return self.iter.error("Unexpected control character"),
                // no control characters found
                None => {}
            }

            match self.last_c {
                '0'..='9' => value_repr.push(self.last_c),
                'e' | 'E' => {
                    if maybe_num && e_appeared {
                        // number cannot have two 'e'/'E' in scientific notation
                        maybe_num = false
                    } else {
                        e_appeared = true
                    }
                    value_repr.push('e');
                }
                '.' => {
                    if maybe_num && (p_appeared || e_appeared) {
                        // number cannot have two '.' in decimal notation
                        // number cannot have '.' after 'e'/'E'
                        maybe_num = false
                    } else {
                        p_appeared = true
                    }
                    value_repr.push(self.last_c)
                }
                _ => {
                    maybe_num = false;
                    value_repr.push(self.last_c)
                }
            }

            self._next_char()?;
        }

        let v = if maybe_num {
            if p_appeared || e_appeared {
                if let Ok(v) = value_repr.parse::<f64>() {
                    let Some(v) = serde_json::Number::from_f64(if positive { v } else { -v })
                    else {
                        unreachable!()
                    };
                    serde_json::Value::Number(v)
                } else {
                    serde_json::Value::String(value_repr)
                }
            } else {
                if let Ok(v) = value_repr.parse::<i64>() {
                    serde_json::Value::Number(serde_json::Number::from(if positive {
                        v
                    } else {
                        -v
                    }))
                } else {
                    serde_json::Value::String(value_repr)
                }
            }
        } else {
            match value_repr.as_str().trim() {
                // python literals
                "None" => serde_json::Value::Null,
                "True" => serde_json::Value::Bool(true),
                "False" => serde_json::Value::Bool(false),
                // json literals
                "null" => serde_json::Value::Null,
                "true" => serde_json::Value::Bool(true),
                "false" => serde_json::Value::Bool(false),
                _ => serde_json::Value::String(value_repr),
            }
        };
        Ok(v)
    }

    fn _expect_key(&mut self) -> ModalResult<String> {
        if let Some(k) = self._test_text(false)? {
            Ok(k)
        } else {
            self._test_ukey()
        }
    }

    fn _expect_val(&mut self, in_object: bool) -> ModalResult<serde_json::Value> {
        if let Some(v) = self._test_text(true)? {
            Ok(serde_json::Value::String(v))
        } else {
            self._test_uval(in_object)
        }
    }

    pub fn tokenize(&mut self) -> ModalResult<Option<serde_json::Value>> {
        // Stack of opening brackets (true: object, false: array)
        let mut opens: Vec<bool> = Vec::new();

        if self._test_ctrl(false).expect("Infallible").is_none() {
            return if 'n'.eq_ignore_ascii_case(&self.last_c)
                && ('o'.eq_ignore_ascii_case(&self._next_char()?)
                    && 'n'.eq_ignore_ascii_case(&self._next_char()?)
                    && 'e'.eq_ignore_ascii_case(&self._next_char()?))
                || ('u'.eq_ignore_ascii_case(&self.last_c)
                    && 'l'.eq_ignore_ascii_case(&self._next_char()?)
                    && 'l'.eq_ignore_ascii_case(&self._next_char()?))
            {
                Ok(Some(serde_json::Value::Null))
            } else {
                self.iter.error("Expected control character")
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
                self._skip_ws()?;

                // When there are no more control characters, break.
                let t = match self._test_ctrl(false).expect("Infallible") {
                    Some(t) => t,
                    None => break 'ctrl,
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
                    _ => return self.iter.error("Unexpected control character"),
                }

                // remove trailing comma before closing brackets
                if let JsonToken::ArrClose | JsonToken::ObjClose = t
                    && let Some(JsonToken::Comma) = self.tokens.last()
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
                self._next_char()?;
            }

            // Skip whitespaces after control characters
            self._skip_ws()?;

            if in_object {
                // when in an object, after a comma or opening bracket, expect key
                if let Some(JsonToken::ObjStart | JsonToken::Comma) = self.tokens.last() {
                    let key = self._expect_key()?;
                    self.tokens.push(JsonToken::Key(key));

                    // colons are allowed after key
                    allow_colon = true;
                    // commas are not allowed after key
                    allow_comma = false;
                } else
                // after a colon, expect value
                if let Some(JsonToken::Colon) = self.tokens.last() {
                    let val = self._expect_val(true)?;
                    self.tokens.push(JsonToken::Val(val));

                    // colons are not allowed after value
                    allow_colon = false;
                    // commas are allowed after value
                    allow_comma = true;
                } else {
                    return self.iter.error("Unexpected control character");
                }
            } else {
                // when in an array, after a comma or opening bracket, expect value
                if let Some(JsonToken::ArrStart | JsonToken::Comma) = self.tokens.last() {
                    let val = self._expect_val(false)?;
                    self.tokens.push(JsonToken::Val(val));

                    // colons are not allowed in array
                    allow_colon = false;
                    // commas are allowed in array
                    allow_comma = true;
                } else {
                    return self.iter.error("Unexpected control character");
                }
            }
        }

        // Note, that missing closing brackets will be recovered automatically
        //  as the tokenizer will not check their presense, only the order, if any.

        tokens_to_new_json(self.iter.span, &self.tokens).map_err(|e| {
            let mut e = ContextError::from_input(&e.input);
            e.push(winnow::error::StrContext::Expected(
                winnow::error::StrContextValue::Description("Cannot parse JSON"),
            ));
            ErrMode::Cut(e)
        })
    }
}
