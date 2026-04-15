use crate::{CutResult, Span};

#[cfg_attr(test, derive(Debug))]
pub(super) enum JsonToken {
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

struct Cursor<'a> {
    span: Span<'a>,
    base: Option<serde_json::Value>,
    path: Vec<Path>,
    xkey: Option<String>,
}

impl<'a> Cursor<'a> {
    pub fn new(span: Span<'a>) -> Self {
        Self {
            span,
            base: None,
            path: Vec::new(),
            xkey: None,
        }
    }
    pub fn traverse_map<'b>(
        &'b mut self,
    ) -> CutResult<'a, &'b mut serde_json::Map<String, serde_json::Value>> {
        let mut container_ref: &'b mut _ = self
            .base
            .get_or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));

        for elem in self.path.iter() {
            match elem {
                Path::Key(k) => {
                    let serde_json::Value::Object(o) = container_ref else {
                        return Err(crate::InputError::at(self.span));
                    };
                    container_ref = o.get_mut(k).ok_or(crate::InputError::at(self.span))?
                }
                Path::Index(i) => {
                    let serde_json::Value::Array(a) = container_ref else {
                        return Err(crate::InputError::at(self.span));
                    };
                    container_ref = a.get_mut(*i).ok_or(crate::InputError::at(self.span))?
                }
            }
        }

        let serde_json::Value::Object(o) = container_ref else {
            return Err(crate::InputError::at(self.span));
        };

        Ok(o)
    }

    pub fn traverse_arr<'b>(&'b mut self) -> CutResult<'a, &'b mut Vec<serde_json::Value>> {
        let mut container_ref: &'b mut _ = self
            .base
            .get_or_insert_with(|| serde_json::Value::Array(vec![]));

        for elem in self.path.iter() {
            match elem {
                Path::Key(k) => {
                    let serde_json::Value::Object(o) = container_ref else {
                        return Err(crate::InputError::at(self.span));
                    };
                    container_ref = o.get_mut(k).ok_or(crate::InputError::at(self.span))?
                }
                Path::Index(i) => {
                    let serde_json::Value::Array(a) = container_ref else {
                        return Err(crate::InputError::at(self.span));
                    };
                    container_ref = a.get_mut(*i).ok_or(crate::InputError::at(self.span))?
                }
            }
        }

        let serde_json::Value::Array(o) = container_ref else {
            return Err(crate::InputError::at(self.span));
        };

        Ok(o)
    }

    pub fn add_new_container(&mut self, key: Option<String>, is_array: bool) -> CutResult<'a, ()> {
        if self.base.is_none() {
            if is_array {
                self.base = Some(serde_json::Value::Array(Vec::new()));
            } else {
                self.base = Some(serde_json::Value::Object(serde_json::Map::new()));
            }
            return Ok(());
        }

        if let Some(k) = key.as_deref() {
            let o = self.traverse_map()?;
            o.insert(
                k.to_owned(),
                if is_array {
                    serde_json::Value::Array(Vec::new())
                } else {
                    serde_json::Value::Object(serde_json::Map::new())
                },
            );
            self.path.push(Path::Key(k.to_owned()));
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
    pub fn move_up(&mut self) {
        _ = self.path.pop();
    }

    pub fn push_kv(&mut self, key: Option<String>, value: serde_json::Value) -> CutResult<'a, ()> {
        if let Some(key) = key {
            let o = self.traverse_map()?;

            o.insert(key, value);
        } else {
            let a = self.traverse_arr()?;

            a.push(value);
        }
        Ok(())
    }

    pub fn finalize(self) -> Option<serde_json::Value> {
        self.base
    }

    pub fn add(&mut self, token: &JsonToken) -> CutResult<'a, ()> {
        match token {
            JsonToken::ArrStart => {
                let key = self.xkey.take();
                self.add_new_container(key, true)
            }
            JsonToken::ObjStart => {
                let key = self.xkey.take();
                self.add_new_container(key, false)
            }
            JsonToken::ArrClose | JsonToken::ObjClose => {
                self.move_up();
                Ok(())
            }
            JsonToken::Key(k) => {
                let None = self.xkey.replace(k.clone()) else {
                    return Err(crate::InputError::at(self.span));
                };
                Ok(())
            }
            JsonToken::Val(v) => {
                let key = self.xkey.take();
                if let serde_json::Value::String(s) = v {
                    let s = crate::utils::Unescaper::default()
                        .enc8259(true)
                        .enc_uni(true)
                        .do_unescape(Span::new(s.as_bytes()))
                        .expect("As all unescape should be ok");
                    self.push_kv(key, serde_json::Value::String(s))
                } else {
                    self.push_kv(key, v.clone())
                }
            }
            JsonToken::Colon | JsonToken::Comma => Ok(()),
        }
    }
}

pub(super) fn tokens_to_new_json<'a>(
    span: Span<'a>,
    tokens: &[JsonToken],
) -> CutResult<'a, Option<serde_json::Value>> {
    let x = tokens
        .iter()
        .try_fold(Cursor::new(span), |mut cursor, token| {
            cursor.add(token).map(|()| cursor)
        })?
        .finalize();

    Ok(x)
}
