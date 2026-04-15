use winnow::ModalResult;

use crate::Span;

mod cursor;
mod parser;

pub fn permissive_json<'a>(span: Span<'a>) -> ModalResult<Option<serde_json::Value>> {
    if let Some(mut tok) = parser::Tokenizer::new(span) {
        tok.tokenize()
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::permissive_json;
    use crate::{Span, utils::jsonext::cursor::JsonToken};

    #[test]
    fn test_tokenizer() {
        let data = Span::new(b"None");
        let json = permissive_json(data)
            .expect("Should have succeeded")
            .expect("Should be not None");
        assert!(matches!(json, Value::Null), "Expected Null, got {json:?}");

        eprintln!("{data:?}");
        eprintln!("{json:?}");
    }
}
