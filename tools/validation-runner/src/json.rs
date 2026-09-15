//! Owns JSON encoding for run records.
//!
//! This module writes the smallest JSON the records need. It does not own
//! record content, field names, or file layout.

/// A JSON object under construction. Keys keep insertion order.
#[derive(Debug, Default)]
pub struct Object {
    body: String,
}

impl Object {
    pub const fn new() -> Self {
        Self {
            body: String::new(),
        }
    }

    pub fn string(&mut self, key: &str, value: &str) {
        self.key(key);
        self.body.push_str(&quote(value));
    }

    pub fn number(&mut self, key: &str, value: u64) {
        self.key(key);
        self.body.push_str(&value.to_string());
    }

    pub fn strings(&mut self, key: &str, values: &[String]) {
        self.key(key);
        self.body.push('[');
        for (index, value) in values.iter().enumerate() {
            if index > 0 {
                self.body.push(',');
            }
            self.body.push_str(&quote(value));
        }
        self.body.push(']');
    }

    pub fn object(&mut self, key: &str, value: &Self) {
        self.key(key);
        self.body.push_str(&value.encode());
    }

    pub fn encode(&self) -> String {
        let mut encoded = String::with_capacity(self.body.len().saturating_add(2));
        encoded.push('{');
        encoded.push_str(&self.body);
        encoded.push('}');
        encoded
    }

    fn key(&mut self, key: &str) {
        if !self.body.is_empty() {
            self.body.push(',');
        }
        self.body.push_str(&quote(key));
        self.body.push(':');
    }
}

/// Encodes one JSON string literal.
pub fn quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len().saturating_add(2));
    quoted.push('"');
    for character in value.chars() {
        match character {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            control if control < '\u{20}' => {
                let code = u32::from(control);
                quoted.push_str("\\u00");
                quoted.push(hex_digit(code.checked_div(16).unwrap_or(0)));
                quoted.push(hex_digit(code.checked_rem(16).unwrap_or(0)));
            }
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}

/// Renders one hexadecimal digit of a control character escape.
fn hex_digit(value: u32) -> char {
    char::from_digit(value, 16).unwrap_or('0')
}

#[cfg(test)]
mod tests {
    use super::{Object, quote};

    #[test]
    fn quotes_control_characters_and_delimiters() {
        assert_eq!(quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(quote("line\nbreak"), "\"line\\nbreak\"");
        assert_eq!(quote("\u{1}"), "\"\\u0001\"");
    }

    #[test]
    fn encodes_objects_in_insertion_order() {
        let mut inner = Object::new();
        inner.number("attempt", 2);

        let mut outer = Object::new();
        outer.string("segment", "unit-tests");
        outer.object("detail", &inner);
        outer.strings("required", &["a".to_owned(), "b".to_owned()]);

        assert_eq!(
            outer.encode(),
            "{\"segment\":\"unit-tests\",\"detail\":{\"attempt\":2},\"required\":[\"a\",\"b\"]}"
        );
    }
}
