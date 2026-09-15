//! Owns JSON encoding and decoding for run records.
//!
//! This module handles the smallest JSON the records need. It does not own
//! record content, field names, or file layout.

use std::iter::Peekable;
use std::str::Chars;

use crate::error::{Result, failed};

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

/// A value a journal entry can hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    String(String),
    Number(u64),
}

/// Reads one JSON object whose values are strings or numbers.
///
/// Journal entries have that shape. Anything else is a record the runner
/// did not write, and reading it as evidence would be a guess.
pub fn parse_flat_object(text: &str) -> Result<Vec<(String, Value)>> {
    let mut characters = text.trim().chars().peekable();
    if characters.next() != Some('{') {
        return failed("a journal entry must be a JSON object");
    }

    let mut fields: Vec<(String, Value)> = Vec::new();
    skip_whitespace(&mut characters);
    if characters.peek() == Some(&'}') {
        return Ok(fields);
    }

    loop {
        skip_whitespace(&mut characters);
        if characters.peek() != Some(&'"') {
            return failed("a journal entry key must be a string");
        }
        let key = parse_string(&mut characters)?;

        skip_whitespace(&mut characters);
        if characters.next() != Some(':') {
            return failed("a journal entry key must be followed by a value");
        }

        skip_whitespace(&mut characters);
        let value = match characters.peek() {
            Some('"') => Value::String(parse_string(&mut characters)?),
            Some(digit) if digit.is_ascii_digit() => Value::Number(parse_number(&mut characters)?),
            _ => return failed("a journal entry value must be a string or a number"),
        };
        fields.push((key, value));

        skip_whitespace(&mut characters);
        match characters.next() {
            Some(',') => {}
            Some('}') => return Ok(fields),
            _ => return failed("a journal entry must end after its last value"),
        }
    }
}

/// Reads one string field from a parsed journal entry.
pub fn string_field<'a>(fields: &'a [(String, Value)], key: &str) -> Option<&'a str> {
    fields.iter().find_map(|(name, value)| match value {
        Value::String(text) if name == key => Some(text.as_str()),
        _ => None,
    })
}

/// Reads one number field from a parsed journal entry.
pub fn number_field(fields: &[(String, Value)], key: &str) -> Option<u64> {
    fields.iter().find_map(|(name, value)| match value {
        Value::Number(number) if name == key => Some(*number),
        _ => None,
    })
}

fn skip_whitespace(characters: &mut Peekable<Chars<'_>>) {
    while characters
        .peek()
        .is_some_and(|character| character.is_whitespace())
    {
        let _ = characters.next();
    }
}

fn parse_string(characters: &mut Peekable<Chars<'_>>) -> Result<String> {
    if characters.next() != Some('"') {
        return failed("a JSON string must start with a quotation mark");
    }

    let mut value = String::new();
    loop {
        match characters.next() {
            Some('"') => return Ok(value),
            Some('\\') => value.push(parse_escape(characters)?),
            Some(character) => value.push(character),
            None => return failed("a JSON string must be closed"),
        }
    }
}

fn parse_escape(characters: &mut Peekable<Chars<'_>>) -> Result<char> {
    match characters.next() {
        Some('"') => Ok('"'),
        Some('\\') => Ok('\\'),
        Some('/') => Ok('/'),
        Some('n') => Ok('\n'),
        Some('r') => Ok('\r'),
        Some('t') => Ok('\t'),
        Some('b') => Ok('\u{8}'),
        Some('f') => Ok('\u{c}'),
        Some('u') => parse_unicode_escape(characters),
        _ => failed("a JSON string holds an escape the runner does not read"),
    }
}

fn parse_unicode_escape(characters: &mut Peekable<Chars<'_>>) -> Result<char> {
    let mut digits = String::new();
    for _ in 0..4 {
        match characters.next() {
            Some(digit) if digit.is_ascii_hexdigit() => digits.push(digit),
            _ => return failed("a unicode escape needs four hexadecimal digits"),
        }
    }

    let Ok(code) = u32::from_str_radix(&digits, 16) else {
        return failed("a unicode escape holds a value the runner cannot read");
    };
    let Some(character) = char::from_u32(code) else {
        return failed("a unicode escape holds a value that is not a character");
    };
    Ok(character)
}

fn parse_number(characters: &mut Peekable<Chars<'_>>) -> Result<u64> {
    let mut digits = String::new();
    while characters.peek().is_some_and(char::is_ascii_digit) {
        if let Some(digit) = characters.next() {
            digits.push(digit);
        }
    }

    let Ok(number) = digits.parse::<u64>() else {
        return failed("a journal entry holds a number the runner cannot read");
    };
    Ok(number)
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
    fn reads_back_every_field_it_wrote() -> crate::error::Result<()> {
        let mut object = Object::new();
        object.string("segment", "unit-tests");
        object.number("attempt", 2);
        object.string("note", "a \"quoted\" note\nwith a break");

        let fields = super::parse_flat_object(&object.encode())?;

        assert_eq!(super::string_field(&fields, "segment"), Some("unit-tests"));
        assert_eq!(super::number_field(&fields, "attempt"), Some(2));
        assert_eq!(
            super::string_field(&fields, "note"),
            Some("a \"quoted\" note\nwith a break")
        );
        assert_eq!(super::string_field(&fields, "absent"), None);
        Ok(())
    }

    #[test]
    fn refuses_text_that_is_not_a_flat_object() {
        assert!(super::parse_flat_object("not json").is_err());
        assert!(super::parse_flat_object("{\"key\":").is_err());
        assert!(super::parse_flat_object("{\"key\":{}}").is_err());
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
