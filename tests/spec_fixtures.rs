//! Runs the vendored `rp1-spec` `v0.2.0` fixture corpus against the protocol
//! codec.
//!
//! The corpus is test data. This harness reads every fixture, offers its
//! input in the declared direction, and asserts the exact outcome the
//! fixture states.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use rp1db::protocol::{self, Frame, Kind, Outgoing, OutgoingPayload, Payload, Role, Step};

/// Runs every fixture in the vendored corpus.
#[test]
fn corpus_conformance() -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rp1-spec-v0.2.0");
    let mut files = Vec::new();
    collect_json_files(&root, &mut files)?;
    files.sort();
    assert_eq!(
        files.len(),
        71,
        "expected 71 fixtures, found {}",
        files.len()
    );
    for file in &files {
        run_fixture(file)?;
    }
    Ok(())
}

/// Collects every `*.json` file below `directory`.
fn collect_json_files(directory: &Path, out: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_json_files(&path, out)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
            out.push(path);
        }
    }
    Ok(())
}

/// Loads one fixture and checks its outcome.
fn run_fixture(path: &Path) -> Result<(), Box<dyn Error>> {
    let text = fs::read_to_string(path)?;
    let value = Parser::new(&text).parse()?;
    let id = value
        .get("id")
        .and_then(Json::as_str)
        .ok_or_else(|| format!("{}: missing id", path.display()))?
        .to_string();
    let revision = value
        .get("revision")
        .and_then(Json::as_str)
        .ok_or_else(|| format!("fixture {id}: missing revision"))?;
    assert_eq!(revision, "v0.2.0", "fixture {id}: wrong revision");
    let direction = value
        .get("direction")
        .and_then(Json::as_str)
        .ok_or_else(|| format!("fixture {id}: missing direction"))?;
    let input = value
        .get("input")
        .ok_or_else(|| format!("fixture {id}: missing input"))?;
    let expect = value
        .get("expect")
        .ok_or_else(|| format!("fixture {id}: missing expect"))?;
    let role = role_of(&id, input)?;
    match direction {
        "decode" => {
            let bytes_hex = input
                .get("bytes")
                .and_then(Json::as_str)
                .ok_or_else(|| format!("fixture {id}: missing input.bytes"))?;
            let bytes = hex_decode(bytes_hex)?;
            let in_flight =
                declared_in_flight(&id, input)?.unwrap_or_else(|| default_in_flight(&bytes));
            run_decode(&id, &bytes, role, &in_flight, expect)?;
        }
        "encode" => run_encode(&id, input, expect)?,
        "both" => {
            run_encode(&id, input, expect)?;
            let bytes_hex = expect
                .get("bytes")
                .and_then(Json::as_str)
                .ok_or_else(|| format!("fixture {id}: missing expect.bytes"))?;
            let bytes = hex_decode(bytes_hex)?;
            let in_flight =
                declared_in_flight(&id, input)?.unwrap_or_else(|| default_in_flight(&bytes));
            run_decode(&id, &bytes, role, &in_flight, expect)?;
        }
        other => return Err(format!("fixture {id}: unknown direction {other}").into()),
    }
    Ok(())
}

/// Returns the role a fixture offers its bytes to.
fn role_of(id: &str, input: &Json) -> Result<Role, Box<dyn Error>> {
    match input.get("role").and_then(Json::as_str) {
        Some("client") => Ok(Role::Client),
        Some("server") | None => Ok(Role::Server),
        Some(other) => Err(format!("fixture {id}: unknown role {other}").into()),
    }
}

/// Returns the declared in-flight set, when the fixture states one.
fn declared_in_flight(id: &str, input: &Json) -> Result<Option<Vec<u64>>, Box<dyn Error>> {
    match input.get("in_flight") {
        Some(json) => {
            let array = json
                .as_array()
                .ok_or_else(|| format!("fixture {id}: in_flight must be an array"))?;
            let mut out = Vec::new();
            for item in array {
                let text = item
                    .as_str()
                    .ok_or_else(|| format!("fixture {id}: in_flight id must be a string"))?;
                out.push(text.parse::<u64>()?);
            }
            Ok(Some(out))
        }
        None => Ok(None),
    }
}

/// Builds the in-flight set that makes every connection-state check pass.
///
/// A fixture that states no `in_flight` asserts its outcome at a receiver
/// where every check reading connection state passes. A request opener must
/// find its id not in flight; a frame that names a request must find it in
/// flight.
fn default_in_flight(bytes: &[u8]) -> Vec<u64> {
    if bytes.get(1).copied() == Some(1) {
        return Vec::new();
    }
    request_id_from(bytes)
        .map(|request_id| vec![request_id])
        .unwrap_or_default()
}

/// Reads the request identity field of a frame header.
fn request_id_from(bytes: &[u8]) -> Option<u64> {
    let slice = bytes.get(12..20)?;
    let array: [u8; 8] = slice.try_into().ok()?;
    Some(u64::from_le_bytes(array))
}

/// Checks one decode expectation.
fn run_decode(
    id: &str,
    bytes: &[u8],
    role: Role,
    in_flight: &[u64],
    expect: &Json,
) -> Result<(), Box<dyn Error>> {
    let outcome = expect
        .get("outcome")
        .and_then(Json::as_str)
        .ok_or_else(|| format!("fixture {id}: missing outcome"))?;
    let step = protocol::decode(bytes, role, in_flight);
    match outcome {
        "success" => match step {
            Step::Frame(frame) => {
                if let Some(consumed) = expect.get("bytes_consumed").and_then(Json::as_i64) {
                    assert_eq!(
                        usize::try_from(consumed)?,
                        bytes.len(),
                        "fixture {id}: bytes_consumed"
                    );
                }
                if let Some(retires) = expect.get("retires").and_then(Json::as_str) {
                    assert_eq!(
                        frame.retires().value().to_string().as_str(),
                        retires,
                        "fixture {id}: retires"
                    );
                }
                let fields = expect
                    .get("fields")
                    .ok_or_else(|| format!("fixture {id}: missing expect.fields"))?;
                check_fields(id, &frame, fields)?;
            }
            other => return Err(format!("fixture {id}: expected frame, got {other:?}").into()),
        },
        "failure" => match step {
            Step::Failure { failure, consumed } => {
                let class = expect
                    .get("class")
                    .and_then(Json::as_str)
                    .ok_or_else(|| format!("fixture {id}: missing class"))?;
                let scope = expect
                    .get("scope")
                    .and_then(Json::as_str)
                    .ok_or_else(|| format!("fixture {id}: missing scope"))?;
                assert_eq!(failure.class().name(), class, "fixture {id}: class");
                assert_eq!(failure.scope().name(), scope, "fixture {id}: scope");
                if let Some(consumed_expected) = expect.get("bytes_consumed").and_then(Json::as_i64)
                {
                    assert_eq!(
                        consumed,
                        usize::try_from(consumed_expected)?,
                        "fixture {id}: bytes_consumed"
                    );
                }
            }
            other => return Err(format!("fixture {id}: expected failure, got {other:?}").into()),
        },
        "incomplete" => {
            let required = expect
                .get("bytes_required")
                .and_then(Json::as_i64)
                .ok_or_else(|| format!("fixture {id}: missing bytes_required"))?;
            match step {
                Step::Need(count) => assert_eq!(
                    count,
                    usize::try_from(required)?,
                    "fixture {id}: bytes_required"
                ),
                other => {
                    return Err(format!("fixture {id}: expected incomplete, got {other:?}").into());
                }
            }
        }
        other => return Err(format!("fixture {id}: unknown outcome {other}").into()),
    }
    Ok(())
}

/// Checks every field the fixture states against the decoded frame.
fn check_fields(id: &str, frame: &Frame<'_>, fields: &Json) -> Result<(), Box<dyn Error>> {
    let object = fields
        .as_object()
        .ok_or_else(|| format!("fixture {id}: fields must be an object"))?;
    for (key, expected) in object {
        check_field(id, frame, key, expected)?;
    }
    Ok(())
}

/// Checks one named field against the decoded frame.
fn check_field(
    id: &str,
    frame: &Frame<'_>,
    key: &str,
    expected: &Json,
) -> Result<(), Box<dyn Error>> {
    let header = frame.header();
    match key {
        "version" => assert_eq!(
            i64::from(header.version().value()),
            number(id, key, expected)?,
            "fixture {id}: {key}"
        ),
        "kind" => assert_eq!(
            i64::from(header.kind().value()),
            number(id, key, expected)?,
            "fixture {id}: {key}"
        ),
        "flags" => assert_eq!(
            i64::from(header.flags().value()),
            number(id, key, expected)?,
            "fixture {id}: {key}"
        ),
        "code" => assert_eq!(
            i64::from(header.code()),
            number(id, key, expected)?,
            "fixture {id}: {key}"
        ),
        "metadata_length" => assert_eq!(
            i64::from(header.metadata_length()),
            number(id, key, expected)?,
            "fixture {id}: {key}"
        ),
        "payload_length" => assert_eq!(
            i64::from(header.payload_length()),
            number(id, key, expected)?,
            "fixture {id}: {key}"
        ),
        "request_id" => {
            let text = string(id, key, expected)?;
            assert_eq!(
                header.request_id().value().to_string().as_str(),
                text,
                "fixture {id}: {key}"
            );
        }
        "metadata" => check_metadata(id, frame, expected)?,
        "logical_length" => {
            let text = string(id, key, expected)?;
            let Payload::Warm { logical_length } = frame.payload() else {
                return Err(format!("fixture {id}: expected a warm payload").into());
            };
            assert_eq!(
                logical_length.to_string().as_str(),
                text,
                "fixture {id}: {key}"
            );
        }
        "detail_length" => {
            let Payload::Error { detail, .. } = frame.payload() else {
                return Err(format!("fixture {id}: expected an error payload").into());
            };
            assert_eq!(
                i64::try_from(detail.len())?,
                number(id, key, expected)?,
                "fixture {id}: {key}"
            );
        }
        "detail_bytes" => {
            let Payload::Error { detail, .. } = frame.payload() else {
                return Err(format!("fixture {id}: expected an error payload").into());
            };
            assert_eq!(
                hex_encode(detail).as_str(),
                string(id, key, expected)?,
                "fixture {id}: {key}"
            );
        }
        "text" => {
            let Payload::Error { text, .. } = frame.payload() else {
                return Err(format!("fixture {id}: expected an error payload").into());
            };
            assert_eq!(
                hex_encode(text).as_str(),
                string(id, key, expected)?,
                "fixture {id}: {key}"
            );
        }
        other => return Err(format!("fixture {id}: unknown field {other}").into()),
    }
    Ok(())
}

/// Checks the decoded metadata region against the fixture's entries.
fn check_metadata(id: &str, frame: &Frame<'_>, expected: &Json) -> Result<(), Box<dyn Error>> {
    let array = expected
        .as_array()
        .ok_or_else(|| format!("fixture {id}: metadata must be an array"))?;
    let entries = frame.metadata().entries();
    assert_eq!(
        entries.len(),
        array.len(),
        "fixture {id}: metadata entry count"
    );
    for (entry, expected_entry) in entries.iter().zip(array.iter()) {
        let identifier = expected_entry
            .get("identifier")
            .ok_or_else(|| format!("fixture {id}: entry missing identifier"))?;
        assert_eq!(
            i64::from(entry.identifier()),
            number(id, "metadata.identifier", identifier)?,
            "fixture {id}: metadata identifier"
        );
        let value = expected_entry
            .get("value")
            .ok_or_else(|| format!("fixture {id}: entry missing value"))?;
        assert_eq!(
            hex_encode(entry.value()).as_str(),
            string(id, "metadata.value", value)?,
            "fixture {id}: metadata value"
        );
    }
    Ok(())
}

/// Checks one encode expectation.
fn run_encode(id: &str, input: &Json, expect: &Json) -> Result<(), Box<dyn Error>> {
    let fields = input
        .get("fields")
        .ok_or_else(|| format!("fixture {id}: missing input.fields"))?;
    let kind_value = u8::try_from(number(
        id,
        "kind",
        fields
            .get("kind")
            .ok_or_else(|| format!("fixture {id}: missing kind"))?,
    )?)?;
    let kind =
        Kind::from_wire(kind_value).ok_or_else(|| format!("fixture {id}: unassigned kind"))?;
    let code = u16::try_from(number(
        id,
        "code",
        fields
            .get("code")
            .ok_or_else(|| format!("fixture {id}: missing code"))?,
    )?)?;
    let request_id = string(
        id,
        "request_id",
        fields
            .get("request_id")
            .ok_or_else(|| format!("fixture {id}: missing request_id"))?,
    )?
    .parse::<u64>()?;
    let mut metadata_owned: Vec<(u16, Vec<u8>)> = Vec::new();
    if let Some(metadata) = fields.get("metadata") {
        let array = metadata
            .as_array()
            .ok_or_else(|| format!("fixture {id}: metadata must be an array"))?;
        for entry in array {
            let identifier = u16::try_from(number(
                id,
                "identifier",
                entry
                    .get("identifier")
                    .ok_or_else(|| format!("fixture {id}: entry missing identifier"))?,
            )?)?;
            let value = entry
                .get("value")
                .ok_or_else(|| format!("fixture {id}: entry missing value"))?;
            metadata_owned.push((identifier, hex_decode(string(id, "value", value)?)?));
        }
    }
    let payload_bytes = optional_bytes(id, fields.get("payload").and_then(Json::as_str))?;
    let detail_bytes = optional_bytes(id, fields.get("detail_bytes").and_then(Json::as_str))?;
    let text_bytes = optional_bytes(id, fields.get("text").and_then(Json::as_str))?;
    let payload = if fields.get("payload").is_some() {
        OutgoingPayload::Opaque(&payload_bytes)
    } else if let Some(logical_length) = fields.get("logical_length").and_then(Json::as_str) {
        OutgoingPayload::Warm(logical_length.parse::<u64>()?)
    } else if fields.get("detail_bytes").is_some() || fields.get("text").is_some() {
        OutgoingPayload::Error {
            detail: &detail_bytes,
            text: &text_bytes,
        }
    } else {
        OutgoingPayload::Opaque(&[])
    };
    let metadata_refs: Vec<(u16, &[u8])> = metadata_owned
        .iter()
        .map(|(identifier, value)| (*identifier, value.as_slice()))
        .collect();
    let outgoing = Outgoing {
        kind,
        code,
        request_id,
        metadata: &metadata_refs,
        payload,
    };
    let bytes = protocol::encode(&outgoing)?;
    let expected_hex = expect
        .get("bytes")
        .and_then(Json::as_str)
        .ok_or_else(|| format!("fixture {id}: missing expect.bytes"))?;
    assert_eq!(
        hex_encode(&bytes).as_str(),
        expected_hex,
        "fixture {id}: encoded bytes"
    );
    Ok(())
}

/// Decodes a byte string, or returns an empty vector when absent.
fn optional_bytes(id: &str, text: Option<&str>) -> Result<Vec<u8>, Box<dyn Error>> {
    text.map_or_else(
        || Ok(Vec::new()),
        |value| hex_decode(value).map_err(|error| format!("fixture {id}: {error}").into()),
    )
}

/// Reads a number from a JSON value.
fn number(id: &str, key: &str, value: &Json) -> Result<i64, Box<dyn Error>> {
    value
        .as_i64()
        .ok_or_else(|| format!("fixture {id}: {key} must be a number").into())
}

/// Reads a string from a JSON value.
fn string<'a>(id: &str, key: &str, value: &'a Json) -> Result<&'a str, Box<dyn Error>> {
    value
        .as_str()
        .ok_or_else(|| format!("fixture {id}: {key} must be a string").into())
}

/// Decodes a lowercase hexadecimal byte string.
fn hex_decode(text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if text.len() & 1 != 0 {
        return Err("hex string has an odd length".into());
    }
    let mut out = Vec::new();
    for chunk in text.as_bytes().chunks_exact(2) {
        let [high, low] = chunk else {
            return Err("hex string has an odd length".into());
        };
        out.push((hex_nibble(*high)? << 4) | hex_nibble(*low)?);
    }
    Ok(out)
}

/// Encodes bytes as a lowercase hexadecimal string.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes.iter().copied() {
        push_hex(&mut out, byte >> 4);
        push_hex(&mut out, byte & 0x0f);
    }
    out
}

/// Appends one lowercase hexadecimal digit.
fn push_hex(out: &mut String, value: u8) {
    if let Some(character) = char::from_digit(u32::from(value), 16) {
        out.push(character);
    }
}

/// Converts one hexadecimal digit to its value.
fn hex_nibble(byte: u8) -> Result<u8, Box<dyn Error>> {
    match byte {
        b'0'..=b'9' => Ok(byte.wrapping_sub(b'0')),
        b'a'..=b'f' => Ok(byte.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Ok(byte.wrapping_sub(b'A').wrapping_add(10)),
        other => Err(format!("invalid hexadecimal digit {other}").into()),
    }
}

/// A parsed JSON value.
#[derive(Debug)]
enum Json {
    /// A JSON `null`.
    Null,
    /// A JSON number, restricted to integers.
    Number(i64),
    /// A JSON string.
    String(String),
    /// A JSON array.
    Array(Vec<Self>),
    /// A JSON object, preserving member order.
    Object(Vec<(String, Self)>),
}

impl Json {
    /// Returns the value of a member, or `None` when absent or not an object.
    fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(fields) => fields
                .iter()
                .find(|(name, _)| name.as_str() == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    /// Returns the string value, or `None`.
    fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    /// Returns the integer value, or `None`.
    const fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Number(value) => Some(*value),
            _ => None,
        }
    }

    /// Returns the array items, or `None`.
    fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Returns the object members, or `None`.
    fn as_object(&self) -> Option<&[(String, Self)]> {
        match self {
            Self::Object(fields) => Some(fields),
            _ => None,
        }
    }
}

/// A minimal recursive-descent JSON parser.
struct Parser<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Parser<'a> {
    /// Builds a parser over a JSON document.
    const fn new(text: &'a str) -> Self {
        Self {
            bytes: text.as_bytes(),
            position: 0,
        }
    }

    /// Parses the whole document and rejects trailing content.
    fn parse(mut self) -> Result<Json, Box<dyn Error>> {
        let value = self.parse_value()?;
        self.skip_whitespace();
        if self.peek().is_some() {
            return Err("trailing content after JSON value".into());
        }
        Ok(value)
    }

    /// Returns the current byte without consuming it.
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    /// Consumes one byte when one is available.
    const fn advance(&mut self) {
        if self.position < self.bytes.len() {
            self.position = self.position.saturating_add(1);
        }
    }

    /// Consumes and returns the current byte.
    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.advance();
        Some(byte)
    }

    /// Skips JSON whitespace.
    fn skip_whitespace(&mut self) {
        while let Some(b' ' | b'\n' | b'\r' | b'\t') = self.peek() {
            self.advance();
        }
    }

    /// Parses one JSON value.
    fn parse_value(&mut self) -> Result<Json, Box<dyn Error>> {
        self.skip_whitespace();
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Json::String(self.parse_string()?)),
            Some(b'n') => self.parse_literal("null", Json::Null),
            Some(b'-' | b'0'..=b'9') => Ok(Json::Number(self.parse_number()?)),
            _ => Err("unexpected token in JSON".into()),
        }
    }

    /// Parses a bare literal word.
    fn parse_literal(&mut self, word: &str, value: Json) -> Result<Json, Box<dyn Error>> {
        for expected in word.bytes() {
            match self.bump() {
                Some(actual) if actual == expected => {}
                _ => return Err(format!("expected literal {word}").into()),
            }
        }
        Ok(value)
    }

    /// Parses an object.
    fn parse_object(&mut self) -> Result<Json, Box<dyn Error>> {
        self.advance();
        let mut fields = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.advance();
            return Ok(Json::Object(fields));
        }
        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            self.skip_whitespace();
            if self.bump() != Some(b':') {
                return Err("expected colon in JSON object".into());
            }
            let value = self.parse_value()?;
            fields.push((key, value));
            self.skip_whitespace();
            match self.bump() {
                Some(b',') => {}
                Some(b'}') => return Ok(Json::Object(fields)),
                _ => return Err("expected comma or brace in JSON object".into()),
            }
        }
    }

    /// Parses an array.
    fn parse_array(&mut self) -> Result<Json, Box<dyn Error>> {
        self.advance();
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.advance();
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_whitespace();
            match self.bump() {
                Some(b',') => {}
                Some(b']') => return Ok(Json::Array(items)),
                _ => return Err("expected comma or bracket in JSON array".into()),
            }
        }
    }

    /// Parses a string, including its escape sequences.
    fn parse_string(&mut self) -> Result<String, Box<dyn Error>> {
        if self.bump() != Some(b'"') {
            return Err("expected string in JSON".into());
        }
        let mut out = String::new();
        loop {
            let byte = self.bump().ok_or("unterminated JSON string")?;
            match byte {
                b'"' => return Ok(out),
                b'\\' => {
                    let escape = self.bump().ok_or("unterminated JSON escape")?;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let code = self.parse_hex4()?;
                            out.push(char::from_u32(code).ok_or("invalid unicode escape")?);
                        }
                        _ => return Err("invalid JSON escape".into()),
                    }
                }
                other => out.push(char::from(other)),
            }
        }
    }

    /// Parses the four hex digits of a unicode escape.
    fn parse_hex4(&mut self) -> Result<u32, Box<dyn Error>> {
        let mut value: u32 = 0;
        for _ in 0..4 {
            let byte = self.bump().ok_or("short unicode escape")?;
            let digit = hex_nibble(byte)?;
            value = value
                .checked_mul(16)
                .and_then(|current| current.checked_add(u32::from(digit)))
                .ok_or("unicode escape overflow")?;
        }
        Ok(value)
    }

    /// Parses an integer number.
    fn parse_number(&mut self) -> Result<i64, Box<dyn Error>> {
        let negative = if self.peek() == Some(b'-') {
            self.advance();
            true
        } else {
            false
        };
        let mut value: i64 = 0;
        let mut digits = false;
        while let Some(byte) = self.peek() {
            if !byte.is_ascii_digit() {
                break;
            }
            self.advance();
            digits = true;
            let digit = i64::from(byte.wrapping_sub(b'0'));
            value = value
                .checked_mul(10)
                .and_then(|current| current.checked_add(digit))
                .ok_or("integer overflow in JSON number")?;
        }
        if !digits {
            return Err("expected digits in JSON number".into());
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err("non-integer JSON number is not supported".into());
        }
        if negative {
            value = value
                .checked_neg()
                .ok_or("integer overflow in JSON number")?;
        }
        Ok(value)
    }
}
