//! Apple property lists (XML or binary), and an XML writer that reproduces `plistlib.dumps` byte for
//! byte (the oracle fixtures compare the request bodies exactly).
//!
//! Parsing is delegated to the `plist` crate (it handles both XML and the binary format Apple can
//! answer with); writing is ours so the tabs, key sorting and 76-column base64 wrapping match the
//! Python. See `app/android/.../apple/Plist.kt` and `findmy/util/parsers.py`.

use std::collections::BTreeMap;

use base64::Engine as _;

use crate::error::{Error, Result};

/// A property-list value. Dictionaries keep their keys sorted, as `plistlib` writes them.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    String(String),
    Integer(i64),
    Real(f64),
    Boolean(bool),
    Data(Vec<u8>),
    /// The ISO-8601 text of a `<date>`; the flows here never read one, so it is kept verbatim.
    Date(String),
    Array(Vec<Value>),
    Dict(BTreeMap<String, Value>),
}

impl Value {
    pub fn as_dict(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Dict(d) => Some(d),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// An integer or real as `i64` (Apple sometimes answers a number as either).
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Integer(i) => Some(*i),
            Value::Real(f) if f.fract() == 0.0 => Some(*f as i64),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_data(&self) -> Option<&[u8]> {
        match self {
            Value::Data(d) => Some(d),
            _ => None,
        }
    }

    /// Dictionary lookup; `None` for a missing key or a non-dictionary.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_dict().and_then(|d| d.get(key))
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::String(s.to_string())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(s)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Boolean(b)
    }
}

impl From<i64> for Value {
    fn from(i: i64) -> Self {
        Value::Integer(i)
    }
}

impl From<f64> for Value {
    fn from(f: f64) -> Self {
        Value::Real(f)
    }
}

impl From<Vec<u8>> for Value {
    fn from(d: Vec<u8>) -> Self {
        Value::Data(d)
    }
}

/// Builds a `Value::Dict` from pairs, conveniently for the request bodies.
pub fn dict<K: Into<String>, I: IntoIterator<Item = (K, Value)>>(pairs: I) -> Value {
    Value::Dict(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
}

/// Parses an XML or binary plist.
pub fn parse(bytes: &[u8]) -> Result<Value> {
    let value = plist::from_bytes::<plist::Value>(bytes)
        .map_err(|_| Error::Backend("the reply is not a property list".into()))?;
    Ok(convert(value))
}

/// Parses a plist whose root must be a dictionary (`Plist.parseDict`).
pub fn parse_dict(bytes: &[u8]) -> Result<BTreeMap<String, Value>> {
    match parse(bytes)? {
        Value::Dict(d) => Ok(d),
        _ => Err(Error::Backend("property list root is not a dictionary".into())),
    }
}

fn convert(v: plist::Value) -> Value {
    match v {
        plist::Value::String(s) => Value::String(s),
        plist::Value::Integer(i) => Value::Integer(i.as_signed().unwrap_or(0)),
        plist::Value::Real(f) => Value::Real(f),
        plist::Value::Boolean(b) => Value::Boolean(b),
        plist::Value::Data(d) => Value::Data(d),
        plist::Value::Date(d) => Value::Date(d.to_xml_format()),
        plist::Value::Array(a) => Value::Array(a.into_iter().map(convert).collect()),
        plist::Value::Dictionary(d) => {
            Value::Dict(d.into_iter().map(|(k, v)| (k, convert(v))).collect())
        }
        plist::Value::Uid(u) => Value::Integer(u.get() as i64),
        _ => Value::String(String::new()),
    }
}

/// Serialises a dictionary as an XML plist, exactly as `plistlib.dumps` does.
pub fn to_xml(root: &Value) -> Vec<u8> {
    let mut w = Writer { out: Vec::new() };
    w.out.extend_from_slice(PLIST_HEADER);
    w.out.extend_from_slice(b"<plist version=\"1.0\">\n");
    w.write_value(root, 0);
    w.out.extend_from_slice(b"</plist>\n");
    w.out
}

/// Serialises a dictionary as an XML plist and returns it as a `String`.
pub fn to_xml_string(root: &Value) -> String {
    String::from_utf8(to_xml(root)).expect("plist XML is UTF-8")
}

const PLIST_HEADER: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n";

struct Writer {
    out: Vec<u8>,
}

impl Writer {
    fn writeln(&mut self, line: &[u8], indent: usize) {
        if !line.is_empty() {
            self.out.extend(std::iter::repeat(b'\t').take(indent));
            self.out.extend_from_slice(line);
        }
        self.out.push(b'\n');
    }

    fn simple(&mut self, element: &str, text: &str, indent: usize) {
        let line = format!("<{element}>{text}</{element}>");
        self.writeln(line.as_bytes(), indent);
    }

    fn empty(&mut self, element: &str, indent: usize) {
        self.writeln(format!("<{element}/>").as_bytes(), indent);
    }

    fn write_value(&mut self, value: &Value, indent: usize) {
        match value {
            Value::String(s) => self.simple("string", &escape(s), indent),
            Value::Boolean(true) => self.empty("true", indent),
            Value::Boolean(false) => self.empty("false", indent),
            Value::Integer(i) => self.simple("integer", &i.to_string(), indent),
            Value::Real(f) => self.simple("real", &python_repr(*f), indent),
            Value::Date(s) => self.simple("date", &escape(s), indent),
            Value::Data(d) => self.write_bytes(d, indent),
            Value::Array(a) => {
                if a.is_empty() {
                    self.empty("array", indent);
                } else {
                    self.writeln(b"<array>", indent);
                    for v in a {
                        self.write_value(v, indent + 1);
                    }
                    self.writeln(b"</array>", indent);
                }
            }
            Value::Dict(d) => {
                if d.is_empty() {
                    self.empty("dict", indent);
                } else {
                    self.writeln(b"<dict>", indent);
                    for (k, v) in d {
                        self.simple("key", &escape(k), indent + 1);
                        self.write_value(v, indent + 1);
                    }
                    self.writeln(b"</dict>", indent);
                }
            }
        }
    }

    fn write_bytes(&mut self, data: &[u8], indent: usize) {
        self.writeln(b"<data>", indent);
        // plistlib: maxlinelength = max(16, 76 - len(tabs.expandtabs())); a tab is 8 columns.
        let max_line = 76usize.saturating_sub(8 * indent).max(16);
        let max_bin = (max_line / 4) * 3;
        for chunk in data.chunks(max_bin.max(1)) {
            let line = base64::engine::general_purpose::STANDARD.encode(chunk);
            self.writeln(line.as_bytes(), indent);
        }
        self.writeln(b"</data>", indent);
    }
}

/// `plistlib` uses Python's `repr(float)`; Rust's `Display` drops the `.0`, `Debug` keeps it.
fn python_repr(f: f64) -> String {
    if f.is_nan() {
        return "nan".to_string();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf".to_string() } else { "-inf".to_string() };
    }
    format!("{f:?}")
}

/// `plistlib._escape`: control characters are refused; CRLF/CR become LF, then the three entities.
fn escape(text: &str) -> String {
    let mut t = text.replace("\r\n", "\n").replace('\r', "\n");
    t = t.replace('&', "&amp;");
    t = t.replace('<', "&lt;");
    t = t.replace('>', "&gt;");
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_the_canonical_header_and_sorts_keys() {
        let v = dict([("b", Value::Integer(1)), ("a", Value::String("x".into()))]);
        let xml = to_xml_string(&v);
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        let a = xml.find("<key>a</key>").unwrap();
        let b = xml.find("<key>b</key>").unwrap();
        assert!(a < b);
        assert!(xml.ends_with("</plist>\n"));
    }

    #[test]
    fn round_trips_data_and_wraps_at_plistlib_widths() {
        let data = vec![0u8; 120];
        let v = dict([("blob", Value::Data(data))]);
        let xml = to_xml_string(&v);
        // At indent 1, max_line = 76 - 8 = 68, max_bin = 51; base64 of 51 bytes is 68 chars.
        let lines: Vec<&str> = xml.lines().filter(|l| l.starts_with('\t') && !l.contains('<')).collect();
        assert!(lines.iter().all(|l| l.len() <= 68 + 1));
        let parsed = parse(xml.as_bytes()).unwrap();
        assert_eq!(parsed, v);
    }
}
