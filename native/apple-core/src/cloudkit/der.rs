//! The small DER reader the protection structures need (port of `findmy/cloudkit/der.py` and
//! `apple/cloudkit/Der.kt`): definite lengths, explicit tags, high tag numbers. Identical acceptance
//! to the Python, including what it rejects (indefinite lengths, truncation).

use num_bigint::{BigInt, BigUint};

use crate::error::{Error, Result};

fn der_error(message: impl Into<String>) -> Error {
    Error::Backend(message.into())
}

pub const CLASS_UNIVERSAL: u8 = 0x00;
pub const CLASS_APPLICATION: u8 = 0x40;
pub const CLASS_CONTEXT: u8 = 0x80;

pub const TAG_INTEGER: u32 = 0x02;
pub const TAG_OCTET_STRING: u32 = 0x04;
pub const TAG_SEQUENCE: u32 = 0x10;
pub const TAG_SET: u32 = 0x11;
pub const TAG_UTF8_STRING: u32 = 0x0C;

/// One tag-length-value element (port of `DerElement`). `raw` is the element's own bytes, tag and
/// length included: the protection structure's HMAC covers the DER of its members as they arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerElement {
    pub tag_class: u8,
    pub constructed: bool,
    pub tag_number: u32,
    pub content: Vec<u8>,
    pub raw: Vec<u8>,
}

impl DerElement {
    pub fn is_context(&self, number: u32) -> bool {
        self.tag_class == CLASS_CONTEXT && self.tag_number == number
    }

    pub fn is_universal(&self, number: u32) -> bool {
        self.tag_class == CLASS_UNIVERSAL && self.tag_number == number
    }

    /// This element's content as a sequence of elements.
    pub fn children(&self) -> Result<Vec<DerElement>> {
        if !self.constructed {
            return Err(der_error(format!(
                "Cannot read children of a primitive element (tag {})",
                self.tag_number
            )));
        }
        parse_all(&self.content)
    }

    /// Step inside an explicitly tagged element (exactly one child).
    pub fn unwrap_one(&self) -> Result<DerElement> {
        let inner = self.children()?;
        if inner.len() != 1 {
            return Err(der_error(format!(
                "Expected exactly one element inside tag {}, got {}",
                self.tag_number,
                inner.len()
            )));
        }
        Ok(inner.into_iter().next().unwrap())
    }

    /// INTEGER, signed big-endian; an empty content reads as 0 (as Python).
    pub fn as_int(&self) -> BigInt {
        if self.content.is_empty() {
            BigInt::from(0)
        } else {
            BigInt::from_signed_bytes_be(&self.content)
        }
    }

    /// The content as an unsigned big-endian integer (PCS's key types, versions and counts).
    pub fn as_uint(&self) -> BigUint {
        BigUint::from_bytes_be(&self.content)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.content
    }

    pub fn as_string(&self) -> String {
        String::from_utf8_lossy(&self.content).into_owned()
    }
}

fn read_length(data: &[u8], start: usize) -> Result<(u64, usize)> {
    let mut offset = start;
    if offset >= data.len() {
        return Err(der_error("Truncated DER: no length byte"));
    }
    let first = data[offset] as u64;
    offset += 1;
    if first < 0x80 {
        return Ok((first, offset));
    }
    let num_bytes = (first & 0x7f) as usize;
    if num_bytes == 0 {
        return Err(der_error("Indefinite-length DER is not supported"));
    }
    if offset + num_bytes > data.len() {
        return Err(der_error("Truncated DER: length runs past the end"));
    }
    let mut length: u64 = 0;
    for i in 0..num_bytes {
        length = (length << 8) | (data[offset + i] as u64);
    }
    Ok((length, offset + num_bytes))
}

/// One element at `start`, and the offset just past it.
pub fn parse_one(data: &[u8], start: usize) -> Result<(DerElement, usize)> {
    let mut offset = start;
    if offset >= data.len() {
        return Err(der_error("Truncated DER: no tag byte"));
    }
    let identifier = data[offset];
    offset += 1;
    let tag_class = identifier & 0xC0;
    let constructed = identifier & 0x20 != 0;
    let mut tag_number = (identifier & 0x1F) as u32;
    if tag_number == 0x1F {
        tag_number = 0;
        loop {
            if offset >= data.len() {
                return Err(der_error("Truncated DER: unterminated high tag number"));
            }
            let b = data[offset];
            offset += 1;
            tag_number = (tag_number << 7) | ((b & 0x7f) as u32);
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    let (length, after) = read_length(data, offset)?;
    offset = after;
    if length > (data.len() - offset) as u64 {
        return Err(der_error(format!(
            "Truncated DER: element claims {length} bytes, {} remain",
            data.len() - offset
        )));
    }
    let end = offset + length as usize;
    Ok((
        DerElement {
            tag_class,
            constructed,
            tag_number,
            content: data[offset..end].to_vec(),
            raw: data[start..end].to_vec(),
        },
        end,
    ))
}

pub fn parse_all(data: &[u8]) -> Result<Vec<DerElement>> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let (element, next) = parse_one(data, offset)?;
        out.push(element);
        offset = next;
    }
    Ok(out)
}

pub fn encode_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![length as u8];
    }
    let mut body = length.to_be_bytes().to_vec();
    while body.first() == Some(&0) {
        body.remove(0);
    }
    let mut out = vec![(0x80 | body.len()) as u8];
    out.extend_from_slice(&body);
    out
}

/// Re-encode a constructed element without member `index`, keeping the other members' bytes as they
/// arrived.
pub fn rebuild_without(element: &DerElement, index: usize) -> Result<Vec<u8>> {
    if element.raw.first().map(|b| b & 0x1F) == Some(0x1F) {
        return Err(der_error("Cannot rebuild an element with a multi-byte tag"));
    }
    let mut body = Vec::new();
    for (i, child) in element.children()?.iter().enumerate() {
        if i != index {
            body.extend_from_slice(&child.raw);
        }
    }
    let mut out = vec![element.raw[0]];
    out.extend_from_slice(&encode_length(body.len()));
    out.extend_from_slice(&body);
    Ok(out)
}

/// Parse an `[APPLICATION n] EXPLICIT` wrapper and return what is inside it.
pub fn expect_application(data: &[u8], tag_number: u32) -> Result<DerElement> {
    let (element, _) = parse_one(data, 0)?;
    if element.tag_class != CLASS_APPLICATION || element.tag_number != tag_number {
        return Err(der_error(format!(
            "Expected an [APPLICATION {tag_number}] element, got class 0x{:02x} tag {}",
            element.tag_class, element.tag_number
        )));
    }
    element.unwrap_one()
}
