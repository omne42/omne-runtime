use std::ffi::{OsStr, OsString};

use serde::Serialize;
use serde::ser::{SerializeMap, SerializeSeq, Serializer};

pub(crate) fn serialize_os_string<S>(value: &OsString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    SerializedOsStr(value.as_os_str()).serialize(serializer)
}

pub(crate) fn serialize_os_strings<S>(values: &[OsString], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(values.len()))?;
    for value in values {
        seq.serialize_element(&SerializedOsStr(value.as_os_str()))?;
    }
    seq.end()
}

struct SerializedOsStr<'a>(&'a OsStr);

impl Serialize for SerializedOsStr<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(value) = self.0.to_str() {
            return serializer.serialize_str(value);
        }

        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("display", &self.0.to_string_lossy())?;
        #[cfg(unix)]
        map.serialize_entry("unix_bytes_hex", &unix_bytes_hex(self.0))?;
        #[cfg(windows)]
        map.serialize_entry("windows_wide_hex", &windows_wide_hex(self.0))?;
        map.end()
    }
}

#[cfg(unix)]
fn unix_bytes_hex(value: &OsStr) -> String {
    use std::os::unix::ffi::OsStrExt;

    encode_hex_bytes(value.as_bytes())
}

#[cfg(windows)]
fn windows_wide_hex(value: &OsStr) -> String {
    use std::os::windows::ffi::OsStrExt;

    let mut encoded = String::new();
    for code_unit in value.encode_wide() {
        push_hex_byte(&mut encoded, (code_unit >> 8) as u8);
        push_hex_byte(&mut encoded, code_unit as u8);
    }
    encoded
}

fn encode_hex_bytes(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        push_hex_byte(&mut encoded, byte);
    }
    encoded
}

fn push_hex_byte(buf: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    buf.push(HEX[(byte >> 4) as usize] as char);
    buf.push(HEX[(byte & 0x0f) as usize] as char);
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;

    use super::*;

    #[test]
    fn utf8_os_string_serializes_as_plain_string() {
        let value = OsString::from("echo");
        let json =
            serde_json::to_value(SerializedOsStr(value.as_os_str())).expect("serialize utf8 value");

        assert_eq!(json, serde_json::json!("echo"));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_os_string_serializes_with_display_and_raw_bytes() {
        let value = OsString::from_vec(vec![0x66, 0x6f, 0x80]);
        let json = serde_json::to_value(SerializedOsStr(value.as_os_str()))
            .expect("serialize non-utf8 value");

        assert_eq!(
            json,
            serde_json::json!({
                "display": "fo\u{fffd}",
                "unix_bytes_hex": "666f80"
            })
        );
    }
}
