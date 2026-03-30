use std::ffi::{OsStr, OsString};

use serde::Serialize;
use serde::ser::{SerializeSeq, Serializer};

#[derive(Debug, Clone, Copy)]
pub(crate) struct LossyOsStr<'a>(pub(crate) &'a OsStr);

impl Serialize for LossyOsStr<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string_lossy())
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct LossyOsStrings<'a>(pub(crate) &'a [OsString]);

impl Serialize for LossyOsStrings<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for value in self.0 {
            seq.serialize_element(&LossyOsStr(value.as_os_str()))?;
        }
        seq.end()
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ExactOsStr<'a>(pub(crate) &'a OsStr);

impl Serialize for ExactOsStr<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        exact_os_string_value(self.0).serialize(serializer)
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ExactOsStrings<'a>(pub(crate) &'a [OsString]);

impl Serialize for ExactOsStrings<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for value in self.0 {
            seq.serialize_element(&ExactOsStr(value.as_os_str()))?;
        }
        seq.end()
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct LossyEnvPairs<'a>(pub(crate) &'a [(OsString, OsString)]);

impl Serialize for LossyEnvPairs<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for (name, value) in self.0 {
            seq.serialize_element(&LossyEnvPair {
                name: LossyOsStr(name.as_os_str()),
                value: LossyOsStr(value.as_os_str()),
            })?;
        }
        seq.end()
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ExactEnvPairs<'a>(pub(crate) &'a [(OsString, OsString)]);

impl Serialize for ExactEnvPairs<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for (name, value) in self.0 {
            seq.serialize_element(&ExactEnvPair {
                name: ExactOsStr(name.as_os_str()),
                value: ExactOsStr(value.as_os_str()),
            })?;
        }
        seq.end()
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
struct LossyEnvPair<'a> {
    name: LossyOsStr<'a>,
    value: LossyOsStr<'a>,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct ExactEnvPair<'a> {
    name: ExactOsStr<'a>,
    value: ExactOsStr<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
struct ExactOsStringValue {
    encoding: ExactOsStringEncoding,
    value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ExactOsStringEncoding {
    Utf8,
    #[cfg(unix)]
    UnixBytesHex,
    #[cfg(windows)]
    WindowsUtf16LeHex,
    #[cfg(all(not(unix), not(windows)))]
    PlatformDebug,
}

fn exact_os_string_value(value: &OsStr) -> ExactOsStringValue {
    if let Some(text) = value.to_str() {
        return ExactOsStringValue {
            encoding: ExactOsStringEncoding::Utf8,
            value: text.to_string(),
        };
    }

    non_utf8_exact_os_string_value(value)
}

#[cfg(unix)]
fn non_utf8_exact_os_string_value(value: &OsStr) -> ExactOsStringValue {
    use std::os::unix::ffi::OsStrExt;

    ExactOsStringValue {
        encoding: ExactOsStringEncoding::UnixBytesHex,
        value: encode_hex(value.as_bytes()),
    }
}

#[cfg(windows)]
fn non_utf8_exact_os_string_value(value: &OsStr) -> ExactOsStringValue {
    use std::os::windows::ffi::OsStrExt;

    let mut bytes = Vec::new();
    for unit in value.encode_wide() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    ExactOsStringValue {
        encoding: ExactOsStringEncoding::WindowsUtf16LeHex,
        value: encode_hex(&bytes),
    }
}

#[cfg(all(not(unix), not(windows)))]
fn non_utf8_exact_os_string_value(value: &OsStr) -> ExactOsStringValue {
    ExactOsStringValue {
        encoding: ExactOsStringEncoding::PlatformDebug,
        value: format!("{value:?}"),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(char::from(HEX[(byte >> 4) as usize]));
        encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_values_serialize_exactly() {
        let value = serde_json::to_value(ExactOsStr(OsStr::new("echo"))).expect("serialize");
        assert_eq!(
            value,
            serde_json::json!({
                "encoding": "utf8",
                "value": "echo"
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_unix_values_serialize_as_hex() {
        use std::os::unix::ffi::OsStringExt;

        let value = OsString::from_vec(vec![0x66, 0x6f, 0x80]);
        let serialized = serde_json::to_value(ExactOsStr(value.as_os_str())).expect("serialize");
        assert_eq!(
            serialized,
            serde_json::json!({
                "encoding": "unix_bytes_hex",
                "value": "666f80"
            })
        );
    }
}
