use std::ffi::{OsStr, OsString};

use serde::de::Error as DeError;
use serde::ser::{SerializeSeq, Serializer};
use serde::{Deserialize, Deserializer, Serialize};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct ExactOsStringValue {
    pub(crate) encoding: ExactOsStringEncoding,
    pub(crate) value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExactOsStringEncoding {
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

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
enum LossyOrExactOsString {
    Utf8(String),
    Exact(ExactOsStringValue),
}

#[allow(dead_code)]
impl LossyOrExactOsString {
    fn into_os_string(self) -> Result<OsString, String> {
        match self {
            Self::Utf8(value) => Ok(OsString::from(value)),
            Self::Exact(value) => exact_os_string_value_into_os_string(value),
        }
    }
}

#[allow(dead_code)]
pub(crate) fn deserialize_lossy_or_exact_os_string<'de, D>(
    deserializer: D,
) -> Result<OsString, D::Error>
where
    D: Deserializer<'de>,
{
    LossyOrExactOsString::deserialize(deserializer)?
        .into_os_string()
        .map_err(D::Error::custom)
}

#[allow(dead_code)]
pub(crate) fn deserialize_lossy_or_exact_os_strings<'de, D>(
    deserializer: D,
) -> Result<Vec<OsString>, D::Error>
where
    D: Deserializer<'de>,
{
    Vec::<LossyOrExactOsString>::deserialize(deserializer)?
        .into_iter()
        .map(LossyOrExactOsString::into_os_string)
        .collect::<Result<_, _>>()
        .map_err(D::Error::custom)
}

#[allow(dead_code)]
fn exact_os_string_value_into_os_string(value: ExactOsStringValue) -> Result<OsString, String> {
    match value.encoding {
        ExactOsStringEncoding::Utf8 => Ok(OsString::from(value.value)),
        #[cfg(unix)]
        ExactOsStringEncoding::UnixBytesHex => decode_unix_bytes_hex_os_string(&value.value),
        #[cfg(windows)]
        ExactOsStringEncoding::WindowsUtf16LeHex => {
            decode_windows_utf16_le_hex_os_string(&value.value)
        }
        #[cfg(all(not(unix), not(windows)))]
        ExactOsStringEncoding::PlatformDebug => {
            Err("platform_debug exact OS string input is unsupported on this platform".to_string())
        }
    }
}

#[cfg(unix)]
#[allow(dead_code)]
fn decode_unix_bytes_hex_os_string(hex: &str) -> Result<OsString, String> {
    use std::os::unix::ffi::OsStringExt;

    decode_hex(hex).map(OsString::from_vec)
}

#[cfg(windows)]
#[allow(dead_code)]
fn decode_windows_utf16_le_hex_os_string(hex: &str) -> Result<OsString, String> {
    let bytes = decode_hex(hex)?;
    let chunks = bytes.chunks_exact(2);
    if !chunks.remainder().is_empty() {
        return Err("windows_utf16_le_hex value must contain an even number of bytes".to_string());
    }

    let units = chunks
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&units)
        .map(OsString::from)
        .map_err(|err| format!("invalid UTF-16 exact OS string value: {err}"))
}

#[allow(dead_code)]
fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("hex value must contain an even number of characters".to_string());
    }

    (0..hex.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&hex[index..index + 2], 16)
                .map_err(|_| format!("invalid hex at byte offset {index}"))
        })
        .collect()
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

    #[test]
    fn decode_hex_rejects_odd_length() {
        let err = decode_hex("abc").expect_err("odd-length hex should fail");
        assert!(err.contains("even number"));
    }

    #[cfg(unix)]
    #[test]
    fn deserialize_exact_unix_bytes_into_os_string() {
        use std::os::unix::ffi::OsStringExt;

        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(deserialize_with = "deserialize_lossy_or_exact_os_string")]
            value: OsString,
        }

        let wrapper: Wrapper = serde_json::from_value(serde_json::json!({
            "value": {
                "encoding": "unix_bytes_hex",
                "value": "666f80"
            }
        }))
        .expect("deserialize exact unix bytes");

        assert_eq!(wrapper.value, OsString::from_vec(vec![0x66, 0x6f, 0x80]));
    }

    #[test]
    fn deserialize_utf8_string_into_os_string() {
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(deserialize_with = "deserialize_lossy_or_exact_os_string")]
            value: OsString,
        }

        let wrapper: Wrapper = serde_json::from_value(serde_json::json!({
            "value": "echo"
        }))
        .expect("deserialize utf8 string");

        assert_eq!(wrapper.value, OsString::from("echo"));
    }
}
