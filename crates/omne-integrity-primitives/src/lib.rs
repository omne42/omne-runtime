#![forbid(unsafe_code)]

//! Low-level integrity primitives shared by higher-level tooling.
//!
//! This crate owns policy-free digest parsing and verification helpers so callers do not duplicate
//! `sha256:<hex>` parsing or checksum mismatch reporting.

use std::fmt;
use std::io::{self, Read};

use serde::Serialize;
use sha2::{Digest as _, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Debug)]
pub struct Sha256Hasher {
    inner: Sha256,
}

impl Sha256Hasher {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    pub fn update(&mut self, bytes: impl AsRef<[u8]>) {
        self.inner.update(bytes.as_ref());
    }

    #[must_use]
    pub fn finalize(self) -> Sha256Digest {
        sha256_digest_from_bytes(self.inner.finalize().as_slice())
    }
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifySha256Error {
    expected: Sha256Digest,
    actual: Sha256Digest,
}

impl fmt::Display for VerifySha256Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "checksum mismatch: expected {}, got {}",
            self.expected, self.actual
        )
    }
}

impl std::error::Error for VerifySha256Error {}

#[derive(Debug)]
pub enum VerifySha256ReaderError {
    Read(io::Error),
    Mismatch(VerifySha256Error),
}

impl fmt::Display for VerifySha256ReaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(err) => write!(f, "checksum read failed: {err}"),
            Self::Mismatch(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for VerifySha256ReaderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(err) => Some(err),
            Self::Mismatch(err) => Some(err),
        }
    }
}

pub fn parse_sha256_digest(raw: Option<&str>) -> Option<Sha256Digest> {
    let raw = raw?.trim();
    let value = raw.strip_prefix("sha256:")?.trim();
    decode_sha256_hex(value)
}

pub fn parse_sha256_user_input(raw: &str) -> Option<Sha256Digest> {
    let trimmed = raw.trim();
    parse_sha256_digest(Some(trimmed)).or_else(|| decode_sha256_hex(trimmed))
}

pub fn hash_sha256(content: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256Hasher::new();
    hasher.update(content);
    hasher.finalize()
}

pub fn hash_sha256_json_chain<T>(
    prev_hash: Option<&str>,
    record: &T,
) -> Result<Sha256Digest, serde_json::Error>
where
    T: Serialize + ?Sized,
{
    let mut hasher = Sha256Hasher::new();
    if let Some(prev_hash) = prev_hash {
        hasher.update(prev_hash.as_bytes());
    }
    hasher.update(b"\n");
    let serialized = serde_json::to_vec(record)?;
    hasher.update(&serialized);
    Ok(hasher.finalize())
}

pub fn hash_sha256_reader<R>(reader: &mut R) -> io::Result<Sha256Digest>
where
    R: Read + ?Sized,
{
    let mut hasher = Sha256Hasher::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize())
}

pub fn verify_sha256(content: &[u8], expected: &Sha256Digest) -> Result<(), VerifySha256Error> {
    let actual = hash_sha256(content);
    if actual != *expected {
        return Err(VerifySha256Error {
            expected: expected.clone(),
            actual,
        });
    }
    Ok(())
}

pub fn verify_sha256_reader<R>(
    reader: &mut R,
    expected: &Sha256Digest,
) -> Result<(), VerifySha256ReaderError>
where
    R: Read + ?Sized,
{
    let actual = hash_sha256_reader(reader).map_err(VerifySha256ReaderError::Read)?;
    if actual != *expected {
        return Err(VerifySha256ReaderError::Mismatch(VerifySha256Error {
            expected: expected.clone(),
            actual,
        }));
    }
    Ok(())
}

fn decode_sha256_hex(raw: &str) -> Option<Sha256Digest> {
    let lowered = raw.trim().to_ascii_lowercase();
    if lowered.len() != 64 {
        return None;
    }

    let bytes = lowered.as_bytes();
    let mut out = [0_u8; 32];
    for index in 0..32 {
        let hi = decode_hex_nibble(bytes[index * 2])?;
        let lo = decode_hex_nibble(bytes[index * 2 + 1])?;
        out[index] = (hi << 4) | lo;
    }
    Some(Sha256Digest(out))
}

fn sha256_digest_from_bytes(bytes: &[u8]) -> Sha256Digest {
    let mut out = [0_u8; 32];
    out.copy_from_slice(bytes);
    Sha256Digest(out)
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use serde::Serialize;

    use super::{
        Sha256Hasher, hash_sha256, hash_sha256_json_chain, hash_sha256_reader, parse_sha256_digest,
        parse_sha256_user_input, verify_sha256, verify_sha256_reader,
    };

    #[derive(Serialize)]
    struct DemoRecord<'a> {
        id: u64,
        kind: &'a str,
    }

    #[test]
    fn parse_sha256_digest_accepts_prefixed_hex() {
        let digest = parse_sha256_digest(Some(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ));
        assert_eq!(
            digest.as_ref().map(ToString::to_string).as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn parse_sha256_user_input_accepts_raw_hex() {
        let digest = parse_sha256_user_input(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        assert_eq!(
            digest.as_ref().map(ToString::to_string).as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn hash_sha256_returns_hex_digest() {
        assert_eq!(
            hash_sha256(b"demo").to_string(),
            "2a97516c354b68848cdbd8f54a226a0a55b21ed138e207ad6c5cbb9c00aa5aea"
        );
    }

    #[test]
    fn sha256_hasher_supports_incremental_updates() {
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"de");
        hasher.update(b"mo");
        assert_eq!(
            hasher.finalize().to_string(),
            "2a97516c354b68848cdbd8f54a226a0a55b21ed138e207ad6c5cbb9c00aa5aea"
        );
    }

    #[test]
    fn sha256_digest_exposes_raw_bytes() {
        let digest = hash_sha256(b"demo");
        assert_eq!(
            digest.as_bytes(),
            &[
                0x2a, 0x97, 0x51, 0x6c, 0x35, 0x4b, 0x68, 0x84, 0x8c, 0xdb, 0xd8, 0xf5, 0x4a, 0x22,
                0x6a, 0x0a, 0x55, 0xb2, 0x1e, 0xd1, 0x38, 0xe2, 0x07, 0xad, 0x6c, 0x5c, 0xbb, 0x9c,
                0x00, 0xaa, 0x5a, 0xea,
            ]
        );
        assert_eq!(digest.into_bytes().len(), 32);
    }

    #[test]
    fn hash_sha256_reader_returns_hex_digest() {
        let mut reader = Cursor::new(b"demo");
        assert_eq!(
            hash_sha256_reader(&mut reader)
                .expect("hash from reader")
                .to_string(),
            "2a97516c354b68848cdbd8f54a226a0a55b21ed138e207ad6c5cbb9c00aa5aea"
        );
    }

    #[test]
    fn hash_sha256_json_chain_hashes_json_after_newline() {
        let digest = hash_sha256_json_chain(
            None,
            &DemoRecord {
                id: 7,
                kind: "demo",
            },
        )
        .expect("serialize json chain record");
        assert_eq!(
            digest.to_string(),
            "4ff6c35461aba7cfd131ee068480a8f212921fead8d0578ca7e427f4257318c8"
        );
    }

    #[test]
    fn hash_sha256_json_chain_includes_previous_hash_bytes() {
        let digest = hash_sha256_json_chain(
            Some("prev"),
            &DemoRecord {
                id: 7,
                kind: "demo",
            },
        )
        .expect("serialize json chain record");
        assert_eq!(
            digest.to_string(),
            "4010c0bed3d664a0ad35725bbc68efcbafc92e6ba50288fb38dee48bd2c71caa"
        );
    }

    #[test]
    fn verify_sha256_rejects_mismatch() {
        let expected = parse_sha256_user_input(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("valid sha256");
        let err = verify_sha256(b"demo", &expected).expect_err("checksum should not match");
        assert_eq!(
            err.to_string(),
            "checksum mismatch: expected aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, got 2a97516c354b68848cdbd8f54a226a0a55b21ed138e207ad6c5cbb9c00aa5aea"
        );
    }

    #[test]
    fn verify_sha256_reader_rejects_mismatch() {
        let expected = parse_sha256_user_input(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("valid sha256");
        let mut reader = Cursor::new(b"demo");
        let err =
            verify_sha256_reader(&mut reader, &expected).expect_err("checksum should not match");
        assert_eq!(
            err.to_string(),
            "checksum mismatch: expected aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, got 2a97516c354b68848cdbd8f54a226a0a55b21ed138e207ad6c5cbb9c00aa5aea"
        );
    }
}
