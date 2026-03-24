#![forbid(unsafe_code)]

//! Low-level integrity primitives shared by higher-level tooling.
//!
//! This crate owns policy-free digest parsing and verification helpers so callers do not duplicate
//! `sha256:<hex>` parsing or checksum mismatch reporting.

use std::fmt;
use std::io::{self, Read};

use sha2::{Digest as _, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_prefixed_string(&self) -> String {
        format!("sha256:{self}")
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

impl VerifySha256Error {
    pub fn expected(&self) -> &Sha256Digest {
        &self.expected
    }

    pub fn actual(&self) -> &Sha256Digest {
        &self.actual
    }
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
    let digest = Sha256::digest(content);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    Sha256Digest(out)
}

pub fn hash_sha256_reader<R>(reader: &mut R) -> io::Result<Sha256Digest>
where
    R: Read + ?Sized,
{
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    Ok(Sha256Digest(out))
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

    use super::{
        hash_sha256, hash_sha256_reader, parse_sha256_digest, parse_sha256_user_input,
        verify_sha256, verify_sha256_reader,
    };

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
