#![forbid(unsafe_code)]

//! Low-level archive/compression primitives shared by higher-level tooling.
//!
//! This crate owns reusable archive-format readers and target-binary extraction helpers that
//! should not be duplicated across callers:
//! - supported asset-format detection for `.tar.gz`, `.tar.xz`, and `.zip`
//! - archive entry traversal with normalized path matching
//! - target binary lookup by binary name, tool name, and optional archive hint
//! - extraction of the matched binary bytes

mod binary_archive;

pub use binary_archive::{
    ArchiveBinaryMatch, BinaryArchiveFormat, BinaryArchiveRequest,
    DEFAULT_MAX_EXTRACTED_BINARY_BYTES, ExtractBinaryFromArchiveError, ExtractedArchiveBinary,
    extract_binary_from_archive, extract_binary_from_archive_reader_to_writer,
    is_binary_archive_asset_name,
};
