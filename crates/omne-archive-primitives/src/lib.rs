#![forbid(unsafe_code)]

//! Low-level archive/compression primitives shared by higher-level tooling.
//!
//! This crate owns reusable archive-format readers and target-binary extraction helpers that
//! should not be duplicated across callers:
//! - supported asset-format detection for `.tar.gz`, `.tar.xz`, and `.zip`
//! - archive entry traversal with normalized path matching
//! - target binary lookup by binary name and optional exact archive-relative hint
//! - extraction of the matched binary bytes
//! - archive-tree walking with shared path/link hardening and extraction budgets

mod archive_tree;
mod binary_archive;

pub use archive_tree::{
    ArchiveTreeExtractionLimits, ArchiveTreeVisitor, DEFAULT_MAX_ARCHIVE_TREE_ENTRIES,
    DEFAULT_MAX_ARCHIVE_TREE_EXTRACTED_BYTES, MAX_ZIP_SYMLINK_TARGET_BYTES, WalkArchiveTreeError,
    walk_archive_tree, walk_tar_archive_tree, walk_zip_archive_tree,
};
pub use binary_archive::{
    ArchiveBinaryMatch, BinaryArchiveFormat, BinaryArchiveRequest,
    DEFAULT_MAX_EXTRACTED_BINARY_BYTES, ExtractBinaryFromArchiveError, ExtractedArchiveBinary,
    extract_binary_from_archive, extract_binary_from_archive_reader_to_writer,
    is_binary_archive_asset_name,
};
