#![forbid(unsafe_code)]

//! Reusable artifact download and installation primitives shared by higher-level callers.
//!
//! This crate owns the narrow runtime pipeline that sits above plain archive/integrity/fs
//! primitives:
//! - try an ordered list of download candidates
//! - optionally verify a SHA-256 digest
//! - atomically install a direct binary artifact
//! - extract and install a binary from a supported archive
//! - extract and replace a directory tree from a supported archive

mod archive_tree;
mod artifact_download;
mod binary_artifact;
mod install_lock;

pub use archive_tree::{
    ArchiveTreeInstallRequest, DEFAULT_MAX_ARCHIVE_TREE_ENTRIES,
    DEFAULT_MAX_ARCHIVE_TREE_EXTRACTED_BYTES, download_and_install_archive_tree,
    install_archive_tree_from_bytes, is_archive_tree_asset_name,
};
pub use artifact_download::{
    ArtifactDownloadCandidate, ArtifactDownloader, ArtifactInstallError,
    ArtifactInstallErrorDetail, ArtifactInstallErrorKind,
};
pub use binary_artifact::{
    BinaryArchiveInstallRequest, DownloadBinaryRequest, InstalledArchiveBinary,
    download_and_install_binary_from_archive, download_binary_to_destination,
    install_binary_from_archive,
};
pub use omne_archive_primitives::{
    ArchiveBinaryMatch, DEFAULT_MAX_EXTRACTED_BINARY_BYTES, is_binary_archive_asset_name,
};
