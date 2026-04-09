#![allow(dead_code)]

use std::path::{Path, PathBuf};

pub(crate) fn reject_forbidden_path_ancestors(path: &Path) -> Result<(), String> {
    let absolute = absolute_path_lexical(path)?;
    let Some(parent) = absolute.parent() else {
        return Ok(());
    };

    let mut current = PathBuf::new();
    for component in parent.components() {
        match component {
            std::path::Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            std::path::Component::RootDir => current.push(component.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                current.pop();
            }
            std::path::Component::Normal(segment) => {
                current.push(segment);
                match std::fs::symlink_metadata(&current) {
                    Ok(metadata) => {
                        if file_metadata_has_forbidden_link_ancestor(&metadata)
                            && !is_permitted_platform_root_alias(&current)
                        {
                            return Err(format!(
                                "path must not traverse symlink or reparse-point ancestors: {}",
                                current.display()
                            ));
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => break,
                    Err(err) => return Err(err.to_string()),
                }
            }
        }
    }

    Ok(())
}

fn absolute_path_lexical(path: &Path) -> Result<PathBuf, String> {
    let mut absolute = if path.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir().map_err(|err| err.to_string())?
    };

    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => absolute.push(prefix.as_os_str()),
            std::path::Component::RootDir => absolute.push(component.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                absolute.pop();
            }
            std::path::Component::Normal(segment) => absolute.push(segment),
        }
    }

    Ok(absolute)
}

#[cfg(windows)]
fn file_metadata_has_forbidden_link_ancestor(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn file_metadata_has_forbidden_link_ancestor(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(target_os = "macos")]
fn is_permitted_platform_root_alias(path: &Path) -> bool {
    path.parent() == Some(Path::new("/"))
        && matches!(
            path.file_name(),
            Some(name) if name == std::ffi::OsStr::new("var") || name == std::ffi::OsStr::new("tmp")
        )
}

#[cfg(not(target_os = "macos"))]
fn is_permitted_platform_root_alias(_: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn rejects_symlink_parent_directory() {
        use std::os::unix::fs::symlink;

        use super::reject_forbidden_path_ancestors;

        let dir = tempfile::tempdir().expect("tempdir");
        let real_parent = dir.path().join("real");
        std::fs::create_dir(&real_parent).expect("create real parent");
        let symlink_parent = dir.path().join("linked");
        symlink(&real_parent, &symlink_parent).expect("create symlink parent");

        let err = reject_forbidden_path_ancestors(&symlink_parent.join("file.json"))
            .expect_err("symlink ancestor must fail");
        assert!(err.contains("symlink or reparse-point ancestors"));
    }
}
