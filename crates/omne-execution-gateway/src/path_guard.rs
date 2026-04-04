use std::fs;
use std::io;
use std::path::Path;

pub fn ensure_existing_ancestors_are_real_directories(path: &Path) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };

    for ancestor in parent.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }

        let metadata = match fs::symlink_metadata(ancestor) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("path is not a directory: {}", ancestor.display()),
            ));
        }
    }

    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::io;

    use super::ensure_existing_ancestors_are_real_directories;
    use tempfile::tempdir;

    #[test]
    fn rejects_existing_symlink_ancestor() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().expect("tempdir");
        let target_parent = dir.path().join("real");
        std::fs::create_dir_all(target_parent.join("nested")).expect("create target");
        let linked_parent = dir.path().join("linked");
        symlink(&target_parent, &linked_parent).expect("symlink");

        let err = ensure_existing_ancestors_are_real_directories(
            &linked_parent.join("nested").join("file.json"),
        )
        .expect_err("symlink ancestor should fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
