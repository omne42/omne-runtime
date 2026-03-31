use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::OpenOptions;

use crate::{
    MissingRootPolicy, open_regular_file_at, open_root, read_limited::ReadUtf8Error,
    read_utf8_limited,
};

pub fn read_utf8_regular_file_in_ambient_root_nofollow(
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> io::Result<String> {
    let mut file = open_regular_readonly_file_in_ambient_root_nofollow(path, label)?;
    read_utf8_limited(&mut file, max_bytes).map_err(|err| match err {
        ReadUtf8Error::Io(source) => source,
        ReadUtf8Error::TooLarge { bytes, max_bytes } => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} exceeds size limit ({bytes} > {max_bytes} bytes)"),
        ),
        ReadUtf8Error::InvalidUtf8(source) => {
            io::Error::new(io::ErrorKind::InvalidData, source.to_string())
        }
    })
}

pub fn open_appendable_regular_file_in_ambient_root_nofollow(
    path: &Path,
    label: &str,
) -> io::Result<std::fs::File> {
    let (parent, leaf, normalized) = open_parent_directory(path, label, true)?;
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    options.follow(FollowSymlinks::No);
    let file = parent.open_with(Path::new(&leaf), &options)?;
    ensure_regular_file(file.into_std(), &normalized, label)
}

pub fn validate_appendable_regular_file_in_ambient_root_nofollow(
    path: &Path,
    label: &str,
) -> io::Result<()> {
    let normalized = normalize_absolute_path(path, label)?;
    let leaf = normalized.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} must include a file name: {}", path.display()),
        )
    })?;
    let parent = normalized.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{label} must include a parent directory: {}",
                path.display()
            ),
        )
    })?;
    let Some(parent) = open_root(
        parent,
        label,
        MissingRootPolicy::ReturnNone,
        |_, _, _, error| error,
    )?
    else {
        return Ok(());
    };

    let mut options = OpenOptions::new();
    options.read(true).write(true);
    options.follow(FollowSymlinks::No);
    match parent.into_dir().open_with(Path::new(leaf), &options) {
        Ok(file) => {
            ensure_regular_file(file.into_std(), &normalized, label)?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn open_regular_readonly_file_in_ambient_root_nofollow(
    path: &Path,
    label: &str,
) -> io::Result<std::fs::File> {
    let (parent, leaf, normalized) = open_parent_directory(path, label, false)?;
    let file = open_regular_file_at(&parent, Path::new(&leaf)).map_err(|error| {
        if error.kind() == io::ErrorKind::InvalidData {
            return io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{label} is not a regular file: {}", normalized.display()),
            );
        }
        error
    })?;
    ensure_regular_file(file.into_std(), &normalized, label)
}

fn ensure_regular_file(file: std::fs::File, path: &Path, label: &str) -> io::Result<std::fs::File> {
    let metadata = file.metadata()?;
    if metadata.is_file() {
        return Ok(file);
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{label} is not a regular file: {}", path.display()),
    ))
}

fn open_parent_directory(
    path: &Path,
    label: &str,
    create_missing: bool,
) -> io::Result<(cap_std::fs::Dir, OsString, PathBuf)> {
    let normalized = normalize_absolute_path(path, label)?;
    let leaf = normalized.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} must include a file name: {}", path.display()),
        )
    })?;
    let parent = normalized.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{label} must include a parent directory: {}",
                path.display()
            ),
        )
    })?;
    let policy = if create_missing {
        MissingRootPolicy::Create
    } else {
        MissingRootPolicy::Error
    };
    let parent = open_root(parent, label, policy, |_, _, _, error| error)?.ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, format!("{label} parent not found"))
    })?;
    Ok((parent.into_dir(), leaf.to_os_string(), normalized))
}

fn normalize_absolute_path(path: &Path, label: &str) -> io::Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} must not be empty"),
        ));
    }

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    let mut normalized = PathBuf::new();
    let mut saw_root = false;
    for component in absolute.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                normalized.push(component.as_os_str());
                saw_root = true;
            }
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{label} must not contain `..`: {}", path.display()),
                ));
            }
        }
    }

    if !saw_root {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{label} must resolve to an absolute path: {}",
                path.display()
            ),
        ));
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::io;
    #[cfg(unix)]
    use std::path::PathBuf;

    #[cfg(unix)]
    fn canonical_temp_root(dir: &tempfile::TempDir) -> PathBuf {
        dir.path()
            .canonicalize()
            .expect("canonicalize tempdir root")
    }

    #[cfg(unix)]
    #[test]
    fn read_utf8_regular_file_rejects_ancestor_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("tempdir");
        let root = canonical_temp_root(&dir);
        let real = root.join("real");
        let alias = root.join("alias");
        std::fs::create_dir(&real).expect("real dir");
        std::fs::write(real.join("config.json"), "{}").expect("write config");
        symlink(&real, &alias).expect("symlink alias");

        let err = super::read_utf8_regular_file_in_ambient_root_nofollow(
            &alias.join("config.json"),
            64,
            "config file",
        )
        .expect_err("ancestor symlink must be rejected");
        assert!(matches!(
            err.kind(),
            io::ErrorKind::InvalidInput | io::ErrorKind::Other | io::ErrorKind::NotADirectory
        ));
    }

    #[cfg(unix)]
    #[test]
    fn open_appendable_regular_file_creates_missing_directories_without_following_symlinks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = canonical_temp_root(&dir).join("logs/nested/audit.jsonl");

        super::open_appendable_regular_file_in_ambient_root_nofollow(&path, "audit log")
            .expect("open appendable");

        assert!(path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn validate_appendable_regular_file_allows_missing_parent_directories_without_creating_them() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = canonical_temp_root(&dir).join("logs/nested/audit.jsonl");

        super::validate_appendable_regular_file_in_ambient_root_nofollow(&path, "audit log")
            .expect("validate appendable");

        assert!(!path.exists());
        assert!(!path.parent().expect("audit parent").exists());
    }
}
