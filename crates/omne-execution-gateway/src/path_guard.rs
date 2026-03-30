use std::ffi::OsString;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::str;

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};

pub(crate) fn read_utf8_regular_file_nofollow(
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> io::Result<String> {
    let mut file = open_regular_readonly_nofollow(path, label)?;
    let mut bytes = Vec::new();
    let limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut limited = (&mut file).take(limit);
    limited.read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{label} exceeds size limit ({} > {} bytes)",
                bytes.len(),
                max_bytes
            ),
        ));
    }

    str::from_utf8(&bytes)
        .map(str::to_owned)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
}

pub(crate) fn open_regular_readonly_nofollow(
    path: &Path,
    label: &str,
) -> io::Result<std::fs::File> {
    let (parent, leaf, normalized) = open_parent_directory(path, label, false)?;
    let mut options = OpenOptions::new();
    options.read(true);
    options.follow(FollowSymlinks::No);
    let file = parent.open_with(Path::new(&leaf), &options)?;
    ensure_regular_file(file.into_std(), &normalized, label)
}

#[allow(dead_code)]
pub(crate) fn open_appendable_regular_file_nofollow(
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
) -> io::Result<(Dir, OsString, PathBuf)> {
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
    let (base, components) = split_root(parent, label)?;
    let mut current = Dir::open_ambient_dir(&base, ambient_authority())?;

    for component in components {
        let component = Path::new(&component);
        match current.open_dir_nofollow(component) {
            Ok(next) => current = next,
            Err(error) if error.kind() == io::ErrorKind::NotFound && create_missing => {
                match current.create_dir(component) {
                    Ok(()) => {}
                    Err(create_error) if create_error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(create_error) => return Err(create_error),
                }
                current = current.open_dir_nofollow(component)?;
            }
            Err(error) => return Err(error),
        }
    }

    Ok((current, leaf.to_os_string(), normalized))
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

fn split_root(root: &Path, label: &str) -> io::Result<(PathBuf, Vec<OsString>)> {
    if !root.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} must be absolute: {}", root.display()),
        ));
    }

    let mut base = PathBuf::new();
    let mut components = Vec::new();
    let mut saw_root = false;
    for component in root.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                base.push(component.as_os_str());
                saw_root = true;
            }
            Component::Normal(part) => components.push(part.to_os_string()),
            Component::CurDir | Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{label} must be normalized: {}", root.display()),
                ));
            }
        }
    }

    if !saw_root {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} must be absolute: {}", root.display()),
        ));
    }

    Ok((base, components))
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::PathBuf;

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

        let err =
            super::read_utf8_regular_file_nofollow(&alias.join("config.json"), 64, "config file")
                .expect_err("ancestor symlink must be rejected");
        assert!(matches!(
            err.kind(),
            io::ErrorKind::Other | io::ErrorKind::NotADirectory
        ));
    }

    #[cfg(unix)]
    #[test]
    fn open_appendable_regular_file_creates_missing_directories_without_following_symlinks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = canonical_temp_root(&dir).join("logs/nested/audit.jsonl");

        super::open_appendable_regular_file_nofollow(&path, "audit log")
            .expect("open appendable");

        assert!(path.exists());
    }
}
