use std::path::Path;

use omne_fs_primitives::{MissingRootPolicy, open_regular_file_at, open_root};

const HARD_MAX_TEXT_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_INITIAL_STDIN_CAPACITY: usize = 64 * 1024;
const DEFAULT_INITIAL_FILE_CAPACITY: usize = 8 * 1024;
const MAX_INITIAL_FILE_CAPACITY: usize = 256 * 1024;

fn symlink_rejected_error(path: &Path) -> omne_fs::Error {
    omne_fs::Error::InvalidPath(format!(
        "path resolution for {} detected a symlink; refusing to read text inputs from symlink paths",
        path.display()
    ))
}

fn open_input_file(path: &Path) -> Result<(omne_fs_primitives::File, u64), omne_fs::Error> {
    let leaf = path.file_name().ok_or_else(|| {
        omne_fs::Error::InvalidPath(format!(
            "path {} must include a text input file name",
            path.display()
        ))
    })?;
    let parent = normalize_input_parent(path.parent().unwrap_or_else(|| Path::new(".")));
    let root = open_root(
        &parent,
        "text input parent",
        MissingRootPolicy::Error,
        |_, _, _, error| error,
    )
    .map_err(|err| map_input_path_error(path, "open", err))?
    .ok_or_else(|| omne_fs::Error::IoPath {
        op: "open",
        path: path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("text input parent not found: {}", parent.display()),
        ),
    })?;

    if let Ok(metadata) = root.dir().symlink_metadata(Path::new(leaf))
        && metadata.file_type().is_symlink()
    {
        return Err(symlink_rejected_error(path));
    }

    let file = open_regular_file_at(root.dir(), Path::new(leaf))
        .map_err(|err| map_input_path_error(path, "open", err))?;
    let file_size = file.metadata().map_err(|err| omne_fs::Error::IoPath {
        op: "metadata",
        path: path.to_path_buf(),
        source: err,
    })?;
    Ok((file, file_size.len()))
}

fn normalize_input_parent(parent: &Path) -> std::path::PathBuf {
    #[cfg(not(target_os = "macos"))]
    {
        parent.to_path_buf()
    }

    #[cfg(target_os = "macos")]
    {
        normalize_macos_root_alias(parent)
    }
}

#[cfg(target_os = "macos")]
fn normalize_macos_root_alias(path: &Path) -> std::path::PathBuf {
    if !path.is_absolute() {
        return path.to_path_buf();
    }

    let mut visited = std::path::PathBuf::new();
    let mut normal_index = 0usize;
    let mut components = path.components().peekable();

    while let Some(component) = components.next() {
        visited.push(component.as_os_str());
        if !matches!(component, std::path::Component::Normal(_)) {
            continue;
        }

        match std::fs::symlink_metadata(&visited) {
            Ok(metadata)
                if metadata.file_type().is_symlink()
                    && normal_index == 0
                    && is_macos_root_alias_component(component) =>
            {
                let mut canonical = std::fs::canonicalize(&visited).unwrap_or(visited);
                for remainder in components {
                    canonical.push(remainder.as_os_str());
                }
                return canonical;
            }
            Ok(_) => {}
            Err(_) => return path.to_path_buf(),
        }

        normal_index += 1;
    }

    path.to_path_buf()
}

#[cfg(target_os = "macos")]
fn is_macos_root_alias_component(component: std::path::Component<'_>) -> bool {
    matches!(
        component,
        std::path::Component::Normal(part) if part == "var" || part == "tmp"
    )
}

fn map_input_path_error(path: &Path, op: &'static str, err: std::io::Error) -> omne_fs::Error {
    match err.kind() {
        std::io::ErrorKind::InvalidInput => omne_fs::Error::InvalidPath(format!(
            "path {} is not a safe regular text input file: {err}",
            path.display()
        )),
        _ => omne_fs::Error::IoPath {
            op,
            path: path.to_path_buf(),
            source: err,
        },
    }
}

pub(crate) fn load_text_limited(path: &Path, max_bytes: u64) -> Result<String, omne_fs::Error> {
    if max_bytes == 0 {
        return Err(omne_fs::Error::InvalidPolicy(
            "max input bytes must be > 0".to_string(),
        ));
    }
    if max_bytes > HARD_MAX_TEXT_INPUT_BYTES {
        return Err(omne_fs::Error::InvalidPolicy(format!(
            "max input bytes exceeds hard limit ({HARD_MAX_TEXT_INPUT_BYTES} bytes)"
        )));
    }

    let reads_stdin = path.as_os_str() == "-";
    let bytes = if reads_stdin {
        let mut stdin = std::io::stdin();
        let (bytes, truncated) = omne_fs_primitives::read_to_end_limited_with_capacity(
            &mut stdin,
            usize::try_from(max_bytes).unwrap_or(usize::MAX),
            initial_stdin_capacity(max_bytes),
        )
        .map_err(|err| omne_fs::Error::IoPath {
            op: "read_stdin",
            path: path.to_path_buf(),
            source: err,
        })?;
        let read_size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if truncated {
            return Err(omne_fs::Error::InputTooLarge {
                size_bytes: read_size,
                max_bytes,
            });
        }
        bytes
    } else {
        let (mut file, file_size) = open_input_file(path)?;
        if file_size > max_bytes {
            return Err(omne_fs::Error::InputTooLarge {
                size_bytes: file_size,
                max_bytes,
            });
        }
        let (bytes, truncated) = omne_fs_primitives::read_to_end_limited_with_capacity(
            &mut file,
            usize::try_from(max_bytes).unwrap_or(usize::MAX),
            initial_input_capacity(file_size, max_bytes),
        )
        .map_err(|err| omne_fs::Error::IoPath {
            op: "read",
            path: path.to_path_buf(),
            source: err,
        })?;
        let read_size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if truncated {
            return Err(omne_fs::Error::InputTooLarge {
                size_bytes: file_size.max(read_size),
                max_bytes,
            });
        }
        bytes
    };

    String::from_utf8(bytes).map_err(|err| omne_fs::Error::InvalidUtf8 {
        path: path.to_path_buf(),
        source: err.into(),
    })
}

fn initial_input_capacity(file_size: u64, max_bytes: u64) -> usize {
    usize::try_from(file_size.min(max_bytes))
        .ok()
        .map_or(DEFAULT_INITIAL_FILE_CAPACITY, |capacity| {
            capacity.min(MAX_INITIAL_FILE_CAPACITY)
        })
}

fn initial_stdin_capacity(max_bytes: u64) -> usize {
    usize::try_from(max_bytes)
        .ok()
        .map_or(MAX_INITIAL_STDIN_CAPACITY, |max| {
            max.min(MAX_INITIAL_STDIN_CAPACITY)
        })
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    use super::{initial_input_capacity, initial_stdin_capacity, load_text_limited};

    #[test]
    fn initial_input_capacity_keeps_small_values() {
        assert_eq!(initial_input_capacity(2048, 4096), 2048);
        assert_eq!(initial_input_capacity(0, 4096), 0);
    }

    #[test]
    fn initial_input_capacity_caps_large_values() {
        assert_eq!(
            initial_input_capacity(64 * 1024 * 1024, 64 * 1024 * 1024),
            256 * 1024
        );
    }

    #[test]
    fn initial_stdin_capacity_is_bounded() {
        assert_eq!(initial_stdin_capacity(1024), 1024);
        assert_eq!(initial_stdin_capacity(64 * 1024 * 1024), 64 * 1024);
    }

    #[test]
    fn load_text_limited_reads_regular_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("input.txt");
        std::fs::write(&path, "hello world").expect("write input");

        let loaded = load_text_limited(&path, 128).expect("load input");
        assert_eq!(loaded, "hello world");
    }

    #[cfg(unix)]
    #[test]
    fn load_text_limited_rejects_ancestor_symlink_paths() {
        let temp = tempfile::tempdir().expect("tempdir");
        let real_parent = temp.path().join("real");
        std::fs::create_dir_all(&real_parent).expect("create real parent");
        std::fs::write(real_parent.join("input.txt"), "hello").expect("write input");
        let symlink_parent = temp.path().join("link");
        symlink(&real_parent, &symlink_parent).expect("create symlink parent");

        let err = load_text_limited(&symlink_parent.join("input.txt"), 128)
            .expect_err("ancestor symlink should be rejected");
        assert!(matches!(err, omne_fs::Error::InvalidPath(_)));
    }
}
