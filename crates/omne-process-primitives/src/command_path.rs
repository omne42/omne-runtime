use std::path::{Path, PathBuf};

pub fn resolve_command_path(command: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        if let Some(path) = resolve_command_in_dir(command, &dir) {
            return Some(path);
        }
    }
    None
}

pub fn resolve_command_path_or_standard_location(command: &str) -> Option<PathBuf> {
    resolve_command_path(command).or_else(|| resolve_command_path_from_standard_locations(command))
}

fn resolve_command_path_from_standard_locations(command: &str) -> Option<PathBuf> {
    if command.contains('/') || command.contains('\\') {
        return None;
    }

    #[cfg(not(windows))]
    let candidate_dirs = [
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/opt/homebrew/bin",
        "/opt/local/bin",
    ];
    #[cfg(windows)]
    let candidate_dirs: [&str; 0] = [];

    for dir in candidate_dirs {
        if let Some(path) = resolve_command_in_dir(command, Path::new(dir)) {
            return Some(path);
        }
    }

    None
}

fn resolve_command_in_dir(command: &str, dir: &Path) -> Option<PathBuf> {
    let candidate = dir.join(command);

    #[cfg(windows)]
    {
        let has_ext = Path::new(command).extension().is_some();
        if has_ext {
            return candidate.is_file().then_some(candidate);
        }

        for ext in windows_path_extensions() {
            let ext_candidate = dir.join(format!("{command}{ext}"));
            if ext_candidate.is_file() {
                return Some(ext_candidate);
            }
        }

        return candidate.is_file().then_some(candidate);
    }

    #[cfg(not(windows))]
    {
        candidate.is_file().then_some(candidate)
    }
}

#[cfg(windows)]
fn windows_path_extensions() -> Vec<String> {
    std::env::var("PATHEXT")
        .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string())
        .split(';')
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{resolve_command_path, resolve_command_path_or_standard_location};

    #[test]
    fn missing_command_returns_none() {
        assert!(resolve_command_path("omne-process-primitives-missing-command").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn standard_locations_find_shell() {
        let resolved = resolve_command_path_or_standard_location("sh")
            .expect("resolve shell from PATH or standard locations");
        assert!(resolved.is_file());
    }
}
