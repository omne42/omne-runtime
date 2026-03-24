fn main() {
    if std::env::var_os("CARGO_FEATURE_GIT_PERMISSIONS").is_some() {
        println!(
            "cargo:warning=omne-fs feature 'git-permissions' is enabled; caller must ensure `git` is installed and available in PATH at runtime."
        );
    }
}
