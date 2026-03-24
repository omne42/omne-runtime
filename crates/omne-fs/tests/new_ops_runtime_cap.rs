mod common;

use std::path::PathBuf;

use common::all_permissions_test_policy as test_policy;
use omne_fs::ops::{Context, ListDirRequest, list_dir};
use omne_fs::policy::RootMode;

#[test]
#[ignore = "slow: creates 100k files to validate runtime-cap behavior via public API"]
fn list_dir_runtime_cap_truncates_public_api_when_request_exceeds_cap() {
    const RUNTIME_CAP: usize = 100_000;
    const ENTRY_COUNT: usize = RUNTIME_CAP + 1;
    const MAX_LINE_BYTES_FOR_LARGE_RESULTS: usize = 640;

    let dir = tempfile::tempdir().expect("tempdir");
    for idx in 0..ENTRY_COUNT {
        let path = dir.path().join(format!("file_{idx:06}.txt"));
        std::fs::File::create(path).expect("create");
    }

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_results = ENTRY_COUNT;
    policy.limits.max_line_bytes = MAX_LINE_BYTES_FOR_LARGE_RESULTS;
    let ctx = Context::new(policy).expect("ctx");

    let resp = list_dir(
        &ctx,
        ListDirRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("."),
            max_entries: Some(ENTRY_COUNT),
        },
    )
    .expect("list");

    assert!(resp.truncated);
    assert_eq!(resp.entries.len(), RUNTIME_CAP);
    assert_eq!(resp.entries[0].name, "file_000000.txt");
    assert_eq!(resp.entries[RUNTIME_CAP - 1].name, "file_099999.txt");
}
