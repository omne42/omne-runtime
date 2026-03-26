use std::fs;
use std::path::Path;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use omne_fs::ops::{Context, ListDirRequest, ReadRequest, list_dir, read_file};
#[cfg(feature = "glob")]
use omne_fs::ops::{GlobRequest, glob_paths};
#[cfg(feature = "grep")]
use omne_fs::ops::{GrepRequest, grep};
use omne_fs::policy::{Permissions, SandboxPolicy};
use policy_meta::WriteScope;

fn permissive_policy(root: &Path) -> SandboxPolicy {
    let mut policy =
        SandboxPolicy::single_root("root", root.to_path_buf(), WriteScope::WorkspaceWrite);
    policy.permissions = Permissions {
        read: true,
        glob: true,
        grep: true,
        list_dir: true,
        stat: true,
        edit: true,
        patch: true,
        delete: true,
        mkdir: true,
        write: true,
        move_path: true,
        copy_file: true,
    };
    policy.secrets.deny_globs = Vec::new();
    policy.secrets.redact_regexes = Vec::new();
    policy
}

struct BenchFixture {
    _tempdir: tempfile::TempDir,
    ctx_stable: Context,
    ctx_redaction: Context,
    #[cfg(any(feature = "glob", feature = "grep"))]
    ctx_unstable: Context,
    read_req: ReadRequest,
    list_req: ListDirRequest,
    #[cfg(feature = "glob")]
    glob_req: GlobRequest,
    #[cfg(feature = "grep")]
    grep_req: GrepRequest,
}

fn setup_fixture() -> BenchFixture {
    let tempdir = tempfile::tempdir().expect("tempdir");

    let large_path = tempdir.path().join("large.txt");
    let mut large = String::with_capacity(256 * 1024);
    for i in 0..8_000 {
        let line = format!("line-{i} normal text and maybe needle-{i}\n");
        large.push_str(&line);
    }
    fs::write(&large_path, large).expect("write large file");

    let docs_dir = tempdir.path().join("docs");
    fs::create_dir_all(&docs_dir).expect("mkdir docs");
    for i in 0..600 {
        let text = if i % 8 == 0 {
            "needle appears on some files\n"
        } else {
            "plain content\n"
        };
        fs::write(docs_dir.join(format!("file-{i}.txt")), text).expect("write txt");
    }
    for i in 0..200 {
        fs::write(docs_dir.join(format!("file-{i}.log")), "log content\n").expect("write log");
    }

    let stable_policy = permissive_policy(tempdir.path());
    let ctx_stable = Context::new(stable_policy).expect("ctx stable");
    let ctx_redaction = {
        let mut policy = permissive_policy(tempdir.path());
        policy.secrets.redact_regexes = vec!["needle".to_string()];
        Context::new(policy).expect("ctx redaction")
    };
    #[cfg(any(feature = "glob", feature = "grep"))]
    let ctx_unstable = {
        let mut unstable_policy = permissive_policy(tempdir.path());
        unstable_policy.traversal.stable_sort = false;
        Context::new(unstable_policy).expect("ctx unstable")
    };

    BenchFixture {
        _tempdir: tempdir,
        ctx_stable,
        ctx_redaction,
        #[cfg(any(feature = "glob", feature = "grep"))]
        ctx_unstable,
        read_req: ReadRequest {
            root_id: "root".to_string(),
            path: "large.txt".into(),
            start_line: None,
            end_line: None,
        },
        list_req: ListDirRequest {
            root_id: "root".to_string(),
            path: "docs".into(),
            max_entries: Some(128),
        },
        #[cfg(feature = "glob")]
        glob_req: GlobRequest {
            root_id: "root".to_string(),
            pattern: "docs/**/*.txt".to_string(),
        },
        #[cfg(feature = "grep")]
        grep_req: GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: Some("docs/**/*.txt".to_string()),
        },
    }
}

fn bench_ops(c: &mut Criterion) {
    let fixture = setup_fixture();

    c.bench_function("read/full_large_file", |b| {
        b.iter_batched(
            || fixture.read_req.clone(),
            |req| read_file(&fixture.ctx_stable, req).expect("read"),
            BatchSize::PerIteration,
        );
    });
    c.bench_function("read/full_large_file_with_redaction_regex", |b| {
        b.iter_batched(
            || fixture.read_req.clone(),
            |req| read_file(&fixture.ctx_redaction, req).expect("read"),
            BatchSize::PerIteration,
        );
    });

    c.bench_function("list_dir/top_k_entries", |b| {
        b.iter_batched(
            || fixture.list_req.clone(),
            |req| list_dir(&fixture.ctx_stable, req).expect("list_dir"),
            BatchSize::PerIteration,
        );
    });

    #[cfg(feature = "glob")]
    c.bench_function("glob/txt_files_stable_sort", |b| {
        b.iter_batched(
            || fixture.glob_req.clone(),
            |req| glob_paths(&fixture.ctx_stable, req).expect("glob"),
            BatchSize::PerIteration,
        );
    });

    #[cfg(feature = "glob")]
    c.bench_function("glob/txt_files_unstable_order", |b| {
        b.iter_batched(
            || fixture.glob_req.clone(),
            |req| glob_paths(&fixture.ctx_unstable, req).expect("glob"),
            BatchSize::PerIteration,
        );
    });

    #[cfg(feature = "grep")]
    c.bench_function("grep/plain_query_stable_sort", |b| {
        b.iter_batched(
            || fixture.grep_req.clone(),
            |req| grep(&fixture.ctx_stable, req).expect("grep"),
            BatchSize::PerIteration,
        );
    });

    #[cfg(feature = "grep")]
    c.bench_function("grep/plain_query_stable_sort_with_redaction_regex", |b| {
        b.iter_batched(
            || fixture.grep_req.clone(),
            |req| grep(&fixture.ctx_redaction, req).expect("grep"),
            BatchSize::PerIteration,
        );
    });

    #[cfg(feature = "grep")]
    c.bench_function("grep/plain_query_unstable_order", |b| {
        b.iter_batched(
            || fixture.grep_req.clone(),
            |req| grep(&fixture.ctx_unstable, req).expect("grep"),
            BatchSize::PerIteration,
        );
    });
}

criterion_group!(benches, bench_ops);
criterion_main!(benches);
