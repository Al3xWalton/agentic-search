//! Exercises the actual std-only build entrypoint and resolver against isolated source roots.
//! Fixtures use existing local Git history, never commits, recursive Cargo, data or network.

#![deny(missing_docs)]

#[path = "../build_support/revision.rs"]
mod revision;

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
const ENV_SHA: &str = "ABCDEF0123456789ABCDEF0123456789ABCDEF01";

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root =
            PathBuf::from(std::env::var_os("STORY584_SCRATCH").expect("external STORY584_SCRATCH"))
                .join(format!(
                    "revision-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn archive(&self) -> PathBuf {
        let root = self.0.join("archive");
        fs::create_dir_all(root.join("crates/core/build_support")).unwrap();
        fs::create_dir_all(root.join("crates/core/src")).unwrap();
        fs::write(root.join("Cargo.toml"), "[workspace]\n").unwrap();
        fs::write(root.join("Cargo.lock"), "version = 3\n").unwrap();
        fs::write(
            root.join("SOURCE_OFFER.md"),
            include_bytes!("../../../SOURCE_OFFER.md"),
        )
        .unwrap();
        root
    }
    fn clone_repo(&self) -> PathBuf {
        let root = self.0.join("repository");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        // Git 2.55 can flip shared core.sparseCheckout across worktrees; a full local
        // clone avoids that shared state and costs under a second for this 50 MB fixture.
        let out = Command::new("git")
            .args(["clone", "--no-hardlinks", "--local"])
            .arg(source)
            .arg(&root)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        git(&root, &["checkout", "--detach", "HEAD"]);
        prepare_checked_inputs(&root);
        root
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn git(root: &Path, args: &[&str]) -> Output {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn add_worktree(root: &Path, worktree: &Path) {
    git(
        root,
        &[
            "worktree",
            "add",
            "--detach",
            worktree.to_str().unwrap(),
            "HEAD",
        ],
    );
    assert!(
        worktree.join("crates/core/Cargo.toml").is_file(),
        "worktree fixture must contain crates/core"
    );
    assert!(worktree.join(".git").is_file());
}

fn head(root: &Path) -> String {
    String::from_utf8(git(root, &["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim_end()
        .to_owned()
}

fn prepare_checked_inputs(root: &Path) {
    let output = git(root, &["rev-parse", "--git-path", "info/exclude"]);
    let path = String::from_utf8(output.stdout).unwrap();
    let exclude = root.join(path.trim_end());
    let mut ignored = fs::read_to_string(&exclude).unwrap();
    // The inherited HEAD lacks these files; use real regular files with a known blob.
    for path in [
        "crates/core/build.rs",
        "crates/core/build_support/revision.rs",
    ] {
        if !root.join(path).exists() {
            fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
            fs::write(root.join(path), fs::read(root.join("Cargo.toml")).unwrap()).unwrap();
            ignored.push_str(&format!("\n/{path}\n"));
        }
    }
    fs::write(exclude, ignored).unwrap();
}

fn fixture_command(root: &Path, args: &[&str]) -> Option<Output> {
    // The uncommitted source-offer files do not exist in the inherited history.
    // Supply their HEAD outcomes through the seam; hash-object reads the real files.
    for path in [
        "crates/core/build.rs",
        "crates/core/build_support/revision.rs",
    ] {
        let committed = format!("HEAD:{path}");
        let present = Command::new("git")
            .current_dir(root)
            .args(["cat-file", "-e", &committed])
            .output()
            .unwrap()
            .status
            .success();
        if !present && args == ["rev-parse", "--verify", "--quiet", &committed] {
            println!("Historical fixture seam: {committed} uses HEAD:Cargo.toml");
            return Some(git(
                root,
                &["rev-parse", "--verify", "--quiet", "HEAD:Cargo.toml"],
            ));
        }
    }
    Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .ok()
}

fn resolve_committed(root: &Path, environment: Option<&str>) -> revision::Revision {
    revision::resolve_with(root, environment, |args| fixture_command(root, args))
}

fn compile_build(fixture: &Fixture) -> PathBuf {
    let binary = fixture.0.join("actual-build");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("build.rs");
    let result = Command::new("rustc")
        .env("CARGO_PKG_REPOSITORY", env!("CARGO_PKG_REPOSITORY"))
        .args(["--edition=2021", "--crate-name", "source_offer_build"])
        .arg(source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    binary
}

fn run_build(binary: &Path, root: &Path, out: &Path, environment: Option<&str>) -> String {
    fs::create_dir_all(out).unwrap();
    let mut cmd = Command::new(binary);
    cmd.env("CARGO_MANIFEST_DIR", root.join("crates/core"))
        .env("OUT_DIR", out)
        .env_remove("SOURCE_REVISION");
    if let Some(value) = environment {
        cmd.env("SOURCE_REVISION", value);
    }
    let result = cmd.output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}

fn record_offer(kind: &str, out: &Path) {
    let document = fs::read_to_string(out.join("SOURCE_OFFER.md")).unwrap();
    let block = document
        .split("<!-- source-offer-contract:start -->")
        .nth(1)
        .unwrap()
        .split("<!-- source-offer-contract:end -->")
        .next()
        .unwrap();
    println!("{kind} fixture contract:{block}");
    if let Some(directory) = std::env::var_os("STORY584_ARTIFACT_DIR") {
        let directory = PathBuf::from(directory);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join(format!("{kind}-SOURCE_OFFER.md")), document).unwrap();
    }
}

fn prepare_template(root: &Path) {
    fs::write(
        root.join("SOURCE_OFFER.md"),
        include_bytes!("../../../SOURCE_OFFER.md"),
    )
    .unwrap();
    // The fixture's offer is a build input, but this historical HEAD predates that file.
    let exclude = root.join(".git/info/exclude");
    let mut ignored = fs::read_to_string(&exclude).unwrap();
    ignored.push_str("\nSOURCE_OFFER.md\n");
    fs::write(exclude, ignored).unwrap();
}

#[test]
fn revision_rejects_wrong_length() {
    for value in [
        "",
        "a",
        "abcdef0",
        &"a".repeat(39),
        &"a".repeat(41),
        &format!("{ENV_SHA}\n"),
    ] {
        assert_eq!(revision::valid_sha(value), None, "accepted {value:?}");
    }
    assert_eq!(
        revision::valid_sha(ENV_SHA).unwrap(),
        ENV_SHA.to_ascii_lowercase()
    );
}

#[test]
fn revision_rejects_non_hex() {
    for value in [
        "z".repeat(40),
        format!("{}\r", "a".repeat(39)),
        format!("{}\n", "a".repeat(39)),
        "é".repeat(20),
        format!("{};", "a".repeat(39)),
        format!(" {}", "a".repeat(39)),
    ] {
        assert_eq!(revision::valid_sha(&value), None);
    }
}

#[test]
fn git_revision_wins() {
    let fixture = Fixture::new();
    let root = fixture.clone_repo();
    let selected = resolve_committed(&root, Some(ENV_SHA));
    assert_eq!(selected.revision, head(&root));
    assert_eq!(selected.source, "git");
    let worktree = fixture.0.join("worktree");
    add_worktree(&root, &worktree);
    prepare_checked_inputs(&worktree);
    assert_eq!(resolve_committed(&worktree, Some(ENV_SHA)), selected);
}

#[test]
fn symlinked_checked_input_is_unknown() {
    use std::io::Write;
    use std::process::Stdio;

    let fixture = Fixture::new();
    let root = fixture.clone_repo();
    let input = root.join("crates/core/build.rs");
    fs::remove_file(&input).unwrap();
    let link_text = "symlink-payload";
    fs::write(root.join("crates/core/symlink-payload"), link_text).unwrap();
    std::os::unix::fs::symlink(link_text, &input).unwrap();
    let exclude = root.join(".git/info/exclude");
    let mut ignored = fs::read_to_string(&exclude).unwrap();
    ignored.push_str("\n/crates/core/symlink-payload\n");
    fs::write(exclude, ignored).unwrap();
    // Keep the fixture clean even once the build script exists in the inherited HEAD.
    if !git(&root, &["ls-files", "--", "crates/core/build.rs"])
        .stdout
        .is_empty()
    {
        git(
            &root,
            &["update-index", "--assume-unchanged", "crates/core/build.rs"],
        );
    }
    assert!(git(
        &root,
        &["status", "--porcelain=v1", "--untracked-files=normal"]
    )
    .stdout
    .is_empty());
    let mut hash = Command::new("git")
        .current_dir(&root)
        .args(["hash-object", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    hash.stdin
        .take()
        .unwrap()
        .write_all(link_text.as_bytes())
        .unwrap();
    let link_blob = hash.wait_with_output().unwrap();
    assert!(link_blob.status.success());
    let followed = git(&root, &["hash-object", "--", "crates/core/build.rs"]);
    assert_eq!(link_blob.stdout, followed.stdout);
    println!("Symlink link-text and followed-file Git hashes are equal");
    // Inject the committed link blob without creating a commit in the disposable clone.
    let selected = revision::resolve_with(&root, Some(ENV_SHA), |args| {
        if args
            == [
                "rev-parse",
                "--verify",
                "--quiet",
                "HEAD:crates/core/build.rs",
            ]
        {
            return Some(git(&root, &["hash-object", "--", "crates/core/build.rs"]));
        }
        fixture_command(&root, args)
    });
    assert_eq!(selected.revision, "unknown");
    assert_eq!(selected.source, "unknown");
}

#[test]
fn symlinked_git_is_unknown() {
    let fixture = Fixture::new();
    let root = fixture.clone_repo();
    let metadata = fixture.0.join("foreign.git");
    fs::rename(root.join(".git"), &metadata).unwrap();
    std::os::unix::fs::symlink(metadata, root.join(".git")).unwrap();
    assert_eq!(revision::resolve(&root, Some(ENV_SHA)).source, "unknown");
    let selected = resolve_committed(&root, Some(ENV_SHA));
    assert_eq!(selected.revision, "unknown");
    assert_eq!(selected.source, "unknown");
}

#[test]
fn foreign_history_is_unknown() {
    let fixture = Fixture::new();
    let root = fixture.clone_repo();
    let initial = git(&root, &["rev-list", "--max-parents=0", "HEAD"]);
    let initial = String::from_utf8(initial.stdout).unwrap();
    // Reuse the existing initial commit instead of creating an empty fixture commit.
    git(&root, &["checkout", "--detach", initial.trim_end()]);
    let metadata = fixture.0.join("foreign.git");
    fs::rename(root.join(".git"), &metadata).unwrap();
    fs::write(
        root.join(".git"),
        format!("gitdir: {}\n", metadata.display()),
    )
    .unwrap();
    git(&root, &["config", "core.worktree", root.to_str().unwrap()]);
    fs::write(metadata.join("info/exclude"), "*\n").unwrap();
    fs::create_dir_all(root.join("crates/core/build_support")).unwrap();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for path in [
        "Cargo.lock",
        "crates/core/Cargo.toml",
        "crates/core/build.rs",
        "crates/core/build_support/revision.rs",
    ] {
        fs::write(root.join(path), fs::read(source.join(path)).unwrap()).unwrap();
    }
    assert!(root.join(".git").is_file());
    assert!(git(
        &root,
        &["status", "--porcelain=v1", "--untracked-files=normal"]
    )
    .stdout
    .is_empty());
    let top = String::from_utf8(git(&root, &["rev-parse", "--show-toplevel"]).stdout).unwrap();
    assert_eq!(
        Path::new(top.trim_end()).canonicalize().unwrap(),
        root.canonicalize().unwrap()
    );
    println!(
        "Foreign gitfile: clean status, matching toplevel, existing initial HEAD {}",
        head(&root)
    );
    let selected = revision::resolve(&root, Some(ENV_SHA));
    assert_eq!(selected.revision, "unknown");
    assert_eq!(selected.source, "unknown");
}

#[test]
fn committed_inputs_are_verified() {
    let fixture = Fixture::new();
    let root = fixture.clone_repo();
    let selected = resolve_committed(&root, None);
    assert_eq!(selected.revision, head(&root));
    assert_eq!(selected.source, "git");
    let real = revision::resolve(&root, None);
    let missing = Command::new("git")
        .current_dir(&root)
        .args([
            "cat-file",
            "-e",
            "HEAD:crates/core/build_support/revision.rs",
        ])
        .output()
        .unwrap();
    assert_eq!(
        real.source,
        if missing.status.success() {
            "git"
        } else {
            "unknown"
        }
    );
    for path in [
        "Cargo.toml",
        "Cargo.lock",
        "crates/core/Cargo.toml",
        "crates/core/build.rs",
        "crates/core/build_support/revision.rs",
    ] {
        let committed = format!("HEAD:{path}");
        for args_to_fail in [
            vec!["rev-parse", "--verify", "--quiet", committed.as_str()],
            vec!["hash-object", "--", path],
        ] {
            let rejected = revision::resolve_with(&root, None, |args| {
                if args == args_to_fail {
                    None
                } else {
                    fixture_command(&root, args)
                }
            });
            assert_eq!(rejected.source, "unknown", "failed {args_to_fail:?}");
        }
        let rejected = revision::resolve_with(&root, None, |args| {
            let mut output = fixture_command(&root, args)?;
            if args == ["hash-object", "--", path] {
                output.stdout = b"different\n".to_vec();
            }
            Some(output)
        });
        assert_eq!(rejected.source, "unknown", "mismatch {path}");
    }
}

#[test]
fn archive_uses_environment_revision() {
    let fixture = Fixture::new();
    let root = fixture.archive();
    let selected = revision::resolve(&root, Some(ENV_SHA));
    assert_eq!(selected.revision, ENV_SHA.to_ascii_lowercase());
    assert_eq!(selected.source, "environment");
    let binary = compile_build(&fixture);
    let output = run_build(&binary, &root, &fixture.0.join("out"), Some(ENV_SHA));
    assert!(output.contains("cargo:rustc-env=AVA_SEARCH_REVISION_SOURCE=environment\n"));
    record_offer("environment", &fixture.0.join("out"));
    let offer = fs::read_to_string(fixture.0.join("out/SOURCE_OFFER.md")).unwrap();
    assert!(offer.contains(&format!("revision={}\n", ENV_SHA.to_ascii_lowercase())));
}

#[test]
fn unknown_revision_is_honest() {
    let fixture = Fixture::new();
    let root = fixture.archive();
    for value in [
        None,
        Some("HEAD"),
        Some("$(touch injected)"),
        Some("; false"),
        Some("\r\n"),
        Some("https://example.invalid"),
    ] {
        let selected = revision::resolve(&root, value);
        assert_eq!(selected.revision, "unknown");
        assert_eq!(selected.source, "unknown");
    }
    let binary = compile_build(&fixture);
    let output = run_build(
        &binary,
        &root,
        &fixture.0.join("out"),
        Some("$(touch injected)"),
    );
    assert!(
        output.contains("cargo:warning=Source revision unknown; this build is not release-ready\n")
    );
    assert!(!output.contains("touch injected"));
    assert!(!root.join("injected").exists());
    record_offer("unknown", &fixture.0.join("out"));
    let offer = fs::read_to_string(fixture.0.join("out/SOURCE_OFFER.md")).unwrap();
    assert!(offer.contains("source_url=https://github.com/Al3xWalton/agentic-search\n"));
    assert!(offer.contains("revision=unknown\n"));
    let missing = revision::resolve_with(&root, None, |_| panic!("archive must not invoke git"));
    assert_eq!(missing.revision, "unknown");
}

#[test]
fn dirty_git_is_unknown() {
    let fixture = Fixture::new();
    let root = fixture.clone_repo();
    fs::write(root.join("README.md"), "dirty\n").unwrap();
    for staged in [false, true] {
        if staged {
            git(&root, &["add", "README.md"]);
        }
        let selected = resolve_committed(&root, Some(ENV_SHA));
        assert_eq!(selected.revision, "unknown");
        assert_eq!(selected.source, "unknown");
    }
}

#[test]
fn parent_git_is_not_archive_git() {
    let fixture = Fixture::new();
    let parent = fixture.clone_repo();
    let root = parent.join("unpacked");
    fs::create_dir(&root).unwrap();
    let selected = revision::resolve(&root, Some(ENV_SHA));
    assert_eq!(selected.revision, ENV_SHA.to_ascii_lowercase());
    assert_eq!(selected.source, "environment");
}

#[test]
fn git_top_level_must_match_root() {
    let fixture = Fixture::new();
    let root = fixture.clone_repo();
    let other = fixture.0.join("other");
    fs::create_dir(&other).unwrap();
    git(&root, &["config", "core.worktree", other.to_str().unwrap()]);
    let selected = revision::resolve(&root, Some(ENV_SHA));
    assert_eq!(selected.revision, "unknown");
    assert_eq!(selected.source, "unknown");
    assert_eq!(
        revision::resolve_with(&root, Some(ENV_SHA), |_| None).revision,
        "unknown"
    );
    use std::os::unix::process::ExitStatusExt;
    let selected = revision::resolve_with(&root, Some(ENV_SHA), |args| {
        let bytes = if args.contains(&"--show-toplevel") {
            format!("{}\n", other.display()).into_bytes()
        } else if args.contains(&"--verify") || args.contains(&"hash-object") {
            format!("{ENV_SHA}\n").into_bytes()
        } else {
            Vec::new()
        };
        Some(Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: bytes,
            stderr: Vec::new(),
        })
    });
    assert_eq!(selected.revision, "unknown");
}

#[test]
fn build_script_reports_missing_template() {
    let fixture = Fixture::new();
    let root = fixture.archive();
    fs::remove_file(root.join("SOURCE_OFFER.md")).unwrap();
    let binary = compile_build(&fixture);
    let out = fixture.0.join("out");
    fs::create_dir(&out).unwrap();
    let result = Command::new(binary)
        .env("CARGO_MANIFEST_DIR", root.join("crates/core"))
        .env("OUT_DIR", out)
        .env_remove("SOURCE_REVISION")
        .output()
        .unwrap();
    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    eprintln!("missing-template stderr: {stderr}");
    assert!(stderr.contains("SOURCE_OFFER.md"), "{stderr}");
    assert!(stderr.contains("NotFound"), "{stderr}");
}

#[test]
fn build_script_embeds_selected_revision() {
    let fixture = Fixture::new();
    let root = fixture.clone_repo();
    prepare_template(&root);
    let binary = compile_build(&fixture);
    let out = fixture.0.join("out");
    let output = run_build(&binary, &root, &out, Some(ENV_SHA));
    let selected = revision::resolve(&root, Some(ENV_SHA));
    assert!(output.contains(&format!(
        "cargo:rustc-env=AVA_SEARCH_REVISION={}\n",
        selected.revision
    )));
    assert!(output.contains(&format!(
        "cargo:rustc-env=AVA_SEARCH_REVISION_SOURCE={}\n",
        selected.source
    )));
    record_offer(selected.source, &out);
    let rendered = fs::read_to_string(out.join("SOURCE_OFFER.md")).unwrap();
    assert!(rendered.contains(&format!("revision={}\n", selected.revision)));
    fs::write(root.join("README.md"), "dirty\n").unwrap();
    let second = run_build(&binary, &root, &out, Some(ENV_SHA));
    assert!(second.contains("cargo:rustc-env=AVA_SEARCH_REVISION=unknown\n"));
    assert!(fs::read_to_string(out.join("SOURCE_OFFER.md"))
        .unwrap()
        .contains("revision=unknown\n"));
    let archive = fixture.archive();
    let output = run_build(&binary, &archive, &out, Some(ENV_SHA));
    assert!(output.contains(&format!(
        "cargo:rustc-env=AVA_SEARCH_REVISION={}\n",
        ENV_SHA.to_ascii_lowercase()
    )));
}

#[test]
fn build_script_tracks_environment() {
    let fixture = Fixture::new();
    let root = fixture.archive();
    let binary = compile_build(&fixture);
    let out = fixture.0.join("out");
    let first = run_build(&binary, &root, &out, None);
    assert!(first.contains("cargo:rerun-if-env-changed=SOURCE_REVISION\n"));
    let second = run_build(&binary, &root, &out, Some(ENV_SHA));
    assert!(second.contains(&format!(
        "cargo:rustc-env=AVA_SEARCH_REVISION={}\n",
        ENV_SHA.to_ascii_lowercase()
    )));
}

fn assert_git_watches(root: &Path, output: &str, branch: bool) {
    let mut names = vec![
        "HEAD".to_owned(),
        "index".to_owned(),
        "packed-refs".to_owned(),
        "commondir".to_owned(),
        "config".to_owned(),
    ];
    if branch {
        names.push(
            String::from_utf8(git(root, &["symbolic-ref", "HEAD"]).stdout)
                .unwrap()
                .trim_end()
                .to_owned(),
        );
    }
    for name in names {
        let path =
            String::from_utf8(git(root, &["rev-parse", "--git-path", &name]).stdout).unwrap();
        let path = PathBuf::from(path.trim_end());
        let path = if path.is_absolute() {
            path
        } else {
            root.join(path)
        };
        assert!(
            output
                .lines()
                .any(|line| line == format!("cargo:rerun-if-changed={}", path.display())),
            "missing watch {name}: {output}"
        );
    }
    for name in [
        ".git",
        "Cargo.toml",
        "Cargo.lock",
        "crates",
        "scripts",
        "SOURCE_OFFER.md",
        "crates/core/build_support",
    ] {
        assert!(
            output.contains(&format!(
                "cargo:rerun-if-changed={}\n",
                root.join(name).display()
            )),
            "missing source watch {name}"
        );
    }
}

#[test]
fn build_script_tracks_git_and_sources() {
    let fixture = Fixture::new();
    let root = fixture.clone_repo();
    git(&root, &["checkout", "-b", "fixture-branch"]);
    prepare_template(&root);
    revision::emit_watches(&root);
    let binary = compile_build(&fixture);
    let first = run_build(&binary, &root, &fixture.0.join("out"), None);
    assert_git_watches(&root, &first, true);
    let worktree = fixture.0.join("worktree");
    add_worktree(&root, &worktree);
    fs::write(
        worktree.join("SOURCE_OFFER.md"),
        include_bytes!("../../../SOURCE_OFFER.md"),
    )
    .unwrap();
    let output = run_build(&binary, &worktree, &fixture.0.join("worktree-out"), None);
    assert_git_watches(&worktree, &output, false);
    let previous = String::from_utf8(git(&root, &["rev-parse", "HEAD^"]).stdout).unwrap();
    git(&root, &["checkout", "--detach", previous.trim_end()]);
    let second = run_build(&binary, &root, &fixture.0.join("out"), None);
    assert!(second.contains(&format!(
        "cargo:rustc-env=AVA_SEARCH_REVISION={}\n",
        revision::resolve(&root, None).revision
    )));
}
