//! Exercises the actual std-only build entrypoint and resolver against isolated source roots.
//! Fixtures use local Git history and disposable commits, never recursive Cargo, data or network.
//! Every fixture Git command disables automatic maintenance with maintenance.auto=false and
//! automatic-GC heuristics with gc.auto=0, so waiting for it leaves no detached writer.
//! Ordinary users report cleanup through finish: at most 20 removals and 19 waits of 25 ms
//! (475 ms deliberate waiting, not a filesystem or scheduler deadline). Drop adds one silent,
//! immediate best-effort removal, including during unwinding, without changing finish's result.

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

const CLEANUP_ATTEMPTS: usize = 20;
const CLEANUP_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(25);

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
            .args(["-c", "maintenance.auto=false", "-c", "gc.auto=0"])
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
    fn finish(self) -> std::io::Result<()> {
        self.finish_with(|root| fs::remove_dir_all(root))
    }

    fn finish_with(
        self,
        mut remove: impl FnMut(&Path) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        let mut attempt = 1;
        loop {
            match remove(&self.0) {
                Ok(()) => return Ok(()),
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound && !self.0.try_exists()? =>
                {
                    return Ok(());
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::DirectoryNotEmpty
                        && attempt < CLEANUP_ATTEMPTS =>
                {
                    std::thread::sleep(CLEANUP_RETRY_DELAY);
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn git(root: &Path, args: &[&str]) -> Output {
    let output = Command::new("git")
        .args(["-c", "maintenance.auto=false", "-c", "gc.auto=0"])
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
            .args(["-c", "maintenance.auto=false", "-c", "gc.auto=0"])
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
        .args(["-c", "maintenance.auto=false", "-c", "gc.auto=0"])
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
    fixture.finish().unwrap();
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
        .args(["-c", "maintenance.auto=false", "-c", "gc.auto=0"])
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
    fixture.finish().unwrap();
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
    fixture.finish().unwrap();
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
    fixture.finish().unwrap();
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
        .args(["-c", "maintenance.auto=false", "-c", "gc.auto=0"])
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
    fixture.finish().unwrap();
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
    fixture.finish().unwrap();
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
    fixture.finish().unwrap();
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
    fixture.finish().unwrap();
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
    fixture.finish().unwrap();
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
    fixture.finish().unwrap();
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
    fixture.finish().unwrap();
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
    fixture.finish().unwrap();
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
    fixture.finish().unwrap();
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
    assert!(
        root.join("SOURCE_OFFER.md").is_file(),
        "fixture root must carry the template"
    );
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
    let before = head(&root);
    // On pull_request, HEAD^ is the merge commit's base branch, which lacks the Story's
    // build inputs; an empty fixture commit changes the revision without changing its tree.
    git(
        &root,
        &[
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--allow-empty",
            "-q",
            "-m",
            "fixture: move HEAD",
        ],
    );
    let moved = head(&root);
    assert_ne!(moved, before);
    let second = run_build(&binary, &root, &fixture.0.join("out"), None);
    assert!(second.contains(&format!("cargo:rustc-env=AVA_SEARCH_REVISION={}\n", moved)));
    assert!(second.contains("cargo:rustc-env=AVA_SEARCH_REVISION_SOURCE=git\n"));
    fixture.finish().unwrap();
}

mod cleanup_contract {
    //! Checks cleanup through real filesystem failures, compiled source, and the actual commit test.

    use super::*;
    use std::{io, os::unix::fs::PermissionsExt, panic, sync::mpsc, time::Duration};

    const SOURCE: &str = include_str!("build_revision_contract.rs");
    const COORDINATION_TIMEOUT: Duration = Duration::from_secs(2);

    struct RestorePermissions {
        path: PathBuf,
        permissions: fs::Permissions,
    }

    impl Drop for RestorePermissions {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.path, self.permissions.clone());
        }
    }

    fn protected_subject(fixture: &Fixture) -> (Fixture, PathBuf, RestorePermissions) {
        let root = fixture.0.join("subject");
        let directory = root.join("protected");
        fs::create_dir_all(&directory).unwrap();
        let file = directory.join("file");
        fs::write(&file, "owned").unwrap();
        let guard = RestorePermissions {
            permissions: fs::metadata(&directory).unwrap().permissions(),
            path: directory.clone(),
        };
        fs::set_permissions(directory, fs::Permissions::from_mode(0o500)).unwrap();
        (Fixture(root), file, guard)
    }

    #[test]
    fn finish_retries_after_late_writer() {
        let fixture = Fixture::new();
        let root = fixture.0.join("subject");
        let child = root.join("child");
        fs::create_dir_all(&child).unwrap();
        fs::write(child.join("old"), "old").unwrap();
        let subject = Fixture(root.clone());
        let (start_tx, start_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let writer_child = child.clone();
        let writer = std::thread::spawn(move || -> io::Result<()> {
            start_rx
                .recv_timeout(COORDINATION_TIMEOUT)
                .map_err(io::Error::other)?;
            fs::create_dir(&writer_child)?;
            fs::write(writer_child.join("late"), "late")?;
            done_tx.send(()).map_err(io::Error::other)
        });
        let mut calls = 0;
        let mut first_error = None;
        let result = subject.finish_with(|root| {
            calls += 1;
            if calls == 1 {
                fs::remove_dir_all(&child)?;
                start_tx.send(()).map_err(io::Error::other)?;
                done_rx
                    .recv_timeout(COORDINATION_TIMEOUT)
                    .map_err(io::Error::other)?;
                let result = fs::remove_dir(root);
                first_error = result.as_ref().err().map(io::Error::kind);
                result
            } else {
                fs::remove_dir_all(root)
            }
        });
        // Joining before assertions also covers an early return from the removal adapter.
        let joined = writer.join();
        println!("late writer: first_error={first_error:?}, calls={calls}, result={result:?}");
        assert!(
            joined.is_ok_and(|result| result.is_ok()),
            "writer must finish"
        );
        assert_eq!(first_error, Some(io::ErrorKind::DirectoryNotEmpty));
        assert!(
            result.is_ok(),
            "finish must retry the real late-writer error"
        );
        assert_eq!(calls, 2);
        assert!(!root.try_exists().unwrap());
        fixture.finish().unwrap();
    }

    #[test]
    fn drop_does_not_panic_on_undeletable_root() {
        let fixture = Fixture::new();
        let (subject, file, permissions) = protected_subject(&fixture);
        let precondition = fs::remove_file(&file);
        println!("drop permission precondition: {precondition:?}");
        if precondition.as_ref().err().map(io::Error::kind) != Some(io::ErrorKind::PermissionDenied)
        {
            drop(permissions);
            drop(subject);
            panic!("permission-denied witness precondition failed: {precondition:?}");
        }
        let result = panic::catch_unwind(|| drop(subject));
        drop(permissions);
        assert!(result.is_ok(), "Drop must not panic on PermissionDenied");
        fixture.finish().unwrap();
    }

    #[test]
    fn finish_reports_retry_exhaustion() {
        let fixture = Fixture::new();
        let root = fixture.0.join("exhaustion");
        fs::create_dir(&root).unwrap();
        let subject = Fixture(root);
        let mut calls = 0;
        let started = std::time::Instant::now();
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            subject.finish_with(|_| {
                calls += 1;
                Err(io::Error::from(io::ErrorKind::DirectoryNotEmpty))
            })
        }));
        println!(
            "exhaustion: calls={calls}, elapsed={:?}, result={result:?}",
            started.elapsed()
        );
        assert!(result.is_ok(), "explicit cleanup must not panic");
        let result = result.unwrap();
        assert_eq!(calls, CLEANUP_ATTEMPTS);
        assert_eq!(
            result.as_ref().err().map(io::Error::kind),
            Some(io::ErrorKind::DirectoryNotEmpty),
            "finish must report exhausted DirectoryNotEmpty"
        );

        let (subject, file, permissions) = protected_subject(&fixture);
        let precondition = fs::remove_file(&file);
        println!("finish permission precondition: {precondition:?}");
        if precondition.as_ref().err().map(io::Error::kind) != Some(io::ErrorKind::PermissionDenied)
        {
            drop(permissions);
            drop(subject);
            panic!("permission-denied witness precondition failed: {precondition:?}");
        }
        let result = panic::catch_unwind(|| subject.finish());
        drop(permissions);
        assert!(result.is_ok(), "finish must return its removal error");
        assert_eq!(
            result.unwrap().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );

        let absent = fixture.0.join("absent");
        Fixture(absent).finish().unwrap();
        let present = fixture.0.join("present");
        fs::create_dir(&present).unwrap();
        let result = Fixture(present).finish_with(|_| Err(io::ErrorKind::NotFound.into()));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
        fixture.finish().unwrap();
    }

    // Literals stay atomic so source examples and comments cannot count as executable builders.
    // Unsupported raw literals fail closed; this fixed source shape uses ordinary Rust strings.
    fn source_tokens(source: &str) -> Vec<(usize, &str)> {
        let bytes = source.as_bytes();
        let mut tokens = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            let start = index;
            if bytes[index].is_ascii_whitespace() {
                index += 1;
            } else if source[index..].starts_with("//") {
                index += source[index..].find('\n').unwrap_or(bytes.len() - index);
            } else if source[index..].starts_with("/*") {
                index += 2;
                let mut depth = 1;
                while depth > 0 {
                    assert!(index < bytes.len(), "unterminated source comment");
                    if source[index..].starts_with("/*") {
                        depth += 1;
                        index += 2;
                    } else if source[index..].starts_with("*/") {
                        depth -= 1;
                        index += 2;
                    } else {
                        index += source[index..].chars().next().unwrap().len_utf8();
                    }
                }
            } else {
                assert!(
                    !source[index..].starts_with("r#") && !source[index..].starts_with("r\""),
                    "unsupported raw source literal"
                );
                if bytes[index] == b'"' {
                    index += 1;
                    loop {
                        assert!(index < bytes.len(), "unterminated source string");
                        let byte = bytes[index];
                        index += 1;
                        if byte == b'\\' {
                            index += 1;
                        } else if byte == b'"' {
                            break;
                        }
                    }
                } else if bytes[index] == b'\'' && bytes.get(index + 2) == Some(&b'\'') {
                    index += 3;
                } else if bytes[index] == b'\''
                    && bytes.get(index + 1) == Some(&b'\\')
                    && bytes.get(index + 3) == Some(&b'\'')
                {
                    index += 4;
                } else if bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_' {
                    index += 1;
                    while index < bytes.len()
                        && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
                    {
                        index += 1;
                    }
                } else {
                    index += source[index..].chars().next().unwrap().len_utf8();
                }
                tokens.push((start, &source[start..index]));
            }
        }
        tokens
    }

    #[test]
    fn every_fixture_git_command_disables_background_work() {
        let tokens = source_tokens(SOURCE);
        let builder = ["Command", ":", ":", "new", "(", "\"git\"", ")"];
        let flags = ".args([\"-c\", \"maintenance.auto=false\", \"-c\", \"gc.auto=0\"])";
        let mut checked = 0;
        for window in tokens.windows(builder.len()) {
            if window.iter().map(|(_, token)| *token).eq(builder) {
                checked += 1;
                let (offset, last) = window.last().unwrap();
                let rest = SOURCE[offset + last.len()..].trim_start();
                assert!(
                    rest.starts_with(flags),
                    "fixture Git builder must disable background work at byte {}",
                    window[0].0
                );
            }
        }
        assert!(checked >= 6, "must inspect all six baseline Git builders");
        println!("checked {checked} actual fixture Git builders");
    }

    #[test]
    fn fixture_tests_finish_explicitly() {
        let expected = [
            "git_revision_wins",
            "symlinked_checked_input_is_unknown",
            "symlinked_git_is_unknown",
            "foreign_history_is_unknown",
            "committed_inputs_are_verified",
            "archive_uses_environment_revision",
            "unknown_revision_is_honest",
            "dirty_git_is_unknown",
            "parent_git_is_not_archive_git",
            "git_top_level_must_match_root",
            "build_script_reports_missing_template",
            "build_script_embeds_selected_revision",
            "build_script_tracks_environment",
            "build_script_tracks_git_and_sources",
        ];
        let tokens = source_tokens(SOURCE);
        let values: Vec<_> = tokens.iter().map(|(_, token)| *token).collect();
        let mut depth = 0;
        let mut checked = std::collections::BTreeSet::new();
        let mut top_level_function = None;
        for (index, &(offset, token)) in tokens.iter().enumerate() {
            if depth == 0 && token == "fn" {
                top_level_function = Some(values[index + 1]);
            }
            if depth == 0
                && token == "fn"
                && index >= 4
                && values[index - 4..index] == ["#", "[", "test", "]"]
            {
                let name = values[index + 1];
                assert!(
                    SOURCE[..offset].ends_with('\n'),
                    "unsupported non-column-zero test: {name}"
                );
                assert_eq!(
                    &values[index + 2..index + 5],
                    &["(", ")", "{"],
                    "unsupported test header: {name}"
                );
                let opening = index + 4;
                let mut nested = 1;
                let mut closing = None;
                for (end, value) in values.iter().enumerate().skip(opening + 1) {
                    match *value {
                        "{" => nested += 1,
                        "}" => nested -= 1,
                        _ => {}
                    }
                    if nested == 0 {
                        closing = Some(end);
                        break;
                    }
                }
                let closing = closing.expect("test closing brace must exist");
                let end = tokens[closing].0;
                assert!(
                    SOURCE[..end].ends_with('\n'),
                    "unsupported non-column-zero closing brace: {name}"
                );
                let body = &values[opening + 1..closing];
                let constructors = body
                    .windows(6)
                    .filter(|window| *window == ["Fixture", ":", ":", "new", "(", ")"])
                    .count();
                if expected.contains(&name) || constructors > 0 {
                    assert!(checked.insert(name), "ambiguous test function: {name}");
                    assert_eq!(
                        constructors, 1,
                        "exactly one fixture construction required: {name}"
                    );
                    let final_statement = [
                        "fixture", ".", "finish", "(", ")", ".", "unwrap", "(", ")", ";",
                    ];
                    assert!(
                        body.ends_with(&final_statement)
                            && SOURCE[tokens[opening].0 + 1..end]
                                .trim_end()
                                .ends_with("fixture.finish().unwrap();"),
                        "fixture test must finish explicitly: {name}"
                    );
                }
            }
            if let Some(name) = top_level_function
                .filter(|_| values[index..].starts_with(&["Fixture", ":", ":", "new", "(", ")"]))
            {
                assert!(
                    checked.contains(name),
                    "unsupported fixture test shape: {name}"
                );
            }
            match token {
                "{" => depth += 1,
                "}" => depth -= 1,
                _ => {}
            }
            if token == "}" && depth == 0 {
                top_level_function = None;
            }
        }
        for name in expected {
            assert!(checked.contains(name), "missing fixture test: {name}");
        }
        let delegation = "fn finish(self) -> std::io::Result<()> {\n        self.finish_with(|root| fs::remove_dir_all(root))\n    }";
        let delegations = tokens
            .iter()
            .filter(|(offset, token)| *token == "fn" && SOURCE[*offset..].starts_with(delegation))
            .count();
        assert_eq!(
            delegations, 1,
            "finish must delegate to the shared removal loop"
        );
        println!(
            "checked {} explicit fixture lifecycles and finish delegation",
            checked.len()
        );
    }

    #[test]
    fn git_commit_starts_no_background_maintenance() {
        let fixture = Fixture::new();
        let trace = fixture.0.join("commit-trace.jsonl");
        assert!(trace.is_absolute());
        let config = fixture.0.join("gitconfig");
        fs::write(
            &config,
            "[maintenance]\n\tauto = true\n\tautoDetach = true\n[gc]\n\tauto = 6700\n",
        )
        .unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "build_script_tracks_git_and_sources",
                "--nocapture",
            ])
            .env("GIT_TRACE2_EVENT", &trace)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", &config)
            .env_remove("GIT_CONFIG_COUNT")
            .env_remove("GIT_CONFIG_PARAMETERS")
            .output()
            .unwrap();
        let raw = fs::read(&trace).unwrap();
        if let Some(directory) = std::env::var_os("STORY584_ARTIFACT_DIR") {
            let directory = PathBuf::from(directory).join("cleanup-contract");
            fs::create_dir_all(&directory).unwrap();
            fs::write(directory.join("trace.jsonl"), &raw).unwrap();
            fs::write(directory.join("child.stdout"), &output.stdout).unwrap();
            fs::write(directory.join("child.stderr"), &output.stderr).unwrap();
            fs::write(directory.join("child.status"), output.status.to_string()).unwrap();
            fs::copy(config, directory.join("gitconfig")).unwrap();
        }
        assert!(
            output.status.success(),
            "commit test child must pass: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let text = std::str::from_utf8(&raw).unwrap();
        let mut records = 0;
        let mut commit = false;
        let mut background = Vec::new();
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let record: serde_json::Value =
                serde_json::from_str(line).expect("valid Git trace JSONL");
            assert!(record.is_object(), "Git trace record must be an object");
            records += 1;
            let event = record["event"].as_str().expect("Git trace event name");
            if event == "start" || event == "child_start" {
                let argv: Vec<_> = record["argv"]
                    .as_array()
                    .expect("Git trace argv")
                    .iter()
                    .map(|value| value.as_str().expect("Git trace argv string"))
                    .collect();
                if event == "start"
                    && argv.ends_with(&[
                        "commit",
                        "--allow-empty",
                        "-q",
                        "-m",
                        "fixture: move HEAD",
                    ])
                {
                    commit = true;
                }
                if event == "child_start"
                    && argv.iter().any(|arg| matches!(*arg, "maintenance" | "gc"))
                {
                    background.push(argv.into_iter().map(str::to_owned).collect::<Vec<_>>());
                }
            }
        }
        assert!(records > 0, "Git trace evidence must be nonempty");
        assert!(commit, "trace must include the actual empty fixture commit");
        println!("trace: records={records}, exact_commit={commit}, background={background:?}");
        assert!(
            background.is_empty(),
            "fixture commit must start no background maintenance or gc: {background:?}"
        );
        fixture.finish().unwrap();
    }
}
