//! Exercises the Rust repository guards on disposable fixtures, including ignored bytes and failures.
//! No fixture downloads data, changes the supplied repositories, or invokes Cargo recursively.

#![deny(missing_docs)]

use std::{
    fs,
    os::unix::{fs::symlink, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
const PIN: &str = "[toolchain]\nchannel = \"1.98.0\"\n";
const NOTICE: &str = include_str!("../../../NOTICE");
const BOM: &str = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"component":{"name":"stract"}},"components":[{"name":"dependency"}]}"#;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root =
            PathBuf::from(std::env::var_os("STORY584_SCRATCH").expect("external STORY584_SCRATCH"))
                .join(format!(
                    "guard-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn write(&self, name: &str, contents: impl AsRef<[u8]>) {
        let path = self.0.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
    fn guard(&self, name: &str) -> anyhow::Result<()> {
        match name {
            "toolchain-pin" => xtask::guards::toolchain_pin(&self.0).map(|_| ()),
            "no-developer-paths" => xtask::guards::no_developer_paths(&self.0),
            "check-notices" => {
                xtask::guards::check_notices(&self.0, Some(&self.0.join(".baseline")))
            }
            _ => panic!("unknown fixture guard"),
        }
    }
    fn run(&self, name: &str, args: &[&str]) -> anyhow::Result<()> {
        match name {
            "check-sbom" => xtask::guards::check_sbom(Path::new(args[0])),
            "no-developer-paths" => xtask::guards::no_developer_paths(Path::new(args[1])),
            "install-tools" => xtask::install::verify_archive(Path::new(args[1]), args[2]),
            "source-tree" => {
                xtask::source_tree::source_tree(Path::new(args[1]), Path::new(args[2]))
            }
            _ => panic!("unknown fixture guard"),
        }
    }
    fn notice(&self) {
        self.write("NOTICE", NOTICE);
        self.write("LICENSE.md", "upstream licence\n");
        self.write(".baseline/LICENSE.md", "upstream licence\n");
        self.write(
            "source.rs",
            "// Copyright upstream\n// Full licence block\n\nfn old() {}\n",
        );
        self.write(
            ".baseline/source.rs",
            "// Copyright upstream\n// Full licence block\n\nfn old() {}\n",
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn accepts(result: anyhow::Result<()>) {
    assert!(result.is_ok(), "{result:?}");
}
fn rejects(result: anyhow::Result<()>) {
    let error = result.expect_err("guard accepted invalid fixture");
    assert!(!error.to_string().is_empty(), "missing diagnostic");
}
fn forbidden() -> Vec<u8> {
    [b"/".as_slice(), b"Users/fixture-owner/example"].concat()
}

#[test]
fn toolchain_missing_is_rejected() {
    let fixture = Fixture::new();
    rejects(fixture.guard("toolchain-pin"));
    fixture.write("rust-toolchain.toml", PIN);
    accepts(fixture.guard("toolchain-pin"));
}

#[test]
fn toolchain_wrong_version_is_rejected() {
    let fixture = Fixture::new();
    fixture.write("rust-toolchain.toml", PIN);
    accepts(fixture.guard("toolchain-pin"));
    for invalid in [
        "[toolchain]\nchannel = \"stable\"\n",
        "# channel = \"1.98.0\"\n[other]\nchannel = \"1.98.0\"\n",
        "[toolchain]\nchannel = 1.98.0\n",
        "[toolchain]\nchannel = \"1.98\"\n",
    ] {
        fixture.write("rust-toolchain.toml", invalid);
        rejects(fixture.guard("toolchain-pin"));
    }
}

#[test]
fn toolchain_duplicate_channel_is_rejected() {
    let fixture = Fixture::new();
    fixture.write("rust-toolchain.toml", PIN);
    accepts(fixture.guard("toolchain-pin"));
    fixture.write(
        "rust-toolchain.toml",
        format!("{PIN}channel = \"1.98.0\"\n"),
    );
    rejects(fixture.guard("toolchain-pin"));
}

#[test]
fn developer_paths_are_rejected() {
    let fixture = Fixture::new();
    fixture.write("clean", "source\n");
    accepts(fixture.guard("no-developer-paths"));
    fixture.write(".gitignore", "*.log\n");
    for name in ["ignored.log", ".hidden.json", "binary.BIN", "UPPER.LOG"] {
        let content = [b"\0prefix".as_slice(), &forbidden(), b"\xffsuffix"].concat();
        fixture.write(name, content);
        rejects(fixture.guard("no-developer-paths"));
        fs::remove_file(fixture.0.join(name)).unwrap();
    }
    rejects(fixture.run(
        "no-developer-paths",
        &["--root", fixture.0.join("absent").to_str().unwrap()],
    ));
}

#[test]
fn developer_path_names_are_rejected() {
    let fixture = Fixture::new();
    fixture.write("safe", "safe");
    accepts(fixture.guard("no-developer-paths"));
    fixture.write("Users/fixture-owner/example", "safe");
    rejects(fixture.guard("no-developer-paths"));
}

#[test]
fn developer_symlink_targets_are_rejected() {
    let fixture = Fixture::new();
    fixture.write("safe", "safe");
    symlink("safe", fixture.0.join("link")).unwrap();
    accepts(fixture.guard("no-developer-paths"));
    fs::remove_file(fixture.0.join("link")).unwrap();
    symlink(
        String::from_utf8(forbidden()).unwrap(),
        fixture.0.join("link"),
    )
    .unwrap();
    rejects(fixture.guard("no-developer-paths"));
}

#[test]
fn developer_path_exemption_is_exact() {
    let fixture = Fixture::new();
    fixture.write(
        "crates/xtask/tests/fixtures/no-developer-paths/forbidden.txt",
        forbidden(),
    );
    accepts(fixture.guard("no-developer-paths"));
    for name in [
        "crates/xtask/tests/fixtures-evil/bad",
        "nested/crates/xtask/tests/fixtures/no-developer-paths/bad",
        "crates/xtask/tests/fixtures/no-developer-paths-evil/bad",
    ] {
        fixture.write(name, forbidden());
        rejects(fixture.guard("no-developer-paths"));
        fs::remove_file(fixture.0.join(name)).unwrap();
    }
    symlink(
        String::from_utf8(forbidden()).unwrap(),
        fixture
            .0
            .join("crates/xtask/tests/fixtures/no-developer-paths/link"),
    )
    .unwrap();
    rejects(fixture.guard("no-developer-paths"));
}

#[test]
fn notice_missing_is_rejected() {
    let fixture = Fixture::new();
    fixture.notice();
    accepts(fixture.guard("check-notices"));
    fs::remove_file(fixture.0.join("NOTICE")).unwrap();
    rejects(fixture.guard("check-notices"));
}

#[test]
fn notice_content_is_required() {
    let fixture = Fixture::new();
    fixture.notice();
    accepts(fixture.guard("check-notices"));
    for (before, after) in [
        (
            "Agentic Search is derived from Stract (https://github.com/StractOrg/stract).",
            "Derived elsewhere.",
        ),
        (
            "8ac40b023e0a49f55cdd5b599841ea46d0503ec9",
            "0000000000000000000000000000000000000000",
        ),
        ("2026-09-10", "undated"),
        (
            "The public git history records modified files and their relevant dates.",
            "History omitted.",
        ),
    ] {
        fixture.write("NOTICE", NOTICE.replace(before, after));
        rejects(fixture.guard("check-notices"));
    }
}

#[test]
fn licence_bytes_are_preserved() {
    let fixture = Fixture::new();
    fixture.notice();
    accepts(fixture.guard("check-notices"));
    fixture.write("LICENSE.md", "different licence\n");
    rejects(fixture.guard("check-notices"));
    fs::remove_file(fixture.0.join("LICENSE.md")).unwrap();
    rejects(fixture.guard("check-notices"));
}

#[test]
fn upstream_notices_are_preserved() {
    let fixture = Fixture::new();
    fixture.notice();
    fixture.write(
        "source.rs",
        "// Copyright upstream\n// Full licence block\n\nfn changed() {}\n",
    );
    accepts(fixture.guard("check-notices"));
    fixture.write(
        "source.rs",
        "// Copyright upstream\n// Shortened block\n\nfn changed() {}\n",
    );
    rejects(fixture.guard("check-notices"));
    fs::remove_file(fixture.0.join("source.rs")).unwrap();
    rejects(fixture.guard("check-notices"));
}

#[test]
fn sbom_missing_or_empty_is_rejected() {
    let fixture = Fixture::new();
    let path = fixture.0.join("bom.json");
    let args = [path.to_str().unwrap()];
    rejects(fixture.run("check-sbom", &args));
    fixture.write("bom.json", "");
    rejects(fixture.run("check-sbom", &args));
    fixture.write("bom.json", BOM);
    accepts(fixture.run("check-sbom", &args));
}

#[test]
fn sbom_shape_is_required() {
    let fixture = Fixture::new();
    let path = fixture.0.join("bom.json");
    let args = [path.to_str().unwrap()];
    fixture.write("bom.json", BOM);
    accepts(fixture.run("check-sbom", &args));
    for invalid in [
        "{".to_owned(),
        BOM.replace("CycloneDX", "SPDX"),
        BOM.replace("1.5", "1.4"),
        BOM.replace("stract", "other"),
        BOM.replace("[{\"name\":\"dependency\"}]", "[]"),
        "null".to_owned(),
        BOM.replace("[{\"name\":\"dependency\"}]", "{}"),
    ] {
        fixture.write("bom.json", invalid);
        rejects(fixture.run("check-sbom", &args));
    }
}

#[test]
fn tool_archive_checksum_is_required() {
    let fixture = Fixture::new();
    fixture.write("archive", "abc");
    let path = fixture.0.join("archive");
    accepts(fixture.run(
        "install-tools",
        &[
            "--verify-archive",
            path.to_str().unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ],
    ));
    rejects(fixture.run(
        "install-tools",
        &["--verify-archive", path.to_str().unwrap(), &"0".repeat(64)],
    ));
    fs::remove_file(path.clone()).unwrap();
    rejects(fixture.run(
        "install-tools",
        &["--verify-archive", path.to_str().unwrap(), &"0".repeat(64)],
    ));
}

#[test]
fn secret_scanner_failure_is_fatal() {
    let fixture = Fixture::new();
    fixture.write("scanner", "native command seam");
    fixture.write(".spike/evidence", "retained evidence");
    let scanner = fixture.0.join("scanner");
    let reports = fixture.0.join("reports");
    let mut calls = 0;
    let result =
        xtask::artifacts::secrets_with(&fixture.0, &scanner, &reports, &fixture.0, |command| {
            let args: Vec<_> = command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
            assert_eq!(args.contains(&"--config".to_owned()), calls == 1);
            assert!(args.contains(&"--ignore-gitleaks-allow".to_owned()));
            for name in ["GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML"] {
                assert!(command
                    .get_envs()
                    .any(|(key, value)| key == name && value.is_none()));
            }
            calls += 1;
            Ok(ExitStatus::from_raw(if calls == 1 { 1 << 8 } else { 0 }))
        });
    assert_eq!(calls, 2);
    assert_eq!(xtask::exit_code(&result.unwrap_err()), 1);
    accepts(xtask::artifacts::secrets_with(
        &fixture.0,
        &scanner,
        &reports,
        &fixture.0,
        |_| Ok(ExitStatus::from_raw(0)),
    ));
    fixture.write("bad", forbidden());
    rejects(xtask::artifacts::secrets_with(
        &fixture.0,
        &scanner,
        &reports,
        &fixture.0,
        |_| Ok(ExitStatus::from_raw(0)),
    ));
}

#[test]
fn source_tree_enumeration_failure_is_fatal() {
    let fixture = Fixture::new();
    let dest = fixture.0.join("export");
    let failing_root = fixture.0.join("source");
    fs::create_dir(&failing_root).unwrap();
    rejects(fixture.run(
        "source-tree",
        &[
            "--root",
            failing_root.to_str().unwrap(),
            dest.to_str().unwrap(),
        ],
    ));
    let output = xtask::source_tree::source_tree_with(&failing_root, &dest, |root, args| {
        if args == ["rev-parse", "--show-toplevel"] {
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: root.as_os_str().as_encoded_bytes().to_vec(),
                stderr: Vec::new(),
            })
        } else {
            Ok(Output {
                status: ExitStatus::from_raw(1 << 8),
                stdout: Vec::new(),
                stderr: b"enumeration fixture failure".to_vec(),
            })
        }
    });
    rejects(output);
    let source = fixture.0.join("real");
    fs::create_dir(&source).unwrap();
    assert!(Command::new("git")
        .args(["init", "--quiet"])
        .arg(&source)
        .status()
        .unwrap()
        .success());
    fs::write(source.join(".gitignore"), "*.log\n").unwrap();
    fs::write(source.join("retained.log"), "tracked bytes").unwrap();
    assert!(Command::new("git")
        .current_dir(&source)
        .args(["add", "-f", "retained.log"])
        .status()
        .unwrap()
        .success());
    fs::write(source.join("authored"), "current bytes").unwrap();
    fs::write(source.join("tabs\tand\nnewlines"), "NUL-safe name").unwrap();
    symlink("authored", source.join("link")).unwrap();
    accepts(fixture.run(
        "source-tree",
        &["--root", source.to_str().unwrap(), dest.to_str().unwrap()],
    ));
    assert_eq!(
        fs::read(dest.join("retained.log")).unwrap(),
        b"tracked bytes"
    );
    assert_eq!(fs::read(dest.join("authored")).unwrap(), b"current bytes");
    assert_eq!(
        fs::read(dest.join("tabs\tand\nnewlines")).unwrap(),
        b"NUL-safe name"
    );
    assert_eq!(
        fs::read_link(dest.join("link")).unwrap(),
        Path::new("authored")
    );
}

#[test]
fn secret_allowlist_paths_are_exact() {
    let config: toml::Value =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.gitleaks.toml"))
            .unwrap()
            .parse()
            .unwrap();
    let paths: Vec<_> = config["allowlist"]["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|path| path.as_str().unwrap())
        .collect();
    assert_eq!(
        paths,
        [
            "crates/core/testcases/.*",
            "crates/optics/testcases/samples/.*",
        ]
    );
}

#[test]
fn ci_init_derives_scratch_from_runner_temp() {
    let fixture = Fixture::new();
    fixture.write("env", "EXISTING=value\n");
    fixture.write("path", "existing-bin\n");
    let runner = fixture.0.join("runner");
    let init = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_xtask"));
        command
            .args(["ci-init", "--no-toolchain"])
            .env("GITHUB_ENV", fixture.0.join("env"))
            .env("GITHUB_PATH", fixture.0.join("path"))
            .env_remove("RUNNER_TEMP");
        for name in [
            "STORY584_SCRATCH",
            "STORY584_TOOLS",
            "STORY584_ARTIFACT_DIR",
            "WASM_PACK_CACHE",
            "CARGO_TARGET_DIR",
        ] {
            command.env_remove(name);
        }
        command
    };
    let result = init().env("RUNNER_TEMP", &runner).output().unwrap();
    assert!(result.status.success(), "{result:?}");
    let contents = fs::read_to_string(fixture.0.join("env")).unwrap();
    eprintln!("ci-init exports:\n{contents}");
    let exports: std::collections::BTreeMap<_, _> = contents
        .lines()
        .map(|line| line.split_once('=').unwrap())
        .collect();
    assert_eq!(exports.len(), 6);
    assert_eq!(exports["EXISTING"], "value");
    for (name, suffix) in [
        ("STORY584_SCRATCH", "story584-scratch"),
        ("STORY584_TOOLS", "story584-tools"),
        ("STORY584_ARTIFACT_DIR", "story584-artifacts"),
        ("WASM_PACK_CACHE", "story584-scratch/wasm-pack-cache"),
    ] {
        assert_eq!(Path::new(exports[name]), runner.join(suffix));
        assert!(Path::new(exports[name]).is_dir());
    }
    let target = Path::new(exports["CARGO_TARGET_DIR"]);
    assert!(target.is_dir());
    assert_eq!(target.parent().unwrap(), runner.join("story584-scratch"));
    assert!(target
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("target-"));
    let bin = runner.join("story584-tools/bin");
    assert!(bin.is_dir());
    assert_eq!(
        fs::read_to_string(fixture.0.join("path")).unwrap(),
        format!("existing-bin\n{}\n", bin.display())
    );
    let second = init().env("RUNNER_TEMP", &runner).output().unwrap();
    assert!(second.status.success(), "{second:?}");
    let contents = fs::read_to_string(fixture.0.join("env")).unwrap();
    let targets: Vec<_> = contents
        .lines()
        .filter_map(|line| line.strip_prefix("CARGO_TARGET_DIR="))
        .collect();
    assert_eq!(targets.len(), 2);
    assert_ne!(targets[0], targets[1]);
    let local = init()
        .env("STORY584_SCRATCH", fixture.0.join("local-scratch"))
        .env("STORY584_TOOLS", fixture.0.join("local-tools"))
        .env("STORY584_ARTIFACT_DIR", fixture.0.join("local-artifacts"))
        .output()
        .unwrap();
    assert!(local.status.success(), "{local:?}");
    assert!(fs::read_to_string(fixture.0.join("env"))
        .unwrap()
        .contains(&format!(
            "STORY584_SCRATCH={}\n",
            fixture.0.join("local-scratch").display()
        )));
    let missing = init().output().unwrap();
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("RUNNER_TEMP or all STORY584_"));
}

#[test]
fn workflow_lint_rejects_runner_context_at_workflow_level() {
    let fixture = Fixture::new();
    let path = fixture.0.join("ci.yaml");
    let source = include_str!("fixtures/workflow/workflow-context.yaml");
    for context in [
        "runner", "env", "steps", "job", "matrix", "strategy", "needs",
    ] {
        fixture.write("ci.yaml", source.replace("runner.", &format!("{context}.")));
        let error = xtask::workflow::workflow_lint(&path)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("line 3: unavailable context in workflow env"),
            "{error}"
        );
    }
    for context in ["runner", "env", "steps", "job"] {
        fixture.write("ci.yaml", format!("jobs:\n  linux:\n    runs-on: ubuntu-latest\n    env:\n      BAD: ${{{{ {context}.value }}}}\n"));
        let error = xtask::workflow::workflow_lint(&path)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("line 5: unavailable context in job env"),
            "{error}"
        );
    }
    fixture.write("ci.yaml", source);
    let result = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("workflow-lint")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("line 3:"));
}

#[test]
fn workflow_lint_rejects_unpinned_action() {
    let fixture = Fixture::new();
    let path = fixture.0.join("ci.yaml");
    let source = include_str!("fixtures/workflow/unpinned-action.yaml");
    for revision in [
        "v7",
        "main",
        "1234567",
        &"A".repeat(40),
        &"a".repeat(39),
        &"a".repeat(41),
    ] {
        fixture.write("ci.yaml", source.replace("v7", revision));
        let error = xtask::workflow::workflow_lint(&path)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("line 6: uses must end in @ plus 40 lowercase hex"),
            "{error}"
        );
    }
}

#[test]
fn workflow_lint_accepts_current_workflow() {
    accepts(xtask::workflow::workflow_lint(
        &xtask::repository_root().join(".github/workflows/ci.yaml"),
    ));
    let fixture = Fixture::new();
    let path = fixture.0.join("ci.yaml");
    let source = include_str!("fixtures/workflow/valid.yaml");
    fixture.write("ci.yaml", source);
    accepts(xtask::workflow::workflow_lint(&path));
    fixture.write(
        "ci.yaml",
        source.replace("    runs-on: ubuntu-latest\n", ""),
    );
    let error = xtask::workflow::workflow_lint(&path)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("line 5: job linux is missing runs-on"),
        "{error}"
    );
    fixture.write("ci.yaml", "env:\n  BAD: ${{ runner.temp }}\njobs:\n  first:\n    steps:\n      - uses: actions/checkout@v7\n  second:\n    steps: []\n");
    let error = xtask::workflow::workflow_lint(&path)
        .unwrap_err()
        .to_string();
    for diagnostic in [
        "line 2:",
        "line 4: job first is missing runs-on",
        "line 6:",
        "line 7: job second is missing runs-on",
    ] {
        assert!(error.contains(diagnostic), "{error}");
    }
}
