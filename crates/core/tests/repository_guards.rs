//! Runs the actual repository guards on disposable fixtures, including ignored bytes and failures.
//! No fixture downloads data, changes the supplied repositories, or invokes Cargo recursively.

#![deny(missing_docs)]

use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output},
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
    fn guard(&self, name: &str) -> Output {
        self.run(name, &["--root", self.0.to_str().unwrap()])
    }
    fn run(&self, name: &str, args: &[&str]) -> Output {
        Command::new(script(name))
            .args(args)
            .env("VERIFICATION", self.0.join("reports"))
            .output()
            .unwrap()
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

fn script(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/ci")
        .join(name)
}
fn accepts(output: Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn rejects(output: Output) {
    assert!(!output.status.success(), "guard accepted invalid fixture");
    assert!(!output.stderr.is_empty(), "missing diagnostic");
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
        "scripts/ci/fixtures/no-developer-paths/forbidden.txt",
        forbidden(),
    );
    accepts(fixture.guard("no-developer-paths"));
    for name in [
        "scripts/ci/fixtures-evil/bad",
        "nested/scripts/ci/fixtures/no-developer-paths/bad",
        "scripts/ci/fixtures/no-developer-paths-evil/bad",
    ] {
        fixture.write(name, forbidden());
        rejects(fixture.guard("no-developer-paths"));
        fs::remove_file(fixture.0.join(name)).unwrap();
    }
    symlink(
        String::from_utf8(forbidden()).unwrap(),
        fixture
            .0
            .join("scripts/ci/fixtures/no-developer-paths/link"),
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
    fixture.write(
        "scanner",
        "#!/bin/sh\necho 'harmless scanner fixture' >&2\nexit 1\n",
    );
    let scanner = fixture.0.join("scanner");
    fs::set_permissions(&scanner, fs::Permissions::from_mode(0o755)).unwrap();
    let args = [
        "--root",
        fixture.0.to_str().unwrap(),
        "--scanner",
        scanner.to_str().unwrap(),
    ];
    let output = fixture.run("secrets", &args);
    assert_eq!(output.status.code(), Some(1));
    fixture.write("scanner", "#!/bin/sh\nexit 0\n");
    accepts(fixture.run("secrets", &args));
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
    fixture.write("bin/git", "#!/bin/sh\ncase \"$*\" in *--show-toplevel*) printf '%s\\n' \"$FIXTURE_ROOT\";; *) echo 'enumeration fixture failure' >&2; exit 1;; esac\n");
    fs::set_permissions(fixture.0.join("bin/git"), fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(script("source-tree"))
        .args([
            "--root",
            failing_root.to_str().unwrap(),
            dest.to_str().unwrap(),
        ])
        .env("FIXTURE_ROOT", &failing_root)
        .env(
            "PATH",
            format!(
                "{}:{}",
                fixture.0.join("bin").display(),
                std::env::var("PATH").unwrap()
            ),
        )
        .output()
        .unwrap();
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
