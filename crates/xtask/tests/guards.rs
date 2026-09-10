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
