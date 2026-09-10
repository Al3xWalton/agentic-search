//! Execute CI steps serially and keep runner setup out of shell entrypoints.

use anyhow::{Context, Result};
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    process::Command,
};

const INHERITED_LINTS: &[&str] = &[
    // 2 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::chunks_exact_to_as_chunks",
    // 1 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::cloned_ref_to_slice_refs",
    // 23 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::doc_overindented_list_items",
    // 7 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::double_ended_iterator_last",
    // 1 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::drain_collect",
    // 10 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::io_other_error",
    // 1 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::large_enum_variant",
    // 1 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::len_zero",
    // 1 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::manual_checked_ops",
    // 1 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::manual_clear",
    // 7 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::manual_div_ceil",
    // 1 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::manual_is_multiple_of",
    // 4 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::manual_repeat_n",
    // 1 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::manual_saturating_arithmetic",
    // 2 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::needless_borrows_for_generic_args",
    // 1 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::neg_multiply",
    // 1 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::question_mark",
    // 1 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::redundant_pattern_matching",
    // 1 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::repr_packed_without_abi",
    // 3 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::result_large_err",
    // 1 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::unbuffered_bytes",
    // 11 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::unnecessary_sort_by",
    // 3 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::useless_borrows_in_formatting",
    // 1 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::useless_conversion",
    // 1 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::useless_format",
    // 1 inherited files; upstream clippy repair — orchestrator files the Story.
    "clippy::vec_init_then_push",
    // 5 inherited files; upstream clippy repair — orchestrator files the Story.
    "dead_code",
    // 2 inherited files; upstream clippy repair — orchestrator files the Story.
    "mismatched_lifetime_syntaxes",
    // 1 inherited files; upstream clippy repair — orchestrator files the Story.
    "unused_imports",
    // 2 inherited files; upstream clippy repair — orchestrator files the Story.
    "unused_parens",
];

fn cargo(root: &Path, args: &[&str]) -> Result<()> {
    crate::run(Command::new("cargo").current_dir(root).args(args))
}

/// Check native feature modes, inherited lint policy, WASM, and the unchanged frontend.
pub fn check() -> Result<()> {
    let root = crate::repository_root();
    cargo(&root, &["fmt", "--check"])?;
    for args in [
        vec!["check", "--locked"],
        vec!["check", "--locked", "--no-default-features"],
        vec!["check", "--locked", "--all-features"],
        vec!["check", "--locked", "--features", "dev"],
    ] {
        cargo(&root, &args)?;
    }
    let mut args = vec![
        "clippy",
        "--locked",
        "--workspace",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ];
    for lint in INHERITED_LINTS {
        args.extend(["-A", lint]);
    }
    cargo(&root, &args)?;
    // The inherited allowance never masks warnings introduced into the tooling crate.
    cargo(
        &root,
        &[
            "clippy",
            "--locked",
            "-p",
            "xtask",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    crate::run(
        Command::new("wasm-pack")
            .current_dir(root.join("crates/client-wasm"))
            .args(["build", "--target", "web", "--locked"]),
    )?;
    for args in [vec!["ci"], vec!["run", "check"], vec!["run", "lint"]] {
        crate::run(
            Command::new("npm")
                .current_dir(root.join("frontend"))
                .args(args),
        )?;
    }
    Ok(())
}

/// Run the embedded source-offer contract and actual build-entrypoint witnesses.
pub fn source_offer() -> Result<()> {
    let root = crate::repository_root();
    cargo(
        &root,
        &[
            "test",
            "--locked",
            "-p",
            "stract",
            "--lib",
            "source_offer_consistency",
            "--",
            "--nocapture",
        ],
    )?;
    cargo(
        &root,
        &[
            "test",
            "--locked",
            "-p",
            "stract",
            "--test",
            "build_revision_contract",
        ],
    )
}

/// Scan an explicit fixture directory, or a fresh source projection for the actual repository.
pub fn no_developer_paths(root: Option<&Path>) -> Result<()> {
    if let Some(root) = root {
        return crate::guards::no_developer_paths(root);
    }
    let scratch = crate::Scratch::new("paths")?;
    let source = scratch.0.join("source");
    crate::source_tree::source_tree(&crate::repository_root(), &source)?;
    crate::guards::no_developer_paths(&source)
}

/// Run the original CI order, stopping at the first failing command.
pub fn ci_all() -> Result<()> {
    let root = crate::repository_root();
    println!("{}", crate::guards::toolchain_pin(&root)?);
    no_developer_paths(None)?;
    crate::guards::check_notices(&root, None)?;
    cargo(
        &root,
        &["test", "--locked", "-p", "xtask", "--test", "guards"],
    )?;
    source_offer()?;
    check()?;
    cargo(&root, &["build", "--locked", "--release"])?;
    cargo(&root, &["test", "--locked", "--workspace"])?;
    crate::artifacts::licenses()?;
    crate::artifacts::sbom()?;
    crate::guards::check_sbom(&crate::external_env("STORY584_ARTIFACT_DIR")?.join("sbom.json"))?;
    crate::artifacts::secrets(None, None)
}

fn append_env(name: &str, value: &Path) -> Result<()> {
    let file = env::var_os("GITHUB_ENV").context("ci-init: missing GITHUB_ENV")?;
    writeln!(
        OpenOptions::new().append(true).open(file)?,
        "{name}={}",
        value.display()
    )?;
    Ok(())
}

/// Initialize hosted runner directories and toolchain with only a Cargo call in workflow shell.
pub fn ci_init() -> Result<()> {
    let channel = crate::guards::toolchain_pin(&crate::repository_root())?;
    crate::run(Command::new("rustup").args([
        "toolchain",
        "install",
        &channel,
        "--profile",
        "minimal",
        "--component",
        "rustfmt",
        "--component",
        "clippy",
        "--target",
        "wasm32-unknown-unknown",
    ]))?;
    for name in [
        "STORY584_SCRATCH",
        "STORY584_TOOLS",
        "STORY584_ARTIFACT_DIR",
    ] {
        let directory = crate::external_env(name)?;
        fs::create_dir_all(&directory)?;
    }
    append_env("CARGO_TARGET_DIR", &crate::scratch_directory("target")?)?;
    let path_file = env::var_os("GITHUB_PATH").context("ci-init: missing GITHUB_PATH")?;
    writeln!(
        OpenOptions::new().append(true).open(path_file)?,
        "{}",
        crate::external_env("STORY584_TOOLS")?.join("bin").display()
    )?;
    crate::run(Command::new("rustc").args(["--version", "--verbose"]))?;
    crate::run(Command::new("cargo").arg("--version"))?;
    if env::consts::OS == "macos" {
        crate::run(Command::new("xcodebuild").arg("-version"))?;
        crate::run(Command::new("clang").arg("--version"))?;
    }
    println!(
        "ImageOS={} ImageVersion={}",
        env::var("ImageOS").unwrap_or_default(),
        env::var("ImageVersion").unwrap_or_default()
    );
    Ok(())
}

/// Install the same Linux native prerequisites used by the existing workflow.
pub fn native_deps() -> Result<()> {
    crate::run(Command::new("sudo").args(["apt-get", "update"]))?;
    crate::run(Command::new("sudo").args([
        "apt-get",
        "install",
        "-y",
        "build-essential",
        "clang",
        "pkg-config",
        "libssl-dev",
        "liburing-dev",
    ]))?;
    crate::run(Command::new("clang").arg("--version"))
}

/// Record the frontend runtime versions supplied by setup-node.
pub fn node_versions() -> Result<()> {
    crate::run(Command::new("node").arg("--version"))?;
    crate::run(Command::new("npm").arg("--version"))
}
