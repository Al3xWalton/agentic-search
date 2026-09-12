//! Execute CI steps serially and keep runner setup out of shell entrypoints.

use anyhow::{bail, Context, Result};
use std::{
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

/// Enumerated inherited lints accepted only on untouched source by the strict diagnostic checker.
pub(crate) const INHERITED_LINTS: &[&str] = &[
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
    crate::workflow::workflow_lint(&root.join(".github/workflows/ci.yaml"))?;
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
    crate::ingestion::strict_clippy_touched(None)?;
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
    crate::workflow::workflow_lint(&root.join(".github/workflows/ci.yaml"))?;
    println!("{}", crate::guards::toolchain_pin(&root)?);
    no_developer_paths(None)?;
    crate::guards::check_notices(&root, None)?;
    cargo(
        &root,
        &["test", "--locked", "-p", "xtask", "--test", "guards"],
    )?;
    crate::ingestion::crawler_user_agent(&root)?;
    crate::ingestion::crawler_dependency_deny(&root)?;
    crate::ingestion::crawler_policy_check(&root.join("CRAWLER_POLICY.md"))?;
    cargo(
        &root,
        &[
            "test",
            "--locked",
            "-p",
            "xtask",
            "--test",
            "ingestion_guards",
        ],
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

fn validate_export(name: &str, value: &Path) -> Result<()> {
    let bytes = value.as_os_str().as_encoded_bytes();
    // A newline in a command-file value injects variables into later steps.
    if bytes.iter().any(|byte| *byte < 0x20 || *byte == 0x7f) {
        bail!("ci-init: {name} contains control bytes");
    }
    if bytes.is_empty() || !value.is_absolute() {
        bail!("ci-init: {name} must be a non-empty absolute path");
    }
    Ok(())
}

/// an exported path is accepted only if (1) it is absolute; (2) after the root every
/// `std::path::Component` is `Normal` — any `CurDir`, `ParentDir`, `Prefix` or `RootDir` after
/// the first is rejected before anything else is examined; (3) walking from the path upward, the
/// nearest **existing** ancestor canonicalises to a directory that is neither the repository root
/// nor inside it; (4) every existing component from that ancestor down to the path is not a
/// symlink (`symlink_metadata`); (5) after `create_dir_all`, the created directory canonicalises
/// to a location satisfying (3). Because (2) forbids `..` and (4) forbids symlinks among existing
/// components, creating the missing tail below a verified-outside ancestor cannot enter the
/// repository. **Out of scope, stated in the doc:** a symlink inserted into the external ancestor
/// between the check and the creation — whoever can do that owns the runner's temp directory and
/// therefore the runner.
fn checked_external(name: &str, value: &Path, root: &Path) -> Result<PathBuf> {
    validate_export(name, value)?;
    let path = crate::external_path(value, root)
        .map_err(|_| anyhow::anyhow!("ci-init: {name} must point outside the repository"))?;
    validate_export(name, &path)?;
    Ok(path)
}

fn checked_created(name: &str, value: &Path, root: &Path) -> Result<PathBuf> {
    let created = value
        .canonicalize()
        .map_err(|_| anyhow::anyhow!("ci-init: cannot canonicalize {name} after creation"))?;
    checked_external(name, &created, root)
}

/// Initialize directory exports with explicit environment inputs for isolated command-file fixtures.
pub fn ci_init_exports(root: &Path, environment: impl Fn(&str) -> Option<OsString>) -> Result<()> {
    let required = |name| environment(name).with_context(|| format!("ci-init: missing {name}"));
    let command_file = |name| -> Result<PathBuf> {
        let value = required(name)?;
        checked_external(name, Path::new(&value), root)
    };
    let env_file = command_file("GITHUB_ENV")?;
    let path_file = command_file("GITHUB_PATH")?;
    // Workflow/job env has no runner context; derive paths after the step starts.
    let names = [
        ("STORY584_SCRATCH", "story584-scratch"),
        ("STORY584_TOOLS", "story584-tools"),
        ("STORY584_ARTIFACT_DIR", "story584-artifacts"),
    ];
    let mut directories = if let Some(runner_temp) = environment("RUNNER_TEMP") {
        let runner_temp = checked_external("RUNNER_TEMP", Path::new(&runner_temp), root)?;
        names.map(|(_, suffix)| runner_temp.join(suffix))
    } else {
        let directory = |name| {
            let path = required(name).context(
                "ci-init: RUNNER_TEMP or all STORY584_SCRATCH/STORY584_TOOLS/STORY584_ARTIFACT_DIR must be set",
            )?;
            checked_external(name, Path::new(&path), root)
        };
        [
            directory(names[0].0)?,
            directory(names[1].0)?,
            directory(names[2].0)?,
        ]
    };
    for ((name, _), directory) in names.iter().zip(&mut directories) {
        *directory = checked_external(name, directory, root)?;
    }
    let mut cache = checked_external(
        "WASM_PACK_CACHE",
        &directories[0].join("wasm-pack-cache"),
        root,
    )?;
    let mut tools_bin = checked_external("STORY584_TOOLS/bin", &directories[1].join("bin"), root)?;
    for (name, directory) in names
        .iter()
        .zip(&mut directories)
        .map(|((name, _), path)| (*name, path))
        .chain([
            ("WASM_PACK_CACHE", &mut cache),
            ("STORY584_TOOLS/bin", &mut tools_bin),
        ])
    {
        fs::create_dir_all(&*directory).with_context(|| format!("ci-init: create {name}"))?;
        *directory = checked_created(name, directory, root)?;
    }
    let target = crate::scratch_directory_in(&directories[0], "target")
        .context("ci-init: create CARGO_TARGET_DIR")?;
    let target = checked_created("CARGO_TARGET_DIR", &target, root)?;
    let mut exports: Vec<_> = names
        .iter()
        .zip(&directories)
        .map(|((name, _), path)| (*name, path))
        .collect();
    exports.extend([("WASM_PACK_CACHE", &cache), ("CARGO_TARGET_DIR", &target)]);
    for (name, value) in &exports {
        validate_export(name, value)?;
    }
    validate_export("STORY584_TOOLS/bin", &tools_bin)?;
    let mut env_file = OpenOptions::new().append(true).open(env_file)?;
    let mut path_file = OpenOptions::new().append(true).open(path_file)?;
    for (name, value) in exports {
        writeln!(env_file, "{name}={}", value.display())?;
    }
    writeln!(path_file, "{}", tools_bin.display())?;
    Ok(())
}

/// Initialize hosted runner directories and toolchain with only a Cargo call in workflow shell.
pub fn ci_init(no_toolchain: bool) -> Result<()> {
    ci_init_exports(&crate::repository_root(), |name| env::var_os(name))?;
    if no_toolchain {
        return Ok(());
    }
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
