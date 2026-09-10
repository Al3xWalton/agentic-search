//! Produce compliance artifacts from source projections and propagate scanner failures.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::Path,
    process::{Command, ExitStatus},
};

/// Generate and collect every member BOM, retaining the service BOM as the canonical artifact.
pub fn sbom() -> Result<()> {
    let container = crate::Scratch::new("sbom")?;
    let root = container.0.join("source");
    crate::source_tree::source_tree(&crate::repository_root(), &root)?;
    let artifacts = crate::external_env("STORY584_ARTIFACT_DIR")?;
    fs::create_dir_all(artifacts.join("members"))?;
    let lock = fs::read(root.join("Cargo.lock"))?;
    println!("Cargo.lock SHA256 {}", hex::encode(Sha256::digest(&lock)));
    let metadata = fs::File::create(container.0.join("metadata.json"))?;
    crate::run(
        Command::new("cargo")
            .current_dir(&root)
            .args(["metadata", "--locked", "--format-version", "1"])
            .stdout(metadata),
    )?;
    // The pinned tool defaults to crate-name.cdx.json; request the contract filename explicitly.
    crate::run(
        Command::new("cargo")
            .current_dir(&root)
            .env("CARGO_NET_OFFLINE", "true")
            .args([
                "cyclonedx",
                "--format",
                "json",
                "--spec-version",
                "1.5",
                "--all",
                "--target",
                "all",
                "--override-filename",
                "bom",
            ]),
    )?;
    if fs::read(root.join("Cargo.lock"))? != lock {
        bail!("sbom: Cargo.lock changed");
    }
    let metadata: Value = serde_json::from_slice(&fs::read(container.0.join("metadata.json"))?)?;
    let members = metadata["workspace_members"]
        .as_array()
        .context("sbom: missing workspace members")?;
    let packages = metadata["packages"]
        .as_array()
        .context("sbom: missing packages")?;
    for package in packages
        .iter()
        .filter(|package| members.contains(&package["id"]))
    {
        let manifest = Path::new(
            package["manifest_path"]
                .as_str()
                .context("sbom: missing manifest path")?,
        );
        let bom = manifest
            .parent()
            .context("sbom: missing manifest directory")?
            .join("bom.json");
        if !bom.is_file() {
            bail!(
                "sbom: missing member BOM {}",
                manifest.strip_prefix(&root)?.display()
            );
        }
        let relative = bom.strip_prefix(&root)?;
        let destination = artifacts.join("members").join(relative);
        fs::create_dir_all(
            destination
                .parent()
                .context("sbom: missing artifact parent")?,
        )?;
        fs::copy(&bom, destination)?;
        println!("sbom: collected {}", relative.display());
    }
    fs::copy(
        root.join("crates/core/bom.json"),
        artifacts.join("sbom.json"),
    )?;
    crate::guards::check_sbom(&artifacts.join("sbom.json"))
}

/// Render the reviewed licence policy and require a nonempty result.
pub fn licenses() -> Result<()> {
    let artifacts = crate::external_env("STORY584_ARTIFACT_DIR")?;
    fs::create_dir_all(&artifacts)?;
    let output = artifacts.join("licenses.html");
    crate::run(
        Command::new("cargo")
            .current_dir(crate::repository_root())
            .args([
                "about",
                "generate",
                "--fail",
                "-c",
                "scripts/licenses/licenses.toml",
                "scripts/licenses/template.hbs",
            ])
            .stdout(fs::File::create(&output)?),
    )?;
    if output.metadata()?.len() == 0 {
        bail!("licenses: empty licence report");
    }
    Ok(())
}

/// Scan a fixture root directly, or project the repository before both source scans.
pub fn secrets(root: Option<&Path>, scanner: Option<&Path>) -> Result<()> {
    let container = crate::Scratch::new("secrets")?;
    let projection = container.0.join("source");
    let root = match root {
        Some(root) => root,
        None => {
            crate::source_tree::source_tree(&crate::repository_root(), &projection)?;
            &projection
        }
    };
    let default_scanner;
    let scanner = match scanner {
        Some(scanner) => scanner,
        None => {
            default_scanner = crate::external_env("STORY584_TOOLS")?.join("bin/gitleaks");
            &default_scanner
        }
    };
    let reports = if std::env::var_os("VERIFICATION").is_some() {
        crate::external_env("VERIFICATION")?
    } else {
        crate::external_env("STORY584_ARTIFACT_DIR")?
    };
    secrets_with(root, scanner, &reports, &container.0, |command| {
        Ok(command.status()?)
    })
}

/// Exercise scanner exit propagation and invocation arguments without a shell fixture.
pub fn secrets_with(
    root: &Path,
    scanner: &Path,
    reports: &Path,
    scratch: &Path,
    mut scan: impl FnMut(&mut Command) -> Result<ExitStatus>,
) -> Result<()> {
    fs::create_dir_all(reports)?;
    let scanner = scanner.canonicalize().context("secrets: missing scanner")?;
    let root = root.canonicalize()?;
    let reports = reports.canonicalize()?;
    let mut status = 0;
    for (source, report, use_config) in [
        (
            root.join(".spike"),
            reports.join("gitleaks-spike.json"),
            false,
        ),
        (root.clone(), reports.join("gitleaks-tree.json"), true),
    ] {
        if !use_config && !source.is_dir() {
            println!("secrets: evidence subtree absent before evidence import");
            continue;
        }
        let mut command = Command::new(&scanner);
        // Evidence uses default rules; only the whole-tree scan applies reviewed fixture paths.
        command
            .current_dir(scratch)
            .env_remove("GITLEAKS_CONFIG")
            .env_remove("GITLEAKS_CONFIG_TOML")
            .arg("dir")
            .arg(source)
            .args([
                "--redact",
                "--no-banner",
                "--ignore-gitleaks-allow",
                "--report-format",
                "json",
                "--report-path",
            ])
            .arg(report);
        if use_config {
            command.arg("--config").arg(root.join(".gitleaks.toml"));
        }
        let result = scan(&mut command)?;
        if !result.success() {
            status = result.code().unwrap_or(1);
        }
    }
    if status != 0 {
        return Err(crate::CommandFailure {
            code: status,
            label: "secrets: scanner".to_owned(),
        }
        .into());
    }
    crate::guards::no_developer_paths(&root)
}
