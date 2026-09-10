//! Install the reviewed tool versions, verifying downloaded archive bytes before extraction.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::{env, fs, path::Path, process::Command};

/// Reject a downloaded archive unless its SHA-256 equals the published digest.
pub fn verify_archive(file: &Path, expected: &str) -> Result<()> {
    let actual = hex::encode(Sha256::digest(
        fs::read(file).context("install-tools: unreadable archive")?,
    ));
    if actual != expected {
        bail!("install-tools: archive checksum mismatch");
    }
    println!("install-tools: archive checksum verified");
    Ok(())
}

/// Install serially into an external directory, with a separate disposable build target.
pub fn install_tools(destination: &Path) -> Result<()> {
    let destination = crate::external_path(destination, &crate::repository_root())
        .context("install-tools: tool directory must be external")?;
    fs::create_dir_all(destination.join("bin"))?;
    let target = crate::Scratch::new("target-tools")?;
    for (name, version, features) in [
        ("wasm-pack", "0.15.0", None),
        // cargo-about exposes its executable only with the cli feature.
        ("cargo-about", "0.9.2", Some("cli")),
        ("cargo-cyclonedx", "0.5.9", None),
    ] {
        let mut command = Command::new("cargo");
        command
            .args(["install", "--locked", "--version", version, name, "--root"])
            .arg(&destination)
            .env("CARGO_TARGET_DIR", &target.0);
        if let Some(features) = features {
            command.args(["--features", features]);
        }
        crate::run(&mut command)?;
    }
    // Digests are from the v8.30.1 release checksums, independent of downloaded archive bytes.
    let (asset, digest) = match (env::consts::OS, env::consts::ARCH) {
        ("macos", "aarch64") => (
            "gitleaks_8.30.1_darwin_arm64.tar.gz",
            "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
        ),
        ("linux", "x86_64") => (
            "gitleaks_8.30.1_linux_x64.tar.gz",
            "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
        ),
        _ => bail!("install-tools: unsupported platform"),
    };
    let archive = destination.join(asset);
    crate::run(
        Command::new("curl")
            .args(["--fail", "--location", "--proto", "=https", "--tlsv1.2"])
            .arg(format!(
                "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/{asset}"
            ))
            .arg("-o")
            .arg(&archive),
    )?;
    verify_archive(&archive, digest)?;
    crate::run(
        Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(destination.join("bin"))
            .arg("gitleaks"),
    )?;
    let mut paths = vec![destination.join("bin")];
    paths.extend(env::split_paths(&env::var_os("PATH").unwrap_or_default()));
    let path = env::join_paths(paths)?;
    for (tool, args) in [
        ("wasm-pack", vec!["--version"]),
        ("cargo", vec!["about", "--version"]),
        ("cargo", vec!["cyclonedx", "--version"]),
        ("gitleaks", vec!["version"]),
    ] {
        crate::run(Command::new(tool).args(args).env("PATH", &path))?;
    }
    Ok(())
}
