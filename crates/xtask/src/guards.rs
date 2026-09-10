//! Validate repository files without shell parsing or text-decoding assumptions for source bytes.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{fs, path::Path, process::Command};
use walkdir::WalkDir;

const BASE: &str = "8ac40b023e0a49f55cdd5b599841ea46d0503ec9";

/// Read the unique pinned channel from the actual toolchain table.
pub fn toolchain_pin(root: &Path) -> Result<String> {
    let file = root.join("rust-toolchain.toml");
    if !file.is_file() {
        bail!("toolchain-pin: missing toolchain file");
    }
    let text = fs::read_to_string(file).context("toolchain-pin: unreadable toolchain file")?;
    let parsed = match text.parse::<toml::Value>() {
        Ok(value) => value,
        Err(error) => return Err(error).context("toolchain-pin: invalid toolchain file"),
    };
    let channel = parsed
        .get("toolchain")
        .and_then(|table| table.get("channel"))
        .and_then(toml::Value::as_str)
        .context("toolchain-pin: exactly one toolchain channel is required")?;
    if channel != "1.98.0" {
        bail!("toolchain-pin: channel must be 1.98.0");
    }
    Ok(channel.to_owned())
}

fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

/// Inspect every regular file, filename and link target in an already exported source tree.
pub fn no_developer_paths(root: &Path) -> Result<()> {
    if !root.is_dir() {
        bail!("no-developer-paths: missing source root");
    }
    let needle = [b"/".as_slice(), b"Users/"].concat();
    let mut failures = Vec::new();
    for entry in WalkDir::new(root).follow_links(false).min_depth(1) {
        let entry = entry.context("no-developer-paths: traversal failed")?;
        let relative = entry.path().strip_prefix(root)?;
        let relative_path_bytes =
            [b"/".as_slice(), relative.as_os_str().as_encoded_bytes()].concat();
        if contains(&relative_path_bytes, &needle) {
            failures.push(format!("developer filename in {relative:?}"));
        }
        if entry.file_type().is_symlink() {
            let target = fs::read_link(entry.path())?;
            let symlink_target_bytes = target.as_os_str().as_encoded_bytes();
            if contains(symlink_target_bytes, &needle) {
                failures.push(format!("developer symlink in {relative:?}"));
            }
        } else if entry.file_type().is_file() {
            let exempt = relative.parent().is_some_and(|parent| {
                parent.starts_with("crates/xtask/tests/fixtures/no-developer-paths")
            });
            let content = fs::read(entry.path()).context("no-developer-paths: unreadable file")?;
            if !exempt && contains(&content, &needle) {
                failures.push(format!("developer content in {relative:?}"));
            }
        }
    }
    if !failures.is_empty() {
        bail!(
            "no-developer-paths: {}",
            failures.join("\nno-developer-paths: ")
        );
    }
    println!("no-developer-paths: clean");
    Ok(())
}

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git").current_dir(root).args(args).output()?;
    if !output.status.success() {
        bail!(
            "check-notices: git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(output.stdout)
}

fn baseline(root: &Path, fixture: Option<&Path>, path: &str) -> Result<Vec<u8>> {
    match fixture {
        Some(directory) => Ok(fs::read(directory.join(path))?),
        None => git(root, &["show", &format!("{BASE}:{path}")]),
    }
}

fn leading(data: &[u8]) -> Vec<u8> {
    data.split_inclusive(|byte| *byte == b'\n')
        .take_while(|line| line.starts_with(b"//") && !line.starts_with(b"//!"))
        .flatten()
        .copied()
        .collect()
}

fn dated_statement(text: &str) -> bool {
    let prefix = "Modified for Agentic Search on ";
    let suffix =
        ": repository identity, build/CI,\nsource-offer support and sanitised research evidence.";
    text.match_indices(prefix).any(|(start, _)| {
        let rest = &text.as_bytes()[start + prefix.len()..];
        rest.len() >= 10
            && rest[10..].starts_with(suffix.as_bytes())
            && rest[..10].iter().enumerate().all(|(i, byte)| {
                if i == 4 || i == 7 {
                    *byte == b'-'
                } else {
                    byte.is_ascii_digit()
                }
            })
    })
}

/// Preserve provenance text, exact licence bytes, and upstream leading notice blocks.
pub fn check_notices(root: &Path, fixture_baseline: Option<&Path>) -> Result<()> {
    if !root.join("NOTICE").is_file() {
        bail!("check-notices: missing NOTICE");
    }
    let text = fs::read_to_string(root.join("NOTICE"))?;
    if !text
        .contains("Agentic Search is derived from Stract (https://github.com/StractOrg/stract).")
    {
        bail!("check-notices: missing derivation");
    }
    if !text.contains(BASE) {
        bail!("check-notices: missing upstream base");
    }
    if !dated_statement(&text) {
        bail!("check-notices: missing dated modification statement");
    }
    if !text.contains("The public git history records modified files and their relevant dates.") {
        bail!("check-notices: missing public history statement");
    }
    if fs::read(root.join("LICENSE.md"))? != baseline(root, fixture_baseline, "LICENSE.md")? {
        bail!("check-notices: LICENSE bytes changed");
    }
    let paths = if let Some(directory) = fixture_baseline {
        WalkDir::new(directory)
            .into_iter()
            .map(|entry| entry.map_err(anyhow::Error::from))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .filter(|entry| {
                entry.file_type().is_file()
                    && entry.path().extension().is_some_and(|ext| ext == "rs")
            })
            .map(|entry| {
                Ok(entry
                    .path()
                    .strip_prefix(directory)?
                    .to_str()
                    .context("non-UTF-8 notice path")?
                    .to_owned())
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        git(
            root,
            &[
                "diff",
                "--no-renames",
                "--diff-filter=MD",
                "--name-only",
                "-z",
                BASE,
                "--",
                "*.rs",
            ],
        )?
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| String::from_utf8(path.to_vec()).map_err(Into::into))
        .collect::<Result<Vec<_>>>()?
    };
    for path in paths {
        // Rustfmt leaves leading blocks unchanged; their post-fmt bytes equal the base.
        let expected = leading(&baseline(root, fixture_baseline, &path)?);
        let current = root.join(&path);
        if !current.is_file() || leading(&fs::read(&current)?) != expected {
            bail!("check-notices: upstream leading notice changed: {path}");
        }
    }
    println!("check-notices: provenance and upstream bytes preserved");
    Ok(())
}

/// Require a nonempty CycloneDX 1.5 dependency inventory for the service crate.
pub fn check_sbom(path: &Path) -> Result<()> {
    if !path.is_file() || path.metadata()?.len() == 0 {
        bail!("check-sbom: missing or empty BOM");
    }
    let bom: Value = match serde_json::from_slice(&fs::read(path)?) {
        Ok(value) => value,
        Err(_) => bail!("check-sbom: invalid JSON"),
    };
    if bom.get("bomFormat").and_then(Value::as_str) != Some("CycloneDX") {
        bail!("check-sbom: wrong format");
    }
    if bom.get("specVersion").and_then(Value::as_str) != Some("1.5") {
        bail!("check-sbom: wrong schema version");
    }
    if bom
        .pointer("/metadata/component/name")
        .and_then(Value::as_str)
        != Some("stract")
    {
        bail!("check-sbom: wrong service");
    }
    let components = bom.get("components").and_then(Value::as_array);
    if components.is_none_or(Vec::is_empty) {
        bail!("check-sbom: components must be a nonempty array");
    }
    println!("check-sbom: valid service CycloneDX 1.5 BOM");
    Ok(())
}
