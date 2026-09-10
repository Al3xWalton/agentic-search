//! Resolves build identity from an owned Git root or an explicitly identified archive.
//! Metadata failures yield unknown identity; command arguments never contain environment input.
//!
//! Source metadata is the builder's self-attestation, preventing accidental misattribution
//! from nested archives, dirty or moved worktrees, symlinked Git metadata or checked inputs,
//! and foreign history missing the build inputs. A builder deliberately tracking identical
//! inputs can also edit the constants or binary; defeating that builder is out of scope.
//! Forks must set their package repository and SOURCE_OFFER.md to their corresponding source.

#![deny(missing_docs)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Validated build revision and its provenance, with no host information.
#[derive(Debug, PartialEq, Eq)]
pub struct Revision {
    /// Lowercase full SHA-1, or the literal unknown.
    pub revision: String,
    /// One of git, environment, or unknown.
    pub source: &'static str,
}

/// Validates exactly forty ASCII hex characters without trimming input.
pub fn valid_sha(value: &str) -> Option<String> {
    (value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

fn unknown() -> Revision {
    Revision {
        revision: "unknown".to_owned(),
        source: "unknown",
    }
}

fn git(root: &Path, args: &[&str]) -> Option<Output> {
    Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .ok()
}

fn stdout(output: Option<Output>) -> Option<String> {
    let output = output.filter(|output| output.status.success())?;
    let text = String::from_utf8(output.stdout).ok()?;
    Some(text.strip_suffix('\n').unwrap_or(&text).to_owned())
}

/// Resolves metadata using fixed Git subprocess arguments and an optional archive SHA.
pub fn resolve(root: &Path, environment: Option<&str>) -> Revision {
    resolve_with(root, environment, |args| git(root, args))
}

/// Applies the same resolver to command outcomes supplied by an offline fixture.
/// The callback is never invoked for a root without its own Git metadata.
pub fn resolve_with(
    root: &Path,
    environment: Option<&str>,
    mut command: impl FnMut(&[&str]) -> Option<Output>,
) -> Revision {
    // A symlinked .git can attribute this source tree to another repository.
    if std::fs::symlink_metadata(root.join(".git"))
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return unknown();
    }
    if !root.join(".git").exists() {
        return environment
            .and_then(valid_sha)
            .map_or_else(unknown, |revision| Revision {
                revision,
                source: "environment",
            });
    }
    let Some(top) = stdout(command(&["rev-parse", "--show-toplevel"])) else {
        return unknown();
    };
    if Path::new(&top).canonicalize().ok() != root.canonicalize().ok() {
        return unknown();
    }
    let Some(head) = stdout(command(&["rev-parse", "--verify", "HEAD"])) else {
        return unknown();
    };
    let Some(status) = command(&["status", "--porcelain=v1", "--untracked-files=normal"])
        .filter(|output| output.status.success())
    else {
        return unknown();
    };
    if !status.stdout.is_empty() {
        return unknown();
    }
    // A foreign repository can ignore this whole tree and still report clean status.
    // Its HEAD must also contain the blobs used to build the source offer.
    for (committed, input) in [
        ("HEAD:Cargo.toml", "Cargo.toml"),
        ("HEAD:Cargo.lock", "Cargo.lock"),
        ("HEAD:crates/core/Cargo.toml", "crates/core/Cargo.toml"),
        ("HEAD:crates/core/build.rs", "crates/core/build.rs"),
        (
            "HEAD:crates/core/build_support/revision.rs",
            "crates/core/build_support/revision.rs",
        ),
    ] {
        // Git hashes a committed symlink's link text, while hash-object follows it.
        // Equal hashes can therefore hide uncommitted bytes behind a symlinked input.
        if !std::fs::symlink_metadata(root.join(input))
            .is_ok_and(|metadata| metadata.file_type().is_file())
        {
            return unknown();
        }
        let Some(expected) = stdout(command(&["rev-parse", "--verify", "--quiet", committed]))
        else {
            return unknown();
        };
        let Some(actual) = stdout(command(&["hash-object", "--", input])) else {
            return unknown();
        };
        if expected != actual {
            return unknown();
        }
    }
    valid_sha(&head).map_or_else(unknown, |revision| Revision {
        revision,
        source: "git",
    })
}

fn git_path(root: &Path, name: &str) -> Option<PathBuf> {
    let path = PathBuf::from(stdout(git(root, &["rev-parse", "--git-path", name]))?);
    let path = if path.is_absolute() {
        path
    } else {
        root.join(path)
    };
    watch_directive(&path)?;
    Some(path)
}

fn watch_directive(path: &Path) -> Option<String> {
    if path
        .as_os_str()
        .as_encoded_bytes()
        .iter()
        .any(|byte| *byte < 0x20 || *byte == 0x7f)
    {
        return None;
    }
    Some(format!("cargo:rerun-if-changed={}", path.display()))
}

fn watch(path: &Path) {
    match watch_directive(path) {
        Some(directive) => println!("{directive}"),
        None => println!("cargo:warning=Skipped a rebuild watch: path contains control characters"),
    }
}

/// Emits rebuild inputs for environment, source edits, staging and Git ref movement.
/// Worktree ref paths come from Git so common-directory metadata is also watched.
pub fn emit_watches(root: &Path) {
    println!("cargo:rerun-if-env-changed=SOURCE_REVISION");
    watch(&root.join(".git"));
    watch(&root.join("crates/core/build.rs"));
    watch(&root.join("crates/core/build_support"));
    for source in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "crates",
        "fuzz",
        "scripts",
        ".github",
        ".spike",
        ".gitmodules",
        "SOURCE_OFFER.md",
        "NOTICE",
        "README.md",
    ] {
        watch(&root.join(source));
    }
    if root.join(".git").exists() {
        for name in ["commondir", "config"] {
            if let Some(path) = git_path(root, name) {
                watch(&path);
            }
        }
        if let Some(path) = git_path(root, "HEAD") {
            watch(&path);
        }
        if let Some(path) = git_path(root, "index") {
            watch(&path);
        }
        if let Some(path) = git_path(root, "packed-refs") {
            watch(&path);
        }
        if let Some(branch) = stdout(git(root, &["symbolic-ref", "-q", "HEAD"])) {
            if let Some(path) = git_path(root, &branch) {
                watch(&path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_rejects_control_characters() {
        for byte in (0..0x20).chain(std::iter::once(0x7f)) {
            let path = format!("source{}cargo:rustc-env=INJECTED=yes", char::from(byte));
            assert_eq!(watch_directive(Path::new(&path)), None, "byte {byte}");
        }
    }

    #[test]
    fn watch_emits_plain_paths() {
        for path in ["/source/.git", "source with spaces/config", "source/é"] {
            assert_eq!(
                watch_directive(Path::new(path)),
                Some(format!("cargo:rerun-if-changed={path}"))
            );
        }
    }
}
