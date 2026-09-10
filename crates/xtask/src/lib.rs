//! Repository verification and tool installation, shared by the CLI and fixture tests.

#![deny(missing_docs)]

/// Artifact generation and secret-scanner orchestration.
pub mod artifacts;
/// Serial CI commands and runner initialization.
pub mod ci;
/// Pure file guards used by CI and disposable fixtures.
pub mod guards;
/// Pinned tool installation and archive verification.
pub mod install;
/// NUL-safe export of the current repository and initialized submodules.
pub mod source_tree;
/// Workflow context, action pin and runner checks.
pub mod workflow;

use anyhow::{bail, Context, Result};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// A child command's exit status, retained across contextual diagnostics.
#[derive(Debug)]
pub struct CommandFailure {
    /// Exit status to propagate to the caller.
    pub code: i32,
    /// Command or guard responsible for the failure.
    pub label: String,
}

impl std::fmt::Display for CommandFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: exited {}", self.label, self.code)
    }
}
impl std::error::Error for CommandFailure {}

/// Preserve child exit codes; file and validation errors exit with status one.
pub fn exit_code(error: &anyhow::Error) -> i32 {
    error.downcast_ref::<CommandFailure>().map_or(1, |e| e.code)
}

/// Run one subprocess to completion before starting the next command.
pub fn run(command: &mut Command) -> Result<()> {
    println!("xtask: {command:?}");
    let status = command.status().context("could not start command")?;
    if !status.success() {
        return Err(CommandFailure {
            code: status.code().unwrap_or(1),
            label: format!("{command:?}"),
        }
        .into());
    }
    Ok(())
}

/// Locate the source root of this workspace.
pub fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Require an explicitly configured directory outside the repository.
pub fn external_env(name: &str) -> Result<PathBuf> {
    let path = env::var_os(name).with_context(|| format!("{name}: external directory required"))?;
    external_path(Path::new(&path), &repository_root())
}

/// Resolve a new or existing path through its nearest existing ancestor.
pub fn resolved_path(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return path.canonicalize().context("cannot resolve path");
    }
    let absolute = std::path::absolute(path)?;
    let parent = absolute.parent().context("path has no parent")?;
    let name = absolute.file_name().context("path has no filename")?;
    Ok(resolved_path(parent)?.join(name))
}

/// Reject output directories within the source tree, including symlink aliases.
pub fn external_path(path: &Path, root: &Path) -> Result<PathBuf> {
    let path = resolved_path(path)?;
    if path.starts_with(root.canonicalize()?) {
        bail!("output directory must be external");
    }
    Ok(path)
}

/// Create a uniquely named directory under the external scratch root.
pub fn scratch_directory(prefix: &str) -> Result<PathBuf> {
    let scratch = external_env("STORY584_SCRATCH")?;
    scratch_directory_in(&scratch, prefix)
}

/// Allocate within a validated scratch root before runner environment exports take effect.
pub(crate) fn scratch_directory_in(scratch: &Path, prefix: &str) -> Result<PathBuf> {
    fs::create_dir_all(scratch)?;
    loop {
        let path = scratch.join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

/// Own a disposable directory created by this process.
pub struct Scratch(pub PathBuf);
impl Scratch {
    /// Allocate an external directory that is removed when the task finishes.
    pub fn new(prefix: &str) -> Result<Self> {
        Ok(Self(scratch_directory(prefix)?))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
