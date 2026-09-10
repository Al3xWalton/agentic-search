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
    path::{Component, Path, PathBuf},
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

/// Require absolute, plain components before resolving the ancestor and checking the tail.
pub fn resolved_path(path: &Path) -> Result<PathBuf> {
    let mut components = path.components();
    // Components hides internal `.` segments, so the raw names must be checked too.
    if !path.is_absolute()
        || components.next() != Some(Component::RootDir)
        || components.any(|component| !matches!(component, Component::Normal(_)))
        || path
            .as_os_str()
            .as_encoded_bytes()
            .split(|byte| *byte == b'/')
            .any(|name| name == b".")
    {
        bail!("output path must be absolute with only normal components");
    }
    let mut ancestor = path;
    let mut tail = Vec::new();
    let mut resolved = loop {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                // Path::exists hides dangling links, whose future targets can be in-tree.
                if metadata.file_type().is_symlink() {
                    bail!("output path contains a symlink");
                }
                break ancestor.canonicalize().context("cannot resolve ancestor")?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tail.push(ancestor.file_name().context("path has no filename")?);
                ancestor = ancestor.parent().context("path has no parent")?;
            }
            Err(error) => return Err(error).context("cannot inspect output path"),
        }
    };
    for component in tail.into_iter().rev() {
        resolved.push(component);
        match fs::symlink_metadata(&resolved) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!("output path contains a symlink");
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("cannot inspect output component"),
        }
    }
    Ok(resolved)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn checked_external_rejects_dangling_symlink() {
        let fixture = Scratch::new("containment-test").unwrap();
        let root = fixture.0.join("repository");
        fs::create_dir(&root).unwrap();
        let target = root.join("not-created");
        let alias = fixture.0.join("alias");
        symlink(&target, &alias).unwrap();
        assert!(!alias.exists());
        assert!(fs::symlink_metadata(&alias)
            .unwrap()
            .file_type()
            .is_symlink());
        for path in [&alias, &alias.join("child"), &alias.join("child/deeper")] {
            assert!(
                external_path(path, &root).is_err(),
                "accepted dangling link: {path:?}"
            );
        }
        assert!(!target.exists());
        assert!(external_path(&root, &root).is_err());
        assert!(external_path(&root.join("missing"), &root).is_err());
        let outside = fixture.0.join("outside/child");
        assert_eq!(external_path(&outside, &root).unwrap(), outside);
        fs::create_dir(fixture.0.join("outside")).unwrap();
        fs::remove_file(&alias).unwrap();
        symlink(fixture.0.join("outside"), &alias).unwrap();
        assert!(external_path(&alias, &root).is_err());
        assert!(external_path(&alias.join("missing"), &root).is_err());
    }

    #[test]
    fn checked_external_rejects_parent_and_current_components() {
        let fixture = Scratch::new("components-test").unwrap();
        let missing = fixture.0.join("nonexistent");
        let root = missing.join("repository");
        for suffix in [
            "tmp/x/../y",
            "tmp/./y",
            "tmp/x/../../repo/z",
            "tmp/y/.",
            "tmp/y/..",
        ] {
            let path = missing.join(suffix);
            let error = format!("{:#}", external_path(&path, &root).unwrap_err());
            assert_eq!(
                error, "output path must be absolute with only normal components",
                "wrong rejection for {path:?}"
            );
        }
        for path in [
            Path::new(""),
            Path::new("relative"),
            Path::new("./relative"),
        ] {
            assert_eq!(
                format!("{:#}", external_path(path, &root).unwrap_err()),
                "output path must be absolute with only normal components"
            );
        }
        let error = format!(
            "{:#}",
            external_path(&missing.join("plain/child"), &root).unwrap_err()
        );
        assert_ne!(
            error,
            "output path must be absolute with only normal components"
        );
        assert!(!missing.exists());
    }
}
