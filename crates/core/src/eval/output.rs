// SPDX-License-Identifier: AGPL-3.0-only
//! Reserve private, create-new evaluator outputs before any request is sent.
//! Existing paths, symlinks and unsafe ancestors are rejected; partial runs remain for audit.
//! This writer never truncates a file, retries under another name or creates product data.

use super::{input, Argument, ArgumentReason, EvalError};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

fn parents(path: &Path) -> Result<PathBuf, EvalError> {
    parents_after_creation(path, |_| {})
}

fn parents_after_creation(
    path: &Path,
    after_creation: impl FnOnce(&Path),
) -> Result<PathBuf, EvalError> {
    let path = input::inspect_path(path, true)?;
    let parent = path.parent().ok_or(EvalError::UnsafePath)?;
    let mut prefix = PathBuf::new();
    for component in parent.components() {
        prefix.push(component);
        if fs::symlink_metadata(&prefix).is_err() {
            DirBuilder::new()
                .mode(0o700)
                .create(&prefix)
                .map_err(|_| EvalError::Io)?;
        }
    }
    after_creation(parent);
    input::inspect_path(parent, false)?;
    Ok(path)
}

/// Create one mode-0600, no-follow regular file; collisions never overwrite content.
pub fn create(path: &Path) -> Result<File, EvalError> {
    let path = parents(path)?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                EvalError::OutputExists
            } else {
                EvalError::Io
            }
        })
}

/// One reserved JSON report and optional numeric raw-response directory.
pub struct Output {
    path: PathBuf,
    file: File,
    raw: Option<PathBuf>,
    complete: PathBuf,
}

impl Output {
    /// Reserve a report and its raw sibling before networking; any collision fails preflight.
    pub fn reserve(path: &Path, raw: bool) -> Result<Self, EvalError> {
        let path = parents(path)?;
        let parent = path.parent().ok_or(EvalError::UnsafePath)?;
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or(EvalError::UnsafePath)?;
        let complete = parent.join(format!("{stem}.complete"));
        let raw_path = parent.join(format!("{stem}.raw"));
        for candidate in [&path, &complete]
            .into_iter()
            .chain(raw.then_some(&raw_path))
        {
            input::inspect_path(candidate, true)?;
            if fs::symlink_metadata(candidate).is_ok() {
                return Err(EvalError::OutputExists);
            }
        }
        let file = create(&path)?;
        let raw = if raw {
            DirBuilder::new()
                .mode(0o700)
                .create(&raw_path)
                .map_err(|_| EvalError::OutputExists)?;
            input::inspect_path(&raw_path, false)?;
            Some(raw_path)
        } else {
            None
        };
        Ok(Self {
            path,
            file,
            raw,
            complete,
        })
    }

    /// Reserve a numeric raw file; label ids and URLs never become filesystem names.
    pub fn raw(&self, ordinal: usize) -> Result<(PathBuf, File), EvalError> {
        if ordinal >= input::MAX_LABELS {
            return Err(EvalError::LabelLimit);
        }
        let path = self
            .raw
            .as_ref()
            .ok_or(EvalError::InvalidInput)?
            .join(format!("{ordinal:04}.json"));
        let file = create(&path)?;
        Ok((path, file))
    }

    /// Serialize and sync the completed report, then create its separate completion marker.
    pub fn finish(mut self, value: &impl serde::Serialize) -> Result<(), EvalError> {
        serde_json::to_writer_pretty(&mut self.file, value).map_err(|_| EvalError::Io)?;
        self.file.write_all(b"\n").map_err(|_| EvalError::Io)?;
        self.file.sync_all().map_err(|_| EvalError::Io)?;
        let mut marker = create(&self.complete)?;
        marker.write_all(b"complete\n").map_err(|_| EvalError::Io)?;
        marker.sync_all().map_err(|_| EvalError::Io)?;
        Ok(())
    }

    /// Absolute report identity, for local manifests only.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Resolve this product's repository from git, verifying its marker and stract workspace member.
/// Missing or unrelated repositories return IdentityMismatch without creating output.
pub fn product_root() -> Result<PathBuf, EvalError> {
    let root = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|_| EvalError::Io)?;
    if !root.status.success() {
        return Err(EvalError::IdentityMismatch);
    }
    let root = PathBuf::from(
        String::from_utf8(root.stdout)
            .map_err(|_| EvalError::IdentityMismatch)?
            .trim_end(),
    );
    if !is_product_root(&root) {
        return Err(EvalError::IdentityMismatch);
    }
    Ok(root)
}

fn is_product_root(root: &Path) -> bool {
    let check = || -> Result<bool, EvalError> {
        input::open(&root.join("crates/core/src/eval/mod.rs"))?;
        let workspace = input::read(&root.join("Cargo.toml"))?;
        let package = input::read(&root.join("crates/core/Cargo.toml"))?;
        let workspace: toml::Value = toml::from_str(
            std::str::from_utf8(&workspace.bytes).map_err(|_| EvalError::IdentityMismatch)?,
        )
        .map_err(|_| EvalError::IdentityMismatch)?;
        let package: toml::Value = toml::from_str(
            std::str::from_utf8(&package.bytes).map_err(|_| EvalError::IdentityMismatch)?,
        )
        .map_err(|_| EvalError::IdentityMismatch)?;
        Ok(workspace
            .get("workspace")
            .and_then(|w| w.get("members"))
            .and_then(toml::Value::as_array)
            .is_some_and(|members| {
                members
                    .iter()
                    .any(|member| member.as_str() == Some("crates/core"))
            })
            && package
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(toml::Value::as_str)
                == Some("stract"))
    };
    check().unwrap_or(false)
}

/// Reject outputs inside this product repository or any input directory before reservation.
/// An unrelated repository or a process outside git fails with IdentityMismatch.
pub fn external(path: &Path, inputs: &[PathBuf]) -> Result<(), EvalError> {
    if !path.is_absolute() {
        return Err(EvalError::Argument {
            argument: Argument::Out,
            reason: ArgumentReason::AbsoluteOutput,
        });
    }
    let path = input::argument_path(path, true, Argument::Out)?;
    let root = product_root()?;
    if path.starts_with(root) {
        return Err(EvalError::Argument {
            argument: Argument::Out,
            reason: ArgumentReason::OutputRepository,
        });
    }
    for source in inputs {
        let source = input::inspect_path(source, false)?;
        let boundary = if source.is_dir() {
            source.as_path()
        } else {
            source.parent().ok_or(EvalError::UnsafePath)?
        };
        if path.starts_with(boundary) {
            return Err(EvalError::Argument {
                argument: Argument::Out,
                reason: ArgumentReason::OutputInput,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod creation_contract {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn output_owned_ancestor_revalidated() {
        let dir = crate::gen_temp_dir().unwrap();
        let path = dir.as_ref().join("new/tail/out.json");
        let result = parents_after_creation(&path, |parent| {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o777)).unwrap();
        });
        assert!(matches!(result, Err(EvalError::UnsafePath)));
        assert!(!path.exists());
    }
}
