// SPDX-License-Identifier: AGPL-3.0-only
//! Bound and validate every evaluator file read before allocation or network activity.
//! Files are regular, opened read-only without following links, and hashed as read.
//! Root-owned system ancestors are trusted; writable descendants and foreign owners are not.

use super::{Argument, ArgumentReason, EvalError};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
};

/// Maximum label, run, configuration or manifest input bytes (64 MiB).
pub const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum streamed corpus record bytes (8 MiB).
pub const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
/// Maximum corpus records across all supplied files.
pub const MAX_RECORDS: usize = 1_000_000;
/// Maximum labels accepted by generic evaluation commands.
pub const MAX_LABELS: usize = 1000;
/// Maximum acceptable URLs per label.
pub const MAX_ANSWERS: usize = 32;
/// Maximum UTF-8 bytes per URL.
pub const MAX_URL_BYTES: usize = 8192;

/// Read input and its content identity; bytes never come from an unchecked file kind.
#[derive(Debug)]

pub struct Document {
    /// Absolute validated path, retained only in local evaluation artifacts.
    pub path: PathBuf,
    /// Complete bounded input bytes.
    pub bytes: Vec<u8>,
    /// Lowercase SHA-256 of those exact bytes.
    pub sha256: String,
}

/// Return a raw-component-validated absolute path; dot components and controls are rejected.
pub fn absolute(path: &Path) -> Result<PathBuf, EvalError> {
    let text = path.to_str().ok_or(EvalError::UnsafePath)?;
    if text.is_empty()
        || text.chars().any(char::is_control)
        || text.split('/').any(|p| p == "." || p == "..")
    {
        return Err(EvalError::UnsafePath);
    }
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .map_err(|_| EvalError::Io)?
            .join(path))
    }
}

/// Validate each existing component, including dangling links and non-private ancestors.
/// Missing tails are allowed only for output preparation; callers revalidate after creation.
pub fn inspect_path(path: &Path, allow_missing: bool) -> Result<PathBuf, EvalError> {
    inspect_path_named(path, allow_missing, None)
}

/// Validate a CLI path with a fixed argument and the precise failed component rule.
/// Missing output tails may be allowed; links and writable or foreign ancestors never are.
pub fn argument_path(
    path: &Path,
    allow_missing: bool,
    argument: Argument,
) -> Result<PathBuf, EvalError> {
    inspect_path_named(path, allow_missing, Some(argument))
}

fn inspect_path_named(
    path: &Path,
    allow_missing: bool,
    argument: Option<Argument>,
) -> Result<PathBuf, EvalError> {
    let invalid = |reason| {
        argument.map_or(EvalError::UnsafePath, |argument| EvalError::Argument {
            argument,
            reason,
        })
    };
    let absolute =
        absolute(path).map_err(|error| argument.map_or(error, |arg| error.argument(arg)))?;
    let mut prefix = PathBuf::new();
    // geteuid reads process identity and cannot dereference user-controlled memory.
    let uid = unsafe { libc::geteuid() };
    for component in absolute.components() {
        prefix.push(component);
        match fs::symlink_metadata(&prefix) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(invalid(ArgumentReason::Symlink));
                }
                if prefix != absolute && !meta.is_dir() {
                    return Err(invalid(ArgumentReason::RegularFile));
                }
                if meta.is_dir() {
                    let trusted_tmp = (prefix == Path::new("/tmp")
                        || prefix == Path::new("/private/tmp"))
                        && meta.uid() == 0
                        && meta.mode() & 0o1000 != 0;
                    if meta.mode() & 0o022 != 0 && !trusted_tmp {
                        return Err(invalid(ArgumentReason::WritableAncestor));
                    }
                    if meta.uid() != uid && meta.uid() != 0 {
                        return Err(invalid(ArgumentReason::Owner));
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && allow_missing => {}
            Err(_) => return Err(EvalError::Io),
        }
    }
    Ok(absolute)
}

/// Open a regular input without following its final component; verify opened inode identity.
pub fn open(path: &Path) -> Result<File, EvalError> {
    let path = inspect_path(path, false)?;
    let before = fs::symlink_metadata(&path).map_err(|_| EvalError::Io)?;
    if !before.is_file() {
        return Err(EvalError::UnsafePath);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|_| EvalError::Io)?;
    let after = file.metadata().map_err(|_| EvalError::Io)?;
    if !after.is_file() || (before.dev(), before.ino()) != (after.dev(), after.ino()) {
        return Err(EvalError::InputChanged);
    }
    Ok(file)
}

/// Read at most 64 MiB and retain its SHA; changing size or an oversized stream is rejected.
pub fn read(path: &Path) -> Result<Document, EvalError> {
    let path = absolute(path)?;
    let mut file = open(&path)?;
    let length = file.metadata().map_err(|_| EvalError::Io)?.len();
    if length > MAX_INPUT_BYTES {
        return Err(EvalError::InputLimit);
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| EvalError::Io)?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(EvalError::InputLimit);
    }
    if bytes.len() as u64 != length || file.metadata().map_err(|_| EvalError::Io)?.len() != length {
        return Err(EvalError::InputChanged);
    }
    let sha256 = sha256(&bytes);
    Ok(Document {
        path,
        bytes,
        sha256,
    })
}

/// Re-read and verify a labels/configuration identity before or after its use.
pub fn verify(path: &Path, expected: &str) -> Result<(), EvalError> {
    if read(path)?.sha256 != expected {
        return Err(EvalError::InputChanged);
    }
    Ok(())
}

/// SHA-256 of exact bytes, used for local artifact identities rather than URL canonicalization.
pub fn sha256(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Stream bounded JSONL records, rejecting an overlong line before growing an unbounded buffer.
pub fn records(
    path: &Path,
    total: &mut usize,
    mut visit: impl FnMut(&[u8]) -> Result<(), EvalError>,
) -> Result<usize, EvalError> {
    records_with_limit(path, total, MAX_RECORDS, &mut visit)
}

/// Stream records with an injected count ceiling for fast boundary witnesses.
/// Production callers use `records`, which fixes the ceiling at one million.
pub fn records_with_limit(
    path: &Path,
    total: &mut usize,
    limit: usize,
    mut visit: impl FnMut(&[u8]) -> Result<(), EvalError>,
) -> Result<usize, EvalError> {
    let mut reader = BufReader::new(open(path)?);
    let mut count = 0;
    loop {
        let mut record = Vec::new();
        let read = reader
            .by_ref()
            .take((MAX_RECORD_BYTES + 1) as u64)
            .read_until(b'\n', &mut record)
            .map_err(|_| EvalError::Io)?;
        if read == 0 {
            break;
        }
        if read > MAX_RECORD_BYTES {
            return Err(EvalError::InputLimit);
        }
        if *total >= limit {
            return Err(EvalError::CorpusLimit);
        }
        *total += 1;
        count += 1;
        visit(&record)?;
    }
    Ok(count)
}

/// Regular-file identity used to detect replacement or modification during streaming.
/// The tuple is device, inode, byte length, mtime seconds and nanoseconds.
pub fn file_identity(path: &Path) -> Result<(u64, u64, u64, i64, i64), EvalError> {
    let file = open(path)?;
    let m = file.metadata().map_err(|_| EvalError::Io)?;
    Ok((m.dev(), m.ino(), m.len(), m.mtime(), m.mtime_nsec()))
}

/// Hash a regular file incrementally, including executables and pre-open index segments.
pub fn hash_file(path: &Path) -> Result<String, EvalError> {
    let before = file_identity(path)?;
    let mut file = open(path)?;
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = [0; 64 * 1024];
    loop {
        let n = file.read(&mut buffer).map_err(|_| EvalError::Io)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    if before != file_identity(path)? {
        return Err(EvalError::InputChanged);
    }
    Ok(digest
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
