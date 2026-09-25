//! Same-directory publication that preserves the prior destination on pre-rename failure.

use ::egress::Error;
use anyhow::{Context, Result};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn destination(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_file() => Err(anyhow::Error::from(Error::Io)),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Error::Io.into()),
    }
    .with_context(|| format!("inspect output {}", path.display()))
}

fn create(parent: &Path) -> Result<(PathBuf, File)> {
    for _ in 0..32 {
        let path = parent.join(format!(
            ".egress-sign-{}-{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(Error::Io).context("create publication temp"),
        }
    }
    Err(Error::Io).context("publication temp collisions")
}

/// Resolves normal filesystem aliases, protects the private input and replaces only regular output.
pub(super) fn write(out: &Path, key: &Path, bytes: &[u8]) -> Result<()> {
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = parent
        .canonicalize()
        .map_err(|_| Error::Io)
        .context("resolve output parent")?;
    let name = out.file_name().ok_or(Error::Io)?;
    let out = parent.join(name);
    let key = key
        .canonicalize()
        .map_err(|_| Error::Io)
        .context("resolve private input")?;
    if out == key {
        return Err(Error::Io).context("output equals private input");
    }
    destination(&out)?;
    let (temp, mut file) = create(&parent)?;
    let result = (move || -> Result<()> {
        file.write_all(bytes)
            .map_err(|_| Error::Io)
            .context("write publication temp")?;
        file.set_permissions(fs::Permissions::from_mode(0o644))
            .map_err(|_| Error::Io)
            .context("set publication mode")?;
        file.sync_all()
            .map_err(|_| Error::Io)
            .context("sync publication temp")?;
        drop(file);
        Ok(())
    })()
    .and_then(|()| {
        destination(&out)?;
        fs::rename(&temp, &out)
            .map_err(|_| Error::Io)
            .context("rename publication temp")
    });
    match result {
        Ok(()) => Ok(()),
        // Cleanup failure must not replace the original publication failure and its reason.
        Err(error) => match fs::remove_file(&temp) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(error.context(format!("remove owned publication temp: {cleanup}"))),
        },
    }
}
