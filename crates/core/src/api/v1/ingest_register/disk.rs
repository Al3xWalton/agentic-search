//! Persists bounded metadata snapshots through the shared private-file hardening boundary.
//! The final snapshot is authoritative; stale temporary files are disposable only under ownership.

#![deny(missing_docs)]

use super::{
    validate_snapshot, Entry, IngestSeams, IngestStage, Snapshot, MAX_INGEST_REGISTER_BYTES,
};
use crate::{
    api::v1::suppression::DocumentId,
    compliance::disk::{self, OpenMode},
};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const MAX_DIRECTORY_ENTRIES: usize = 1_024;

/// Hardened snapshot owner whose lock outlives every file operation.
pub(super) struct Disk {
    /// Authoritative metadata file inside the private sibling directory.
    pub(super) path: PathBuf,
    hooks: Arc<dyn super::IngestHooks>,
    compliance_hooks: Arc<dyn disk::ComplianceHooks>,
    _owner: disk::OwnerLock,
}

impl Disk {
    /// Validates the sibling and acquires ownership before sweeping disposable temporary files.
    pub(super) fn open(suppression: &Path, seams: &IngestSeams) -> io::Result<(Self, bool)> {
        let mut sibling = suppression.as_os_str().to_owned();
        sibling.push(".ingest");
        let root = disk::normalized(Path::new(&sibling))?;
        let fresh = match fs::symlink_metadata(&root) {
            Ok(_) => false,
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => return Err(error),
        };
        let path = disk::private_parent(&root.join("snapshot.json"))?;
        let lock = open_ingest(
            &root.join("owner.lock"),
            OpenMode::OwnerFile,
            seams.compliance_hooks.as_ref(),
        )?;
        let owner = disk::lock_exclusive(lock)?;
        let disk = Self {
            path,
            hooks: seams.hooks.clone(),
            compliance_hooks: seams.compliance_hooks.clone(),
            _owner: owner,
        };
        disk.sweep_owned_temps()?;
        Ok((disk, fresh))
    }

    /// Observes a finite transaction stage without exposing private metadata.
    pub(super) fn stage(&self, stage: IngestStage) -> io::Result<()> {
        self.hooks.at(stage)
    }

    /// Bounds bytes before decoding and rejects every invalid or future receipt before use.
    pub(super) fn read(&self, now: i64) -> io::Result<BTreeMap<DocumentId, Entry>> {
        let file = open_ingest(&self.path, OpenMode::Read, self.compliance_hooks.as_ref())?;
        let bytes = disk::read_bounded(file, MAX_INGEST_REGISTER_BYTES as u64)?;
        self.hooks.at(IngestStage::Decode)?;
        let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        validate_snapshot(&snapshot, now)?;
        Ok(snapshot
            .entries
            .into_iter()
            .map(|entry| (entry.id.clone(), entry))
            .collect())
    }

    fn sweep_owned_temps(&self) -> io::Result<()> {
        let root = self.path.parent().expect("validated ingest directory");
        // Bound the complete enumeration before removing even one safe candidate.
        let mut entries = Vec::new();
        for entry in fs::read_dir(root)? {
            entries.push(entry?);
            if entries.len() > MAX_DIRECTORY_ENTRIES {
                return Err(io::Error::other("ingest directory exceeds entry limit"));
            }
        }
        let mut candidates = Vec::new();
        for entry in entries {
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| disk::owned_temp_name(name, &["snapshot"]))
            {
                let path = entry.path();
                let file = open_ingest(&path, OpenMode::Read, self.compliance_hooks.as_ref())?;
                candidates.push((path, file));
            }
        }
        let removed = !candidates.is_empty();
        for (path, file) in candidates {
            drop(file);
            fs::remove_file(path)?;
        }
        if removed {
            disk::sync_parent(&self.path)?;
        }
        Ok(())
    }

    /// Syncs a replacement and reports whether failure occurred after the authoritative rename.
    pub(super) fn persist(&self, bytes: &[u8], renamed: &mut bool) -> io::Result<()> {
        self.hooks.at(IngestStage::Open)?;
        let sequence = TEMP_SEQUENCE
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_add(1)
            })
            .map_err(|_| io::Error::other("ingest temp sequence full"))?;
        let temp =
            self.path
                .with_file_name(format!("snapshot.{}.{}.tmp", std::process::id(), sequence));
        let mut file = open_ingest(&temp, OpenMode::CreateNew, self.compliance_hooks.as_ref())?;
        let result = self.replace(&mut file, &temp, bytes, renamed);
        drop(file);
        if !*renamed {
            // This name was created by this call. Validate its inode again before cleanup;
            // a same-uid replacement remains outside the store's filesystem threat model.
            let file = open_ingest(&temp, OpenMode::Read, self.compliance_hooks.as_ref())?;
            drop(file);
            fs::remove_file(&temp)?;
            disk::sync_parent(&temp)?;
        }
        result
    }

    fn replace(
        &self,
        file: &mut File,
        temp: &Path,
        bytes: &[u8],
        renamed: &mut bool,
    ) -> io::Result<()> {
        self.hooks
            .at(IngestStage::Write)
            .and_then(|()| file.write_all(bytes))?;
        self.hooks
            .at(IngestStage::SyncFile)
            .and_then(|()| file.sync_all())?;
        self.hooks.at(IngestStage::Rename)?;
        fs::rename(temp, &self.path)?;
        *renamed = true;
        // Directory sync makes the authoritative name durable before publishing its metadata.
        self.hooks
            .at(IngestStage::SyncDirectory)
            .and_then(|()| disk::sync_parent(&self.path))?;
        Ok(())
    }
}

fn open_ingest(path: &Path, mode: OpenMode, hooks: &dyn disk::ComplianceHooks) -> io::Result<File> {
    disk::open_for(path, mode, hooks)
}
