//! Removes only individually managed raw objects under an exclusively owned store.
//! Original deadlines never lengthen; no-store, reserved, gone and interrupted writes purge
//! immediately. Metadata and ledger have no TTL. Unknown/foreign/link objects are reported,
//! never deleted. A hostile same-privilege concurrent filesystem writer is outside this model.

#![deny(missing_docs)]

use super::{
    host_state::{atomic_write, validate_store_root, HostRegistry},
    record::BodyRetentionReason,
    Error, Result,
};
use crate::config::ingestion::ValidatedPolicy;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

/// Publication lifecycle of a managed raw-body object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObjectState {
    /// Manifest was committed before its raw staging file; any interrupted write is purged.
    Pending,
    /// Atomic body publication and manifest acknowledgement completed.
    Retained,
    /// Raw staging/final paths were removed; manifest remains as accountability metadata.
    Deleted,
}
/// Per-target raw-object manifest; it contains no HTML, clean text or snippets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectManifest {
    /// Fixed managed-object schema version, currently one.
    pub schema_version: u16,
    /// Exact ID of the exclusively owned parent store.
    pub store_id: String,
    /// Opaque UUID identifying the original target admission.
    pub target_id: String,
    /// SHA-256 of the exact operational URL, for conditional deletion joins.
    pub url_key: String,
    /// Fixed relative opaque objects/<UUID>.warc.gz path.
    pub body_object: String,
    /// Original UTC parse time, unaffected by copying or a 304.
    pub parsed_at_utc: DateTime<Utc>,
    /// Original immutable raw deadline, at most 30 days from parse.
    pub raw_expires_at_utc: DateTime<Utc>,
    /// Actual decoded body bytes retained within the one-record WARC.
    pub body_bytes: u64,
    /// Compressed WARC file bytes after publication; zero while pending.
    pub object_bytes: u64,
    /// Pending/retained/deleted lifecycle state.
    pub state: ObjectState,
    /// Retention reason, including immediate no-store/reserved/gone deletion.
    pub body_retention: BodyRetentionReason,
    /// UTC deletion acknowledgement; no metadata expiry is inferred.
    pub deleted_at_utc: Option<DateTime<Utc>>,
}
/// Complete raw-store scan metrics; failed/backlogged deletion is never reported as success.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionReport {
    /// Number of managed manifests examined.
    pub scanned: u64,
    /// Number of raw objects due for expiry or immediate deletion.
    pub expired: u64,
    /// Number of manifests whose existing raw files were successfully deleted.
    pub deleted: u64,
    /// Invalid/foreign/link objects, unaccounted files or failed deletions.
    pub failed: u64,
    /// Age in seconds of the oldest overdue raw object remaining after this scan.
    pub oldest_overdue_seconds: u64,
}
impl RetentionReport {
    /// Fails a non-dry-run command with any invalid object or unresolved deletion backlog.
    pub fn ensure_success(&self) -> Result<()> {
        let failed_deletions = self.failed;
        if failed_deletions > 0 || self.oldest_overdue_seconds > 0 {
            return Err(Error::RetentionBacklog);
        }
        Ok(())
    }
}
/// Derives only the fixed relative raw-object path from a validated opaque target UUID.
pub fn object_name(target_id: &str) -> Result<String> {
    if uuid::Uuid::parse_str(target_id).is_err() {
        return Err(Error::StoreRefused);
    }
    Ok(format!("objects/{target_id}.warc.gz"))
}
/// Validates store identity, exact relative object grammar and every regular-file/link boundary.
/// Missing files are returned as None; symlinks (including dangling) and hardlinks are refused.
pub fn validate_owned_store_and_object(
    registry: &HostRegistry,
    manifest: &ObjectManifest,
    staging: bool,
) -> Result<Option<PathBuf>> {
    let root = validate_store_root(registry.root())?;
    if manifest.schema_version != 1
        || manifest.store_id != registry.identity().store_id
        || manifest.body_object != object_name(&manifest.target_id)?
        || manifest.url_key.len() != 64
        || !manifest
            .url_key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || manifest.raw_expires_at_utc < manifest.parsed_at_utc
        || manifest.raw_expires_at_utc > manifest.parsed_at_utc + chrono::TimeDelta::days(30)
    {
        return Err(Error::StoreRefused);
    }
    let relative = if staging {
        format!("{}.pending", manifest.body_object)
    } else {
        manifest.body_object.clone()
    };
    let path = root.join(relative);
    let parent = path.parent().ok_or(Error::StoreRefused)?;
    let parent_meta = fs::symlink_metadata(parent).map_err(|_| Error::StoreRefused)?;
    if !parent_meta.is_dir() || parent_meta.file_type().is_symlink() {
        return Err(Error::StoreRefused);
    }
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() && meta.nlink() == 1 => {
            Ok(Some(path))
        }
        Ok(_) => Err(Error::StoreRefused),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(Error::StoreRefused),
    }
}
pub(super) fn manifest_path(registry: &HostRegistry, target_id: &str) -> Result<PathBuf> {
    object_name(target_id)?;
    Ok(registry
        .root()
        .join("manifests")
        .join(format!("{target_id}.json")))
}
pub(super) fn persist_manifest(registry: &HostRegistry, manifest: &ObjectManifest) -> Result<()> {
    atomic_write(
        &manifest_path(registry, &manifest.target_id)?,
        &serde_json::to_vec(manifest).map_err(|_| Error::RecordInvalid)?,
    )
    .map_err(|_| Error::SinkWrite)
}
pub(super) fn manifests(registry: &HostRegistry) -> Result<Vec<ObjectManifest>> {
    let directory = registry.root().join("manifests");
    let metadata = fs::symlink_metadata(&directory).map_err(|_| Error::StoreRefused)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(Error::StoreRefused);
    }
    let mut result = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| Error::StoreRefused)? {
        let path = entry.map_err(|_| Error::StoreRefused)?.path();
        let metadata = fs::symlink_metadata(&path).map_err(|_| Error::StoreRefused)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.nlink() != 1
            || path.extension().is_none_or(|s| s != "json")
        {
            return Err(Error::StoreRefused);
        }
        let manifest: ObjectManifest =
            serde_json::from_slice(&fs::read(&path).map_err(|_| Error::StoreRefused)?)
                .map_err(|_| Error::StoreRefused)?;
        if path != manifest_path(registry, &manifest.target_id)? {
            return Err(Error::StoreRefused);
        }
        result.push(manifest);
    }
    result.sort_by(|a, b| a.target_id.cmp(&b.target_id));
    Ok(result)
}
fn deadline(manifest: &ObjectManifest, policy: &ValidatedPolicy) -> Result<DateTime<Utc>> {
    let shortened = manifest
        .parsed_at_utc
        .checked_add_signed(chrono::TimeDelta::days(i64::from(
            policy.get().retention.raw_body_max_age_days,
        )))
        .ok_or(Error::RecordInvalid)?;
    Ok(manifest.raw_expires_at_utc.min(shortened))
}
pub(super) fn delete_manifest_objects(
    registry: &HostRegistry,
    manifest: &mut ObjectManifest,
    now: DateTime<Utc>,
) -> Result<bool> {
    let final_path = validate_owned_store_and_object(registry, manifest, false)?;
    let staging = validate_owned_store_and_object(registry, manifest, true)?;
    let mut deleted = false;
    for path in final_path.into_iter().chain(staging) {
        fs::remove_file(path).map_err(|_| Error::RetentionBacklog)?;
        deleted = true;
    }
    fs::File::open(registry.root().join("objects"))
        .and_then(|f| f.sync_all())
        .map_err(|_| Error::RetentionBacklog)?;
    manifest.state = ObjectState::Deleted;
    manifest.deleted_at_utc = Some(now);
    persist_manifest(registry, manifest)?;
    Ok(deleted)
}
/// Scans every managed raw object under the owner lock; dry-run reports due objects without deletion.
/// Unknown files remain untouched and contribute failures. Config shortening takes effect immediately.
pub fn run(
    registry: &HostRegistry,
    policy: &ValidatedPolicy,
    now: DateTime<Utc>,
    dry_run: bool,
) -> Result<RetentionReport> {
    validate_store_root(registry.root())?;
    let mut report = RetentionReport::default();
    let mut known = BTreeSet::new();
    for mut manifest in manifests(registry)? {
        report.scanned += 1;
        known.insert(manifest.body_object.clone());
        known.insert(format!("{}.pending", manifest.body_object));
        let paths = match (
            validate_owned_store_and_object(registry, &manifest, false),
            validate_owned_store_and_object(registry, &manifest, true),
        ) {
            (Ok(a), Ok(b)) => (a, b),
            _ => {
                report.failed += 1;
                continue;
            }
        };
        let raw_expiry = deadline(&manifest, policy)?;
        let due = now >= raw_expiry
            || manifest.body_retention != BodyRetentionReason::Retained
            || manifest.state != ObjectState::Retained;
        let exists = paths.0.is_some() || paths.1.is_some();
        if !exists {
            if manifest.state == ObjectState::Retained {
                report.failed += 1;
            } else if manifest.state == ObjectState::Pending && !dry_run {
                manifest.state = ObjectState::Deleted;
                manifest.deleted_at_utc = Some(now);
                persist_manifest(registry, &manifest)?;
            }
            continue;
        }
        if !due {
            continue;
        }
        report.expired += 1;
        let overdue =
            u64::try_from(now.signed_duration_since(raw_expiry).num_seconds()).unwrap_or(0);
        if dry_run {
            report.oldest_overdue_seconds = report.oldest_overdue_seconds.max(overdue);
            continue;
        }
        if manifest.body_retention == BodyRetentionReason::Retained {
            manifest.body_retention = BodyRetentionReason::Expired;
        }
        match delete_manifest_objects(registry, &mut manifest, now) {
            Ok(true) => report.deleted += 1,
            Ok(false) => {}
            Err(_) => {
                report.failed += 1;
                report.oldest_overdue_seconds = report.oldest_overdue_seconds.max(overdue);
            }
        }
    }
    for entry in fs::read_dir(registry.root().join("objects")).map_err(|_| Error::StoreRefused)? {
        let path = entry.map_err(|_| Error::StoreRefused)?.path();
        let relative = path
            .strip_prefix(registry.root())
            .map_err(|_| Error::StoreRefused)?
            .to_str()
            .ok_or(Error::StoreRefused)?;
        if !known.contains(relative) {
            report.failed += 1;
        }
    }
    Ok(report)
}
/// Independently verifies that no raw object remaining after a job is due/forbidden/unaccounted.
pub fn scan(
    registry: &HostRegistry,
    policy: &ValidatedPolicy,
    now: DateTime<Utc>,
) -> Result<RetentionReport> {
    let mut report = run(registry, policy, now, true)?;
    report.failed = report.failed.saturating_add(report.expired);
    report.ensure_success()?;
    Ok(report)
}

/// Verifies the exact managed directory grammar before creating or using it.
pub(super) fn managed_directory(root: &Path, name: &str) -> Result<PathBuf> {
    if !matches!(name, "objects" | "manifests") {
        return Err(Error::StoreRefused);
    }
    let path = root.join(name);
    if let Ok(meta) = fs::symlink_metadata(&path) {
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(Error::StoreRefused);
        }
    } else {
        fs::create_dir(&path).map_err(|_| Error::SinkWrite)?;
    }
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(|_| Error::SinkWrite)?;
    Ok(path)
}
