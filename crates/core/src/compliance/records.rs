//! Owns immutable salted records independently of ticket and serving-rule availability.
//! Read views capture only published versions and never initialize, recover or acquire a lock.
//! Pending bytes authorize repair of an unpublished torn final under the exclusive record owner.

#![deny(missing_docs)]

use super::{
    bounds::{self, BoundKey},
    disk::{self, ComplianceHooks, ComplianceStage, OpenMode},
    model::{sha256, Entropy, Hex64},
    record_index::{self, Prefix, RecordIndex, RecordIndexRow},
    record_types::{
        self, require, text, ApprovalStatus, RecordBody, RecordEnvelope, RecordKind, RecordRef,
        ReviewScope,
    },
    Error, Result,
};
use crate::{
    config::compliance::{DeploymentMode, ValidatedComplianceConfig},
    crawler::politeness::Clock,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

/// Runtime-only private wrapper; exports must never disclose salts or commitments.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredRecord {
    /// Fixed wrapper format one.
    pub format_version: u64,
    /// Independent random salt.
    pub salt: Hex64,
    /// Domain-separated salted envelope commitment.
    pub commitment: Hex64,
    /// Strict immutable imported envelope.
    pub record: RecordEnvelope,
}

/// Snapshot of published immutable versions, safe to retain after all files are closed.
#[derive(Clone, Default)]
pub struct RecordView {
    records: BTreeMap<RecordRef, RecordEnvelope>,
    heads: BTreeMap<String, (RecordRef, RecordKind)>,
    /// Captured committed index sequence.
    pub sequence: u64,
    /// Captured observation instant, never a substitute for an approval timestamp.
    pub observed_at: i64,
}
impl RecordView {
    /// Verifies intrinsic immutable history in publication order, independently of admission.
    pub fn validated(records: impl IntoIterator<Item = RecordEnvelope>, now: i64) -> Result<Self> {
        let mut view = Self {
            observed_at: now,
            ..Self::default()
        };
        for record in records {
            record.validate(now).map_err(|_| Error::Unavailable)?;
            validate_predecessor(&record, &view.heads).map_err(|_| Error::Unavailable)?;
            validate_references(&record, &view).map_err(|_| Error::Unavailable)?;
            view.insert(record);
        }
        Ok(view)
    }
    /// All published versions in deterministic reference order, including superseded records.
    pub fn records(&self) -> &BTreeMap<RecordRef, RecordEnvelope> {
        &self.records
    }
    /// Resolves one immutable reference, never silently substituting a newer version.
    pub fn get(&self, reference: &RecordRef) -> Option<&RecordEnvelope> {
        self.records.get(reference)
    }
    /// Current published version of an identifier.
    pub fn latest(&self, id: &str) -> Option<&RecordEnvelope> {
        self.heads
            .get(id)
            .and_then(|(reference, _)| self.get(reference))
    }
    /// Current versions in identifier order, for selection and review consumers.
    pub fn current(&self) -> impl Iterator<Item = &RecordEnvelope> {
        self.heads
            .values()
            .filter_map(|(reference, _)| self.get(reference))
    }
    /// Selects the latest version of the sole manifest identity, refusing ambiguity.
    pub fn manifest(&self) -> Result<Option<&RecordEnvelope>> {
        let manifests = self
            .current()
            .filter(|record| record.kind == RecordKind::Manifest)
            .collect::<Vec<_>>();
        if manifests.len() > 1 {
            return Err(Error::InvalidInput);
        }
        Ok(manifests.first().copied())
    }
    fn insert(&mut self, record: RecordEnvelope) {
        let reference = record.reference();
        self.heads
            .insert(record.id.clone(), (reference.clone(), record.kind));
        self.records.insert(reference, record);
    }
}

/// Validates a prospective immutable version and its references without entropy or filesystem work.
pub fn validate_candidate(
    config: &ValidatedComplianceConfig,
    view: &RecordView,
    record: &RecordEnvelope,
    now: i64,
) -> Result<()> {
    record.validate(now)?;
    validate_configuration_binding(config, record)?;
    if record.kind == RecordKind::Manifest && record.version == 1 {
        require(
            view.current()
                .filter(|existing| existing.kind == RecordKind::Manifest)
                .all(|existing| existing.id == record.id),
        )?;
    }
    if config.settings().deployment_mode == DeploymentMode::Hosted {
        require_operational_record(record)?;
    }
    validate_predecessor(record, &view.heads)?;
    validate_references(record, view)?;
    Ok(())
}

fn validate_configuration_binding(
    config: &ValidatedComplianceConfig,
    record: &RecordEnvelope,
) -> Result<()> {
    if let RecordBody::Manifest(manifest) = &record.body {
        require(manifest.statement_version == config.settings().statement_version)?;
    }
    if let Some(assessment) = record.assessment() {
        if assessment.approval_status == ApprovalStatus::Approved {
            require(
                record_types::catalog_complete(config)
                    && config.settings().priority_catalog_version.as_ref()
                        == Some(&assessment.priority_catalog_version),
            )?;
        }
    }
    Ok(())
}

/// Enforces operational approval before service owners are opened; periodic lateness is advisory.
pub fn validate_hosted(
    config: &ValidatedComplianceConfig,
    publication: &Result<RecordView>,
    now: i64,
) -> Result<()> {
    let deployment_mode = config.settings().deployment_mode;
    if deployment_mode == DeploymentMode::Local {
        return Ok(());
    }
    let view = publication.as_ref().map_err(|error| *error)?;
    require_operational_inputs(view)?;
    let selected = view.manifest()?.ok_or(Error::InvalidInput)?;
    validate_references(selected, view)?;
    for record in std::iter::once(selected).chain(super::reviews::selected(view)?) {
        record.validate(now)?;
        validate_configuration_binding(config, record)?;
    }
    let RecordBody::Manifest(manifest) = &selected.body else {
        return Err(Error::InvalidInput);
    };
    require(manifest.approval_status == ApprovalStatus::Approved)?;
    let caa = resolve(view, &manifest.caa, RecordKind::Caa)?;
    let access = caa
        .assessment()
        .and_then(|assessment| assessment.access.as_ref())
        .ok_or(Error::InvalidInput)?;
    if access.conclusion == super::record_types::AccessConclusion::Likely
        && super::clock::child_risk_overdue(access.concluded_at, now)?
    {
        require(manifest.cra.is_some())?;
    }
    // Freshness is reported by the command surface, never treated as a serving failure.
    super::reviews::freshness(view, now)?;
    Ok(())
}

fn require_operational_inputs(view: &RecordView) -> Result<()> {
    for record in view.records.values() {
        require_operational_record(record)?;
    }
    Ok(())
}

fn require_operational_record(record: &RecordEnvelope) -> Result<()> {
    require(!record.id.starts_with("sample."))?;
    let bytes = canonical(record)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Error::InvalidInput)?;
    require(!text.contains("sample — not an approval"))
}

/// Serializes recursively sorted JSON; stored wrappers additionally carry exactly one LF.
pub fn canonical(value: &impl Serialize) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value).map_err(|_| Error::InvalidInput)?;
    serde_json::to_vec(&value).map_err(|_| Error::InvalidInput)
}

/// Commits the exact envelope bytes with an independent full-width salt and framed length.
pub fn record_commitment(salt: &Hex64, record: &RecordEnvelope) -> Result<Hex64> {
    let bytes = canonical(record)?;
    let length = u64::try_from(bytes.len())
        .map_err(|_| Error::InvalidInput)?
        .to_be_bytes();
    Hex64::parse(&sha256(&[
        b"AVA619-RECORD-v1\0",
        salt.bytes().as_slice(),
        &length,
        &bytes,
    ]))
}

/// Applies the existing owner/link/mode/symlink predicates at every real record-file open.
pub(crate) fn open_records(
    path: &Path,
    mode: OpenMode,
    hooks: &dyn ComplianceHooks,
) -> io::Result<File> {
    disk::open_for(path, mode, hooks)
}

fn wrapper_bytes(stored: &StoredRecord) -> Result<Vec<u8>> {
    let mut bytes = canonical(stored)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn final_path(config: &ValidatedComplianceConfig, reference: &RecordRef) -> PathBuf {
    config
        .records_dir()
        .join(&reference.id)
        .join(format!("{:010}.json", reference.version))
}

fn pending_path(config: &ValidatedComplianceConfig, reference: &RecordRef) -> PathBuf {
    config
        .records_dir()
        .join(".pending")
        .join(format!("{}-{:010}.json", reference.id, reference.version))
}

fn read_bytes(path: &Path, hooks: &dyn ComplianceHooks) -> Result<Vec<u8>> {
    let file = open_records(path, OpenMode::Read, hooks).map_err(|_| Error::Unavailable)?;
    disk::read_bounded(file, BoundKey::MaxRecordBytes.spec().max).map_err(|_| Error::Unavailable)
}

fn decode_stored(bytes: &[u8], hooks: &dyn ComplianceHooks) -> Result<StoredRecord> {
    hooks
        .at(ComplianceStage::BeforeDecode)
        .map_err(|_| Error::Unavailable)?;
    let stored: StoredRecord = serde_json::from_slice(bytes).map_err(|_| Error::Unavailable)?;
    if stored.format_version != 1 || wrapper_bytes(&stored)? != bytes {
        return Err(Error::Unavailable);
    }
    if stored.commitment != record_commitment(&stored.salt, &stored.record)? {
        return Err(Error::Unavailable);
    }
    Ok(stored)
}

fn decode_and_validate_stored(
    bytes: &[u8],
    now: i64,
    hooks: &dyn ComplianceHooks,
) -> Result<StoredRecord> {
    let stored = decode_stored(bytes, hooks)?;
    stored
        .record
        .validate(now)
        .map_err(|_| Error::Unavailable)?;
    Ok(stored)
}

fn bind_wrapper(stored: &StoredRecord, row: &RecordIndexRow) -> Result<()> {
    if stored.record.reference().to_string() != row.record_ref
        || stored.record.kind.as_str() != row.record_kind
        || stored.commitment.as_str() != row.commitment
    {
        return Err(Error::Unavailable);
    }
    Ok(())
}

fn load_published(
    config: &ValidatedComplianceConfig,
    prefix: &Prefix,
    now: i64,
    hooks: &dyn ComplianceHooks,
    cache: &mut BTreeMap<RecordRef, StoredRecord>,
) -> Result<RecordView> {
    let mut records = Vec::new();
    for row in prefix.rows.iter().filter(|row| row.event == "record_added") {
        let reference = RecordRef::parse(&row.record_ref).map_err(|_| Error::Unavailable)?;
        let stored = match cache.entry(reference.clone()) {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                let bytes = read_bytes(&final_path(config, &reference), hooks)?;
                entry.insert(decode_stored(&bytes, hooks)?)
            }
        };
        bind_wrapper(stored, row)?;
        records.push(stored.record.clone());
        bounds::reserve(0, records.len() as u64, BoundKey::MaxRecords.spec().max, 0)
            .map_err(|_| Error::Unavailable)?;
    }
    let mut view = RecordView::validated(records, now)?;
    view.sequence = prefix.head.sequence;
    Ok(view)
}

/// Reads head, captured index and each published wrapper once, then checks head monotonicity.
/// An absent directory is empty; existing malformed stores are unavailable without any repair.
pub fn read_view(
    config: &ValidatedComplianceConfig,
    clock: &dyn Clock,
    hooks: &dyn ComplianceHooks,
) -> Result<RecordView> {
    match fs::symlink_metadata(config.records_dir()) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(RecordView {
                observed_at: clock.utc().timestamp(),
                ..RecordView::default()
            });
        }
        Ok(_) => {}
        Err(_) => return Err(Error::Unavailable),
    }
    let mut cache = BTreeMap::new();
    let mut retried = false;
    loop {
        let (head, before) = record_index::read_head(config, hooks)?;
        let (prefix, now) = record_index::read_prefix(config, &head, hooks, clock)?;
        let view = load_published(config, &prefix, now, hooks, &mut cache)?;
        let (_, after) = record_index::read_head(config, hooks)?;
        if !disk::checkpoint_stable(&before, &after) {
            return Err(Error::Unavailable);
        }
        if before == after || retried {
            return Ok(view);
        }
        retried = true;
    }
}

fn validate_predecessor(
    record: &RecordEnvelope,
    heads: &BTreeMap<String, (RecordRef, RecordKind)>,
) -> Result<()> {
    match heads.get(&record.id) {
        None => require(record.version == 1 && record.supersedes.is_none()),
        Some((previous, kind)) => require(
            previous.version.checked_add(1) == Some(record.version)
                && record.supersedes.as_ref() == Some(previous)
                && record.kind == *kind,
        ),
    }
}

/// Resolves immutable typed references and checks service/approval relationships in one place.
pub fn validate_references(record: &RecordEnvelope, view: &RecordView) -> Result<()> {
    match &record.body {
        RecordBody::Manifest(manifest) => {
            for (reference, kind) in [
                (&manifest.icra, RecordKind::Icra),
                (&manifest.caa, RecordKind::Caa),
                (&manifest.measures, RecordKind::Measures),
            ]
            .into_iter()
            .chain(
                manifest
                    .cra
                    .iter()
                    .map(|reference| (reference, RecordKind::Cra)),
            ) {
                let selected = resolve(view, reference, kind)?;
                require(selected.service() == Some(manifest.service.as_str()))?;
                if let Some(assessment) = selected.assessment() {
                    require(assessment.responsible_person == manifest.accountable_person)?;
                    if manifest.approval_status == ApprovalStatus::Approved {
                        require(assessment.approval_status == ApprovalStatus::Approved)?;
                    }
                } else if let RecordBody::Measures(measures) = &selected.body {
                    if manifest.approval_status == ApprovalStatus::Approved {
                        require(measures.approval_status == ApprovalStatus::Approved)?;
                    }
                }
            }
        }
        RecordBody::Review(review) => {
            let selected = view.get(&review.assessment).ok_or(Error::InvalidInput)?;
            require(match review.scope {
                ReviewScope::Compliance => selected.kind == RecordKind::Measures,
                ReviewScope::Risk => matches!(selected.kind, RecordKind::Icra | RecordKind::Cra),
                ReviewScope::ChildAccess => selected.kind == RecordKind::Caa,
            })?;
        }
        _ => {}
    }
    Ok(())
}

/// Requires the exact referenced version and expected kind.
pub fn resolve<'a>(
    view: &'a RecordView,
    reference: &RecordRef,
    kind: RecordKind,
) -> Result<&'a RecordEnvelope> {
    let record = view.get(reference).ok_or(Error::InvalidInput)?;
    require(record.kind == kind)?;
    Ok(record)
}

struct AdditionPlan {
    record: RecordEnvelope,
    wrapper_bytes: u64,
}
struct Usage {
    versions: u64,
    bytes: u64,
}

/// Computes the complete reservation, including pending/final copies and recovery headroom.
pub fn record_reservation_bytes(used: u64, wrapper_bytes: u64) -> Result<u64> {
    let overhead = BoundKey::JournalRow
        .spec()
        .max
        .checked_mul(3)
        .ok_or(Error::Capacity)?;
    wrapper_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(used))
        .and_then(|bytes| bytes.checked_add(overhead))
        .and_then(|bytes| bytes.checked_add(BoundKey::ReservedJournalBytes.spec().min))
        .ok_or(Error::Capacity)
}

fn reserve_addition(
    plan: &AdditionPlan,
    usage: &Usage,
    config: &ValidatedComplianceConfig,
) -> Result<()> {
    bounds::reserve(usage.versions, 1, config.settings().max_records, 0)?;
    bounds::reserve(
        0,
        record_reservation_bytes(usage.bytes, plan.wrapper_bytes)?,
        config.settings().max_records_bytes,
        0,
    )?;
    Ok(())
}

/// Exclusive blocking record writer; its lock is independent of every service owner.
pub struct RecordStore {
    config: ValidatedComplianceConfig,
    clock: Arc<dyn Clock>,
    entropy: Arc<dyn Entropy>,
    hooks: Arc<dyn ComplianceHooks>,
    index: RecordIndex,
    view: RecordView,
    available: bool,
    _owner: disk::OwnerLock,
}

impl RecordStore {
    /// Opens only the record owner, verifies history, and completes recoverable pending additions.
    pub fn open(
        config: &ValidatedComplianceConfig,
        clock: Arc<dyn Clock>,
        entropy: Arc<dyn Entropy>,
        hooks: Arc<dyn ComplianceHooks>,
    ) -> Result<Self> {
        let lock_path = config.records_lock();
        let owner = open_records(&lock_path, OpenMode::OwnerFile, hooks.as_ref())
            .map_err(|_| Error::Unavailable)?;
        let owner = disk::lock_exclusive(owner).map_err(|_| Error::Unavailable)?;
        let index = RecordIndex::open(config, clock.clone(), hooks.clone())?;
        let view = load_published(
            config,
            &index.prefix,
            clock.utc().timestamp(),
            hooks.as_ref(),
            &mut BTreeMap::new(),
        )?;
        let mut store = Self {
            config: config.clone(),
            clock,
            entropy,
            hooks,
            index,
            view,
            available: true,
            _owner: owner,
        };
        store.recover_additions()?;
        store.inventory()?;
        Ok(store)
    }
    /// Returns the last successful published snapshot without additional filesystem access.
    pub fn view(&self) -> &RecordView {
        &self.view
    }
    /// Validates and reserves before drawing a salt, then durably publishes exactly one version.
    pub fn add(&mut self, record: RecordEnvelope, actor: &str) -> Result<(RecordRef, u64)> {
        if !self.available {
            return Err(Error::Unavailable);
        }
        validate_candidate(
            &self.config,
            &self.view,
            &record,
            self.clock.utc().timestamp(),
        )?;
        text(actor, BoundKey::Actor)?;
        let placeholder = Hex64::parse(&"0".repeat(64))?;
        let size = wrapper_bytes(&StoredRecord {
            format_version: 1,
            salt: placeholder.clone(),
            commitment: placeholder,
            record: record.clone(),
        })?
        .len() as u64;
        bounds::reserve(0, size, self.config.settings().max_record_bytes, 0)?;
        let plan = AdditionPlan {
            record,
            wrapper_bytes: size,
        };
        let usage = self.inventory()?;
        reserve_addition(&plan, &usage, &self.config)?;
        let salt = Hex64::random(self.entropy.as_ref())?;
        let stored = StoredRecord {
            format_version: 1,
            commitment: record_commitment(&salt, &plan.record)?,
            salt,
            record: plan.record,
        };
        let bytes = wrapper_bytes(&stored)?;
        bounds::reserve(
            0,
            bytes.len() as u64,
            self.config.settings().max_record_bytes,
            0,
        )?;
        self.available = false;
        let result = self.persist(stored, &bytes, actor);
        if result.is_ok() {
            self.available = true;
        }
        result
    }
    fn persist(
        &mut self,
        stored: StoredRecord,
        bytes: &[u8],
        actor: &str,
    ) -> Result<(RecordRef, u64)> {
        let reference = stored.record.reference();
        let pending = pending_path(&self.config, &reference);
        self.create_file(&pending, bytes, false)?;
        self.index.stage(ComplianceStage::AfterRecordStageSync)?;
        self.index.append(RecordIndexRow::intent(
            &reference,
            stored.record.kind,
            stored.commitment.as_str(),
            actor,
        ))?;
        self.index.stage(ComplianceStage::AfterIntentSync)?;
        let row = self
            .index
            .prefix
            .rows
            .last()
            .ok_or(Error::Unavailable)?
            .clone();
        let intent = Intent {
            row,
            pending: bytes.to_vec(),
        };
        let path = final_path(&self.config, &reference);
        self.create_file(&path, bytes, true)?;
        let final_bytes = read_bytes(&path, self.hooks.as_ref())?;
        verify_final(&intent, &final_bytes)?;
        self.index.stage(ComplianceStage::AfterRecordSync)?;
        self.index.stage(ComplianceStage::BeforeCompletionRow)?;
        let sequence = self.index.append(RecordIndexRow::completion(&intent.row))?;
        self.remove_verified(&pending, bytes)?;
        self.view.insert(stored.record);
        self.view.sequence = sequence;
        self.view.observed_at = self.clock.utc().timestamp();
        Ok((reference, sequence))
    }
    fn create_file(&self, path: &Path, bytes: &[u8], final_write: bool) -> Result<()> {
        let mut file = open_records(path, OpenMode::CreateNew, self.hooks.as_ref())
            .map_err(|_| Error::Unavailable)?;
        if final_write {
            self.index.stage(ComplianceStage::DuringRecordWrite)?;
        }
        file.write_all(bytes).map_err(|_| Error::Unavailable)?;
        file.sync_all().map_err(|_| Error::Unavailable)?;
        disk::sync_parent(path).map_err(|_| Error::Unavailable)
    }
    fn remove_verified(&self, path: &Path, expected: &[u8]) -> Result<()> {
        if read_bytes(path, self.hooks.as_ref())? != expected {
            return Err(Error::Unavailable);
        }
        fs::remove_file(path).map_err(|_| Error::Unavailable)?;
        disk::sync_parent(path).map_err(|_| Error::Unavailable)
    }
    fn recover_additions(&mut self) -> Result<()> {
        let intents = self
            .index
            .prefix
            .pairing
            .pending
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for row in intents {
            self.recover_intent(row)?;
        }
        self.cleanup_pending()?;
        Ok(())
    }
    fn recover_intent(&mut self, row: RecordIndexRow) -> Result<()> {
        let reference = RecordRef::parse(&row.record_ref).map_err(|_| Error::Unavailable)?;
        let pending = pending_path(&self.config, &reference);
        let final_path = final_path(&self.config, &reference);
        let bytes = match fs::symlink_metadata(&pending) {
            Ok(_) => read_bytes(&pending, self.hooks.as_ref())?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                read_bytes(&final_path, self.hooks.as_ref())?
            }
            Err(_) => return Err(Error::Unavailable),
        };
        let stored =
            decode_and_validate_stored(&bytes, self.clock.utc().timestamp(), self.hooks.as_ref())?;
        bind_wrapper(&stored, &row)?;
        validate_predecessor(&stored.record, &self.view.heads).map_err(|_| Error::Unavailable)?;
        validate_references(&stored.record, &self.view).map_err(|_| Error::Unavailable)?;
        let intent = Intent {
            row,
            pending: bytes,
        };
        self.recover_final(&final_path, &intent)?;
        let final_bytes = read_bytes(&final_path, self.hooks.as_ref())?;
        verify_final(&intent, &final_bytes)?;
        self.index.stage(ComplianceStage::AfterRecordSync)?;
        self.index.stage(ComplianceStage::BeforeCompletionRow)?;
        self.index.append(RecordIndexRow::completion(&intent.row))?;
        self.view.insert(stored.record);
        self.view.sequence = self.index.prefix.head.sequence;
        if pending.exists() {
            self.remove_verified(&pending, &intent.pending)?;
        }
        Ok(())
    }
    fn recover_final(&self, path: &Path, intent: &Intent) -> Result<()> {
        match open_records(path, OpenMode::Read, self.hooks.as_ref()) {
            Ok(file) => {
                let observed_length = file.metadata().map_err(|_| Error::Unavailable)?.len();
                let bytes =
                    disk::read_capped(&file, observed_length, BoundKey::MaxRecordBytes.spec().max)
                        .map_err(|_| Error::Unavailable)?;
                if bytes == intent.pending {
                    return self.sync_recovered_final(&file, path);
                }
                // Leave a different complete wrapper intact for the intent's byte-binding refusal.
                if decode_and_validate_stored(
                    &bytes,
                    self.clock.utc().timestamp(),
                    self.hooks.as_ref(),
                )
                .is_ok()
                {
                    return Ok(());
                }
                fs::remove_file(path).map_err(|_| Error::Unavailable)?;
                disk::sync_parent(path).map_err(|_| Error::Unavailable)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::Unavailable),
        }
        self.create_file(path, &intent.pending, true)
    }
    fn sync_recovered_final(&self, file: &File, path: &Path) -> Result<()> {
        file.sync_all().map_err(|_| Error::Unavailable)?;
        self.index
            .stage(ComplianceStage::AfterRecoveredRecordFileSync)?;
        disk::sync_parent(path).map_err(|_| Error::Unavailable)?;
        self.index
            .stage(ComplianceStage::AfterRecoveredRecordParentSync)
    }
    fn cleanup_pending(&self) -> Result<()> {
        let root = self.config.records_dir().join(".pending");
        let entries = match fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(Error::Unavailable),
        };
        for entry in entries {
            let path = entry.map_err(|_| Error::Unavailable)?.path();
            let reference = pending_reference(&path)?;
            let bytes = read_bytes(&path, self.hooks.as_ref())?;
            if let Some(row) = self.index.prefix.pairing.published.get(&reference) {
                let stored = decode_and_validate_stored(
                    &bytes,
                    self.clock.utc().timestamp(),
                    self.hooks.as_ref(),
                )?;
                bind_wrapper(&stored, row)?;
                let final_bytes =
                    read_bytes(&final_path(&self.config, &reference), self.hooks.as_ref())?;
                if bytes != final_bytes {
                    return Err(Error::Unavailable);
                }
            }
            self.remove_verified(&path, &bytes)?;
        }
        Ok(())
    }
    fn inventory(&self) -> Result<Usage> {
        let known = self
            .view
            .records
            .keys()
            .map(|reference| final_path(&self.config, reference))
            .collect::<BTreeSet<_>>();
        let bytes = inventory_directory(
            self.config.records_dir(),
            &known,
            &self.config,
            &self.index,
            self.hooks.as_ref(),
        )?;
        bounds::reserve(0, bytes, BoundKey::MaxRecordsBytes.spec().max, 0)?;
        Ok(Usage {
            versions: self.view.records.len() as u64,
            bytes,
        })
    }
}

struct Intent {
    row: RecordIndexRow,
    pending: Vec<u8>,
}
fn verify_final(intent: &Intent, final_bytes: &[u8]) -> Result<()> {
    let stored: StoredRecord =
        serde_json::from_slice(final_bytes).map_err(|_| Error::Unavailable)?;
    if final_bytes != intent.pending || stored.commitment.as_str() != intent.row.commitment {
        return Err(Error::Unavailable);
    }
    Ok(())
}

fn pending_reference(path: &Path) -> Result<RecordRef> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Error::Unavailable)?;
    let (id, version) = name
        .strip_suffix(".json")
        .and_then(|name| name.rsplit_once('-'))
        .ok_or(Error::Unavailable)?;
    let version_number = version.parse::<u32>().map_err(|_| Error::Unavailable)?;
    if format!("{version_number:010}") != version {
        return Err(Error::Unavailable);
    }
    RecordRef::parse(&format!("{id}:{version_number}")).map_err(|_| Error::Unavailable)
}

fn inventory_directory(
    root: &Path,
    known: &BTreeSet<PathBuf>,
    config: &ValidatedComplianceConfig,
    index: &RecordIndex,
    hooks: &dyn ComplianceHooks,
) -> Result<u64> {
    let mut bytes = 0u64;
    for entry in fs::read_dir(root).map_err(|_| Error::Unavailable)? {
        let entry = entry.map_err(|_| Error::Unavailable)?;
        if root == config.records_dir() && index.unclaimed_quarantine(&entry.file_name()) {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|_| Error::Unavailable)?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            let sentinel = path.join(".ownership-check");
            disk::private_parent(&sentinel).map_err(|_| Error::Unavailable)?;
            let size = inventory_directory(&path, known, config, index, hooks)?;
            bytes = bytes.checked_add(size).ok_or(Error::Capacity)?;
        } else {
            let file =
                open_records(&path, OpenMode::Read, hooks).map_err(|_| Error::Unavailable)?;
            if path.parent() != Some(config.records_dir()) && !known.contains(&path) {
                return Err(Error::Unavailable);
            }
            bytes = bytes
                .checked_add(file.metadata().map_err(|_| Error::Unavailable)?.len())
                .ok_or(Error::Capacity)?;
        }
    }
    Ok(bytes)
}
