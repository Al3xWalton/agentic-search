//! Maintains the independent ordered record chain, its committed checkpoint and bounded recovery.
//! Published prefixes are immutable; recovery accepts only verified suffixes and final torn rows.
//! The caller retains the record owner lock for every mutating operation in this module.

#![deny(missing_docs)]

use super::{
    bounds::{self, BoundKey},
    clock,
    disk::{self, ComplianceHooks, ComplianceStage, OpenMode, QuarantineStore},
    model::{sha256, Hex64},
    record_types::{text, RecordKind, RecordRef},
    records::open_records,
    Error, Result,
};
use crate::{config::compliance::ValidatedComplianceConfig, crawler::politeness::Clock};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Counts the canonical origin checkpoint and empty index before the first addition.
pub fn initial_record_bytes() -> Result<u64> {
    Ok(Head::origin().bytes()?.len() as u64)
}

/// Ordered scalar index row; the final hash covers every preceding field and excludes the LF.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordIndexRow {
    /// Fixed format one.
    pub format_version: u64,
    /// Contiguous global sequence.
    pub sequence: u64,
    /// Previous row digest, or the runtime zero origin.
    pub previous_hash: String,
    /// Nondecreasing UTC seconds.
    pub at: i64,
    /// Closed intent, completion or tail recovery event.
    pub event: String,
    /// Bounded operator claim, or system.recovery for tail recovery.
    pub actor: String,
    /// Scalar immutable record reference, empty for recovery.
    pub record_ref: String,
    /// Closed record category, empty for recovery.
    pub record_kind: String,
    /// Salted envelope commitment, empty for recovery.
    pub commitment: String,
    /// Matched intent sequence on completion, otherwise zero.
    pub intent_sequence: u64,
    /// Torn byte count for recovery, otherwise zero.
    pub quarantined_bytes: u64,
    /// Torn byte digest for recovery, otherwise empty.
    pub quarantine_hash: String,
    /// This row's digest, omitted only when computing the unsigned encoding.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hash: String,
}

impl RecordIndexRow {
    /// Computes the domain-separated digest over the unsigned ordered struct.
    pub fn computed_hash(&self) -> Result<String> {
        let mut unsigned = self.clone();
        unsigned.hash.clear();
        let bytes = serde_json::to_vec(&unsigned).map_err(|_| Error::Unavailable)?;
        Ok(sha256(&[b"AVA619-RECORD-INDEX-v1\0", &bytes]))
    }
    /// Encodes the ordered row and one LF within the shared row cap.
    pub fn bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec(self).map_err(|_| Error::Unavailable)?;
        bytes.push(b'\n');
        BoundKey::JournalRow
            .validate(bytes.len() as u64)
            .map_err(|_| Error::Unavailable)?;
        Ok(bytes)
    }
    /// Constructs unsigned intent metadata before sequence, time and hash assignment.
    pub(crate) fn intent(
        reference: &RecordRef,
        kind: RecordKind,
        commitment: &str,
        actor: &str,
    ) -> Self {
        Self {
            format_version: 1,
            sequence: 0,
            previous_hash: String::new(),
            at: 0,
            event: "record_intent".into(),
            actor: actor.into(),
            record_ref: reference.to_string(),
            record_kind: kind.as_str().into(),
            commitment: commitment.into(),
            intent_sequence: 0,
            quarantined_bytes: 0,
            quarantine_hash: String::new(),
            hash: String::new(),
        }
    }
    /// Copies the immutable binding into the corresponding completion event.
    pub(crate) fn completion(intent: &Self) -> Self {
        let mut row = intent.clone();
        row.event = "record_added".into();
        row.intent_sequence = intent.sequence;
        row
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Atomic commitment to the last fully synced index prefix.
pub(crate) struct Head {
    /// Fixed checkpoint format one.
    pub(crate) format_version: u64,
    /// Final committed row sequence, or zero at origin.
    pub(crate) sequence: u64,
    /// Final row digest, or the runtime zero origin.
    pub(crate) hash: String,
    /// Exact committed byte count, including row terminators.
    pub(crate) byte_length: u64,
}
impl Head {
    fn origin() -> Self {
        Self {
            format_version: 1,
            sequence: 0,
            hash: "0".repeat(64),
            byte_length: 0,
        }
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec(self).map_err(|_| Error::Unavailable)?;
        bytes.push(b'\n');
        BoundKey::JournalRow
            .validate(bytes.len() as u64)
            .map_err(|_| Error::Unavailable)?;
        Ok(bytes)
    }
}

/// Verified intent/completion pairing, independent of filesystem wrappers.
#[derive(Clone, Default)]
pub(crate) struct Pairing {
    /// Uncompleted additions keyed by their unique intent sequence.
    pub(crate) pending: BTreeMap<u64, RecordIndexRow>,
    /// Completed immutable additions keyed by their record reference.
    pub(crate) published: BTreeMap<RecordRef, RecordIndexRow>,
}
impl Pairing {
    fn validate_event(&mut self, row: &RecordIndexRow) -> Result<()> {
        if row.format_version != 1 {
            return Err(Error::Unavailable);
        }
        if row.event == "tail_recovered" {
            return self.validate_recovery(row);
        }
        text(&row.actor, BoundKey::Actor).map_err(|_| Error::Unavailable)?;
        let reference = RecordRef::parse(&row.record_ref).map_err(|_| Error::Unavailable)?;
        let _: RecordKind =
            serde_json::from_value(serde_json::Value::String(row.record_kind.clone()))
                .map_err(|_| Error::Unavailable)?;
        Hex64::parse(&row.commitment).map_err(|_| Error::Unavailable)?;
        if row.quarantined_bytes != 0 || !row.quarantine_hash.is_empty() {
            return Err(Error::Unavailable);
        }
        match row.event.as_str() {
            "record_intent" => {
                if row.intent_sequence != 0
                    || self.published.contains_key(&reference)
                    || self
                        .pending
                        .values()
                        .any(|intent| intent.record_ref == row.record_ref)
                {
                    return Err(Error::Unavailable);
                }
                self.pending.insert(row.sequence, row.clone());
            }
            "record_added" => {
                let intent = self
                    .pending
                    .get(&row.intent_sequence)
                    .ok_or(Error::Unavailable)?;
                if (
                    intent.record_ref.as_str(),
                    intent.record_kind.as_str(),
                    intent.commitment.as_str(),
                    intent.actor.as_str(),
                ) != (
                    row.record_ref.as_str(),
                    row.record_kind.as_str(),
                    row.commitment.as_str(),
                    row.actor.as_str(),
                ) || self.published.contains_key(&reference)
                {
                    return Err(Error::Unavailable);
                }
                self.pending.remove(&row.intent_sequence);
                self.published.insert(reference, row.clone());
            }
            _ => return Err(Error::Unavailable),
        }
        Ok(())
    }
    fn validate_recovery(&self, row: &RecordIndexRow) -> Result<()> {
        Hex64::parse(&row.quarantine_hash).map_err(|_| Error::Unavailable)?;
        BoundKey::JournalRow
            .validate(row.quarantined_bytes)
            .map_err(|_| Error::Unavailable)?;
        if row.actor != "system.recovery"
            || !row.record_ref.is_empty()
            || !row.record_kind.is_empty()
            || !row.commitment.is_empty()
            || row.intent_sequence != 0
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
}

/// Verified complete rows with any strictly uncommitted partial tail kept separate.
pub(crate) struct Prefix {
    /// Canonical complete rows in index order.
    pub(crate) rows: Vec<RecordIndexRow>,
    /// Replayed event bindings for publication and recovery.
    pub(crate) pairing: Pairing,
    /// Verified complete boundary, possibly beyond the published checkpoint for a writer.
    pub(crate) head: Head,
    tail: Vec<u8>,
}

fn checkpoint_agrees(sequence: u64, hash: &str, length: u64, head: &Head) -> bool {
    (sequence, hash, length) == (head.sequence, head.hash.as_str(), head.byte_length)
}

/// Hardened read of a canonical bounded checkpoint without creating files or directories.
pub(crate) fn read_head(
    config: &ValidatedComplianceConfig,
    hooks: &dyn ComplianceHooks,
) -> Result<(Head, Vec<u8>)> {
    let file = open_records(
        &config.records_dir().join("head.json"),
        OpenMode::Read,
        hooks,
    )
    .map_err(|_| Error::Unavailable)?;
    let bytes = disk::read_bounded(file, BoundKey::JournalRow.spec().max)
        .map_err(|_| Error::Unavailable)?;
    hooks
        .at(ComplianceStage::BeforeDecode)
        .map_err(|_| Error::Unavailable)?;
    let head: Head = serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)?;
    Hex64::parse(&head.hash).map_err(|_| Error::Unavailable)?;
    bounds::validate_range(head.byte_length, 0, BoundKey::MaxRecordsBytes.spec().max)
        .map_err(|_| Error::Unavailable)?;
    if head.format_version != 1 || head.bytes()? != bytes {
        return Err(Error::Unavailable);
    }
    Ok((head, bytes))
}

/// Reads exactly the committed byte count and verifies it against the captured checkpoint.
pub(crate) fn read_prefix(
    config: &ValidatedComplianceConfig,
    head: &Head,
    hooks: &dyn ComplianceHooks,
    clock: &dyn Clock,
) -> Result<(Prefix, i64)> {
    let file = open_records(
        &config.records_dir().join("index.jsonl"),
        OpenMode::Read,
        hooks,
    )
    .map_err(|_| Error::Unavailable)?;
    let mut bytes = Vec::new();
    file.take(head.byte_length)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Unavailable)?;
    if bytes.len() as u64 != head.byte_length {
        return Err(Error::Unavailable);
    }
    let observed_at = clock.utc().timestamp();
    Ok((verify(&bytes, head, observed_at, hooks)?, observed_at))
}

fn verify(bytes: &[u8], head: &Head, now: i64, hooks: &dyn ComplianceHooks) -> Result<Prefix> {
    if (bytes.len() as u64) < head.byte_length {
        return Err(Error::Unavailable);
    }
    let mut result = Prefix {
        rows: Vec::new(),
        pairing: Pairing::default(),
        head: Head::origin(),
        tail: Vec::new(),
    };
    let mut committed = checkpoint_agrees(0, &result.head.hash, 0, head);
    let mut last_at = None;
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        let end = result
            .head
            .byte_length
            .checked_add(line.len() as u64)
            .ok_or(Error::Unavailable)?;
        if line.last() != Some(&b'\n') {
            if end < head.byte_length || !committed {
                return Err(Error::Unavailable);
            }
            BoundKey::JournalRow
                .validate(line.len() as u64)
                .map_err(|_| Error::Unavailable)?;
            result.tail = line.to_vec();
            break;
        }
        BoundKey::JournalRow
            .validate(line.len() as u64)
            .map_err(|_| Error::Unavailable)?;
        hooks
            .at(ComplianceStage::BeforeDecode)
            .map_err(|_| Error::Unavailable)?;
        let row: RecordIndexRow = serde_json::from_slice(line).map_err(|_| Error::Unavailable)?;
        let expected_sequence = result
            .head
            .sequence
            .checked_add(1)
            .ok_or(Error::Unavailable)?;
        verify_row(&row, expected_sequence, &result.head.hash, last_at, now)?;
        if row.bytes()? != line {
            return Err(Error::Unavailable);
        }
        result.pairing.validate_event(&row)?;
        result.head = Head {
            format_version: 1,
            sequence: row.sequence,
            hash: row.hash.clone(),
            byte_length: end,
        };
        if end == head.byte_length {
            committed = checkpoint_agrees(row.sequence, &row.hash, end, head);
        }
        if end >= head.byte_length && !committed {
            return Err(Error::Unavailable);
        }
        last_at = Some(row.at);
        result.rows.push(row);
    }
    if !committed {
        return Err(Error::Unavailable);
    }
    Ok(result)
}

fn verify_row(
    row: &RecordIndexRow,
    expected_sequence: u64,
    previous: &str,
    last_at: Option<i64>,
    now: i64,
) -> Result<()> {
    Hex64::parse(&row.hash).map_err(|_| Error::Unavailable)?;
    clock::instant(row.at).map_err(|_| Error::Unavailable)?;
    if row.sequence != expected_sequence
        || row.previous_hash != previous
        || row.computed_hash()? != row.hash
    {
        return Err(Error::Unavailable);
    }
    if row.at > now || last_at.is_some_and(|last| row.at < last) {
        return Err(Error::Unavailable);
    }
    Ok(())
}

/// Append-only index implementation used only while the separate record owner is held.
pub(crate) struct RecordIndex {
    config: ValidatedComplianceConfig,
    clock: Arc<dyn Clock>,
    hooks: Arc<dyn ComplianceHooks>,
    /// Last fully verified in-memory prefix, including recovered additions.
    pub(crate) prefix: Prefix,
}

struct ObservedTail {
    bytes: Vec<u8>,
    base_sequence: u64,
}
impl RecordIndex {
    /// Initializes an empty store or verifies and recovers only its uncommitted suffix.
    pub(crate) fn open(
        config: &ValidatedComplianceConfig,
        clock: Arc<dyn Clock>,
        hooks: Arc<dyn ComplianceHooks>,
    ) -> Result<Self> {
        let mut index = Self {
            config: config.clone(),
            clock,
            hooks,
            prefix: Prefix {
                rows: Vec::new(),
                pairing: Pairing::default(),
                head: Head::origin(),
                tail: Vec::new(),
            },
        };
        index.initialize()?;
        index.sweep_owned_temps()?;
        let (head, _) = read_head(config, index.hooks.as_ref())?;
        let file = open_records(
            &config.records_dir().join("index.jsonl"),
            OpenMode::Read,
            index.hooks.as_ref(),
        )
        .map_err(|_| Error::Unavailable)?;
        let bytes = disk::read_bounded(file, BoundKey::MaxRecordsBytes.spec().max)
            .map_err(|_| Error::Unavailable)?;
        index.prefix = verify(
            &bytes,
            &head,
            index.clock.utc().timestamp(),
            index.hooks.as_ref(),
        )?;
        let observed_tail = if index.prefix.tail.is_empty() {
            None
        } else {
            Some(index.recover_tail()?)
        };
        index.finish_tail(observed_tail)?;
        index.scan_quarantines()?;
        if index.prefix.head.byte_length != head.byte_length {
            index.checkpoint()?;
        }
        Ok(index)
    }
    fn initialize(&mut self) -> Result<()> {
        let root = self.config.records_dir();
        let fresh = match fs::symlink_metadata(root) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => fs::read_dir(root)
                .map_err(|_| Error::Unavailable)?
                .next()
                .is_none(),
            _ => return Err(Error::Unavailable),
        };
        if fresh {
            let path = root.join("index.jsonl");
            let file = open_records(&path, OpenMode::CreateNew, self.hooks.as_ref())
                .map_err(|_| Error::Unavailable)?;
            file.sync_all().map_err(|_| Error::Unavailable)?;
            disk::sync_parent(&path).map_err(|_| Error::Unavailable)?;
            self.checkpoint()?;
        }
        Ok(())
    }
    /// Propagates a failure at an actual persistence boundary before acknowledgement.
    pub(crate) fn stage(&self, stage: ComplianceStage) -> Result<()> {
        self.hooks.at(stage).map_err(|_| Error::Unavailable)?;
        Ok(())
    }
    /// Validates, syncs and checkpoints one closed event before returning its sequence.
    pub(crate) fn append(&mut self, mut row: RecordIndexRow) -> Result<u64> {
        row.sequence = self
            .prefix
            .head
            .sequence
            .checked_add(1)
            .ok_or(Error::Unavailable)?;
        row.previous_hash = self.prefix.head.hash.clone();
        row.at = self.clock.utc().timestamp();
        row.hash = row.computed_hash()?;
        verify_row(
            &row,
            row.sequence,
            &row.previous_hash,
            self.prefix.rows.last().map(|last| last.at),
            row.at,
        )?;
        let mut pairing = self.prefix.pairing.clone();
        pairing.validate_event(&row)?;
        let bytes = row.bytes()?;
        let length = bounds::reserve(
            self.prefix.head.byte_length,
            bytes.len() as u64,
            BoundKey::MaxRecordsBytes.spec().max,
            0,
        )?;
        let mut file = open_records(
            &self.config.records_dir().join("index.jsonl"),
            OpenMode::Append,
            self.hooks.as_ref(),
        )
        .map_err(|_| Error::Unavailable)?;
        if file.metadata().map_err(|_| Error::Unavailable)?.len() != self.prefix.head.byte_length {
            return Err(Error::Unavailable);
        }
        file.write_all(&bytes).map_err(|_| Error::Unavailable)?;
        file.sync_all().map_err(|_| Error::Unavailable)?;
        self.stage(ComplianceStage::AfterJournalSync)?;
        self.prefix.head = Head {
            format_version: 1,
            sequence: row.sequence,
            hash: row.hash.clone(),
            byte_length: length,
        };
        self.prefix.pairing = pairing;
        self.prefix.rows.push(row);
        self.checkpoint()?;
        Ok(self.prefix.head.sequence)
    }
    fn checkpoint(&self) -> Result<()> {
        let (path, mut file) = self.temp("record-head")?;
        file.write_all(&self.prefix.head.bytes()?)
            .map_err(|_| Error::Unavailable)?;
        file.sync_all().map_err(|_| Error::Unavailable)?;
        let final_path = self.config.records_dir().join("head.json");
        match fs::symlink_metadata(&final_path) {
            Ok(_) => {
                open_records(&final_path, OpenMode::Read, self.hooks.as_ref())
                    .map_err(|_| Error::Unavailable)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::Unavailable),
        }
        fs::rename(&path, &final_path).map_err(|_| Error::Unavailable)?;
        self.stage(ComplianceStage::AfterHeadRename)?;
        disk::sync_parent(&final_path).map_err(|_| Error::Unavailable)?;
        self.stage(ComplianceStage::AfterHeadSync)
    }
    fn temp(&self, family: &str) -> Result<(PathBuf, File)> {
        let counter = TEMP_SEQUENCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| Error::Unavailable)?;
        let path = self
            .config
            .records_dir()
            .join(format!("{family}.{}.{counter}.tmp", std::process::id()));
        let file = open_records(&path, OpenMode::CreateNew, self.hooks.as_ref())
            .map_err(|_| Error::Unavailable)?;
        Ok((path, file))
    }
    fn sweep_owned_temps(&self) -> Result<()> {
        for entry in fs::read_dir(self.config.records_dir()).map_err(|_| Error::Unavailable)? {
            let entry = entry.map_err(|_| Error::Unavailable)?;
            if entry.file_name().to_str().is_some_and(|name| {
                disk::owned_temp_name(name, &["record-head", "record-recovery"])
            }) {
                open_records(&entry.path(), OpenMode::Read, self.hooks.as_ref())
                    .map_err(|_| Error::Unavailable)?;
                fs::remove_file(entry.path()).map_err(|_| Error::Unavailable)?;
                disk::sync_parent(&entry.path()).map_err(|_| Error::Unavailable)?;
            }
        }
        Ok(())
    }
    fn recover_tail(&mut self) -> Result<ObservedTail> {
        let tail = ObservedTail {
            bytes: self.prefix.tail.clone(),
            base_sequence: self.prefix.head.sequence,
        };
        let hash = sha256(&[&tail.bytes]);
        let path = self
            .config
            .records_dir()
            .join(format!("quarantine-{}-{hash}.bin", tail.base_sequence));
        self.write_quarantine(&path, &tail.bytes)?;
        let file = open_records(
            &self.config.records_dir().join("index.jsonl"),
            OpenMode::Append,
            self.hooks.as_ref(),
        )
        .map_err(|_| Error::Unavailable)?;
        file.set_len(self.prefix.head.byte_length)
            .map_err(|_| Error::Unavailable)?;
        file.sync_all().map_err(|_| Error::Unavailable)?;
        self.prefix.tail.clear();
        self.stage(ComplianceStage::AfterTailTruncate)?;
        Ok(tail)
    }
    fn finish_tail(&mut self, observed_tail: Option<ObservedTail>) -> Result<()> {
        if let Some(tail) = observed_tail {
            self.append(RecordIndexRow {
                format_version: 1,
                sequence: 0,
                previous_hash: String::new(),
                at: 0,
                event: "tail_recovered".into(),
                actor: "system.recovery".into(),
                record_ref: String::new(),
                record_kind: String::new(),
                commitment: String::new(),
                intent_sequence: 0,
                quarantined_bytes: tail.bytes.len() as u64,
                quarantine_hash: sha256(&[&tail.bytes]),
                hash: String::new(),
            })?;
        }
        Ok(())
    }
    fn accounted_quarantine(&self, name: &std::ffi::OsStr) -> Option<&RecordIndexRow> {
        let name = name.to_str()?;
        let rest = name.strip_prefix("quarantine-")?;
        let (base, suffix) = rest.split_once('-')?;
        let sequence = base.parse::<u64>().ok()?;
        self.prefix.rows.iter().find(|row| {
            row.event == "tail_recovered"
                && sequence.checked_add(1) == Some(row.sequence)
                && sequence.to_string() == base
                && suffix == format!("{}.bin", row.quarantine_hash)
        })
    }
    /// Classifies root artefacts from verified rows without inspecting an unclaimed inode.
    pub(crate) fn unclaimed_quarantine(&self, name: &std::ffi::OsStr) -> bool {
        name.as_encoded_bytes().starts_with(b"quarantine-")
            && self.accounted_quarantine(name).is_none()
    }
    fn scan_quarantines(&self) -> Result<()> {
        let mut count = 0;
        for entry in fs::read_dir(self.config.records_dir()).map_err(|_| Error::Unavailable)? {
            let entry = entry.map_err(|_| Error::Unavailable)?;
            let name = entry.file_name();
            if self.unclaimed_quarantine(&name) {
                count += 1;
                continue;
            }
            if let Some(row) = self.accounted_quarantine(&name) {
                let file = open_records(&entry.path(), OpenMode::Read, self.hooks.as_ref())
                    .map_err(|_| Error::Unavailable)?;
                let bytes = disk::read_bounded(file, BoundKey::JournalRow.spec().max)
                    .map_err(|_| Error::Unavailable)?;
                if bytes.len() as u64 != row.quarantined_bytes
                    || sha256(&[&bytes]) != row.quarantine_hash
                {
                    return Err(Error::Unavailable);
                }
            }
        }
        self.hooks
            .unclaimed_quarantines(QuarantineStore::Records, count);
        Ok(())
    }
    fn write_quarantine(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        match open_records(path, OpenMode::Read, self.hooks.as_ref()) {
            Ok(file) => {
                let present = disk::read_bounded(file, BoundKey::JournalRow.spec().max)
                    .map_err(|_| Error::Unavailable)?;
                if present == bytes {
                    return Ok(());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::Unavailable),
        }
        let (temp, mut file) = self.temp("record-recovery")?;
        file.write_all(bytes).map_err(|_| Error::Unavailable)?;
        file.sync_all().map_err(|_| Error::Unavailable)?;
        fs::rename(temp, path).map_err(|_| Error::Unavailable)?;
        disk::sync_parent(path).map_err(|_| Error::Unavailable)
    }
}
