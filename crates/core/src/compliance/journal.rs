//! Verifies a canonical hash chain against a separately durable checkpoint before publishing tickets.
//! Only uncommitted torn suffixes may be quarantined and truncated; committed bytes are never repaired.
//! An owner capable of rewriting both the complete chain and checkpoint can recompute unkeyed hashes.

#![deny(missing_docs)]

/// Read-only snapshots of a verified committed prefix, safe alongside the journal owner.
pub mod view;

use super::{
    auth,
    bounds::{self, BoundKey, TextClass},
    clock,
    disk::{self, ComplianceHooks, ComplianceStage, OpenMode, QuarantineStore},
    listed::ListedMetadata,
    model::{
        sha256, DecisionKind, DocumentKey, Ground, Hex64, RequesterType, Route, TicketId,
        TicketState,
    },
    Error, Result,
};
use crate::{config::compliance::ValidatedComplianceConfig, crawler::politeness::Clock};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

/// Closed events, including reserved record names and a typed uncommitted-tail recovery audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventName {
    /// New immutable receipt.
    Received,
    /// Durable acknowledgement prepared.
    Acknowledged,
    /// Automatic moderation admission.
    Queued,
    /// Identity evidence requested.
    IdentityRequested,
    /// Identity evidence confirmed.
    IdentityConfirmed,
    /// Clarification requested.
    ClarificationRequested,
    /// Clarification received.
    ClarificationReceived,
    /// Timely reasoned extension notification.
    ExtensionNotified,
    /// Reviewed decision recorded before applying any rule.
    Decided,
    /// Exact rule operation prepared durably.
    ActionIntent,
    /// Provisional or determination operation completed without an actioned lifecycle.
    RulesCommitted,
    /// A rule-bearing grant completed durably.
    Actioned,
    /// Authenticated appeal recorded.
    Appealed,
    /// Reversal operation prepared durably.
    ReversalIntent,
    /// Reversal and do-not-reapply markers completed durably.
    Reversed,
    /// Reasoned appeal disposal without a rule change.
    Upheld,
    /// Enquiries and essential progress communication recorded.
    ProgressCommunicated,
    /// Final authenticated closure.
    Closed,
    /// Retention-authorised personal-file deletion started.
    PurgeIntent,
    /// All managed personal revisions removed.
    Purged,
    /// Aggregate listed-file access audit, never membership data.
    ListAccessed,
    /// Reserved immutable-record intent name; Part C cannot author it.
    RecordIntent,
    /// Reserved immutable-record completion name; Part C cannot author it.
    RecordAdded,
    /// Reserved review name; Part C cannot author it.
    ReviewOpened,
    /// Uncommitted torn bytes were preserved privately and removed from the append position.
    TailRecovered,
}

macro_rules! row_fields {
    ($($(#[$doc:meta])* $field:ident: $type:ty),* $(,)?) => {
        /// Exact scalar chain row. Field declaration order is its canonical on-disk order.
        /// The final two fields describe quarantined torn bytes and are zero/empty otherwise.
        #[derive(Clone, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct JournalRow {
            $($(#[$doc])* pub $field: $type,)*
            /// SHA-256 over the domain-separated canonical unsigned row.
            pub hash: String,
        }
        #[derive(Serialize)]
        struct UnsignedRow<'a> { $($field: &'a $type,)* }
        impl JournalRow {
            fn unsigned(&self) -> UnsignedRow<'_> { UnsignedRow { $($field: &self.$field,)* } }
        }
    };
}
row_fields! {
    /// Sole supported journal format version.
    format_version: u64,
    /// One-based contiguous sequence.
    sequence: u64,
    /// Preceding row's hash, or 64 zeros for the first row.
    previous_hash: String,
    /// Nondecreasing event time in integer UTC seconds.
    at: i64,
    /// Immutable receipt UTC seconds, or -1 for system metadata rows.
    received_at: i64,
    /// Closed lifecycle or operational event.
    event: EventName,
    /// Random ticket capability, empty only for system metadata rows.
    ticket_id: String,
    /// Closed route spelling, empty for system metadata.
    route: String,
    /// Closed requester relationship, empty for system metadata.
    requester_type: String,
    /// Closed resulting lifecycle, empty for system metadata.
    state: String,
    /// Operational alias or reserved system actor; no authenticated-person claim.
    actor: String,
    /// Closed decision kind, or empty.
    decision: String,
    /// Closed serving ground or duplicate-policy clause, never free-form reasons.
    reason_code: String,
    /// Disregard policy version only.
    policy_version: String,
    /// Comma-joined, sorted, distinct public document hashes, never raw URLs.
    asset_ids: String,
    /// Referenced immutable personal revision, or zero for metadata-only rows.
    payload_sequence: u64,
    /// Salted personal commitment, empty for metadata-only rows.
    commitment: String,
    /// Durable intent's sequence, or zero when no operation is referenced.
    intent_sequence: u64,
    /// Persisted rule activation UTC seconds, or -1 when inapplicable.
    effective_at: i64,
    /// Optional capability reference, syntactically checked without public lookup.
    related_ticket_id: String,
    /// Reserved scalar immutable-record reference.
    record_ref: String,
    /// Aggregate list version for list_accessed only.
    list_version: String,
    /// Aggregate URL-entry count for list_accessed only.
    url_count: u64,
    /// Aggregate host-entry count for list_accessed only.
    host_count: u64,
    /// Exact quarantined torn-byte length for tail_recovered only.
    quarantined_bytes: u64,
    /// SHA-256 of quarantined bytes, not those bytes, for tail_recovered only.
    quarantine_hash: String,
}

impl JournalRow {
    pub(crate) fn empty(event: EventName, at: i64) -> Self {
        Self {
            format_version: 1,
            sequence: 0,
            previous_hash: String::new(),
            at,
            received_at: -1,
            event,
            ticket_id: String::new(),
            route: String::new(),
            requester_type: String::new(),
            state: String::new(),
            actor: String::new(),
            decision: String::new(),
            reason_code: String::new(),
            policy_version: String::new(),
            asset_ids: String::new(),
            payload_sequence: 0,
            commitment: String::new(),
            intent_sequence: 0,
            effective_at: -1,
            related_ticket_id: String::new(),
            record_ref: String::new(),
            list_version: String::new(),
            url_count: 0,
            host_count: 0,
            quarantined_bytes: 0,
            quarantine_hash: String::new(),
            hash: String::new(),
        }
    }
    /// Computes the exact unsigned-row digest; useful for independent verified-history inspection.
    pub fn computed_hash(&self) -> Result<String> {
        let bytes = serde_json::to_vec(&self.unsigned()).map_err(|_| Error::Unavailable)?;
        Ok(sha256(&[b"AVA619-JOURNAL-v1\0", &bytes]))
    }
    /// Returns this row's sorted asset keys after strict syntax and uniqueness validation.
    pub fn documents(&self) -> Result<Vec<DocumentKey>> {
        if self.asset_ids.is_empty() {
            return Ok(Vec::new());
        }
        let keys = self
            .asset_ids
            .split(',')
            .map(DocumentKey::parse)
            .collect::<Result<Vec<_>>>()?;
        BoundKey::Urls.validate(keys.len() as u64)?;
        if !keys.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(Error::InvalidInput);
        }
        Ok(keys)
    }
    pub(crate) fn bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec(self).map_err(|_| Error::Unavailable)?;
        bytes.push(b'\n');
        BoundKey::JournalRow
            .validate(bytes.len() as u64)
            .map_err(|_| Error::Capacity)?;
        Ok(bytes)
    }
    fn validate_metadata(&self) -> Result<()> {
        if self.format_version != 1 {
            return Err(Error::Unavailable);
        }
        Hex64::parse(&self.previous_hash)?;
        Hex64::parse(&self.hash)?;
        clock::instant(self.at)?;
        if self.ticket_id.is_empty() {
            return self.validate_system();
        }
        TicketId::parse(&self.ticket_id)?;
        Route::parse(&self.route)?;
        RequesterType::parse(&self.requester_type)?;
        TicketState::parse(&self.state)?;
        clock::instant(self.received_at)?;
        if self.received_at > self.at {
            return Err(Error::Unavailable);
        }
        if !matches!(self.actor.as_str(), "system.intake" | "system.recovery") {
            auth::actor(&self.actor)?;
        }
        self.validate_ticket_fields()?;
        self.validate_event_fields()
    }
    fn validate_event_fields(&self) -> Result<()> {
        use EventName as E;
        let personal = matches!(
            self.event,
            E::Received
                | E::IdentityRequested
                | E::IdentityConfirmed
                | E::ClarificationRequested
                | E::ClarificationReceived
                | E::ExtensionNotified
                | E::Decided
                | E::ActionIntent
                | E::Appealed
                | E::ReversalIntent
                | E::Upheld
                | E::ProgressCommunicated
                | E::Closed
        );
        let rule = matches!(
            self.event,
            E::ActionIntent | E::RulesCommitted | E::Actioned | E::ReversalIntent | E::Reversed
        );
        let operation = rule || matches!(self.event, E::PurgeIntent | E::Purged);
        if personal != (self.payload_sequence != 0)
            || operation != (self.intent_sequence != 0)
            || rule != !self.asset_ids.is_empty()
            || rule != (self.effective_at != -1)
            || (!matches!(self.event, E::Decided | E::Appealed)
                && !self.related_ticket_id.is_empty())
        {
            return Err(Error::Unavailable);
        }
        if rule {
            Ground::parse(&self.reason_code)?;
            let permitted = match self.event {
                E::Actioned | E::ReversalIntent | E::Reversed => self.decision == "granted",
                _ => matches!(
                    self.decision.as_str(),
                    "" | "granted" | "not_intimate_image" | "no_standing"
                ),
            };
            if !permitted || !self.policy_version.is_empty() {
                return Err(Error::Unavailable);
            }
        } else if self.event == E::Decided {
            match DecisionKind::parse(&self.decision)? {
                DecisionKind::ManifestlyUnfounded => {
                    if self.policy_version.is_empty()
                        || self.reason_code != "duplicate_without_new_information"
                        || self.related_ticket_id.is_empty()
                    {
                        return Err(Error::Unavailable);
                    }
                }
                kind => {
                    if !self.policy_version.is_empty()
                        || !self.related_ticket_id.is_empty()
                        || (kind == DecisionKind::Refused && !self.reason_code.is_empty())
                    {
                        return Err(Error::Unavailable);
                    }
                }
            }
        } else if !self.decision.is_empty()
            || !self.reason_code.is_empty()
            || !self.policy_version.is_empty()
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    fn validate_ticket_fields(&self) -> Result<()> {
        if !self.list_version.is_empty()
            || self.url_count != 0
            || self.host_count != 0
            || !self.record_ref.is_empty()
            || self.quarantined_bytes != 0
            || !self.quarantine_hash.is_empty()
            || matches!(
                self.event,
                EventName::ListAccessed
                    | EventName::TailRecovered
                    | EventName::RecordIntent
                    | EventName::RecordAdded
                    | EventName::ReviewOpened
            )
        {
            return Err(Error::Unavailable);
        }
        if !self.decision.is_empty() {
            DecisionKind::parse(&self.decision)?;
        }
        if !self.reason_code.is_empty() && self.reason_code != "duplicate_without_new_information" {
            Ground::parse(&self.reason_code)?;
        }
        if !self.policy_version.is_empty() {
            bounds::text(&self.policy_version, BoundKey::Slug, TextClass::Slug)?;
            if self.decision != "manifestly_unfounded"
                || self.reason_code != "duplicate_without_new_information"
            {
                return Err(Error::Unavailable);
            }
        }
        self.documents()?;
        if (self.payload_sequence == 0) != self.commitment.is_empty() {
            return Err(Error::Unavailable);
        }
        if !self.commitment.is_empty() {
            Hex64::parse(&self.commitment)?;
        }
        if !self.related_ticket_id.is_empty() {
            TicketId::parse(&self.related_ticket_id)?;
        }
        if self.effective_at != -1 {
            clock::instant(self.effective_at)?;
        }
        Ok(())
    }
    fn validate_system(&self) -> Result<()> {
        if !self.route.is_empty()
            || !self.requester_type.is_empty()
            || !self.state.is_empty()
            || self.received_at != -1
            || !self.decision.is_empty()
            || !self.reason_code.is_empty()
            || !self.policy_version.is_empty()
            || !self.asset_ids.is_empty()
            || self.payload_sequence != 0
            || !self.commitment.is_empty()
            || self.intent_sequence != 0
            || self.effective_at != -1
            || !self.related_ticket_id.is_empty()
            || !self.record_ref.is_empty()
        {
            return Err(Error::Unavailable);
        }
        match self.event {
            EventName::ListAccessed => {
                if self.actor != "system.list"
                    || self.quarantined_bytes != 0
                    || !self.quarantine_hash.is_empty()
                {
                    return Err(Error::Unavailable);
                }
                bounds::text(&self.list_version, BoundKey::Slug, TextClass::Slug)?;
                BoundKey::ListEntries.validate(
                    self.url_count
                        .checked_add(self.host_count)
                        .ok_or(Error::Unavailable)?,
                )?;
            }
            EventName::TailRecovered => {
                if self.actor != "system.recovery"
                    || !self.list_version.is_empty()
                    || self.url_count != 0
                    || self.host_count != 0
                {
                    return Err(Error::Unavailable);
                }
                BoundKey::JournalRow.validate(self.quarantined_bytes)?;
                Hex64::parse(&self.quarantine_hash)?;
            }
            _ => return Err(Error::Unavailable),
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    format_version: u64,
    sequence: u64,
    hash: String,
    byte_length: u64,
}

struct VerifiedBytes<'a> {
    rows: Vec<JournalRow>,
    complete_length: u64,
    tail: Option<&'a [u8]>,
}

/// One private journal owner, intended for blocking startup and serialized transaction work.
pub struct Journal {
    root: PathBuf,
    head: Head,
    rows: Vec<JournalRow>,
    config: ValidatedComplianceConfig,
    hooks: Arc<dyn ComplianceHooks>,
    clock: Arc<dyn Clock>,
    recovered_tail: Option<ObservedTail>,
    _owner: disk::OwnerLock,
}

struct ObservedTail {
    bytes: Vec<u8>,
    base_sequence: u64,
}
impl Journal {
    /// Opens and verifies all committed bytes; valid crash suffixes are adopted and torn ones quarantined.
    /// A missing or invalid initialized store fails without modifying its committed prefix.
    pub fn open(
        config: &ValidatedComplianceConfig,
        clock: Arc<dyn Clock>,
        hooks: Arc<dyn ComplianceHooks>,
    ) -> Result<Self> {
        let mut journal = Self::open_unpublished(config, clock, hooks)?;
        journal.finish_recovery()?;
        Ok(journal)
    }

    // Case startup defers checkpoint adoption until payload verification and action reconciliation.
    pub(crate) fn open_unpublished(
        config: &ValidatedComplianceConfig,
        clock: Arc<dyn Clock>,
        hooks: Arc<dyn ComplianceHooks>,
    ) -> Result<Self> {
        let root = config.journal_dir().to_owned();
        let fresh = !root.exists();
        let owner = open_journal(
            &root.join("owner.lock"),
            OpenMode::OwnerFile,
            hooks.as_ref(),
            None,
        )
        .map_err(|_| Error::Unavailable)?;
        let owner = disk::lock_exclusive(owner).map_err(|_| Error::Unavailable)?;
        let mut journal = Self {
            root,
            head: Head {
                format_version: 1,
                sequence: 0,
                hash: "0".repeat(64),
                byte_length: 0,
            },
            rows: Vec::new(),
            config: config.clone(),
            hooks,
            clock,
            recovered_tail: None,
            _owner: owner,
        };
        journal.sweep_owned_temps()?;
        if fresh {
            journal.initialize()?;
        } else {
            journal.load()?;
        }
        Ok(journal)
    }

    /// Returns the verified chain; consumers derive projections and never accept a side database.
    pub fn rows(&self) -> &[JournalRow] {
        &self.rows
    }
    /// Returns the durable committed byte length, excluding quarantined crash artefacts.
    pub fn byte_length(&self) -> u64 {
        self.head.byte_length
    }
    /// Returns the last committed sequence, zero for an empty initialized journal.
    pub fn sequence(&self) -> u64 {
        self.head.sequence
    }
    /// Returns the last event time, or no timestamp for an empty initialized journal.
    pub fn last_at(&self) -> Option<i64> {
        self.rows.last().map(|row| row.at)
    }

    pub(crate) fn prepare_rows(&self, mut rows: Vec<JournalRow>) -> Result<Vec<JournalRow>> {
        let mut sequence = self.head.sequence;
        let mut previous = self.head.hash.clone();
        let mut last_at = self.last_at();
        let now = self.clock.utc().timestamp();
        for row in &mut rows {
            sequence = sequence.checked_add(1).ok_or(Error::Capacity)?;
            row.sequence = sequence;
            row.previous_hash = previous;
            row.hash = row.computed_hash()?;
            verify_time(row, last_at, now)?;
            row.validate_metadata()?;
            row.bytes()?;
            previous = row.hash.clone();
            last_at = Some(row.at);
        }
        Ok(rows)
    }

    pub(crate) fn append(&mut self, row: JournalRow) -> Result<()> {
        self.append_tracked(row, &mut disk::WriteProgress::default())
    }

    pub(crate) fn append_tracked(
        &mut self,
        row: JournalRow,
        progress: &mut disk::WriteProgress,
    ) -> Result<()> {
        verify_link(
            &row,
            self.head
                .sequence
                .checked_add(1)
                .ok_or(Error::Unavailable)?,
            &self.head.hash,
        )?;
        verify_time(&row, self.last_at(), self.clock.utc().timestamp())?;
        let bytes = row.bytes()?;
        let length = bounds::reserve(
            self.head.byte_length,
            bytes.len() as u64,
            self.config.settings().max_journal_bytes,
            0,
        )?;
        let path = self.root.join("events.jsonl");
        let mut file = open_journal(&path, OpenMode::Append, self.hooks.as_ref(), Some(progress))
            .map_err(|_| Error::Unavailable)?;
        progress.mark_started();
        file.write_all(&bytes).map_err(|_| Error::Unavailable)?;
        file.sync_all().map_err(|_| Error::Unavailable)?;
        self.hooks
            .at(ComplianceStage::AfterJournalSync)
            .map_err(|_| Error::Unavailable)?;
        let head = Head {
            format_version: 1,
            sequence: row.sequence,
            hash: row.hash.clone(),
            byte_length: length,
        };
        self.write_head(&head)?;
        self.head = head;
        self.rows.push(row);
        Ok(())
    }

    /// Appends a bounded aggregate audit event after a configured list has become serving-active.
    /// An audit failure must close compliance without unloading successfully established serving rules.
    pub fn record_list_access(&mut self, metadata: &ListedMetadata) -> Result<()> {
        let mut row = JournalRow::empty(EventName::ListAccessed, self.clock.utc().timestamp());
        row.actor = "system.list".into();
        row.list_version = metadata.version.clone();
        row.url_count = metadata.url_count;
        row.host_count = metadata.host_count;
        let row = self.prepare_rows(vec![row])?.remove(0);
        bounds::reserve(
            self.head.byte_length,
            row.bytes()?.len() as u64,
            self.config.settings().max_journal_bytes,
            BoundKey::ReservedJournalBytes.spec().min,
        )?;
        self.append(row)
    }

    fn initialize(&mut self) -> Result<()> {
        let path = self.root.join("events.jsonl");
        let file = open_journal(&path, OpenMode::CreateNew, self.hooks.as_ref(), None)
            .map_err(|_| Error::Unavailable)?;
        file.sync_all().map_err(|_| Error::Unavailable)?;
        disk::sync_parent(&path).map_err(|_| Error::Unavailable)?;
        self.write_head(&self.head)
    }

    fn load(&mut self) -> Result<()> {
        let head = self.read_head()?;
        let file = open_journal(
            &self.root.join("events.jsonl"),
            OpenMode::Read,
            self.hooks.as_ref(),
            None,
        )
        .map_err(|_| Error::Unavailable)?;
        let bytes = disk::read_bounded(file, self.config.settings().max_journal_bytes)
            .map_err(|_| Error::Unavailable)?;
        let VerifiedBytes {
            rows,
            complete_length,
            tail,
        } = self.verify_bytes(&bytes, &head)?;
        self.rows = rows;
        self.head = Head {
            format_version: 1,
            sequence: self.rows.last().map_or(0, |row| row.sequence),
            hash: self
                .rows
                .last()
                .map_or_else(|| "0".repeat(64), |row| row.hash.clone()),
            byte_length: complete_length,
        };
        if let Some(tail) = tail {
            let tail = ObservedTail {
                bytes: tail.to_vec(),
                base_sequence: self.head.sequence,
            };
            self.quarantine_tail(&tail)?;
            self.recovered_tail = Some(tail);
        }
        Ok(())
    }

    pub(crate) fn finish_recovery(&mut self) -> Result<()> {
        if let Some(tail) = self.recovered_tail.take() {
            let mut row = JournalRow::empty(EventName::TailRecovered, self.clock.utc().timestamp());
            row.actor = "system.recovery".into();
            row.quarantined_bytes = tail.bytes.len() as u64;
            row.quarantine_hash = sha256(&[&tail.bytes]);
            let row = self.prepare_rows(vec![row])?.remove(0);
            self.append(row)?;
        }
        self.scan_quarantines()?;
        self.write_head(&self.head)
    }

    fn verify_bytes<'a>(&self, bytes: &'a [u8], head: &Head) -> Result<VerifiedBytes<'a>> {
        let mut rows = Vec::new();
        let mut end = 0u64;
        let mut previous = "0".repeat(64);
        let mut sequence = 0u64;
        let mut committed = checkpoint_agrees(0, &previous, 0, head);
        let mut last_at = None;
        for line in bytes.split_inclusive(|byte| *byte == b'\n') {
            if line.last() != Some(&b'\n') {
                if end < head.byte_length || !committed {
                    return Err(Error::Unavailable);
                }
                BoundKey::JournalRow
                    .validate(line.len() as u64)
                    .map_err(|_| Error::Unavailable)?;
                return Ok(VerifiedBytes {
                    rows,
                    complete_length: end,
                    tail: Some(line),
                });
            }
            BoundKey::JournalRow
                .validate(line.len() as u64)
                .map_err(|_| Error::Unavailable)?;
            self.hooks
                .at(ComplianceStage::BeforeDecode)
                .map_err(|_| Error::Unavailable)?;
            let row: JournalRow = serde_json::from_slice(line).map_err(|_| Error::Unavailable)?;
            sequence = sequence.checked_add(1).ok_or(Error::Unavailable)?;
            verify_link(&row, sequence, &previous)?;
            verify_time(&row, last_at, self.clock.utc().timestamp())?;
            row.validate_metadata()?;
            if row.bytes()? != line {
                return Err(Error::Unavailable);
            }
            end = end
                .checked_add(line.len() as u64)
                .ok_or(Error::Unavailable)?;
            if row.sequence == head.sequence {
                committed = checkpoint_agrees(row.sequence, &row.hash, end, head);
            }
            previous = row.hash.clone();
            last_at = Some(row.at);
            rows.push(row);
        }
        if !committed {
            return Err(Error::Unavailable);
        }
        Ok(VerifiedBytes {
            rows,
            complete_length: end,
            tail: None,
        })
    }

    fn read_head(&self) -> Result<Head> {
        let file = open_journal(
            &self.root.join("head.json"),
            OpenMode::Read,
            self.hooks.as_ref(),
            None,
        )
        .map_err(|_| Error::Unavailable)?;
        let bytes = disk::read_bounded(file, BoundKey::JournalRow.spec().max)
            .map_err(|_| Error::Unavailable)?;
        self.hooks
            .at(ComplianceStage::BeforeDecode)
            .map_err(|_| Error::Unavailable)?;
        let head: Head = serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)?;
        Hex64::parse(&head.hash)?;
        let mut canonical = serde_json::to_vec(&head).map_err(|_| Error::Unavailable)?;
        canonical.push(b'\n');
        if head.format_version != 1 || canonical != bytes {
            return Err(Error::Unavailable);
        }
        Ok(head)
    }

    fn write_head(&self, head: &Head) -> Result<()> {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp = self
            .root
            .join(format!("head.{}.{}.tmp", std::process::id(), sequence));
        let mut file = open_journal(&temp, OpenMode::CreateNew, self.hooks.as_ref(), None)
            .map_err(|_| Error::Unavailable)?;
        let result = self.replace_head(&mut file, &temp, head);
        if temp.exists() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    fn replace_head(&self, file: &mut File, temp: &Path, head: &Head) -> Result<()> {
        let mut bytes = serde_json::to_vec(head).map_err(|_| Error::Unavailable)?;
        bytes.push(b'\n');
        file.write_all(&bytes).map_err(|_| Error::Unavailable)?;
        file.sync_all().map_err(|_| Error::Unavailable)?;
        let destination = self.root.join("head.json");
        fs::rename(temp, &destination).map_err(|_| Error::Unavailable)?;
        self.hooks
            .at(ComplianceStage::AfterHeadRename)
            .map_err(|_| Error::Unavailable)?;
        disk::sync_parent(&destination).map_err(|_| Error::Unavailable)?;
        self.hooks
            .at(ComplianceStage::AfterHeadSync)
            .map_err(|_| Error::Unavailable)
    }

    fn quarantine_tail(&self, tail: &ObservedTail) -> Result<()> {
        let bytes = tail.bytes.as_slice();
        let hash = sha256(&[bytes]);
        let path = self
            .root
            .join(format!("quarantine-{:020}-{hash}.bin", tail.base_sequence));
        match open_journal(&path, OpenMode::Read, self.hooks.as_ref(), None) {
            Ok(file) => {
                let existing = disk::read_bounded(file, BoundKey::JournalRow.spec().max)
                    .map_err(|_| Error::Unavailable)?;
                if existing != bytes {
                    self.replace_quarantine(&path, bytes)?;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.replace_quarantine(&path, bytes)?;
            }
            Err(_) => return Err(Error::Unavailable),
        }
        let file = open_journal(
            &self.root.join("events.jsonl"),
            OpenMode::Append,
            self.hooks.as_ref(),
            None,
        )
        .map_err(|_| Error::Unavailable)?;
        file.set_len(self.head.byte_length)
            .map_err(|_| Error::Unavailable)?;
        file.sync_all().map_err(|_| Error::Unavailable)?;
        self.hooks
            .at(ComplianceStage::AfterTailTruncate)
            .map_err(|_| Error::Unavailable)
    }

    fn replace_quarantine(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        // The lifetime owner lock excludes a live staging writer. Publish complete
        // synced bytes; mismatch replacement is confined to intact-tail recovery.
        let temp = self.root.join(format!(
            "recovery.{}.{}.tmp",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = open_journal(&temp, OpenMode::CreateNew, self.hooks.as_ref(), None)
            .map_err(|_| Error::Unavailable)?;
        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::rename(&temp, path)?;
            disk::sync_parent(path)
        })();
        if temp.exists() {
            let _ = fs::remove_file(&temp);
        }
        result.map_err(|_| Error::Unavailable)
    }

    fn sweep_owned_temps(&self) -> Result<()> {
        // The held lifetime owner lock, not a recognized pid alone, proves no live
        // writer owns these staging files. Harden each candidate before unlinking.
        let entries = fs::read_dir(&self.root).map_err(|_| Error::Unavailable)?;
        let mut removed = false;
        for entry in entries {
            let entry = entry.map_err(|_| Error::Unavailable)?;
            let name = entry.file_name();
            if !name
                .to_str()
                .is_some_and(|name| disk::owned_temp_name(name, &["head", "recovery"]))
            {
                continue;
            }
            let path = entry.path();
            let file = open_journal(&path, OpenMode::Read, self.hooks.as_ref(), None)
                .map_err(|_| Error::Unavailable)?;
            drop(file);
            fs::remove_file(&path).map_err(|_| Error::Unavailable)?;
            removed = true;
        }
        if removed {
            disk::sync_parent(&self.root.join("head.json")).map_err(|_| Error::Unavailable)?;
        }
        Ok(())
    }

    fn scan_quarantines(&self) -> Result<()> {
        let mut count = 0;
        for entry in fs::read_dir(&self.root).map_err(|_| Error::Unavailable)? {
            let entry = entry.map_err(|_| Error::Unavailable)?;
            let name = entry.file_name();
            if !name.as_encoded_bytes().starts_with(b"quarantine-") {
                continue;
            }
            let Some(row) = self.accounted_quarantine(&name) else {
                count += 1;
                continue;
            };
            let file = open_journal(&entry.path(), OpenMode::Read, self.hooks.as_ref(), None)
                .map_err(|_| Error::Unavailable)?;
            let bytes = disk::read_bounded(file, BoundKey::JournalRow.spec().max)
                .map_err(|_| Error::Unavailable)?;
            if bytes.len() as u64 != row.quarantined_bytes
                || sha256(&[&bytes]) != row.quarantine_hash
            {
                return Err(Error::Unavailable);
            }
        }
        self.hooks
            .unclaimed_quarantines(QuarantineStore::Journal, count);
        Ok(())
    }

    fn accounted_quarantine(&self, name: &std::ffi::OsStr) -> Option<&JournalRow> {
        let name = name.to_str()?;
        let rest = name.strip_prefix("quarantine-")?;
        let (base, suffix) = rest.split_once('-')?;
        let sequence = base.parse::<u64>().ok()?;
        // Recovery publication waits for payload and action reconciliation, which can append
        // intervening rows after the captured base and before this recovery row.
        self.rows.iter().find(|row| {
            row.event == EventName::TailRecovered
                && row.sequence > sequence
                && format!("{sequence:020}") == base
                && suffix == format!("{}.bin", row.quarantine_hash)
        })
    }
}

fn verify_link(row: &JournalRow, sequence: u64, previous: &str) -> Result<()> {
    if row.sequence != sequence {
        return Err(Error::Unavailable);
    }
    if row.previous_hash != previous {
        return Err(Error::Unavailable);
    }
    if row.computed_hash()? != row.hash {
        return Err(Error::Unavailable);
    }
    Ok(())
}

fn verify_time(row: &JournalRow, last_at: Option<i64>, now: i64) -> Result<()> {
    if row.at > now || last_at.is_some_and(|last| row.at < last) {
        return Err(Error::Unavailable);
    }
    Ok(())
}

fn checkpoint_agrees(sequence: u64, hash: &str, length: u64, head: &Head) -> bool {
    (sequence, hash, length) == (head.sequence, head.hash.as_str(), head.byte_length)
}

fn open_journal(
    path: &Path,
    mode: OpenMode,
    hooks: &dyn ComplianceHooks,
    progress: Option<&mut disk::WriteProgress>,
) -> io::Result<File> {
    match progress {
        Some(progress) => disk::open_for_tracked(path, mode, hooks, progress),
        None => disk::open_for(path, mode, hooks),
    }
}
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
