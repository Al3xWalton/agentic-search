//! Keeps personal report events outside the chain in immutable, independently salted private files.
//! Commitments bind the ticket, sequence and recursively canonical content; purge never edits history.

#![deny(missing_docs)]

use super::{
    bounds::{self, BoundKey, TextClass},
    disk::{self, ComplianceHooks, ComplianceStage, OpenMode},
    model::{
        sha256, Decision, Delivery, Entropy, Hex64, IdentityEvent, Intake, Necessity, TicketId,
    },
    Error, Result,
};
use crate::config::compliance::ValidatedComplianceConfig;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

/// An essential response prepared by this service; delivery remains an operator attestation.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notice {
    /// Plain notice text; never interpreted as HTML or executable markup.
    pub text: String,
    /// Plain remedy instructions, required for refusal decisions.
    pub remedies: Vec<String>,
}

/// Closed typed personal-event union; none of this content is copied into chain metadata.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PersonalEvent {
    /// Canonical validated intake and every required declaration.
    Intake {
        /// Original personal report fields and route-specific claims.
        intake: Intake,
    },
    /// Identity or clarification request/reply reasons.
    Identity {
        /// Closed evidence event.
        event: IdentityEvent,
        /// Required bounded reasons.
        reasons: String,
    },
    /// Timely reasoned data-rights extension and essential notice.
    Extension {
        /// Statutory complexity or volume basis.
        necessity: Necessity,
        /// Required bounded reasons.
        reasons: String,
        /// Required written notice.
        notice: String,
        /// Operator attestation of delivery at the journal event time.
        delivery: Delivery,
    },
    /// Reviewed disposition, essential notice and reproducible name-rule entropy.
    Decision {
        /// Closed reviewed decision with route-appropriate fields.
        decision: Decision,
        /// Independent salts in intake-name order; generated internally, never accepted over HTTP.
        name_rule_salts: Vec<Hex64>,
        /// The exact essential notice returned to the operator.
        notice: Notice,
    },
    /// Appeal of the original reviewed ticket.
    Appeal {
        /// Required bounded reasons.
        reasons: String,
        /// Optional authenticated association with another complaint.
        related_ticket_id: Option<TicketId>,
    },
    /// Reversal with reasons and an essential notice.
    Reversal {
        /// Required bounded reasons.
        reasons: String,
        /// Operator attestation of communication.
        delivery: Delivery,
        /// Includes the possibility of independent remaining protection without revealing list membership.
        notice: Notice,
    },
    /// Reasoned decision to uphold the original outcome.
    Uphold {
        /// Required bounded reasons.
        reasons: String,
        /// Operator attestation of communication.
        delivery: Delivery,
        /// Essential appeal-disposal notice.
        notice: Notice,
    },
    /// Enquiries and progress communicated without changing any receipt or deadline.
    Progress {
        /// Nonempty enquiry record of at most 4096 bytes.
        enquiries: String,
        /// Nonempty progress update of at most 4096 bytes.
        update: String,
        /// Operator attestation of communication.
        delivery: Delivery,
    },
    /// Final closure reasons.
    Closure {
        /// Required bounded reasons.
        reasons: String,
    },
}

impl PersonalEvent {
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::Intake { intake } => super::tickets::validate_intake(intake),
            Self::Identity { reasons, .. }
            | Self::Appeal { reasons, .. }
            | Self::Closure { reasons } => reason(reasons),
            Self::Extension {
                reasons,
                notice,
                delivery,
                ..
            } => {
                reason(reasons)?;
                narrative(notice)?;
                delivery.validate()
            }
            Self::Decision {
                decision,
                name_rule_salts,
                notice,
            } => {
                decision.validate()?;
                BoundKey::OptionalNames.validate(name_rule_salts.len() as u64)?;
                validate_notice(notice)
            }
            Self::Reversal {
                reasons,
                delivery,
                notice,
            }
            | Self::Uphold {
                reasons,
                delivery,
                notice,
            } => {
                reason(reasons)?;
                delivery.validate()?;
                validate_notice(notice)
            }
            Self::Progress {
                enquiries,
                update,
                delivery,
            } => {
                narrative(enquiries)?;
                narrative(update)?;
                delivery.validate()
            }
        }
    }
}
fn reason(text: &str) -> Result<()> {
    bounds::text(text, BoundKey::Reason, TextClass::Narrative)
}
fn narrative(text: &str) -> Result<()> {
    bounds::text(text, BoundKey::Narrative, TextClass::Narrative)
}
fn validate_notice(notice: &Notice) -> Result<()> {
    // Service notices combine separately bounded reasons and configured contacts.
    // The complete immutable file remains capped; an input narrative still has its own 4096-byte cap.
    bounds::text(&notice.text, BoundKey::ServiceNotice, TextClass::Narrative)?;
    for remedy in &notice.remedies {
        narrative(remedy)?;
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPayload {
    format_version: u64,
    ticket_id: TicketId,
    sequence: u64,
    salt: Hex64,
    content: PersonalEvent,
}

/// Full immutable personal revision, prepared in memory before a transaction's capacity reservation.
pub struct PreparedPayload {
    ticket: TicketId,
    sequence: u64,
    content: PersonalEvent,
    bytes: Vec<u8>,
    commitment: String,
}
impl PreparedPayload {
    /// Returns the salted digest recorded by the referencing journal row.
    pub fn commitment(&self) -> &str {
        &self.commitment
    }
    /// Returns the complete file size, including LF, used by transaction reservation.
    pub fn byte_length(&self) -> u64 {
        self.bytes.len() as u64
    }
    /// Returns the immutable revision sequence used by the filename and commitment.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub(crate) fn content(&self) -> &PersonalEvent {
        &self.content
    }
}

/// Private personal-file access governed by the journal owner's lifetime lock.
pub struct PayloadStore {
    root: PathBuf,
    hooks: Arc<dyn ComplianceHooks>,
}
impl PayloadStore {
    /// Constructs an access adapter; the caller must hold the owning journal lock for mutations.
    pub fn new(config: &ValidatedComplianceConfig, hooks: Arc<dyn ComplianceHooks>) -> Self {
        Self {
            root: config.journal_dir().join("payloads"),
            hooks,
        }
    }

    /// Validates and serializes a complete revision with fresh salt, without touching the filesystem.
    /// Direct-owner boundary-control entry point. The caller must hold the journal owner lock
    /// for the complete operation so revisions cannot race journal recovery.
    pub fn prepare(
        &self,
        ticket: &TicketId,
        sequence: u64,
        content: PersonalEvent,
        entropy: &dyn Entropy,
    ) -> Result<PreparedPayload> {
        let salt = Hex64::random(entropy)?;
        self.prepare_with_salt(ticket, sequence, content, salt)
    }

    pub(crate) fn prepare_with_salt(
        &self,
        ticket: &TicketId,
        sequence: u64,
        content: PersonalEvent,
        salt: Hex64,
    ) -> Result<PreparedPayload> {
        bounds::validate_range(sequence, 1, u64::MAX)?;
        content.validate()?;
        let commitment = commitment(ticket, sequence, &salt, &content)?;
        let stored = StoredPayload {
            format_version: 1,
            ticket_id: ticket.clone(),
            sequence,
            salt,
            content: content.clone(),
        };
        let mut bytes = serde_json::to_vec(&stored).map_err(|_| Error::Unavailable)?;
        bytes.push(b'\n');
        BoundKey::PayloadFile
            .validate(bytes.len() as u64)
            .map_err(|_| Error::Capacity)?;
        Ok(PreparedPayload {
            ticket: ticket.clone(),
            sequence,
            content,
            bytes,
            commitment,
        })
    }

    /// Persists one prepared immutable revision through the same hardened tracked writer.
    /// Transaction owners use the tracked variant to retain progress across their complete plan.
    /// Direct-owner boundary-control entry point. The caller must hold the journal owner lock
    /// for the complete operation so revisions cannot race journal recovery.
    pub fn write(&self, prepared: &PreparedPayload) -> Result<()> {
        self.write_tracked(prepared, &mut disk::WriteProgress::default())
    }

    pub(crate) fn write_tracked(
        &self,
        prepared: &PreparedPayload,
        progress: &mut disk::WriteProgress,
    ) -> Result<()> {
        let path = self.path(&prepared.ticket, prepared.sequence);
        self.hooks
            .at(ComplianceStage::BeforePayloadWrite)
            .map_err(|_| Error::Unavailable)?;
        let mut file = open_payload(
            &path,
            OpenMode::CreateNew,
            self.hooks.as_ref(),
            Some(progress),
        )
        .map_err(|_| Error::Unavailable)?;
        progress.mark_started();
        file.write_all(&prepared.bytes)
            .map_err(|_| Error::Unavailable)?;
        file.sync_all().map_err(|_| Error::Unavailable)?;
        self.read(&prepared.ticket, prepared.sequence, &prepared.commitment)?;
        disk::sync_parent(&path).map_err(|_| Error::Unavailable)?;
        self.hooks
            .at(ComplianceStage::AfterPayloadSync)
            .map_err(|_| Error::Unavailable)
    }

    /// Loads a required, unpurged revision and verifies its exact reference and salted commitment.
    /// Every missing, malformed, oversized or unsafe referenced file fails closed.
    pub fn read(&self, ticket: &TicketId, sequence: u64, expected: &str) -> Result<PersonalEvent> {
        self.read_authorized(ticket, sequence, expected, false)?
            .ok_or(Error::Unavailable)
    }

    /// Reads one reference with absence permitted only when the verified journal authorizes purge.
    /// Callers must derive that authorization from a valid purge intent or completed purge.
    pub fn read_authorized(
        &self,
        ticket: &TicketId,
        sequence: u64,
        expected: &str,
        purge_authorized: bool,
    ) -> Result<Option<PersonalEvent>> {
        self.read_authorized_measured(ticket, sequence, expected, purge_authorized)
            .map(|loaded| loaded.map(|(content, _)| content))
    }

    pub(crate) fn read_authorized_measured(
        &self,
        ticket: &TicketId,
        sequence: u64,
        expected: &str,
        purge_authorized: bool,
    ) -> Result<Option<(PersonalEvent, u64)>> {
        let file = match open_payload(
            &self.path(ticket, sequence),
            OpenMode::Read,
            self.hooks.as_ref(),
            None,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound && purge_authorized => {
                return Ok(None)
            }
            Err(_) => return Err(Error::Unavailable),
        };
        let bytes = disk::read_bounded(file, BoundKey::PayloadFile.spec().max)
            .map_err(|_| Error::Unavailable)?;
        self.hooks
            .at(ComplianceStage::BeforeDecode)
            .map_err(|_| Error::Unavailable)?;
        let stored: StoredPayload =
            serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)?;
        if stored.format_version != 1 || &stored.ticket_id != ticket || stored.sequence != sequence
        {
            return Err(Error::Unavailable);
        }
        stored.content.validate()?;
        if commitment(ticket, sequence, &stored.salt, &stored.content)? != expected {
            return Err(Error::Unavailable);
        }
        let mut canonical = serde_json::to_vec(&stored).map_err(|_| Error::Unavailable)?;
        canonical.push(b'\n');
        if bytes != canonical {
            return Err(Error::Unavailable);
        }
        Ok(Some((stored.content, bytes.len() as u64)))
    }

    pub(crate) fn purge(
        &self,
        ticket: &TicketId,
        references: &BTreeMap<u64, String>,
    ) -> Result<()> {
        for (sequence, expected) in references {
            if self
                .read_authorized(ticket, *sequence, expected, true)?
                .is_none()
            {
                continue;
            }
            self.hooks
                .at(ComplianceStage::BeforePurgeDelete)
                .map_err(|_| Error::Unavailable)?;
            let path = self.path(ticket, *sequence);
            fs::remove_file(&path).map_err(|_| Error::Unavailable)?;
            disk::sync_parent(&path).map_err(|_| Error::Unavailable)?;
            self.hooks
                .at(ComplianceStage::AfterPurgeDelete)
                .map_err(|_| Error::Unavailable)?;
        }
        Ok(())
    }

    pub(crate) fn inventory(
        &self,
        referenced: &BTreeSet<(TicketId, u64)>,
        verified_lengths: &BTreeMap<(TicketId, u64), u64>,
        remove_orphans: bool,
    ) -> Result<BTreeMap<TicketId, u64>> {
        let mut totals = BTreeMap::new();
        if self.root.symlink_metadata().is_ok() {
            disk::private_parent(&self.root.join("probe")).map_err(|_| Error::Unavailable)?;
        }
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(totals),
            Err(_) => return Err(Error::Unavailable),
        };
        for entry in entries {
            let entry = entry.map_err(|_| Error::Unavailable)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Ok(ticket) = TicketId::parse(name) else {
                continue;
            };
            disk::private_parent(&entry.path().join("probe")).map_err(|_| Error::Unavailable)?;
            let mut total = 0u64;
            for (sequence, path) in self.managed_files(&ticket)? {
                let key = (ticket.clone(), sequence);
                if referenced.contains(&key) {
                    let length = verified_lengths.get(&key).ok_or(Error::Unavailable)?;
                    total = total.checked_add(*length).ok_or(Error::Unavailable)?;
                    continue;
                }
                let file = open_payload(&path, OpenMode::Read, self.hooks.as_ref(), None)
                    .map_err(|_| Error::Unavailable)?;
                let bytes = disk::read_bounded(file, BoundKey::PayloadFile.spec().max)
                    .map_err(|_| Error::Unavailable)?;
                if remove_orphans {
                    fs::remove_file(&path).map_err(|_| Error::Unavailable)?;
                    disk::sync_parent(&path).map_err(|_| Error::Unavailable)?;
                } else {
                    total = total
                        .checked_add(bytes.len() as u64)
                        .ok_or(Error::Unavailable)?;
                }
            }
            totals.insert(ticket, total);
        }
        Ok(totals)
    }

    fn managed_files(&self, ticket: &TicketId) -> Result<Vec<(u64, PathBuf)>> {
        let mut files = Vec::new();
        for entry in
            fs::read_dir(self.root.join(ticket.as_str())).map_err(|_| Error::Unavailable)?
        {
            let entry = entry.map_err(|_| Error::Unavailable)?;
            let name = entry.file_name();
            let Some(stem) = name.to_str().and_then(|name| name.strip_suffix(".json")) else {
                continue;
            };
            if stem.len() != 20 || !stem.bytes().all(|byte| byte.is_ascii_digit()) {
                continue;
            }
            let sequence = stem.parse::<u64>().map_err(|_| Error::Unavailable)?;
            bounds::validate_range(sequence, 1, u64::MAX)?;
            files.push((sequence, entry.path()));
        }
        files.sort_by_key(|(sequence, _)| *sequence);
        Ok(files)
    }

    fn path(&self, ticket: &TicketId, sequence: u64) -> PathBuf {
        self.root
            .join(ticket.as_str())
            .join(format!("{sequence:020}.json"))
    }
}

/// Computes the salted commitment over recursively sorted JSON, with identity and length binding.
pub fn commitment(
    ticket: &TicketId,
    sequence: u64,
    salt: &Hex64,
    content: &PersonalEvent,
) -> Result<String> {
    #[derive(Serialize)]
    struct Binding<'a> {
        format_version: u64,
        ticket_id: &'a TicketId,
        sequence: u64,
        content: &'a PersonalEvent,
    }
    let value = serde_json::to_value(Binding {
        format_version: 1,
        ticket_id: ticket,
        sequence,
        content,
    })
    .map_err(|_| Error::Unavailable)?;
    let mut bytes = Vec::new();
    canonical_value(&value, &mut bytes)?;
    Ok(sha256(&[
        b"AVA619-PAYLOAD-v1\0",
        &salt.bytes(),
        &(bytes.len() as u64).to_be_bytes(),
        &bytes,
    ]))
}

fn canonical_value(value: &serde_json::Value, out: &mut Vec<u8>) -> Result<()> {
    use serde_json::Value;
    match value {
        Value::Object(values) => {
            out.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort();
            for (index, key) in keys.iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                out.extend(serde_json::to_vec(key).map_err(|_| Error::Unavailable)?);
                out.push(b':');
                canonical_value(&values[*key], out)?;
            }
            out.push(b'}');
        }
        Value::Array(values) => {
            out.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                canonical_value(value, out)?;
            }
            out.push(b']');
        }
        Value::Number(number) if !number.is_i64() && !number.is_u64() => {
            return Err(Error::InvalidInput)
        }
        _ => out.extend(serde_json::to_vec(value).map_err(|_| Error::Unavailable)?),
    }
    Ok(())
}

fn open_payload(
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
