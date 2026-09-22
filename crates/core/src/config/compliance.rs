//! Defines finite local compliance configuration and validates storage-axis separation before open.
//! Record/publication settings deserialize for compatibility; hosted operation requires later work.

#![deny(missing_docs)]

use crate::compliance::{
    bounds::{self, BoundKey, TextClass},
    clock, disk, Error, Result,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

/// Explicit deployment intent; local defaults never authorize public operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentMode {
    /// Enables the local reporting mechanisms with outstanding operational gates.
    #[default]
    Local,
    /// Requires absolute private storage paths and approved records before service startup.
    Hosted,
}

/// One ordered, operator-supplied statement revision; all values are public policy metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StatementChange {
    /// Bounded slug of this revision.
    pub version: String,
    /// UTC seconds when the revision was adopted.
    pub at: i64,
    /// Nonempty narrative of at most 4096 UTF-8 bytes.
    pub summary: String,
}
impl Default for StatementChange {
    fn default() -> Self {
        Self {
            version: "619.1".into(),
            at: 1789689600,
            summary: "Initial local compliance surfaces; approvals pending".into(),
        }
    }
}

/// Strict, defaulted table shared by both v1 listeners; ceilings apply to complete transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ComplianceConfig {
    /// Defaults to local; hosted requires absolute paths and approved records before serving.
    pub deployment_mode: DeploymentMode,
    /// Optional private root, defaulting to a compliance sibling of the suppression file.
    pub store_dir: Option<PathBuf>,
    /// Optional private record directory, defaulting to a sibling of the journal directory.
    pub records_dir: Option<PathBuf>,
    /// Optional startup bearer file; absence authorizes nobody.
    pub admin_token_file: Option<PathBuf>,
    /// Optional startup hash-only listed file; invalid configured input never becomes empty.
    pub listed_hashes_file: Option<PathBuf>,
    /// Seconds subtracted from 172800; default 172800 makes reported URLs hidden at receipt.
    pub intimate_margin_seconds: u64,
    /// Calendar months after closure, 36..=120, shared by payload and reserved record retention.
    pub retention_months: u32,
    /// Lifetime ticket ceiling, default 10000, permitted 1..=100000; purging does not reduce it.
    pub max_tickets: u64,
    /// Per-ticket event ceiling, 16..=256, including four reserved completion/purge events.
    pub max_ticket_events: u64,
    /// Lifetime journal-byte ceiling, with 65536 bytes reserved for completion and purge.
    pub max_journal_bytes: u64,
    /// Total extant payload bytes across all tickets.
    pub max_payload_bytes: u64,
    /// Combined active rules, reversal markers and listed entries.
    pub max_rules: u64,
    /// Complete serialized serving snapshot bytes, including LF.
    pub max_rules_bytes: u64,
    /// Lifetime limit for all immutable record versions, including superseded records.
    pub max_records: u64,
    /// Complete private wrapper byte limit, including salt, commitment and final LF.
    pub max_record_bytes: u64,
    /// Aggregate record, index, staging and quarantine byte limit.
    pub max_records_bytes: u64,
    /// Bounded active public statement slug, matching the final changelog entry.
    pub statement_version: String,
    /// Ordered public changelog of one to 32 entries.
    pub statement_changes: Vec<StatementChange>,
    /// Reading-age target, 8..=16; this is not a measured accessibility result.
    pub reading_age: u64,
    /// Optional owner-approved priority catalog version, absent until supplied.
    pub priority_catalog_version: Option<String>,
    /// Optional nonempty authoritative catalog source text of at most 4096 bytes.
    pub priority_catalog_source: Option<String>,
    /// Exactly seventeen ordered label slots, each absent or a distinct bounded plain label.
    pub priority_kind_labels: [Option<String>; 17],
    /// Optional public contact text of at most 254 bytes.
    pub public_contact: Option<String>,
    /// Optional canonical credential-free HTTPS ICO complaints URL of at most 2048 bytes.
    pub ico_complaints_url: Option<String>,
    /// Optional proactive-technology statement, at most 4096 bytes.
    pub statement_proactive: Option<String>,
    /// Optional complaints policy narrative, at most 4096 bytes.
    pub statement_complaints: Option<String>,
    /// Optional primary-priority child protection policy, at most 4096 bytes.
    pub statement_children_primary: Option<String>,
    /// Optional priority child protection policy, at most 4096 bytes.
    pub statement_children_priority: Option<String>,
    /// Optional other child protection policy, at most 4096 bytes.
    pub statement_children_other: Option<String>,
    /// Version for the single duplicate-without-new-information policy clause.
    pub unfounded_policy_version: String,
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        let default = |key: BoundKey| key.spec().default.expect("configured default");
        Self {
            deployment_mode: DeploymentMode::Local,
            store_dir: None,
            records_dir: None,
            admin_token_file: None,
            listed_hashes_file: None,
            intimate_margin_seconds: default(BoundKey::IntimateMargin),
            retention_months: default(BoundKey::RetentionMonths) as u32,
            max_tickets: default(BoundKey::MaxTickets),
            max_ticket_events: default(BoundKey::MaxTicketEvents),
            max_journal_bytes: default(BoundKey::MaxJournalBytes),
            max_payload_bytes: default(BoundKey::MaxPayloadBytes),
            max_rules: default(BoundKey::MaxRules),
            max_rules_bytes: default(BoundKey::MaxRulesBytes),
            max_records: default(BoundKey::MaxRecords),
            max_record_bytes: default(BoundKey::MaxRecordBytes),
            max_records_bytes: default(BoundKey::MaxRecordsBytes),
            statement_version: "619.1".into(),
            statement_changes: vec![StatementChange::default()],
            reading_age: default(BoundKey::ReadingAge),
            priority_catalog_version: None,
            priority_catalog_source: None,
            priority_kind_labels: std::array::from_fn(|_| None),
            public_contact: None,
            ico_complaints_url: None,
            statement_proactive: None,
            statement_complaints: None,
            statement_children_primary: None,
            statement_children_priority: None,
            statement_children_other: None,
            unfounded_policy_version: "619.1".into(),
        }
    }
}

/// Immutable validated settings and resolved private paths; construction cannot bypass validation.
#[derive(Clone)]
pub struct ValidatedComplianceConfig {
    settings: ComplianceConfig,
    store: PathBuf,
    journal: PathBuf,
    rules: PathBuf,
    records: PathBuf,
}
impl ValidatedComplianceConfig {
    /// Returns immutable settings after every range and semantic validation has passed.
    pub fn settings(&self) -> &ComplianceConfig {
        &self.settings
    }
    /// Returns the absolute private root shared only as an ancestor, never as an owner lock.
    pub fn store_dir(&self) -> &Path {
        &self.store
    }
    /// Returns the independent journal ownership root.
    pub fn journal_dir(&self) -> &Path {
        &self.journal
    }
    /// Returns the independent serving-rules ownership root.
    pub fn rules_dir(&self) -> &Path {
        &self.rules
    }
    /// Returns the independent record directory, never inside the journal's ownership tree.
    pub fn records_dir(&self) -> &Path {
        &self.records
    }
    /// Returns the record writer's sibling lock without creating or acquiring it.
    pub fn records_lock(&self) -> PathBuf {
        sibling_lock(&self.records)
    }
}

impl ComplianceConfig {
    /// Validates all settings and path identities before opening files; performs no writes.
    /// Hosted storage paths are independent of the working directory; approval is a startup gate.
    pub fn validate(&self, suppression: &Path) -> Result<ValidatedComplianceConfig> {
        self.validate_ranges()?;
        self.validate_text()?;
        let paths_absolute = suppression.is_absolute()
            && [
                &self.store_dir,
                &self.records_dir,
                &self.admin_token_file,
                &self.listed_hashes_file,
            ]
            .into_iter()
            .flatten()
            .all(|path| path.is_absolute());
        if self.deployment_mode == DeploymentMode::Hosted && !paths_absolute {
            return Err(Error::InvalidInput);
        }
        let suppression = absolute(suppression)?;
        let store = absolute(&self.store_dir.clone().unwrap_or_else(|| {
            suppression
                .parent()
                .expect("absolute file")
                .join("compliance")
        }))?;
        let journal = store.join("journal");
        let rules = store.join("rules");
        let records = absolute(
            &self
                .records_dir
                .clone()
                .unwrap_or_else(|| store.join("records")),
        )?;
        let mut separate = vec![suppression, rules.clone(), journal.clone()];
        for file in [&self.admin_token_file, &self.listed_hashes_file]
            .into_iter()
            .flatten()
        {
            let file = absolute(file)?;
            if overlaps(&store, &file) || overlaps(&records, &file) {
                return Err(Error::InvalidInput);
            }
            separate.push(file);
        }
        validate_separation(&separate)?;
        validate_record_paths(&records, &separate)?;
        if overlaps(&store, &separate[0]) {
            return Err(Error::InvalidInput);
        }
        Ok(ValidatedComplianceConfig {
            settings: self.clone(),
            store,
            journal,
            rules,
            records,
        })
    }

    fn validate_ranges(&self) -> Result<()> {
        for (key, value) in [
            (BoundKey::IntimateMargin, self.intimate_margin_seconds),
            (BoundKey::RetentionMonths, u64::from(self.retention_months)),
            (BoundKey::MaxTickets, self.max_tickets),
            (BoundKey::MaxTicketEvents, self.max_ticket_events),
            (BoundKey::MaxJournalBytes, self.max_journal_bytes),
            (BoundKey::MaxPayloadBytes, self.max_payload_bytes),
            (BoundKey::MaxRules, self.max_rules),
            (BoundKey::MaxRulesBytes, self.max_rules_bytes),
            (BoundKey::MaxRecords, self.max_records),
            (BoundKey::MaxRecordBytes, self.max_record_bytes),
            (BoundKey::MaxRecordsBytes, self.max_records_bytes),
            (BoundKey::ReadingAge, self.reading_age),
            (BoundKey::RecordHistory, self.statement_changes.len() as u64),
            (
                BoundKey::PriorityKinds,
                self.priority_kind_labels.len() as u64,
            ),
        ] {
            key.validate(value)?;
        }
        let minimum = crate::compliance::records::record_reservation_bytes(
            crate::compliance::record_index::initial_record_bytes()?,
            self.max_record_bytes,
        )
        .map_err(|_| Error::InvalidInput)?;
        if minimum > self.max_records_bytes {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }

    fn validate_text(&self) -> Result<()> {
        bounds::text(&self.statement_version, BoundKey::Slug, TextClass::Slug)?;
        bounds::text(
            &self.unfounded_policy_version,
            BoundKey::Slug,
            TextClass::Slug,
        )?;
        let mut previous = None;
        for change in &self.statement_changes {
            bounds::text(&change.version, BoundKey::Slug, TextClass::Slug)?;
            bounds::text(&change.summary, BoundKey::Narrative, TextClass::Narrative)?;
            clock::instant(change.at)?;
            if previous.is_some_and(|at| change.at < at) {
                return Err(Error::InvalidInput);
            }
            previous = Some(change.at);
        }
        if self
            .statement_changes
            .last()
            .is_none_or(|last| last.version != self.statement_version)
        {
            return Err(Error::InvalidInput);
        }
        for (value, key, class) in [
            (
                &self.priority_catalog_version,
                BoundKey::Slug,
                TextClass::Slug,
            ),
            (
                &self.priority_catalog_source,
                BoundKey::Narrative,
                TextClass::Narrative,
            ),
            (&self.public_contact, BoundKey::Contact, TextClass::Label),
            (
                &self.statement_proactive,
                BoundKey::Narrative,
                TextClass::Narrative,
            ),
            (
                &self.statement_complaints,
                BoundKey::Narrative,
                TextClass::Narrative,
            ),
            (
                &self.statement_children_primary,
                BoundKey::Narrative,
                TextClass::Narrative,
            ),
            (
                &self.statement_children_priority,
                BoundKey::Narrative,
                TextClass::Narrative,
            ),
            (
                &self.statement_children_other,
                BoundKey::Narrative,
                TextClass::Narrative,
            ),
        ] {
            if let Some(value) = value {
                bounds::text(value, key, class)?;
            }
        }
        let mut labels = BTreeSet::new();
        for label in self.priority_kind_labels.iter().flatten() {
            bounds::text(label, BoundKey::Label, TextClass::Label)?;
            if !labels.insert(label) {
                return Err(Error::InvalidInput);
            }
        }
        if let Some(value) = &self.ico_complaints_url {
            validate_https(value)?;
        }
        Ok(())
    }
}

fn absolute(path: &Path) -> Result<PathBuf> {
    disk::normalized(path).map_err(|_| Error::InvalidInput)
}

fn sibling_lock(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

fn validate_record_paths(records: &Path, other: &[PathBuf]) -> Result<()> {
    let lock = absolute(&sibling_lock(records))?;
    if overlaps(records, &lock) {
        return Err(Error::InvalidInput);
    }
    for path in other {
        for candidate in [path.clone(), sibling_lock(path)] {
            if overlaps(records, &candidate) || overlaps(&lock, &candidate) {
                return Err(Error::InvalidInput);
            }
        }
    }
    Ok(())
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right)
        || right.starts_with(left)
        || fs::metadata(left)
            .ok()
            .zip(fs::metadata(right).ok())
            .is_some_and(|(a, b)| (a.dev(), a.ino()) == (b.dev(), b.ino()))
}

fn validate_separation(paths: &[PathBuf]) -> Result<()> {
    for (index, left) in paths.iter().enumerate() {
        if paths[index + 1..].iter().any(|right| overlaps(left, right)) {
            return Err(Error::InvalidInput);
        }
    }
    Ok(())
}

fn validate_https(raw: &str) -> Result<()> {
    bounds::text(raw, BoundKey::Url, TextClass::Label)?;
    let parsed = url::Url::parse(raw).map_err(|_| Error::InvalidInput)?;
    if parsed.scheme() != "https"
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || parsed.as_str() != raw
        || raw
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b'\\')
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_resolve_isolated_roots_and_validate_hosted_structure() {
        let settings = ComplianceConfig::default();
        assert_eq!(settings.intimate_margin_seconds, 172800);
        assert_eq!(settings.retention_months, 36);
        assert_eq!(settings.max_tickets, 10000);
        let validated = settings
            .validate(Path::new("isolated/suppression.json"))
            .unwrap();
        assert!(validated.store_dir().ends_with("isolated/compliance"));
        assert!(validated.rules_dir().ends_with("isolated/compliance/rules"));
        assert!(validated
            .records_dir()
            .ends_with("isolated/compliance/records"));
        let hosted = ComplianceConfig {
            deployment_mode: DeploymentMode::Hosted,
            ..settings
        };
        assert!(hosted
            .validate(Path::new("isolated/suppression.json"))
            .is_err());
        let absolute = std::env::current_dir()
            .unwrap()
            .join("isolated/suppression.json");
        assert!(hosted.validate(&absolute).is_ok());
    }
}
