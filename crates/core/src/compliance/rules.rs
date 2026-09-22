//! Persists reversible serving decisions independently of the ticket journal's availability.
//! Snapshot replacement builds document indexes once; request assembly only looks up candidates.
//! An observed active deadline cannot regress during this owner's lifetime, even if UTC moves back.

#![deny(missing_docs)]

use super::{
    bounds::{self, BoundKey},
    clock,
    disk::{self, ComplianceHooks, OpenMode},
    listed::{HostCache, ListedData, ListedMatcher},
    model::{sha256, DocumentKey, Ground, Hex64, TicketId},
    Error, Result,
};
use crate::{
    config::compliance::ValidatedComplianceConfig, crawler::politeness::Clock,
    tokenizer::fields::DefaultTokenizer,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicI64, AtomicU64, Ordering},
        Arc,
    },
};
use tantivy::tokenizer::Tokenizer;
use tokio::sync::{RwLock, RwLockReadGuard};

/// Country classification passed through the serving seam without changing rule applicability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleCountry {
    /// Explicit United Kingdom classification.
    Uk,
    /// Explicit non-United-Kingdom classification.
    NonUk,
    /// Unknown classification, retained as unknown.
    Unknown,
}
/// Immutable request context; all country and age combinations receive these serving protections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleContext {
    /// Original geography classification.
    pub country: RuleCountry,
    /// Conservative child treatment, not independent age assurance.
    pub is_child: bool,
    /// Validated conservative UK-measures policy.
    pub uk_measures: bool,
}

/// Actual atomic-replacement stages, using the same stage meanings as legacy suppression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulesStage {
    /// Bounded snapshot bytes are about to be decoded.
    Decode,
    /// A complete candidate passed all size and count reservations.
    Open,
    /// Private temporary bytes are about to be written.
    Write,
    /// Temporary bytes are about to be synced.
    SyncFile,
    /// Synced temporary bytes are about to replace the snapshot.
    Rename,
    /// Rename completed; uncertainty now makes serving unavailable.
    SyncDirectory,
}
/// Synchronous rule-store instrumentation; it receives no identifiers, names, URLs or paths.
pub trait RulesHooks: Send + Sync + 'static {
    /// Observes or fails a real file stage; blocking fixtures must release their wait.
    fn at(&self, stage: RulesStage) -> io::Result<()>;
}
/// No-op production rule-store instrumentation.
pub struct NoRulesHooks;
impl RulesHooks for NoRulesHooks {
    fn at(&self, _: RulesStage) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuleKind {
    Global,
    Name,
}

/// One independently salted name; each token digest represents the entire normalized token.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NameSet {
    salt: Hex64,
    tokens: Vec<Hex64>,
}
impl NameSet {
    /// Converts one validated name to sorted distinct salted token hashes without storing plaintext.
    pub fn new(name: &str, salt: Hex64) -> Result<Self> {
        let normalized = name_tokens(name)?;
        let tokens = normalized
            .iter()
            .map(|token| token_hash(&salt, token))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(Self { salt, tokens })
    }
    fn matches(&self, query: &BTreeSet<String>) -> bool {
        let query = query
            .iter()
            .map(|token| token_hash(&self.salt, token))
            .collect::<BTreeSet<_>>();
        self.tokens.iter().all(|token| query.contains(token))
    }
    fn validate(&self) -> Result<()> {
        BoundKey::NameTokens.validate(self.tokens.len() as u64)?;
        if !self.tokens.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}

fn token_hash(salt: &Hex64, token: &str) -> Hex64 {
    Hex64::parse(&sha256(&[
        b"AVA619-NAME-v1\0",
        &salt.bytes(),
        token.as_bytes(),
    ]))
    .expect("SHA256 is hexadecimal")
}

/// Uses the existing lowercase/NFKD/diacritic tokenizer without stemming or stop-word changes.
pub fn query_tokens(text: &str) -> BTreeSet<String> {
    let mut tokenizer = DefaultTokenizer::default();
    // The leading ASCII space selects the frozen segmenter's Latin run for the complete input;
    // whitespace tokenization drops it, keeping names and queries on the same path.
    let normalized_input = format!(" {text}");
    let mut stream = tokenizer.token_stream(&normalized_input);
    let mut tokens = BTreeSet::new();
    while stream.advance() {
        tokens.insert(stream.token().text.clone());
    }
    tokens
}

/// Validates one evidenced name and returns all its distinct tokenizer tokens, including punctuation.
pub fn name_tokens(text: &str) -> Result<BTreeSet<String>> {
    bounds::text(text, BoundKey::Name, bounds::TextClass::Label)?;
    let tokens = query_tokens(text);
    BoundKey::NameTokens.validate(tokens.len() as u64)?;
    if !tokens
        .iter()
        .any(|token| token.chars().any(char::is_alphanumeric))
    {
        return Err(Error::InvalidInput);
    }
    Ok(tokens)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    rule_id: String,
    ticket_id: TicketId,
    document_id: DocumentKey,
    ground: Ground,
    kind: RuleKind,
    effective_at: i64,
    intent_sequence: u64,
    name_sets: Vec<NameSet>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    document_id: DocumentKey,
    ground: Ground,
    reversed_at: i64,
    intent_sequence: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotFile {
    format_version: u64,
    generation: u64,
    rules: Vec<Rule>,
    do_not_reapply: Vec<Marker>,
    listed: ListedData,
}

/// Indexed serving state held under the live read guard through final JSON serialization.
#[derive(Clone)]
pub struct RulesSnapshot {
    file: SnapshotFile,
    by_document: BTreeMap<DocumentKey, Vec<usize>>,
    listed: ListedMatcher,
    unavailable: bool,
}
impl RulesSnapshot {
    /// Reports whether an uncertain replacement disabled this owner's serving state.
    pub fn unavailable(&self) -> bool {
        self.unavailable
    }
    /// Returns the persisted snapshot generation for lifecycle and no-write observations.
    pub fn generation(&self) -> u64 {
        self.file.generation
    }
    /// Applies global, whole-name, timed and listed gates for one canonical candidate.
    pub fn allows(
        &self,
        document: &DocumentKey,
        canonical_url: &str,
        query: &BTreeSet<String>,
        _context: &RuleContext,
        now: i64,
        hosts: &mut HostCache,
    ) -> bool {
        if self.unavailable || self.listed.denies(document, canonical_url, hosts) {
            return false;
        }
        let Some(indices) = self.by_document.get(document) else {
            return true;
        };
        !indices.iter().any(|index| {
            let rule = &self.file.rules[*index];
            now >= rule.effective_at
                && match rule.kind {
                    RuleKind::Global => true,
                    RuleKind::Name => rule.name_sets.iter().any(|name| name.matches(query)),
                }
        })
    }

    pub(crate) fn has_intent(
        &self,
        ticket: &TicketId,
        documents: &[DocumentKey],
        ground: Ground,
        sequence: u64,
    ) -> bool {
        documents.iter().all(|document| {
            self.file.rules.iter().any(|rule| {
                &rule.ticket_id == ticket
                    && &rule.document_id == document
                    && rule.ground == ground
                    && rule.intent_sequence == sequence
            })
        })
    }
    pub(crate) fn marked(&self, document: &DocumentKey, ground: Ground) -> bool {
        self.file
            .do_not_reapply
            .binary_search_by(|marker| {
                (&marker.document_id, marker.ground.as_str()).cmp(&(document, ground.as_str()))
            })
            .is_ok()
    }
    pub(crate) fn verifies(&self, delta: &RuleDelta) -> bool {
        match delta {
            RuleDelta::Install {
                ticket,
                documents,
                ground,
                effective_at,
                sequence,
                names,
            } => documents.iter().all(|document| {
                self.by_document.get(document).is_some_and(|indices| {
                    indices.iter().any(|index| {
                        let rule = &self.file.rules[*index];
                        &rule.ticket_id == ticket
                            && rule.ground == *ground
                            && rule.intent_sequence == *sequence
                            && rule.effective_at <= *effective_at
                            && rule.name_sets == *names
                    })
                })
            }),
            RuleDelta::Remove { ticket } => {
                !self.file.rules.iter().any(|rule| &rule.ticket_id == ticket)
            }
            RuleDelta::Reverse {
                ticket,
                documents,
                ground,
                ..
            } => {
                !self.file.rules.iter().any(|rule| &rule.ticket_id == ticket)
                    && documents
                        .iter()
                        .all(|document| self.marked(document, *ground))
            }
        }
    }
    fn rebuild(file: SnapshotFile, config: &ValidatedComplianceConfig) -> Result<Self> {
        validate_snapshot(&file)?;
        let listed = ListedMatcher::from_data(file.listed.clone(), config.settings().max_rules)?;
        let mut by_document = BTreeMap::<DocumentKey, Vec<usize>>::new();
        for (index, rule) in file.rules.iter().enumerate() {
            by_document
                .entry(rule.document_id.clone())
                .or_default()
                .push(index);
        }
        Ok(Self {
            file,
            by_document,
            listed,
            unavailable: false,
        })
    }
}

fn validate_snapshot(snapshot: &SnapshotFile) -> Result<()> {
    if snapshot.format_version != 1
        || !snapshot
            .rules
            .windows(2)
            .all(|pair| pair[0].rule_id < pair[1].rule_id)
        || !snapshot.do_not_reapply.windows(2).all(|pair| {
            (&pair[0].document_id, pair[0].ground.as_str())
                < (&pair[1].document_id, pair[1].ground.as_str())
        })
    {
        return Err(Error::RulesUnavailable);
    }
    for rule in &snapshot.rules {
        let expected = rule_id(&rule.ticket_id, &rule.document_id, rule.ground);
        if rule.rule_id != expected
            || (rule.kind == RuleKind::Name) != (rule.ground == Ground::DataDelisting)
            || (rule.kind == RuleKind::Global && !rule.name_sets.is_empty())
        {
            return Err(Error::RulesUnavailable);
        }
        clock::instant(rule.effective_at)?;
        bounds::validate_range(rule.intent_sequence, 1, u64::MAX)?;
        if rule.kind == RuleKind::Name {
            BoundKey::RequiredNames.validate(rule.name_sets.len() as u64)?;
        }
        for name in &rule.name_sets {
            name.validate()?;
        }
    }
    for marker in &snapshot.do_not_reapply {
        clock::instant(marker.reversed_at)?;
        bounds::validate_range(marker.intent_sequence, 1, u64::MAX)?;
    }
    Ok(())
}

fn rule_id(ticket: &TicketId, document: &DocumentKey, ground: Ground) -> String {
    format!(
        "{}:{}:{}",
        ticket.as_str(),
        document.as_str(),
        ground.as_str()
    )
}

/// Exact desired rule delta referenced by a durable journal intent.
#[derive(Clone)]
pub(crate) enum RuleDelta {
    Install {
        ticket: TicketId,
        documents: Vec<DocumentKey>,
        ground: Ground,
        effective_at: i64,
        sequence: u64,
        names: Vec<NameSet>,
    },
    Remove {
        ticket: TicketId,
    },
    Reverse {
        ticket: TicketId,
        documents: Vec<DocumentKey>,
        ground: Ground,
        at: i64,
        sequence: u64,
    },
}

/// A complete, validated, capacity-reserved snapshot ready for an atomic replacement.
pub(crate) struct PreparedRules {
    snapshot: RulesSnapshot,
    bytes: Vec<u8>,
}

/// One independent lifetime rules owner, shared by all v1 listeners.
pub struct RulesStore {
    state: Arc<RwLock<RulesSnapshot>>,
    disk: RulesDisk,
    config: ValidatedComplianceConfig,
    clock: Arc<dyn Clock>,
    observed_utc: AtomicI64,
}
impl RulesStore {
    /// Opens and validates the independent snapshot before serving; invalid existing state is fatal.
    /// Startup recovery takes blocking locks: run in a blocking context, outside an async task.
    /// The configured list has already been safely loaded independently.
    pub fn open(
        config: &ValidatedComplianceConfig,
        clock: Arc<dyn Clock>,
        listed: ListedMatcher,
        compliance_hooks: Arc<dyn ComplianceHooks>,
        hooks: Arc<dyn RulesHooks>,
    ) -> Result<Self> {
        let fresh = !config.rules_dir().exists();
        let disk = RulesDisk::open(config.rules_dir(), compliance_hooks, hooks)
            .map_err(|_| Error::RulesUnavailable)?;
        let mut file = if fresh {
            SnapshotFile {
                format_version: 1,
                generation: 0,
                rules: Vec::new(),
                do_not_reapply: Vec::new(),
                listed: listed.data().clone(),
            }
        } else {
            disk.read(config.settings().max_rules_bytes)?
        };
        RulesSnapshot::rebuild(file.clone(), config)?;
        let list_changed = serde_json::to_vec(&file.listed).map_err(|_| Error::RulesUnavailable)?
            != serde_json::to_vec(listed.data()).map_err(|_| Error::RulesUnavailable)?;
        file.listed = listed.data().clone();
        if list_changed {
            file.generation = file
                .generation
                .checked_add(1)
                .ok_or(Error::RulesUnavailable)?;
        }
        let snapshot = RulesSnapshot::rebuild(file, config)?;
        let prepared = prepare(snapshot, config)?;
        if fresh || list_changed {
            disk.persist(&prepared.bytes, &mut false)
                .map_err(|_| Error::RulesUnavailable)?;
        }
        let observed_utc = AtomicI64::new(clock.utc().timestamp());
        Ok(Self {
            state: Arc::new(RwLock::new(prepared.snapshot)),
            disk,
            config: config.clone(),
            clock,
            observed_utc,
        })
    }

    /// Takes the live post-retrieval gate; hold it until response serialization has finished.
    pub async fn read(&self) -> RwLockReadGuard<'_, RulesSnapshot> {
        self.state.read().await
    }
    /// Checks serving availability before paying for backend retrieval.
    pub async fn unavailable(&self) -> bool {
        self.state.read().await.unavailable
    }
    /// Returns a monotone observed UTC second within this owner's lifetime, without a disk write.
    pub fn serving_now(&self) -> i64 {
        let now = self.clock.utc().timestamp();
        self.observed_utc.fetch_max(now, Ordering::SeqCst).max(now)
    }

    pub(crate) fn prepare_delta(&self, delta: &RuleDelta) -> Result<PreparedRules> {
        let state = self.state.blocking_read();
        if state.unavailable {
            return Err(Error::RulesUnavailable);
        }
        let mut candidate = state.clone();
        apply_delta(&mut candidate, delta)?;
        candidate.file.generation = candidate
            .file
            .generation
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        prepare(
            RulesSnapshot::rebuild(candidate.file, &self.config)?,
            &self.config,
        )
    }

    pub(crate) fn commit(&self, prepared: PreparedRules) -> Result<()> {
        let mut state = self.state.blocking_write();
        if state.unavailable {
            return Err(Error::RulesUnavailable);
        }
        let mut renamed = false;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.disk.persist(&prepared.bytes, &mut renamed)
        }));
        match result {
            Ok(Ok(())) => {
                *state = prepared.snapshot;
                Ok(())
            }
            Ok(Err(_)) => {
                if renamed {
                    state.unavailable = true;
                }
                Err(Error::RulesUnavailable)
            }
            Err(_) => {
                state.unavailable = true;
                Err(Error::RulesUnavailable)
            }
        }
    }

    pub(crate) fn snapshot(&self) -> Result<RulesSnapshot> {
        // Startup precedes publication; refuse unexpected contention without blocking an
        // async caller of the synchronous constructor or panicking inside its runtime.
        self.state
            .try_read()
            .map(|state| state.clone())
            .map_err(|_| Error::RulesUnavailable)
    }
}

fn prepare(snapshot: RulesSnapshot, config: &ValidatedComplianceConfig) -> Result<PreparedRules> {
    let counts = [
        snapshot.file.rules.len(),
        snapshot.file.do_not_reapply.len(),
        snapshot.file.listed.url_hashes.len(),
        snapshot.file.listed.host_hashes.len(),
    ];
    let count = counts.into_iter().try_fold(0u64, |sum, n| {
        sum.checked_add(n as u64).ok_or(Error::Capacity)
    })?;
    bounds::reserve(0, count, config.settings().max_rules, 0)?;
    let mut bytes = serde_json::to_vec(&snapshot.file).map_err(|_| Error::RulesUnavailable)?;
    bytes.push(b'\n');
    bounds::reserve(0, bytes.len() as u64, config.settings().max_rules_bytes, 0)?;
    Ok(PreparedRules { snapshot, bytes })
}

fn apply_delta(snapshot: &mut RulesSnapshot, delta: &RuleDelta) -> Result<()> {
    match delta {
        RuleDelta::Install {
            ticket,
            documents,
            ground,
            effective_at,
            sequence,
            names,
        } => {
            for document in documents {
                if snapshot.marked(document, *ground) {
                    return Err(Error::InvalidTransition);
                }
                let id = rule_id(ticket, document, *ground);
                let earlier = snapshot
                    .file
                    .rules
                    .iter()
                    .find(|rule| rule.rule_id == id)
                    .map(|rule| rule.effective_at)
                    .unwrap_or(*effective_at);
                snapshot.file.rules.retain(|rule| rule.rule_id != id);
                snapshot.file.rules.push(Rule {
                    rule_id: id,
                    ticket_id: ticket.clone(),
                    document_id: document.clone(),
                    ground: *ground,
                    kind: if names.is_empty() {
                        RuleKind::Global
                    } else {
                        RuleKind::Name
                    },
                    effective_at: earlier.min(*effective_at),
                    intent_sequence: *sequence,
                    name_sets: names.clone(),
                });
            }
        }
        RuleDelta::Remove { ticket } => {
            snapshot.file.rules.retain(|rule| &rule.ticket_id != ticket)
        }
        RuleDelta::Reverse {
            ticket,
            documents,
            ground,
            at,
            sequence,
        } => {
            snapshot.file.rules.retain(|rule| &rule.ticket_id != ticket);
            for document in documents {
                if !snapshot.marked(document, *ground) {
                    snapshot.file.do_not_reapply.push(Marker {
                        document_id: document.clone(),
                        ground: *ground,
                        reversed_at: *at,
                        intent_sequence: *sequence,
                    });
                    snapshot.file.do_not_reapply.sort_by(|a, b| {
                        (&a.document_id, a.ground.as_str())
                            .cmp(&(&b.document_id, b.ground.as_str()))
                    });
                }
            }
        }
    }
    snapshot
        .file
        .rules
        .sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    Ok(())
}

struct RulesDisk {
    path: PathBuf,
    compliance_hooks: Arc<dyn ComplianceHooks>,
    hooks: Arc<dyn RulesHooks>,
    _owner: disk::OwnerLock,
}
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
impl RulesDisk {
    fn open(
        root: &Path,
        compliance_hooks: Arc<dyn ComplianceHooks>,
        hooks: Arc<dyn RulesHooks>,
    ) -> io::Result<Self> {
        let owner = open_rules(
            &root.join("owner.lock"),
            OpenMode::OwnerFile,
            compliance_hooks.as_ref(),
        )?;
        let owner = disk::lock_exclusive(owner)?;
        let disk = Self {
            path: root.join("snapshot.json"),
            compliance_hooks,
            hooks,
            _owner: owner,
        };
        disk.sweep_owned_temps()?;
        Ok(disk)
    }
    fn sweep_owned_temps(&self) -> io::Result<()> {
        // The exclusive owner lock is already held: no other pid can still own a
        // live staging file here. Harden every recognized inode before unlinking.
        let root = self
            .path
            .parent()
            .ok_or_else(|| io::Error::other("missing parent"))?;
        let mut removed = false;
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let name = entry.file_name();
            if !name
                .to_str()
                .is_some_and(|name| disk::owned_temp_name(name, &["snapshot"]))
            {
                continue;
            }
            let path = entry.path();
            let file = open_rules(&path, OpenMode::Read, self.compliance_hooks.as_ref())?;
            drop(file);
            fs::remove_file(&path)?;
            removed = true;
        }
        if removed {
            disk::sync_parent(&self.path)?;
        }
        Ok(())
    }
    fn read(&self, cap: u64) -> Result<SnapshotFile> {
        let file = open_rules(&self.path, OpenMode::Read, self.compliance_hooks.as_ref())
            .map_err(|_| Error::RulesUnavailable)?;
        let bytes = disk::read_bounded(file, cap).map_err(|_| Error::RulesUnavailable)?;
        self.hooks
            .at(RulesStage::Decode)
            .map_err(|_| Error::RulesUnavailable)?;
        let snapshot: SnapshotFile =
            serde_json::from_slice(&bytes).map_err(|_| Error::RulesUnavailable)?;
        let mut canonical = serde_json::to_vec(&snapshot).map_err(|_| Error::RulesUnavailable)?;
        canonical.push(b'\n');
        if bytes != canonical {
            return Err(Error::RulesUnavailable);
        }
        Ok(snapshot)
    }
    fn persist(&self, bytes: &[u8], renamed: &mut bool) -> io::Result<()> {
        self.hooks.at(RulesStage::Open)?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path =
            self.path
                .with_file_name(format!("snapshot.{}.{}.tmp", std::process::id(), sequence));
        let mut file = open_rules(&path, OpenMode::CreateNew, self.compliance_hooks.as_ref())?;
        let result = (|| {
            self.hooks.at(RulesStage::Write)?;
            file.write_all(bytes)?;
            self.hooks.at(RulesStage::SyncFile)?;
            file.sync_all()?;
            self.hooks.at(RulesStage::Rename)?;
            fs::rename(&path, &self.path)?;
            *renamed = true;
            self.hooks.at(RulesStage::SyncDirectory)?;
            disk::sync_parent(&self.path)
        })();
        if !*renamed {
            let _ = fs::remove_file(path);
        }
        result
    }
}

fn open_rules(path: &Path, mode: OpenMode, hooks: &dyn ComplianceHooks) -> io::Result<File> {
    disk::open_for(path, mode, hooks)
}
