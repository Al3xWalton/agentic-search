//! Journals admitted targets and projects exactly one durable terminal row per target.
//! The journal is authoritative across crashes; incomplete prior admissions recover as cancelled,
//! never as invented saves. Disk/projection failures make the run incomplete and fail closed.
//! Raw bodies, headers and arbitrary error text never enter this store; records have no TTL here.

#![deny(missing_docs)]

use super::{
    exclusions::{ExclusionPhase, ExclusionReason},
    host_state::{atomic_write, HostRegistry},
    network::{safe_url_for_record, url_key, SafeUrl},
    politeness::Clock,
    record::{AbsenceReason, DocumentRecord, Observation},
    robots_txt::RobotsSnapshot,
    Error, Result,
};
use crate::config::ingestion::ValidatedPolicy;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::unix::fs::OpenOptionsExt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use url::Url;

/// Input provenance, independent of the HTTP subattempt kinds nested within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetKind {
    /// One ordinal in the authorized fixed seed set.
    Seed,
    /// A selected upstream frontier/job URL, including prefetch rejections.
    Frontier,
    /// A standalone feed/frontpage/sitemap refresh with its own terminal row.
    Auxiliary,
}
/// Physical fetch role; every role uses the same transport and host gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FetchKind {
    /// Robots bootstrap or an explicitly admitted robots redirect.
    Robots,
    /// Selected HTML page.
    Page,
    /// Sitemap XML refresh.
    Sitemap,
    /// RSS/Atom refresh.
    Feed,
    /// Live-index frontpage refresh.
    Frontpage,
    /// Conditional page request with prior successful validators.
    Conditional,
}
/// Sanitized wire failure; arbitrary transport error strings never become evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WireError {
    /// Bounded request/connect deadline elapsed.
    Timeout,
    /// DNS or TCP connection failed without a TLS cause.
    Connect,
    /// Native TLS handshake/certificate failure.
    Tls,
    /// Body stream failed or was truncated.
    BodyRead,
    /// Header or received chunk exceeded the body limit.
    TooLarge,
    /// Owned cancellation or an unconsumed response ended the attempt.
    Cancelled,
    /// Host-state durability failed and transport cannot continue.
    HostState,
    /// An unexpected typed transport invariant failed.
    Internal,
}
/// Classified redirect rejection, without raw Location values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RedirectReason {
    /// No unique Location field exists.
    MissingOrConflictingLocation,
    /// Location failed URL, credential or encoding validation.
    InvalidLocation,
    /// HTTPS would be downgraded to HTTP.
    HttpsDowngrade,
    /// Status is a redirect semantic this GET path does not support.
    UnsupportedStatus,
}
/// Sanitized MIME rejection; never carries a raw header value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContentTypeReason {
    /// At least one physical occurrence was not visible ASCII.
    InvalidHeaderBytes,
    /// The field was absent or its valid occurrences contradicted each other.
    MissingOrContradictory,
    /// A visible ASCII value was not valid MIME syntax.
    Invalid,
    /// Valid MIME syntax described an unsupported payload.
    Unsupported,
}
/// Classified non-success HTTP status semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HttpStatusReason {
    /// Actual response did not produce a successful page representation.
    Status,
    /// A 304 arrived without an eligible previous successful representation.
    UnexpectedNotModified,
    /// Versioned challenge evidence blocks further host access.
    Challenge,
}
/// Typed fatal failure cause; never a catch-all raw error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InternalCode {
    /// Host state could not be durably persisted.
    HostStatePersistence,
    /// A required record invariant was violated.
    RecordInvariant,
    /// A scheduler/parser/task invariant failed.
    RuntimeInvariant,
    /// Configuration or owned-store prerequisites failed after target admission.
    Configuration,
}
/// Exactly reachable terminal outcomes in Slice 1; no unknown or legacy retry-only variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum Outcome {
    /// Nonempty eligible body was durably stored, without claiming indexing success.
    Saved,
    /// Nonempty permitted body was durably stored with ineligible/noindex metadata.
    SavedNoindex,
    /// Source redirected to another existing target, which is fetched only once under its own ID.
    RedirectedToSeed {
        /// Actual supported redirect status.
        status: u16,
    },
    /// Valid redirect destination is outside the exact authorized target set and is not fetched.
    RedirectedOffSeed {
        /// Actual supported redirect status.
        status: u16,
    },
    /// Missing, unsafe or unsupported redirect semantics.
    RedirectInvalid {
        /// Typed rejection without raw Location text.
        reason: RedirectReason,
    },
    /// Proposed redirect edge would create a cycle; no repeat request occurs.
    RedirectLoop,
    /// Proposed redirect edge would exceed ten hops; destination is not fetched through that edge.
    RedirectLimit,
    /// Actual robots rules deny the target.
    RobotsDisallowed,
    /// Robots status/parser/redirect failure prevents usable permission.
    RobotsUnreachable,
    /// Publisher delay exceeds the fixed 60-second policy skip threshold.
    CrawlDelayExceedsCeiling,
    /// Existing or robots-induced block/rate deadline prevented the page request.
    HostBlocked,
    /// Literal or vetted DNS address set is private/special; no connection is made.
    RefusedPrivateAddress,
    /// Missing, conflicting, malformed or unsupported page MIME.
    InvalidContentType {
        /// Typed rejection code without publisher bytes.
        reason: ContentTypeReason,
    },
    /// Header or streamed entity exceeded the byte limit.
    ContentTooLarge,
    /// Failed or truncated body stream.
    BodyReadFailed,
    /// Actual status with classified non-body-success semantics.
    HttpStatus {
        /// Received status in 100..=599.
        code: u16,
        /// Fixed semantic classification.
        reason: HttpStatusReason,
    },
    /// 304 preserved a prior successful representation without renewing its body TTL.
    NotModified,
    /// 404/410 emitted a URL tombstone and purged local retained body objects.
    Gone,
    /// Actual request/connect timeout.
    Timeout,
    /// Actual DNS/TCP failure without a TLS cause.
    ConnectError,
    /// Actual native TLS handshake/certificate failure.
    TlsError,
    /// Exact target already completed under this run's policy.
    AlreadyCrawled,
    /// Target does not belong to the supplied job domain.
    DomainMismatch,
    /// A non-default scheme port was refused before network admission.
    PortRefused,
    /// Non-HTTP(S) input was refused.
    SchemeRefused,
    /// Supplied host/geographic/language/listing policy prevented retention or fetching.
    ExcludedByPolicy {
        /// Bounded policy rejection cause.
        reason: ExclusionReason,
        /// Frontier or post-parse decision phase.
        phase: ExclusionPhase,
    },
    /// Parse, credential, host or encoding validation failed without retaining unsafe input.
    InvalidUrl,
    /// Raw input exceeded the 8,192-byte URL limit.
    UrlTooLong,
    /// Selected target matched the inherited ignored extension list.
    IgnoredExtension,
    /// Successful status returned a completed zero-byte entity, never saved as a datum.
    EmptyBody,
    /// Parsed body was intentionally not retained under its recorded body-retention reason.
    ParsedNotRetained,
    /// Durable body sink failed; this outcome never claims a save.
    SinkWriteFailed,
    /// Explicit owned cancellation or recovery of an incomplete prior admission.
    Cancelled,
    /// Unexpected typed failure; the run remains fatal even if this row was recorded.
    InternalError {
        /// Fixed invariant/persistence/configuration failure code.
        code: InternalCode,
    },
}
impl Outcome {
    /// Complete reachable outcome register, kept in bijection with conformance scenarios.
    pub const ALL_KINDS: [&'static str; 34] = [
        "saved",
        "saved-noindex",
        "redirected-to-seed",
        "redirected-off-seed",
        "redirect-invalid",
        "redirect-loop",
        "redirect-limit",
        "robots-disallowed",
        "robots-unreachable",
        "crawl-delay-exceeds-ceiling",
        "host-blocked",
        "refused-private-address",
        "invalid-content-type",
        "content-too-large",
        "body-read-failed",
        "http-status",
        "not-modified",
        "gone",
        "timeout",
        "connect-error",
        "tls-error",
        "already-crawled",
        "domain-mismatch",
        "port-refused",
        "scheme-refused",
        "excluded-by-policy",
        "invalid-url",
        "url-too-long",
        "ignored-extension",
        "empty-body",
        "parsed-not-retained",
        "sink-write-failed",
        "cancelled",
        "internal-error",
    ];
    /// Returns the stable terminal kind without serializing publisher data.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Saved => "saved",
            Self::SavedNoindex => "saved-noindex",
            Self::RedirectedToSeed { .. } => "redirected-to-seed",
            Self::RedirectedOffSeed { .. } => "redirected-off-seed",
            Self::RedirectInvalid { .. } => "redirect-invalid",
            Self::RedirectLoop => "redirect-loop",
            Self::RedirectLimit => "redirect-limit",
            Self::RobotsDisallowed => "robots-disallowed",
            Self::RobotsUnreachable => "robots-unreachable",
            Self::CrawlDelayExceedsCeiling => "crawl-delay-exceeds-ceiling",
            Self::HostBlocked => "host-blocked",
            Self::RefusedPrivateAddress => "refused-private-address",
            Self::InvalidContentType { .. } => "invalid-content-type",
            Self::ContentTooLarge => "content-too-large",
            Self::BodyReadFailed => "body-read-failed",
            Self::HttpStatus { .. } => "http-status",
            Self::NotModified => "not-modified",
            Self::Gone => "gone",
            Self::Timeout => "timeout",
            Self::ConnectError => "connect-error",
            Self::TlsError => "tls-error",
            Self::AlreadyCrawled => "already-crawled",
            Self::DomainMismatch => "domain-mismatch",
            Self::PortRefused => "port-refused",
            Self::SchemeRefused => "scheme-refused",
            Self::ExcludedByPolicy { .. } => "excluded-by-policy",
            Self::InvalidUrl => "invalid-url",
            Self::UrlTooLong => "url-too-long",
            Self::IgnoredExtension => "ignored-extension",
            Self::EmptyBody => "empty-body",
            Self::ParsedNotRetained => "parsed-not-retained",
            Self::SinkWriteFailed => "sink-write-failed",
            Self::Cancelled => "cancelled",
            Self::InternalError { .. } => "internal-error",
        }
    }
    /// Maps every typed source error without a wildcard or arbitrary string fallback.
    pub fn from_error(error: &Error) -> Self {
        match error {
            Error::InvalidContentType(reason) => Self::InvalidContentType {
                reason: match reason.as_str() {
                    "invalid-header-bytes" => ContentTypeReason::InvalidHeaderBytes,
                    "missing-or-contradictory" => ContentTypeReason::MissingOrContradictory,
                    "unsupported" => ContentTypeReason::Unsupported,
                    _ => ContentTypeReason::Invalid,
                },
            },
            Error::FetchFailed { status_code, .. } => Self::HttpStatus {
                code: *status_code,
                reason: HttpStatusReason::Status,
            },
            Error::InvalidUrl => Self::InvalidUrl,
            Error::UrlTooLong => Self::UrlTooLong,
            Error::SchemeRefused => Self::SchemeRefused,
            Error::PortRefused => Self::PortRefused,
            Error::OffScope => Self::ExcludedByPolicy {
                reason: ExclusionReason::OutsideScope,
                phase: ExclusionPhase::Frontier,
            },
            Error::RefusedPrivateAddress => Self::RefusedPrivateAddress,
            Error::ConnectError => Self::ConnectError,
            Error::TlsError => Self::TlsError,
            Error::Timeout => Self::Timeout,
            Error::HostBlocked | Error::Challenge => Self::HostBlocked,
            Error::CrawlDelayExceedsCeiling => Self::CrawlDelayExceedsCeiling,
            Error::RobotsUnreachable => Self::RobotsUnreachable,
            Error::HostStateWrite => Self::InternalError {
                code: InternalCode::HostStatePersistence,
            },
            Error::StoreRefused
            | Error::StoreOwned
            | Error::CountryProviderUnavailable
            | Error::Anyhow(_) => Self::InternalError {
                code: InternalCode::Configuration,
            },
            Error::ExcludedByPolicy { reason, phase } => Self::ExcludedByPolicy {
                reason: *reason,
                phase: *phase,
            },
            Error::RecordInvalid => Self::InternalError {
                code: InternalCode::RecordInvariant,
            },
            Error::ListingBudgetExhausted => Self::ExcludedByPolicy {
                reason: ExclusionReason::ListingBudgetExhausted,
                phase: ExclusionPhase::Frontier,
            },
            Error::Cancelled => Self::Cancelled,
            Error::InternalInvariant | Error::TestNetworkDisabled => Self::InternalError {
                code: InternalCode::RuntimeInvariant,
            },
            Error::DomainMismatch => Self::DomainMismatch,
            Error::AlreadyCrawled => Self::AlreadyCrawled,
            Error::IgnoredExtension => Self::IgnoredExtension,
            Error::EmptyBody => Self::EmptyBody,
            Error::ContentTooLarge => Self::ContentTooLarge,
            Error::ResponseBodyReadFailed => Self::BodyReadFailed,
            Error::InvalidRedirect => Self::RedirectInvalid {
                reason: RedirectReason::InvalidLocation,
            },
            Error::DisallowedPath => Self::RobotsDisallowed,
            Error::SinkWrite | Error::RetentionBacklog => Self::SinkWriteFailed,
            Error::LedgerWrite
            | Error::LedgerIncomplete
            | Error::DuplicateTarget
            | Error::FatalRun => Self::InternalError {
                code: InternalCode::RuntimeInvariant,
            },
        }
    }
}

/// One actual transmitted HTTP subattempt, including failures and bootstrap policy evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchAttempt {
    /// Exact safe operational URL actually transmitted.
    pub requested_url: SafeUrl,
    /// Plain SHA-256 join key for this operational URL.
    pub url_key: String,
    /// Physical request role under the shared transport.
    pub kind: FetchKind,
    /// UTC host-permit admission time.
    pub started_at_utc: DateTime<Utc>,
    /// UTC body/header failure/completion time, explicit absent only while in flight.
    pub finished_at_utc: Observation<DateTime<Utc>>,
    /// Wait before request start, in milliseconds.
    pub queue_time_ms: u64,
    /// Duration from admitted start through body/error, in milliseconds.
    pub fetch_time_ms: u64,
    /// Actual HTTP status or explicit no-response observation.
    pub status: Observation<u16>,
    /// Classified failure, never an error display chain.
    pub error: Option<WireError>,
    /// Immutable decision used by content, or resulting bootstrap observation for robots.
    pub robots: Observation<RobotsSnapshot>,
    /// Entity bytes received, including partial/rejected final chunks.
    pub body_bytes: u64,
    /// Always true for a transmitted request; skipped targets have no invented wire attempt.
    pub scope_admitted: bool,
    /// Latest host retry deadline observed at completion.
    pub retry_at_utc: Option<DateTime<Utc>>,
    /// Latest access block observed at completion.
    pub blocked_until_utc: Option<DateTime<Utc>>,
    /// Safe redirect reference, distinct from requested/final URL and never implicit permission.
    pub redirect: Observation<SafeUrl>,
}
#[derive(Default)]
struct TraceState {
    attempts: Vec<FetchAttempt>,
    last_robots: Option<RobotsSnapshot>,
    country: Option<super::exclusions::HostingCountry>,
}
/// Per-target in-memory subattempt evidence; shared robots misses belong to the refresh owner.
#[derive(Clone, Default)]
pub struct AttemptTrace(Arc<Mutex<TraceState>>);
impl AttemptTrace {
    pub(super) fn redirect(&self, destination: &Url) -> Result<()> {
        if let Some(attempt) = self
            .0
            .lock()
            .map_err(|_| Error::InternalInvariant)?
            .attempts
            .last_mut()
        {
            attempt.redirect = Observation::Present(safe_url_for_record(destination));
        }
        Ok(())
    }
    pub(super) fn country(&self, country: super::exclusions::HostingCountry) -> Result<()> {
        self.0.lock().map_err(|_| Error::InternalInvariant)?.country = Some(country);
        Ok(())
    }
    pub(super) fn hosting_country(&self) -> Result<Option<super::exclusions::HostingCountry>> {
        Ok(self
            .0
            .lock()
            .map_err(|_| Error::InternalInvariant)?
            .country
            .clone())
    }
    /// Returns immutable completed/in-flight evidence without a raw-body buffer.
    pub fn attempts(&self) -> Result<Vec<FetchAttempt>> {
        Ok(self
            .0
            .lock()
            .map_err(|_| Error::InternalInvariant)?
            .attempts
            .clone())
    }
    /// Records the exact robots decision used for this target, including cache hits and denials.
    pub fn robots(&self, snapshot: RobotsSnapshot) -> Result<()> {
        self.0
            .lock()
            .map_err(|_| Error::InternalInvariant)?
            .last_robots = Some(snapshot);
        Ok(())
    }
    /// Returns the last decision without implying that this target performed the shared fetch.
    pub fn last_robots(&self) -> Result<Option<RobotsSnapshot>> {
        Ok(self
            .0
            .lock()
            .map_err(|_| Error::InternalInvariant)?
            .last_robots
            .clone())
    }
    /// Starts evidence at actual host admission, after address and scope validation.
    pub(super) fn start(
        &self,
        url: &Url,
        kind: FetchKind,
        clock: Arc<dyn Clock>,
        started: DateTime<Utc>,
        queue_ms: u64,
    ) -> Result<WireGuard> {
        let mut trace = self.0.lock().map_err(|_| Error::InternalInvariant)?;
        let index = trace.attempts.len();
        trace.attempts.push(FetchAttempt {
            requested_url: safe_url_for_record(url),
            url_key: url_key(url),
            kind,
            started_at_utc: started,
            finished_at_utc: Observation::absent(AbsenceReason::NotAttempted),
            queue_time_ms: queue_ms,
            fetch_time_ms: 0,
            status: Observation::absent(AbsenceReason::NoResponse),
            error: None,
            robots: Observation::absent(AbsenceReason::NotAttempted),
            body_bytes: 0,
            scope_admitted: true,
            retry_at_utc: None,
            blocked_until_utc: None,
            redirect: Observation::absent(AbsenceReason::NotDeclared),
        });
        Ok(WireGuard {
            trace: self.clone(),
            index,
            start_ticks: clock.ticks(),
            clock,
            finished: false,
        })
    }
    /// Attaches completed bootstrap evidence only to this refresh owner's robots attempts.
    pub(super) fn bootstrap_result(
        &self,
        snapshot: &RobotsSnapshot,
        start_index: usize,
    ) -> Result<()> {
        let mut trace = self.0.lock().map_err(|_| Error::InternalInvariant)?;
        for attempt in trace
            .attempts
            .iter_mut()
            .skip(start_index)
            .filter(|a| a.kind == FetchKind::Robots)
        {
            let mut snapshot = snapshot.clone();
            snapshot.decision = super::robots_txt::RobotsDecision::Bootstrap;
            attempt.robots = Observation::Present(snapshot);
        }
        Ok(())
    }
}
/// Owned in-flight evidence; dropping records cancellation, never a terminal ledger append.
pub(super) struct WireGuard {
    trace: AttemptTrace,
    index: usize,
    start_ticks: u64,
    clock: Arc<dyn Clock>,
    finished: bool,
}
impl WireGuard {
    pub(super) fn update(&self, change: impl FnOnce(&mut FetchAttempt)) -> Result<()> {
        let mut trace = self.trace.0.lock().map_err(|_| Error::InternalInvariant)?;
        change(
            trace
                .attempts
                .get_mut(self.index)
                .ok_or(Error::InternalInvariant)?,
        );
        Ok(())
    }
    pub(super) fn finish(&mut self, error: Option<WireError>) -> Result<()> {
        let now = self.clock.utc();
        let elapsed = self.clock.ticks().saturating_sub(self.start_ticks);
        self.update(|attempt| {
            attempt.finished_at_utc = Observation::Present(now);
            attempt.fetch_time_ms = elapsed;
            attempt.error = error;
        })?;
        self.finished = true;
        Ok(())
    }
}
impl Drop for WireGuard {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.finish(Some(WireError::Cancelled));
        }
    }
}

/// One admitted input, with no raw URL stored in the journal; raw input stays in the caller's memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// Opaque per-input UUID, unique even for duplicate URLs.
    pub target_id: String,
    /// Current run UUID.
    pub run_id: String,
    /// Zero-based original input ordinal within this run.
    pub input_ordinal: u32,
    /// Seed/frontier/auxiliary provenance.
    pub kind: TargetKind,
    /// Optional bounded category from authorized seed input.
    pub category: Option<String>,
    /// UTC durable input-admission time.
    pub started_at_utc: DateTime<Utc>,
    /// Explicit partial evidence retained if the process fails before completion.
    pub record: DocumentRecord,
}
/// Exactly one terminal projection for an admitted target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerRow {
    /// Fixed ledger schema version, currently one.
    pub schema_version: u16,
    /// Opaque run identifier.
    pub run_id: String,
    /// Opaque unique input identifier.
    pub target_id: String,
    /// Zero-based input ordinal, unique within the run.
    pub input_ordinal: u32,
    /// Seed/frontier/auxiliary provenance.
    pub kind: TargetKind,
    /// Optional sanitized bounded input category.
    pub category: Option<String>,
    /// UTC durable target-admission time, including prefetch skips.
    pub started_at_utc: DateTime<Utc>,
    /// UTC terminal completion time.
    pub finished_at_utc: DateTime<Utc>,
    /// Tagged terminal outcome and its typed details.
    #[serde(flatten)]
    pub outcome: Outcome,
    /// Partial or complete version-one document evidence.
    pub record: DocumentRecord,
    /// Actual nested HTTP attempts, never extra terminal robot rows.
    pub fetch_attempts: Vec<FetchAttempt>,
    /// Existing target ID for an exact-scope redirect; source is never credited as saved.
    pub destination_target_id: Option<String>,
    /// Safe destination reference, never the source's last-fetched URL.
    pub redirect_destination: Observation<SafeUrl>,
    /// Relative opaque managed WARC path only after a durable acknowledged write.
    pub body_object: Option<String>,
    /// True when the enclosing run must fail despite preserving this row.
    pub fatal: bool,
}
impl LedgerRow {
    /// Builds a terminal row around an admitted target; the caller supplies actual typed completion.
    pub fn from_target(target: &Target, outcome: Outcome, now: DateTime<Utc>) -> Self {
        Self {
            schema_version: 1,
            run_id: target.run_id.clone(),
            target_id: target.target_id.clone(),
            input_ordinal: target.input_ordinal,
            kind: target.kind,
            category: target.category.clone(),
            started_at_utc: target.started_at_utc,
            finished_at_utc: now,
            fatal: matches!(outcome, Outcome::InternalError { .. }),
            outcome,
            record: target.record.clone(),
            fetch_attempts: vec![],
            destination_target_id: None,
            redirect_destination: Observation::absent(AbsenceReason::NotDeclared),
            body_object: None,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u16,
    store_id: String,
    admissions: BTreeMap<String, Target>,
    completions: BTreeMap<String, LedgerRow>,
}
struct LedgerState {
    journal: Journal,
    projected: BTreeSet<String>,
    claimed: BTreeSet<String>,
    redirects: BTreeMap<String, String>,
}
/// One exclusively owned local journal and terminal JSONL projection, shared by all jobs in a run.
pub struct Ledger {
    registry: Arc<HostRegistry>,
    policy: ValidatedPolicy,
    clock: Arc<dyn Clock>,
    run_id: String,
    state: Mutex<LedgerState>,
    failed: AtomicBool,
}
impl Ledger {
    /// Opens under the existing exclusive store owner, recovers incomplete prior inputs as cancelled,
    /// then atomically rebuilds the JSONL projection before admitting this new run.
    pub fn open(
        registry: Arc<HostRegistry>,
        policy: ValidatedPolicy,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>> {
        let path = registry.root().join("attempts.journal");
        for name in ["attempts.journal", "ledger.jsonl"] {
            if fs::symlink_metadata(registry.root().join(name))
                .is_ok_and(|m| m.file_type().is_symlink() || !m.is_file())
            {
                return Err(Error::StoreRefused);
            }
        }
        let mut journal: Journal = if path.exists() {
            serde_json::from_slice(&fs::read(&path).map_err(|_| Error::LedgerWrite)?)
                .map_err(|_| Error::LedgerWrite)?
        } else {
            Journal {
                version: 1,
                store_id: registry.identity().store_id.clone(),
                admissions: BTreeMap::new(),
                completions: BTreeMap::new(),
            }
        };
        if journal.version != 1 || journal.store_id != registry.identity().store_id {
            return Err(Error::StoreRefused);
        }
        for (id, target) in &journal.admissions {
            if id != &target.target_id || target.record.validate().is_err() {
                return Err(Error::LedgerWrite);
            }
            journal
                .completions
                .entry(id.clone())
                .or_insert_with(|| LedgerRow::from_target(target, Outcome::Cancelled, clock.utc()));
        }
        for (id, row) in &journal.completions {
            if id != &row.target_id
                || !journal.admissions.contains_key(id)
                || row.record.validate().is_err()
            {
                return Err(Error::LedgerWrite);
            }
        }
        let ledger = Arc::new(Self {
            registry,
            policy,
            clock,
            run_id: uuid::Uuid::new_v4().to_string(),
            state: Mutex::new(LedgerState {
                journal,
                projected: BTreeSet::new(),
                claimed: BTreeSet::new(),
                redirects: BTreeMap::new(),
            }),
            failed: AtomicBool::new(false),
        });
        {
            let mut state = ledger.state.lock().map_err(|_| Error::LedgerWrite)?;
            ledger.persist(&state.journal)?;
            let mut bytes = Vec::new();
            for row in state.journal.completions.values() {
                serde_json::to_writer(&mut bytes, row).map_err(|_| Error::LedgerWrite)?;
                bytes.push(b'\n');
            }
            atomic_write(&ledger.registry.root().join("ledger.jsonl"), &bytes)
                .map_err(|_| Error::LedgerWrite)?;
            state.projected = state.journal.completions.keys().cloned().collect();
        }
        Ok(ledger)
    }
    /// Returns the current opaque run ID; rows from previous runs remain retained separately.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }
    fn persist(&self, journal: &Journal) -> Result<()> {
        atomic_write(
            &self.registry.root().join("attempts.journal"),
            &serde_json::to_vec(journal).map_err(|_| Error::LedgerWrite)?,
        )
        .map_err(|_| Error::LedgerWrite)
    }
    /// Durably admits an input before any fetch, preserving its ordinal even if its URL is invalid.
    pub fn admit(
        &self,
        input_ordinal: u32,
        kind: TargetKind,
        category: Option<&str>,
        url: Option<&Url>,
    ) -> Result<Target> {
        self.admit_ordinal(Some(input_ordinal), kind, category, url)
    }
    /// Atomically allocates the next run ordinal for a selected frontier or auxiliary target.
    pub fn admit_next(
        &self,
        kind: TargetKind,
        category: Option<&str>,
        url: Option<&Url>,
    ) -> Result<Target> {
        self.admit_ordinal(None, kind, category, url)
    }
    fn admit_ordinal(
        &self,
        input_ordinal: Option<u32>,
        kind: TargetKind,
        category: Option<&str>,
        url: Option<&Url>,
    ) -> Result<Target> {
        if self.failed.load(Ordering::SeqCst) {
            return Err(Error::LedgerWrite);
        }
        let target_id = uuid::Uuid::new_v4().to_string();
        let mut state = self.state.lock().map_err(|_| Error::LedgerWrite)?;
        let input_ordinal = match input_ordinal {
            Some(ordinal) => ordinal,
            None => state
                .journal
                .admissions
                .values()
                .filter(|target| target.run_id == self.run_id)
                .map(|target| target.input_ordinal)
                .max()
                .map(|ordinal| ordinal.checked_add(1).ok_or(Error::InternalInvariant))
                .transpose()?
                .unwrap_or(0),
        };
        let target = Target {
            target_id: target_id.clone(),
            run_id: self.run_id.clone(),
            input_ordinal,
            kind,
            category: category.map(|s| super::record::bounded_metadata(s, 128)),
            started_at_utc: self.clock.utc(),
            record: DocumentRecord::pending(&self.policy, &self.run_id, &target_id, url),
        };
        target.record.validate()?;
        if state
            .journal
            .admissions
            .values()
            .any(|t| t.run_id == self.run_id && t.input_ordinal == input_ordinal)
        {
            return Err(Error::DuplicateTarget);
        }
        state.journal.admissions.insert(target_id, target.clone());
        if self.persist(&state.journal).is_err() {
            self.failed.store(true, Ordering::SeqCst);
            return Err(Error::LedgerWrite);
        }
        Ok(target)
    }
    /// Claims an exact URL once across concurrent jobs in this run; duplicates still need their own row.
    pub fn claim(&self, url: &Url) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| Error::LedgerWrite)?;
        if !state.claimed.insert(url_key(url)) {
            return Err(Error::AlreadyCrawled);
        }
        Ok(())
    }
    /// Adds only an existing admitted target to the redirect graph; rejects cycles and an eleventh hop.
    /// Returns the existing destination ID and terminal source outcome, without issuing a request.
    pub fn redirect(
        &self,
        source: &Target,
        destination: &Url,
        status: u16,
    ) -> Result<(Outcome, Option<String>)> {
        let key = url_key(destination);
        let mut state = self.state.lock().map_err(|_| Error::LedgerWrite)?;
        let destination = state
            .journal
            .admissions
            .values()
            .filter(|target| {
                target.run_id == self.run_id && target.record.url_key.value() == Some(&key)
            })
            .min_by_key(|target| target.input_ordinal)
            .map(|target| target.target_id.clone());
        let Some(destination) = destination else {
            return Ok((Outcome::RedirectedOffSeed { status }, None));
        };
        let mut graph = state.redirects.clone();
        graph.insert(source.target_id.clone(), destination.clone());
        for start in graph.keys() {
            let mut visited = BTreeSet::new();
            let mut current = start;
            let mut hops = 0;
            loop {
                if !visited.insert(current) {
                    return Ok((Outcome::RedirectLoop, Some(destination)));
                }
                let Some(next) = graph.get(current) else {
                    break;
                };
                hops += 1;
                if hops > 10 {
                    return Ok((Outcome::RedirectLimit, Some(destination)));
                }
                current = next;
            }
        }
        state.redirects = graph;
        Ok((Outcome::RedirectedToSeed { status }, Some(destination)))
    }
    fn ensure_unique_target_id(state: &LedgerState, row: &LedgerRow) -> Result<()> {
        if !state.journal.admissions.contains_key(&row.target_id)
            || state.journal.completions.contains_key(&row.target_id)
        {
            return Err(Error::DuplicateTarget);
        }
        Ok(())
    }
    fn append_terminal(&self, row: &LedgerRow) -> Result<()> {
        let mut bytes = serde_json::to_vec(row).map_err(|_| Error::LedgerWrite)?;
        bytes.push(b'\n');
        let mut file = OpenOptions::new()
            .append(true)
            .create(false)
            .mode(0o600)
            .open(self.registry.root().join("ledger.jsonl"))
            .map_err(|_| Error::LedgerWrite)?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| Error::LedgerWrite)
    }
    /// Commits exactly one typed terminal row after any durable sink acknowledgement.
    /// Journal failure or projection failure poisons the run; neither is reported as coverage success.
    pub fn complete(&self, row: LedgerRow) -> Result<()> {
        if self.failed.load(Ordering::SeqCst) {
            return Err(Error::LedgerWrite);
        }
        row.record.validate()?;
        let mut state = self.state.lock().map_err(|_| Error::LedgerWrite)?;
        Self::ensure_unique_target_id(&state, &row)?;
        let target = state
            .journal
            .admissions
            .get(&row.target_id)
            .ok_or(Error::LedgerWrite)?;
        if row.run_id != target.run_id
            || row.input_ordinal != target.input_ordinal
            || row.record.target_id != row.target_id
            || row.record.run_id != row.run_id
        {
            return Err(Error::LedgerWrite);
        }
        state
            .journal
            .completions
            .insert(row.target_id.clone(), row.clone());
        let result: Result<()> = (|| {
            self.persist(&state.journal)?;
            self.append_terminal(&row)?;
            Ok(())
        })();
        if result.is_err() {
            self.failed.store(true, Ordering::SeqCst);
            return Err(Error::LedgerWrite);
        }
        state.projected.insert(row.target_id);
        Ok(())
    }
    fn verify_no_pending_targets(&self, state: &LedgerState) -> Result<()> {
        if state
            .journal
            .admissions
            .keys()
            .any(|id| !state.journal.completions.contains_key(id) || !state.projected.contains(id))
        {
            return Err(Error::LedgerIncomplete);
        }
        Ok(())
    }
    /// Reconciles admissions, journal completions and actual projection IDs; every gap is fatal.
    pub fn finish(&self) -> Result<()> {
        if self.failed.load(Ordering::SeqCst) {
            return Err(Error::LedgerWrite);
        }
        let state = self.state.lock().map_err(|_| Error::LedgerWrite)?;
        self.verify_no_pending_targets(&state)?;
        let rows = Self::read_rows(&self.registry.root().join("ledger.jsonl"))?;
        let ids: BTreeSet<_> = rows.iter().map(|r| r.target_id.clone()).collect();
        if ids.len() != rows.len() || ids != state.projected {
            return Err(Error::LedgerIncomplete);
        }
        Ok(())
    }
    /// Reads and validates every projected row; malformed/truncated lines or duplicate IDs fail.
    pub fn read_rows(path: &std::path::Path) -> Result<Vec<LedgerRow>> {
        let reader = BufReader::new(File::open(path).map_err(|_| Error::LedgerWrite)?);
        let mut rows = Vec::new();
        let mut ids = BTreeSet::new();
        for line in reader.lines() {
            let row: LedgerRow = serde_json::from_str(&line.map_err(|_| Error::LedgerWrite)?)
                .map_err(|_| Error::LedgerWrite)?;
            row.record.validate()?;
            if row.schema_version != 1 || !ids.insert(row.target_id.clone()) {
                return Err(Error::LedgerIncomplete);
            }
            rows.push(row);
        }
        Ok(rows)
    }
    /// Returns current-run rows only, preserving original input order.
    pub fn rows(&self) -> Result<Vec<LedgerRow>> {
        let state = self.state.lock().map_err(|_| Error::LedgerWrite)?;
        let mut rows: Vec<_> = state
            .journal
            .completions
            .values()
            .filter(|row| row.run_id == self.run_id)
            .cloned()
            .collect();
        rows.sort_by_key(|row| row.input_ordinal);
        Ok(rows)
    }
    /// Finds the latest successful representation for the exact URL and origin, across prior runs.
    /// A later Gone supersedes success; no-store records carry no reusable validators.
    pub fn previous_success(&self, url: &Url) -> Result<Option<DocumentRecord>> {
        let key = url_key(url);
        let state = self.state.lock().map_err(|_| Error::LedgerWrite)?;
        let mut candidates: Vec<_> = state
            .journal
            .completions
            .values()
            .filter(|row| row.record.url_key.value() == Some(&key))
            .collect();
        candidates.sort_by_key(|row| (row.finished_at_utc, row.input_ordinal));
        for row in candidates.into_iter().rev() {
            if matches!(row.outcome, Outcome::Gone) {
                return Ok(None);
            }
            if matches!(
                row.outcome,
                Outcome::Saved
                    | Outcome::SavedNoindex
                    | Outcome::ParsedNotRetained
                    | Outcome::NotModified
            ) {
                return Ok(Some(row.record.clone()));
            }
        }
        Ok(None)
    }
    /// Returns the latest parsed declaration even when language policy excluded that response.
    /// A failed or bodyless later request cannot erase previously observed frontier restrictions.
    pub fn previous_languages(&self, url: &Url) -> Result<Option<Vec<String>>> {
        let key = url_key(url);
        let state = self.state.lock().map_err(|_| Error::LedgerWrite)?;
        Ok(state
            .journal
            .completions
            .values()
            .filter(|row| {
                row.record.url_key.value() == Some(&key)
                    && row.record.parsed_at_utc.value().is_some()
            })
            .max_by_key(|row| (row.finished_at_utc, row.input_ordinal))
            .map(|row| row.record.declared_languages.clone()))
    }
    /// Returns all current-run inputs, used for explicit cancellation and exact redirect joins.
    pub fn targets(&self) -> Result<Vec<Target>> {
        let state = self.state.lock().map_err(|_| Error::LedgerWrite)?;
        let mut targets: Vec<_> = state
            .journal
            .admissions
            .values()
            .filter(|t| t.run_id == self.run_id)
            .cloned()
            .collect();
        targets.sort_by_key(|t| t.input_ordinal);
        Ok(targets)
    }
}
