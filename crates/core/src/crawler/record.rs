//! Defines version-one per-target evidence with explicit absent observations and bounded metadata.
//! Records contain no body, cookie, authorization header or raw error; exact operational URLs
//! remove userinfo/fragment and preserve queries. Retention and serving execution live elsewhere.

#![deny(missing_docs)]

use super::{
    directives::{DirectiveObservation, EffectiveDirectives, ParsedDirectives, RightsSignals},
    exclusions::{CountryUnknownReason, ExclusionMatch, HostingCountry},
    host_state::BlockReason,
    network::{safe_url_for_record, sha256, url_key, HostKey, ResponseHeaders, SafeUrl},
    robots_txt::RobotsSnapshot,
    Error, Result,
};
use crate::config::ingestion::{ContentClass, ContentPolicy, ValidatedPolicy};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

/// Why an observation does not exist; no placeholder value is fabricated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AbsenceReason {
    /// Target admission has not produced this observation.
    NotAttempted,
    /// No response arrived from the requested target.
    NoResponse,
    /// The body stream did not complete.
    IncompleteBody,
    /// Publisher did not declare the metadata.
    NotDeclared,
    /// Publisher declaration was present but invalid.
    InvalidDeclaration,
    /// Input could not be parsed as an admissible URL.
    InvalidInput,
    /// Body has not been parsed as a document.
    NotParsed,
    /// Field does not apply to this request kind or outcome.
    NotApplicable,
}
/// Explicit present/absent observation, serialized even when unavailable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "value", rename_all = "kebab-case")]
pub enum Observation<T> {
    /// Observed value, never a synthetic default standing in for an observation.
    Present(T),
    /// The value does not exist for the stated typed reason.
    Absent {
        /// Explicit lifecycle or declaration absence code.
        reason: AbsenceReason,
    },
}
impl<T> Observation<T> {
    /// Creates an explicit absent observation.
    pub fn absent(reason: AbsenceReason) -> Self {
        Self::Absent { reason }
    }
    /// Returns the observed value if one exists, without losing the serialized absence reason.
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Present(value) => Some(value),
            Self::Absent { .. } => None,
        }
    }
    /// Reports absence for validators without inventing a default value.
    pub fn is_none(&self) -> bool {
        self.value().is_none()
    }
}
/// Origin of a content digest, distinguishing 304 reuse from actual received entity bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContentHashSource {
    /// SHA-256 of the completed current response entity, before charset decoding.
    CurrentResponse,
    /// Prior successful representation's digest, preserved by a valid 304.
    PreviousSuccess,
    /// No completed current or prior representation is available.
    Unavailable,
}
/// Raw-body retention decision; metadata/ledger records have no automatic TTL in Slice 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BodyRetentionReason {
    /// A managed body may be retained until its fixed original deadline.
    Retained,
    /// Cache-Control no-store prohibits retention and validator persistence.
    NoStore,
    /// Licence/TDM signals require metadata-only handling pending interpretation.
    RightsReserved,
    /// Local zero TTL, directive limit or exclusion requires metadata-only handling.
    Policy,
    /// Actual 404/410 removes previously retained objects for the URL.
    Gone,
    /// No complete eligible body was received.
    NotReceived,
    /// Original or shortened raw-body TTL elapsed.
    Expired,
}
/// Permitted reuse in Stage 1, independent of publisher restrictions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReuseScope {
    /// No advertising, profiling, image or general-purpose reuse.
    SearchIndexOnly,
}
/// Minimal opaque HTTP validators, never rendered or written to tracing.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Validators {
    /// Safe ETag, at most 1,024 bytes and without controls.
    pub etag: Option<String>,
    /// Safe Last-Modified, at most 1,024 bytes and without controls.
    pub last_modified: Option<String>,
}
impl std::fmt::Debug for Validators {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Validators([protocol values])")
    }
}
impl Validators {
    /// Captures single bounded validators only when every occurrence has visible ASCII bytes.
    /// An invalid occurrence discards that validator, including otherwise valid duplicates.
    pub fn from_headers(headers: &ResponseHeaders) -> Self {
        fn safe(headers: &ResponseHeaders, name: &str) -> Option<String> {
            if headers.invalid(name) {
                return None;
            }
            let values = headers.all(name);
            (values.len() == 1)
                .then(|| values[0].clone())
                .filter(|value| {
                    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
                })
        }
        Self {
            etag: safe(headers, "etag"),
            last_modified: safe(headers, "last-modified"),
        }
    }
    /// Returns both conditional fields for this exact URL/origin lookup only.
    pub fn request_headers(&self) -> Vec<(String, String)> {
        self.etag
            .iter()
            .map(|v| ("If-None-Match".into(), v.clone()))
            .chain(
                self.last_modified
                    .iter()
                    .map(|v| ("If-Modified-Since".into(), v.clone())),
            )
            .collect()
    }
    fn valid(&self) -> bool {
        self.etag
            .iter()
            .chain(self.last_modified.iter())
            .all(|value| {
                !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
            })
    }
}
/// Scope of a future deletion event; one missing URL never implies a missing host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TombstoneScope {
    /// Only this exact operational URL is affected.
    Url,
    /// Reserved for independently confirmed host removal in Story #588.
    Host,
}
/// Deletion handoff metadata retained until downstream acknowledgement in Story #588.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tombstone {
    /// URL-only for a 404/410 response.
    pub scope: TombstoneScope,
    /// UTC time of the actual deletion-triggering observation.
    pub observed_at_utc: DateTime<Utc>,
    /// Downstream deadline, at most 24 hours after observation.
    pub delete_due_at_utc: DateTime<Utc>,
}

/// Required version-one target record; only legacy WARC may omit this entire extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentRecord {
    /// Fixed schema version, currently one.
    pub schema_version: u16,
    /// Opaque per-input identifier; contains no URL.
    pub target_id: String,
    /// Opaque run identifier shared with the journal and ledger.
    pub run_id: String,
    /// First valid declared canonical, or exact final URL; absent only for invalid input.
    pub canonical_url: Observation<SafeUrl>,
    /// Exact original fetch URL, with userinfo/fragment removed and query retained.
    pub requested_url: Observation<SafeUrl>,
    /// Last actually transmitted URL, never an unfetched Location.
    pub final_url: Observation<SafeUrl>,
    /// Plain SHA-256 of the requested operational URL bytes, absent for invalid input.
    pub url_key: Observation<String>,
    /// Plain SHA-256 of the canonical operational URL bytes.
    pub canonical_key: Observation<String>,
    /// UTC actual request start, separate from target queue admission.
    pub retrieved_at_utc: Observation<DateTime<Utc>>,
    /// UTC original parse time; a 304 does not renew this timestamp.
    pub parsed_at_utc: Observation<DateTime<Utc>>,
    /// Actual final HTTP status in 100..=599, absent if no response arrived.
    pub http_status: Observation<u16>,
    /// Lowercase 64-digit SHA-256 of completed entity bytes before decoding.
    pub content_sha256: Observation<String>,
    /// Whether the digest came from this response or a previous representation.
    pub content_hash_source: ContentHashSource,
    /// Immutable robots decision actually used after waiting for the host gate.
    pub robots: Observation<RobotsSnapshot>,
    /// Restrictively merged publisher restrictions.
    pub directives: EffectiveDirectives,
    /// Sanitized directive sources, capped at 256.
    pub directives_seen: Vec<DirectiveObservation>,
    /// Licence and TDM signals without inferred licence permissions.
    pub rights: RightsSignals,
    /// Declared canonical separately from the fallback canonical URL.
    pub rel_canonical: Observation<SafeUrl>,
    /// Declared publisher, at most 256 Unicode scalar values with controls removed.
    pub publisher_name: Observation<String>,
    /// Declared site name, at most 256 Unicode scalar values with controls removed.
    pub site_name: Observation<String>,
    /// Declared document title, at most 512 Unicode scalar values with controls removed.
    pub title: Observation<String>,
    /// Canonical ASCII HostKey, preserving www.
    pub source_domain: Observation<String>,
    /// Primary declared BCP47-shaped language; no classifier result is substituted.
    pub declared_language: Observation<String>,
    /// All valid declarations, preserving deny precedence across conflicting sources.
    pub declared_languages: Vec<String>,
    /// Same declaration as declared_language in Slice 1.
    pub language: Observation<String>,
    /// Policy version used for this request.
    pub crawl_policy_version: String,
    /// Exact exclusion-list version evaluated at frontier and post-parse.
    pub exclusion_version: String,
    /// Version of the common policy containing retention configuration.
    pub retention_policy_version: String,
    /// SHA-256 of canonical serialization of the validated configuration.
    pub policy_config_sha256: String,
    /// Crawler package semantic version used in the fixed identity.
    pub identity_version: String,
    /// Actual fetch duration in milliseconds, excluding queue wait, including body/error.
    pub fetch_time_ms: Observation<u64>,
    /// Host-gate wait in milliseconds before request admission.
    pub queue_time_ms: Observation<u64>,
    /// Received entity byte count, including partial reads on failure.
    pub body_bytes: Observation<u64>,
    /// Bytes durably retained as body content; zero when forbidden or unsuccessful.
    pub retained_body_bytes: u64,
    /// Parsed MIME essence, with explicit absent/invalid state.
    pub media_type: Observation<String>,
    /// Charset actually used for decoding.
    pub charset: Observation<String>,
    /// Unknown declared charset fell back to UTF-8.
    pub charset_fallback: bool,
    /// Minimal validators from the last successful retainable 200 for this exact URL.
    pub validators: Validators,
    /// Publisher/local eligibility; not evidence that an index accepted this record.
    pub index_eligible: bool,
    /// Metadata-only rights/policy handling; no full body enters any index/sink.
    pub index_only: bool,
    /// Always false in Stage 1.
    pub cached_copy: bool,
    /// Effective Unicode-scalar snippet cap, in 0..=300.
    pub snippet_limit_chars: u16,
    /// No preassembled snippet text in Slice 1.
    pub snippet_text: Option<String>,
    /// Publisher explicitly declared a NewsArticle type; no inferred classifier.
    pub recognized_news: bool,
    /// Publisher explicitly declared isAccessibleForFree=false; no paywall bypass.
    pub paywall_detected: bool,
    /// Explicit permission only; absence never grants a news/paywall snippet.
    pub publisher_snippet_permission: Observation<bool>,
    /// Always false; no image download/storage is implemented.
    pub image_storage_allowed: bool,
    /// Restricted search-index-only reuse contract.
    pub reuse_scope: ReuseScope,
    /// Fixed reason for raw-body storage or refusal.
    pub body_retention: BodyRetentionReason,
    /// Original raw deadline anchored to parse time, at most 30 days.
    pub raw_expires_at_utc: Option<DateTime<Utc>>,
    /// Refresh scheduling handoff, no later than seven days after this check.
    pub refresh_due_at_utc: Option<DateTime<Utc>>,
    /// Earliest publisher removal deadline, mirrored for downstream scheduling.
    pub unavailable_after_utc: Option<DateTime<Utc>>,
    /// Optional URL/host deletion handoff; 404/410 produces URL scope only.
    pub tombstone: Option<Tombstone>,
    /// Configured host-list categories; no inferred attributes.
    pub content_classes: Vec<ContentClass>,
    /// All matched four-enum policy actions.
    pub content_policies: Vec<ContentPolicy>,
    /// Provider-backed country or explicit unknown reason.
    pub hosting_country: HostingCountry,
    /// All matching versioned host rule IDs and phases.
    pub exclusion_matches: Vec<ExclusionMatch>,
    /// Applied minimum request gap in milliseconds, at least 500.
    pub effective_gap_ms: u64,
    /// Latest retained rate/backoff deadline.
    pub retry_at_utc: Option<DateTime<Utc>>,
    /// Latest retained access block deadline.
    pub blocked_until_utc: Option<DateTime<Utc>>,
    /// Typed HTTP/challenge/indefinite block cause.
    pub block_reason: Option<BlockReason>,
    /// Consecutive 429/503 counter observed after this target.
    pub consecutive_rate_responses: u32,
    /// Invalid/overflowing Retry-After occurred; raw value is not retained.
    pub retry_after_invalid: bool,
}
impl DocumentRecord {
    /// Creates a partial record at durable target admission, with explicit absent observations.
    pub fn pending(
        policy: &ValidatedPolicy,
        run_id: &str,
        target_id: &str,
        url: Option<&Url>,
    ) -> Self {
        let p = policy.get();
        let declared = || Observation::absent(AbsenceReason::NotDeclared);
        let requested = url
            .map(safe_url_for_record)
            .map(Observation::Present)
            .unwrap_or_else(|| Observation::absent(AbsenceReason::InvalidInput));
        let key = url
            .map(url_key)
            .map(Observation::Present)
            .unwrap_or_else(|| Observation::absent(AbsenceReason::InvalidInput));
        Self {
            schema_version: 1,
            target_id: target_id.into(),
            run_id: run_id.into(),
            canonical_url: Observation::absent(AbsenceReason::NotAttempted),
            requested_url: requested,
            final_url: Observation::absent(AbsenceReason::NotAttempted),
            url_key: key,
            canonical_key: Observation::absent(AbsenceReason::NotAttempted),
            retrieved_at_utc: Observation::absent(AbsenceReason::NotAttempted),
            parsed_at_utc: Observation::absent(AbsenceReason::NotParsed),
            http_status: Observation::absent(AbsenceReason::NoResponse),
            content_sha256: Observation::absent(AbsenceReason::IncompleteBody),
            content_hash_source: ContentHashSource::Unavailable,
            robots: Observation::absent(AbsenceReason::NotAttempted),
            directives: EffectiveDirectives::default(),
            directives_seen: vec![],
            rights: RightsSignals::default(),
            rel_canonical: Observation::absent(AbsenceReason::NotDeclared),
            publisher_name: declared(),
            site_name: declared(),
            title: declared(),
            source_domain: url
                .and_then(|u| HostKey::from_url(u).ok())
                .map(|h| Observation::Present(h.as_str().into()))
                .unwrap_or_else(|| Observation::absent(AbsenceReason::InvalidInput)),
            declared_language: declared(),
            declared_languages: vec![],
            language: declared(),
            crawl_policy_version: p.version.clone(),
            exclusion_version: p.exclusions.version.clone(),
            retention_policy_version: p.version.clone(),
            policy_config_sha256: policy.sha256(),
            identity_version: env!("CARGO_PKG_VERSION").into(),
            fetch_time_ms: Observation::absent(AbsenceReason::NotAttempted),
            queue_time_ms: Observation::absent(AbsenceReason::NotAttempted),
            body_bytes: Observation::absent(AbsenceReason::NoResponse),
            retained_body_bytes: 0,
            media_type: Observation::absent(AbsenceReason::NotDeclared),
            charset: Observation::absent(AbsenceReason::NotParsed),
            charset_fallback: false,
            validators: Validators::default(),
            index_eligible: false,
            index_only: false,
            cached_copy: false,
            snippet_limit_chars: p.retention.snippet_max_chars,
            snippet_text: None,
            recognized_news: false,
            paywall_detected: false,
            publisher_snippet_permission: Observation::absent(AbsenceReason::NotDeclared),
            image_storage_allowed: false,
            reuse_scope: ReuseScope::SearchIndexOnly,
            body_retention: BodyRetentionReason::NotReceived,
            raw_expires_at_utc: None,
            refresh_due_at_utc: None,
            unavailable_after_utc: None,
            tombstone: None,
            content_classes: vec![],
            content_policies: vec![],
            hosting_country: HostingCountry::Unknown {
                reason: CountryUnknownReason::NotResolved,
            },
            exclusion_matches: vec![],
            effective_gap_ms: p.politeness.gap_ms,
            retry_at_utc: None,
            blocked_until_utc: None,
            block_reason: None,
            consecutive_rate_responses: 0,
            retry_after_invalid: false,
        }
    }
    /// Applies current publisher/body policy before any sink can receive a parsed document.
    pub fn apply_policy(
        &mut self,
        parsed: ParsedDirectives,
        policy: &ValidatedPolicy,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.directives = parsed.effective;
        self.directives_seen = parsed.seen;
        self.rights = parsed.rights;
        self.index_eligible = self.directives.index_eligible(now);
        self.index_only = self.rights.index_only() || self.directives.limit_exceeded;
        self.snippet_limit_chars = super::directives::snippet_limit(
            &self.directives,
            policy.get().retention.snippet_max_chars,
            self.recognized_news,
            self.paywall_detected,
            self.publisher_snippet_permission
                .value()
                .copied()
                .unwrap_or(false),
        );
        self.unavailable_after_utc = self.directives.unavailable_after_utc;
        self.refresh_due_at_utc = now.checked_add_signed(chrono::TimeDelta::days(7));
        self.body_retention = if parsed.no_store {
            BodyRetentionReason::NoStore
        } else if self.rights.index_only() {
            BodyRetentionReason::RightsReserved
        } else if self.index_only || policy.get().retention.raw_body_max_age_days == 0 {
            BodyRetentionReason::Policy
        } else {
            BodyRetentionReason::Retained
        };
        self.raw_expires_at_utc = if self.body_retention == BodyRetentionReason::Retained {
            Some(
                now.checked_add_signed(chrono::TimeDelta::days(i64::from(
                    policy.get().retention.raw_body_max_age_days,
                )))
                .ok_or(Error::InternalInvariant)?,
            )
        } else {
            None
        };
        if self.body_retention == BodyRetentionReason::NoStore {
            self.validators = Validators::default();
        }
        Ok(())
    }
    /// Validates every serialized record and all fields required by a completed parse.
    pub fn validate(&self) -> Result<()> {
        let hash = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if self.schema_version != 1
            || uuid::Uuid::parse_str(&self.target_id).is_err()
            || uuid::Uuid::parse_str(&self.run_id).is_err()
            || self.crawl_policy_version.is_empty()
            || self.exclusion_version.is_empty()
            || self.retention_policy_version.is_empty()
            || !hash(&self.policy_config_sha256)
            || self.snippet_limit_chars > 300
            || self.cached_copy
            || self.image_storage_allowed
            || self.snippet_text.is_some()
            || !self.validators.valid()
            || self.directives_seen.len() > 256
            || self.effective_gap_ms < 500
            || self
                .http_status
                .value()
                .is_some_and(|status| !(100..=599).contains(status))
        {
            return Err(Error::RecordInvalid);
        }
        for value in [&self.url_key, &self.canonical_key, &self.content_sha256] {
            if value.value().is_some_and(|value| !hash(value)) {
                return Err(Error::RecordInvalid);
            }
        }
        for (value, limit) in [
            (&self.publisher_name, 256),
            (&self.site_name, 256),
            (&self.title, 512),
        ] {
            if value
                .value()
                .is_some_and(|s| s.chars().count() > limit || s.chars().any(char::is_control))
            {
                return Err(Error::RecordInvalid);
            }
        }
        for value in [
            &self.canonical_url,
            &self.requested_url,
            &self.final_url,
            &self.rel_canonical,
        ]
        .into_iter()
        .filter_map(Observation::value)
        .chain(self.rights.license_urls.iter())
        .chain(self.rights.tdm_policy_urls.iter())
        {
            let parsed = Url::parse(value.as_str()).map_err(|_| Error::RecordInvalid)?;
            if safe_url_for_record(&parsed) != *value
                || value.as_str().len() > 8192
                || !matches!(parsed.scheme(), "http" | "https")
            {
                return Err(Error::RecordInvalid);
            }
        }
        if let (Some(url), Some(key)) = (self.requested_url.value(), self.url_key.value()) {
            if sha256(url.as_str().as_bytes()) != *key {
                return Err(Error::RecordInvalid);
            }
        }
        if let (Some(url), Some(key)) = (self.canonical_url.value(), self.canonical_key.value()) {
            if sha256(url.as_str().as_bytes()) != *key {
                return Err(Error::RecordInvalid);
            }
        }
        if self.parsed_at_utc.value().is_some()
            || self.retained_body_bytes > 0
            || self.index_eligible
        {
            validate_success_fields(self)?;
        }
        if self.body_retention != BodyRetentionReason::Retained
            && (self.retained_body_bytes != 0 || self.raw_expires_at_utc.is_some())
        {
            return Err(Error::RecordInvalid);
        }
        if self.index_only && self.retained_body_bytes != 0 {
            return Err(Error::RecordInvalid);
        }
        Ok(())
    }
}
/// Enforces non-fabricated retrieval/status/hash/robots evidence for every completed document parse.
pub fn validate_success_fields(record: &DocumentRecord) -> Result<()> {
    if record.parsed_at_utc.is_none()
        || record.requested_url.is_none()
        || record.final_url.is_none()
        || record.canonical_url.is_none()
        || record.retrieved_at_utc.is_none()
        || record.http_status.is_none()
        || record.content_sha256.is_none()
        || record.robots.is_none()
        || record.fetch_time_ms.is_none()
        || record.queue_time_ms.is_none()
        || record.body_bytes.is_none()
        || record.content_hash_source == ContentHashSource::Unavailable
    {
        return Err(Error::RecordInvalid);
    }
    if let Some(expiry) = record.raw_expires_at_utc {
        let parsed = record.parsed_at_utc.value().ok_or(Error::RecordInvalid)?;
        if expiry < *parsed || expiry > *parsed + chrono::TimeDelta::days(30) {
            return Err(Error::RecordInvalid);
        }
    }
    Ok(())
}

/// Strips controls and bounds Unicode scalar values without storing unbounded publisher strings.
pub fn bounded_metadata(value: &str, limit: usize) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(limit)
        .collect()
}

/// Captures bounded declared attribution from the existing DOM, independently of frontier extraction.
pub(crate) fn capture_metadata(
    root: &kuchiki::NodeRef,
    record: &mut DocumentRecord,
    headers: &ResponseHeaders,
    final_url: &Url,
) {
    let present = |value: &str, limit| Observation::Present(bounded_metadata(value, limit));
    if let Some(title) = root.select("title").expect("static title selector").next() {
        record.title = present(&title.text_contents(), 512);
    }
    for node in root.select("meta").expect("static meta selector") {
        let attributes = node.attributes.borrow();
        if attributes
            .get("property")
            .is_some_and(|name| name.eq_ignore_ascii_case("og:site_name"))
            && record.site_name.is_none()
        {
            if let Some(value) = attributes.get("content") {
                record.site_name = present(value, 256);
                record.publisher_name = record.site_name.clone();
            }
        }
    }
    let mut invalid_canonical = false;
    for node in root.select("link[rel]").expect("static canonical selector") {
        let attributes = node.attributes.borrow();
        if !attributes
            .get("rel")
            .unwrap_or_default()
            .split_ascii_whitespace()
            .any(|token| token.eq_ignore_ascii_case("canonical"))
        {
            continue;
        }
        let raw = attributes.get("href").unwrap_or_default();
        let canonical = if raw.len() <= 8192
            && !raw.is_empty()
            && !raw.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            final_url
                .join(raw)
                .ok()
                .filter(|url| matches!(url.scheme(), "http" | "https") && url.host_str().is_some())
        } else {
            None
        };
        if let Some(canonical) = canonical {
            let safe = safe_url_for_record(&canonical);
            record.canonical_key = Observation::Present(sha256(safe.as_str().as_bytes()));
            record.rel_canonical = Observation::Present(safe.clone());
            record.canonical_url = Observation::Present(safe);
            break;
        }
        invalid_canonical = true;
    }
    if record.rel_canonical.is_none() && invalid_canonical {
        record.rel_canonical = Observation::absent(AbsenceReason::InvalidDeclaration);
    }
    let mut languages = Vec::new();
    if let Some(html) = root.select("html").expect("static html selector").next() {
        if let Some(raw) = html.attributes.borrow().get("lang") {
            if let Some(language) = super::exclusions::declared_language(raw) {
                languages.push(language);
            } else {
                record.declared_language = Observation::absent(AbsenceReason::InvalidDeclaration);
            }
        }
    }
    for value in headers.all("content-language") {
        for value in value.split(',') {
            if let Some(language) = super::exclusions::declared_language(value) {
                if !languages.contains(&language) {
                    languages.push(language);
                }
            }
        }
    }
    if let Some(language) = languages.first() {
        record.declared_language = Observation::Present(language.clone());
    }
    if headers.invalid("content-language") {
        record.declared_language = Observation::absent(AbsenceReason::InvalidDeclaration);
        languages.clear();
    }
    record.language = record.declared_language.clone();
    record.declared_languages = languages;
    for node in root
        .select("script[type]")
        .expect("static structured metadata selector")
    {
        if !node
            .attributes
            .borrow()
            .get("type")
            .is_some_and(|kind| kind.eq_ignore_ascii_case("application/ld+json"))
        {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&node.text_contents()) {
            capture_structured_metadata(&value, record, 0);
        }
    }
}
fn capture_structured_metadata(value: &serde_json::Value, record: &mut DocumentRecord, depth: u8) {
    if depth > 16 {
        return;
    }
    if let Some(values) = value.as_array() {
        for value in values {
            capture_structured_metadata(value, record, depth + 1);
        }
        return;
    }
    if let Some(object) = value.as_object() {
        if let Some(kind) = object.get("@type") {
            let news = |v: &serde_json::Value| v.as_str().is_some_and(|s| s == "NewsArticle");
            record.recognized_news |= news(kind)
                || kind
                    .as_array()
                    .is_some_and(|values| values.iter().any(news));
        }
        record.paywall_detected |= object
            .get("isAccessibleForFree")
            .is_some_and(|value| value == false);
        if record.publisher_name.is_none() {
            if let Some(name) = object
                .get("publisher")
                .and_then(|publisher| publisher.get("name"))
                .and_then(serde_json::Value::as_str)
            {
                record.publisher_name = Observation::Present(bounded_metadata(name, 256));
            }
        }
        if let Some(graph) = object.get("@graph") {
            capture_structured_metadata(graph, record, depth + 1);
        }
    }
}
