//! Persists host blocks, rate deadlines and listing budgets under one exclusive local owner.
//! Atomic JSON replacement is acknowledged before another request; failed persistence is fatal.
//! Separate stores do not coordinate host ownership. A same-privilege hostile writer is outside
//! the owner-private filesystem model; symlinks and foreign store markers are rejected.
//! Challenge signatures miss localized/JS-only challenges and can reject real verification forms.
//! No challenge is solved and no resource, script or alternate identity is fetched.

#![deny(missing_docs)]

use super::{
    network::{HostKey, ResponseHeaders},
    politeness::{Clock, HostGate, MIN_BLOCK_SECS},
    Error, Result,
};
use crate::config::ingestion::ValidatedPolicy;
use chrono::{DateTime, TimeDelta, Utc};
use fs4::FileExt;
use kuchiki::traits::TendrilSink;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

/// Evidence code for the complete, versioned challenge rule; no challenge text is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChallengeKind {
    /// cf-mitigated: challenge was observed, independent of status/MIME.
    MitigatedHeader,
    /// A challenge-action form and a visible verification phrase were both observed.
    VerificationForm,
    /// An interactive captcha widget and a visible verification phrase were both observed.
    InteractiveWidget,
}

/// Returns only a signature code, never tokens or challenge text.
/// Invalid cf-mitigated bytes imply a challenge; no sentinel or raw bytes are retained.
/// Article/code/script mentions alone do not satisfy the visible interactive challenge rule.
pub fn detect_challenge(headers: &ResponseHeaders, bytes: &[u8]) -> Option<ChallengeKind> {
    if headers.invalid("cf-mitigated")
        || headers
            .all("cf-mitigated")
            .iter()
            .any(|s| s.trim().eq_ignore_ascii_case("challenge"))
    {
        return Some(ChallengeKind::MitigatedHeader);
    }
    let document = kuchiki::parse_html().one(String::from_utf8_lossy(bytes).as_ref());
    let mut visible = String::new();
    for node in document.descendants() {
        if let Some(text) = node.as_text() {
            if !node.ancestors().any(|ancestor| {
                ancestor.as_element().is_some_and(|e| {
                    matches!(
                        e.name.local.as_ref(),
                        "script" | "style" | "code" | "pre" | "head"
                    )
                })
            }) {
                visible.push_str(&text.borrow());
                visible.push(' ');
            }
        }
    }
    let visible = visible
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    if ![
        "verify you are human",
        "checking your browser",
        "complete the security check",
    ]
    .iter()
    .any(|phrase| visible.contains(phrase))
    {
        return None;
    }
    for node in document.select("form").expect("static form selector") {
        let attrs = node.attributes.borrow();
        if let Some(action) = attrs.get("action") {
            let path = action.split(['?', '#']).next().unwrap_or_default();
            if path.contains("/cdn-cgi/challenge-platform/") || path.contains("/challenge/") {
                return Some(ChallengeKind::VerificationForm);
            }
        }
    }
    for node in document
        .select("[class], iframe")
        .expect("static widget selector")
    {
        let attrs = node.attributes.borrow();
        if attrs.get("class").is_some_and(|value| {
            value
                .split_ascii_whitespace()
                .any(|token| matches!(token, "g-recaptcha" | "h-captcha" | "cf-turnstile"))
        }) {
            return Some(ChallengeKind::InteractiveWidget);
        }
        if node.name.local.as_ref() == "iframe" {
            if let Some(source) = attrs.get("src") {
                let base = url::Url::parse("https://fixture.invalid/").expect("fixed origin");
                if base
                    .join(source)
                    .ok()
                    .and_then(|url| url.host_str().map(str::to_owned))
                    .is_some_and(|host| host == "recaptcha.net" || host.ends_with(".recaptcha.net"))
                {
                    return Some(ChallengeKind::InteractiveWidget);
                }
            }
        }
    }
    None
}

/// Classified reason for a persisted host access block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlockReason {
    /// Actual 401, 403 or 429 status observed on any fetch kind.
    HttpStatus(u16),
    /// Version-one challenge detection result without raw evidence text.
    Challenge(ChallengeKind),
    /// Retry deadline cannot fit UTC; fail closed until operator review.
    IndefiniteRateDeadline,
}

/// UTC state persisted across jobs/restarts; active monotonic deadlines are held by HostGate.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostState {
    /// Access block expiry; 401/403/429/challenges impose at least 24 hours.
    pub blocked_until_utc: Option<DateTime<Utc>>,
    /// Classified block cause, without response text.
    pub block_reason: Option<BlockReason>,
    /// Consecutive 429/503 responses, saturated upward, reset only by 2xx/valid 304.
    pub consecutive_rate_responses: u32,
    /// Latest Retry-After/backoff deadline; never shortened to the exponential cap.
    pub retry_at_utc: Option<DateTime<Utc>>,
    /// Invalid or overflowing Retry-After was observed; no raw value is persisted.
    pub retry_after_invalid: bool,
    /// Actual previous request start for conservative restart gap recovery.
    pub last_request_start: Option<DateTime<Utc>>,
    /// Beginning of the current rolling listing-budget window.
    pub listing_window_start_utc: Option<DateTime<Utc>>,
    /// Admitted page attempts in that window; includes failures, excludes robots.
    pub listing_attempts: u64,
}

/// Marker identifying the owned local store; raw-body objects use the same store ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreIdentity {
    /// Fixed managed-store kind; foreign stores are never interpreted as crawl stores.
    pub kind: String,
    /// Store format version, currently one.
    pub version: u16,
    /// Random opaque store identifier persisted before host state or bodies.
    pub store_id: String,
    /// Digest of the policy that initialized the store, not a mutable retention override.
    pub config_sha256: String,
}

/// Exclusive owned local store; one shared instance is retained by transport, sink and ledger.
pub struct HostRegistry {
    root: PathBuf,
    identity: StoreIdentity,
    _owner: File,
    states: Mutex<BTreeMap<HostKey, HostState>>,
    gates: Mutex<BTreeMap<HostKey, Arc<HostGate>>>,
    failed: AtomicBool,
    policy: ValidatedPolicy,
    clock: Arc<dyn Clock>,
}

fn io_error(_: std::io::Error) -> Error {
    Error::HostStateWrite
}

/// Validates an absolute owner-private store path before any write or deletion.
/// Refuses symlinks, non-normal raw components and the source repository or its ancestors.
pub fn validate_store_root(root: &Path) -> Result<PathBuf> {
    let bytes = root.as_os_str().as_encoded_bytes();
    if !root.is_absolute()
        || root
            .components()
            .skip(1)
            .any(|c| !matches!(c, Component::Normal(_)))
        || bytes
            .split(|b| *b == b'/')
            .any(|name| name == b"." || name == b"..")
    {
        return Err(Error::StoreRefused);
    }
    let mut cursor = PathBuf::from("/");
    for component in root.components().skip(1) {
        cursor.push(component.as_os_str());
        match fs::symlink_metadata(&cursor) {
            Ok(m) if m.file_type().is_symlink() => return Err(Error::StoreRefused),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::StoreRefused),
        }
    }
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(io_error)?;
    if root.starts_with(&repository) || repository.starts_with(root) {
        return Err(Error::StoreRefused);
    }
    Ok(root.to_owned())
}

/// Writes a single owned-store file atomically with mode 0600 and acknowledged file/directory sync.
/// The destination must already be inside an exclusively owned validated store.
pub(super) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or(Error::StoreRefused)?;
    let temp = parent.join(format!(".pending-{}", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(io_error)?;
    let result = (|| {
        file.write_all(bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        fs::rename(&temp, path).map_err(io_error)?;
        File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(io_error)
    })();
    if result.is_err() && temp.exists() {
        let _ = fs::remove_file(temp);
    }
    result
}

impl HostRegistry {
    /// Acquires sole ownership before loading state; a second owner or failed write refuses startup.
    /// An uninitialized nonempty directory is never adopted as a managed store.
    pub fn open(root: &Path, policy: ValidatedPolicy, clock: Arc<dyn Clock>) -> Result<Arc<Self>> {
        let root = validate_store_root(root)?;
        if !root.exists() {
            fs::create_dir_all(&root).map_err(io_error)?;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
        }
        let initialized = root.join("store.json").is_file();
        if !initialized && fs::read_dir(&root).map_err(io_error)?.next().is_some() {
            return Err(Error::StoreRefused);
        }
        for name in ["owner.lock", "store.json", "host-state.json"] {
            if fs::symlink_metadata(root.join(name)).is_ok_and(|m| m.file_type().is_symlink()) {
                return Err(Error::StoreRefused);
            }
        }
        let owner = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(root.join("owner.lock"))
            .map_err(io_error)?;
        FileExt::try_lock_exclusive(&owner).map_err(|_| Error::StoreOwned)?;
        let identity: StoreIdentity = if initialized {
            serde_json::from_slice(&fs::read(root.join("store.json")).map_err(io_error)?)
                .map_err(|_| Error::StoreRefused)?
        } else {
            let identity = StoreIdentity {
                kind: "ava-search-local-crawl".into(),
                version: 1,
                store_id: uuid::Uuid::new_v4().to_string(),
                config_sha256: policy.sha256(),
            };
            atomic_write(
                &root.join("store.json"),
                &serde_json::to_vec(&identity).map_err(|_| Error::InternalInvariant)?,
            )?;
            identity
        };
        if identity.kind != "ava-search-local-crawl"
            || identity.version != 1
            || uuid::Uuid::parse_str(&identity.store_id).is_err()
        {
            return Err(Error::StoreRefused);
        }
        let state_path = root.join("host-state.json");
        let states = if state_path.exists() {
            serde_json::from_slice(&fs::read(state_path).map_err(io_error)?)
                .map_err(|_| Error::StoreRefused)?
        } else {
            BTreeMap::new()
        };
        Ok(Arc::new(Self {
            root,
            identity,
            _owner: owner,
            states: Mutex::new(states),
            gates: Mutex::new(BTreeMap::new()),
            failed: AtomicBool::new(false),
            policy,
            clock,
        }))
    }
    /// Returns the validated owner-private root; callers must still validate individual object names.
    pub fn root(&self) -> &Path {
        &self.root
    }
    /// Returns the immutable store marker used to reject foreign manifests.
    pub fn identity(&self) -> &StoreIdentity {
        &self.identity
    }
    /// Returns a cloned state snapshot without holding a map guard across async work.
    pub fn state(&self, host: &HostKey) -> Result<HostState> {
        if self.failed.load(Ordering::SeqCst) {
            return Err(Error::HostStateWrite);
        }
        Ok(self
            .states
            .lock()
            .map_err(|_| Error::InternalInvariant)?
            .get(host)
            .cloned()
            .unwrap_or_default())
    }
    pub(super) fn gate(&self, host: &HostKey) -> Result<Arc<HostGate>> {
        let mut gates = self.gates.lock().map_err(|_| Error::InternalInvariant)?;
        Ok(gates
            .entry(host.clone())
            .or_insert_with(|| {
                Arc::new(HostGate::new(
                    self.policy.get().politeness.max_concurrent_per_host,
                ))
            })
            .clone())
    }
    fn persist_state(&self, states: &BTreeMap<HostKey, HostState>) -> Result<()> {
        atomic_write(
            &self.root.join("host-state.json"),
            &serde_json::to_vec(states).map_err(|_| Error::InternalInvariant)?,
        )
    }
    fn update(
        &self,
        host: &HostKey,
        change: impl FnOnce(&mut HostState) -> Result<()>,
    ) -> Result<()> {
        if self.failed.load(Ordering::SeqCst) {
            return Err(Error::HostStateWrite);
        }
        let mut states = self.states.lock().map_err(|_| Error::InternalInvariant)?;
        change(states.entry(host.clone()).or_default())?;
        if let Err(error) = self.persist_state(&states) {
            self.failed.store(true, Ordering::SeqCst);
            return Err(error);
        }
        Ok(())
    }
    pub(super) fn started(&self, host: &HostKey, now: DateTime<Utc>) -> Result<()> {
        self.update(host, |state| {
            state.last_request_start = Some(now);
            Ok(())
        })
    }
    /// Admits one page to a rolling 24-hour listing budget atomically, before any wire attempt.
    pub fn admit_listing(&self, host: &HostKey, listing_limit: u32) -> Result<()> {
        let now = self.clock.utc();
        self.update(host, |state| {
            if state
                .listing_window_start_utc
                .is_none_or(|start| now.signed_duration_since(start).num_seconds() >= 86_400)
            {
                state.listing_window_start_utc = Some(now);
                state.listing_attempts = 0;
            }
            let attempts = state.listing_attempts;
            if attempts >= u64::from(listing_limit) {
                return Err(Error::ListingBudgetExhausted);
            }
            state.listing_attempts = state.listing_attempts.saturating_add(1);
            Ok(())
        })
    }
    /// Updates block and Retry-After state for every response kind, before body/MIME handling.
    pub fn observe(
        &self,
        host: &HostKey,
        status: u16,
        headers: &ResponseHeaders,
        challenge: Option<ChallengeKind>,
    ) -> Result<()> {
        let now = self.clock.utc();
        let block_secs = self.policy.get().politeness.block_secs.max(MIN_BLOCK_SECS);
        self.update(host, |state| {
            if status == 429 || status == 503 {
                state.consecutive_rate_responses =
                    state.consecutive_rate_responses.saturating_add(1);
                let backoff_secs = backoff_seconds(state.consecutive_rate_responses);
                let mut retry = now.checked_add_signed(TimeDelta::seconds(backoff_secs as i64));
                state.retry_after_invalid |= headers.invalid("retry-after");
                for value in headers.all("retry-after") {
                    match parse_retry_after(value, now) {
                        Some(deadline) => retry = retry.max(Some(deadline)),
                        None => {
                            state.retry_after_invalid = true;
                            if value.trim().bytes().all(|b| b.is_ascii_digit()) {
                                state.block_reason = Some(BlockReason::IndefiniteRateDeadline);
                                state.blocked_until_utc = Some(DateTime::<Utc>::MAX_UTC);
                            }
                        }
                    }
                }
                state.retry_at_utc = state.retry_at_utc.max(retry);
            } else if (200..300).contains(&status) || status == 304 {
                state.consecutive_rate_responses = 0;
                state.retry_at_utc = None;
            }
            if matches!(status, 401 | 403 | 429) || challenge.is_some() {
                let floor = now
                    .checked_add_signed(TimeDelta::seconds(block_secs as i64))
                    .unwrap_or(DateTime::<Utc>::MAX_UTC);
                state.blocked_until_utc = state
                    .blocked_until_utc
                    .max(Some(floor))
                    .max(state.retry_at_utc);
                state.block_reason = Some(
                    challenge
                        .map(BlockReason::Challenge)
                        .unwrap_or(BlockReason::HttpStatus(status)),
                );
            }
            Ok(())
        })
    }
}

/// Returns 900/1800/3600 seconds for the first three consecutive rate responses, capped upward at a day.
pub fn backoff_seconds(consecutive: u32) -> u64 {
    let backoff_secs = 900_u64.saturating_mul(
        1_u64
            .checked_shl(consecutive.saturating_sub(1))
            .unwrap_or(u64::MAX),
    );
    backoff_secs.min(86_400)
}
fn parse_retry_after_date(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc2822(value)
        .ok()
        .map(|date| date.with_timezone(&Utc))
}
/// Parses unsigned delta seconds or an explicit-zone HTTP date; expired dates become now.
/// Overflow/invalid values return None so the caller retains conservative backoff.
pub fn parse_retry_after(value: &str, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let value = value.trim();
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        let seconds = value.parse::<i64>().ok()?;
        return now.checked_add_signed(TimeDelta::try_seconds(seconds)?);
    }
    parse_retry_after_date(value).map(|deadline| deadline.max(now))
}
