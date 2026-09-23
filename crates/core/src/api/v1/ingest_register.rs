//! Owns the bounded metadata register, delivery decisions and cancellation-safe transactions.
//! A writer retains ownership through WAL acknowledgement and its durable completion marker.
//! Acknowledged replays do no work; a recorded version can be re-dispatched by a later PUT.

#![deny(missing_docs)]

mod disk;
#[cfg(test)]
mod tests;

use super::{
    error::{V1Error, V1Failure},
    ingest_dto::{validate_bound, validate_source, IngestBound},
    suppression::{canonical_identity, DocumentId, SuppressionStore},
    AuditedIngestPage, IngestAcknowledgement, IngestBackend, Observer,
};
use crate::{
    compliance::disk::{ComplianceHooks, NoHooks},
    config::ApiConfig,
    crawler::politeness::{Clock, SystemClock},
    live_index::{AUTO_COMMIT_INTERVAL, TTL},
};
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io,
    panic::AssertUnwindSafe,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicI64, Ordering},
        Arc, Mutex as StdMutex, OnceLock, RwLock, Weak,
    },
    time::Duration,
};
use tokio::{sync::Mutex, task::JoinSet};

/// Maximum number of current identifiers retained by one API owner.
pub const MAX_INGEST_ENTRIES: usize = 10_000;
/// Maximum serialized snapshot bytes including its terminal LF.
pub const MAX_INGEST_REGISTER_BYTES: usize = 16_777_216;

/// Finite stages without identifiers, content, paths or other private input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestStage {
    /// Bounded bytes are about to be decoded.
    Decode,
    /// A temporary snapshot is about to be opened through shared hardening.
    Open,
    /// The actual snapshot write operation is reached.
    Write,
    /// The actual snapshot file-sync operation is reached.
    SyncFile,
    /// The synced temporary is about to replace the authoritative snapshot.
    Rename,
    /// The actual directory-sync operation after rename is reached.
    SyncDirectory,
    /// Durable recorded metadata precedes the backend invocation.
    BeforeDispatch,
    /// The backend acknowledged and its local completion marker is durable.
    AfterAcknowledgement,
    /// Expiry maintenance is considering the current snapshot.
    Sweep,
}

/// Synchronous fault/observation seam at actual ingest work boundaries.
pub trait IngestHooks: Send + Sync + 'static {
    /// Observes or fails one finite stage; blocking hooks must eventually release their wait.
    fn at(&self, stage: IngestStage) -> io::Result<()>;
}

struct NoIngestHooks;
impl IngestHooks for NoIngestHooks {
    fn at(&self, _: IngestStage) -> io::Result<()> {
        Ok(())
    }
}

/// Startup clock and real I/O seams; none replaces admission, decoding or path validation.
#[derive(Clone)]
pub struct IngestSeams {
    /// UTC receipt/expiry clock and monotonic maintenance scheduler.
    pub clock: Arc<dyn Clock>,
    /// Finite ingest stages, including fault results from actual writes and syncs.
    pub hooks: Arc<dyn IngestHooks>,
    /// Shared hardening's before-open observation, after all unsafe-inode checks.
    pub compliance_hooks: Arc<dyn ComplianceHooks>,
}

impl Default for IngestSeams {
    fn default() -> Self {
        Self {
            clock: Arc::new(SystemClock::default()),
            hooks: Arc::new(NoIngestHooks),
            compliance_hooks: Arc::new(NoHooks),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Admission {
    Admitted,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Delivery {
    Recorded,
    Acknowledged,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: DocumentId,
    canonical_url: String,
    body_sha256: String,
    version: u64,
    received_at: i64,
    retrieved_at: i64,
    fetch_time_ms: u64,
    source: String,
    admission: Admission,
    delivery: Delivery,
}

/// Admission-validated metadata passed to the serialized decision; it contains no HTML.
pub(super) struct Submission {
    /// Canonical URL identifier.
    pub(super) id: DocumentId,
    /// Identity-preserving canonical URL.
    pub(super) canonical_url: String,
    /// SHA-256 of decoded HTML UTF-8 bytes only.
    pub(super) body_sha256: String,
    /// Captured receipt UTC seconds.
    pub(super) received_at: i64,
    /// Caller-claimed retrieval UTC seconds.
    pub(super) retrieved_at: i64,
    /// Caller-measured fetch milliseconds.
    pub(super) fetch_time_ms: u64,
    /// Bounded operational source claim.
    pub(super) source: String,
}

/// Persisted receipt fields used in the response, including on replay and recorded retries.
pub(super) struct Receipt {
    /// Positive current document version.
    pub(super) version: u64,
    /// Original receipt UTC seconds for this version.
    pub(super) received_at: i64,
}

struct RegisterState {
    entries: BTreeMap<DocumentId, Entry>,
    unavailable: bool,
}

struct Maintenance {
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

/// One local metadata owner, shared across both HTTP listeners by suppression-owner identity.
/// Call shutdown before dropping the last application owner to drain transactions and maintenance.
pub struct IngestRegister {
    state: Arc<Mutex<RegisterState>>,
    disk: Arc<disk::Disk>,
    seams: IngestSeams,
    observed_utc: AtomicI64,
    tasks: Mutex<JoinSet<()>>,
    maintenance: Mutex<Option<Maintenance>>,
    started: AtomicBool,
    closed: AtomicBool,
    observer: RwLock<Arc<dyn Observer>>,
}

impl IngestRegister {
    /// Opens the private sibling of an actual suppression path using production validation.
    /// Existing missing/corrupt snapshots, unsafe files and competing owners fail startup.
    /// This is blocking startup work and must run before entering an async listener.
    pub fn open(suppression_path: &Path, seams: IngestSeams) -> io::Result<Self> {
        let now = seams.clock.utc().timestamp();
        validate_bound(IngestBound::Timestamp, now.into()).map_err(io::Error::other)?;
        let (disk, fresh) = disk::Disk::open(suppression_path, &seams)?;
        let entries = if fresh {
            BTreeMap::new()
        } else {
            disk.read(now)?
        };
        let mut retained = entries.clone();
        retained.retain(|_, entry| !expired(entry, now));
        if fresh || retained.len() != entries.len() {
            let bytes = encode(&retained).map_err(io::Error::other)?;
            disk.persist(&bytes, &mut false)?;
        }
        Ok(Self {
            state: Arc::new(Mutex::new(RegisterState {
                entries: retained,
                unavailable: false,
            })),
            disk: Arc::new(disk),
            observed_utc: AtomicI64::new(now),
            seams,
            tasks: Mutex::new(JoinSet::new()),
            maintenance: Mutex::new(None),
            started: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            observer: RwLock::new(Arc::new(super::NoObserver)),
        })
    }

    /// Returns nondecreasing observed UTC seconds; invalid UTC closes this attempted operation.
    pub(super) fn now(&self) -> Result<i64, V1Error> {
        let now = self.seams.clock.utc().timestamp();
        validate_bound(IngestBound::Timestamp, now.into()).map_err(|_| unavailable())?;
        Ok(self.observed_utc.fetch_max(now, Ordering::SeqCst).max(now))
    }

    /// Replaces finite instrumentation without changing a validation or persistence decision.
    pub(super) fn observe_with(&self, observer: Arc<dyn Observer>) {
        *self.observer.write().expect("ingest observer lock") = observer;
    }

    fn observer(&self) -> Arc<dyn Observer> {
        self.observer.read().expect("ingest observer lock").clone()
    }

    /// Joins all started work, including a maintenance write already in progress.
    /// A stopped register never starts another timer or accepts another write.
    pub async fn shutdown(&self) {
        let mut maintenance = self.maintenance.lock().await;
        if let Some(maintenance) = maintenance.take() {
            let _ = maintenance.stop.send(true);
            let _ = maintenance.task.await;
        }
        self.closed.store(true, Ordering::SeqCst);
        drop(maintenance);
        let mut tasks = self.tasks.lock().await;
        while tasks.join_next().await.is_some() {}
    }

    /// Starts at most one periodic expiry task using the live index's commit interval.
    /// Returns false after an earlier start or shutdown; the task holds no permanent owner cycle.
    pub async fn start_maintenance(self: &Arc<Self>) -> bool {
        let mut maintenance = self.maintenance.lock().await;
        if self.closed.load(Ordering::SeqCst) || self.started.swap(true, Ordering::SeqCst) {
            return false;
        }
        let (stop, mut stopped) = tokio::sync::watch::channel(false);
        let owner = Arc::downgrade(self);
        let clock = self.seams.clock.clone();
        let interval = u64::try_from(AUTO_COMMIT_INTERVAL.as_millis())
            .expect("live-index interval fits milliseconds");
        let first = clock.ticks().checked_add(interval);
        let task = tokio::spawn(async move {
            let mut deadline = first;
            while let Some(next) = deadline {
                tokio::select! {
                    biased;
                    _ = stopped.changed() => break,
                    _ = clock.wait_until(next) => {}
                }
                let Some(register) = owner.upgrade() else {
                    break;
                };
                if register.sweep_expired().await.is_err() {
                    tracing::warn!("Ingest retention unavailable");
                    break;
                }
                drop(register);
                deadline = clock.ticks().checked_add(interval);
            }
        });
        *maintenance = Some(Maintenance { stop, task });
        true
    }

    /// Sweeps expired metadata through the same tracked writer used by PUT, with no replay renewal.
    /// No expired entry means no snapshot write; any sweep failure disables ingest until restart.
    pub async fn sweep_expired(self: &Arc<Self>) -> Result<(), V1Error> {
        let mut tasks = self.tasks.lock().await;
        while tasks.try_join_next().is_some() {}
        let mut state = self.state.clone().lock_owned().await;
        if state.unavailable || self.closed.load(Ordering::SeqCst) {
            return Err(unavailable());
        }
        let owner = self.clone();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tasks.spawn(async move {
            let result = AssertUnwindSafe(owner.sweep(&mut state))
                .catch_unwind()
                .await;
            let result = result.unwrap_or_else(|_| Err(unavailable()));
            if result.is_err() {
                state.unavailable = true;
            }
            let _ = sender.send(result);
        });
        drop(tasks);
        receiver.await.unwrap_or_else(|_| Err(unavailable()))
    }

    async fn sweep(&self, state: &mut RegisterState) -> Result<(), V1Error> {
        self.observer().ingest_sweep();
        self.stage(IngestStage::Sweep).await?;
        let now = self.now()?;
        let mut candidate = state.entries.clone();
        candidate.retain(|_, entry| !expired(entry, now));
        if candidate.len() != state.entries.len() {
            let bytes = encode(&candidate)?;
            self.persist(state, &bytes, self.observer(), Arc::new(()))
                .await?;
            state.entries = candidate;
        }
        Ok(())
    }

    /// Serializes decisions and retains admission through tracked work, returning stored receipts.
    pub(super) async fn submit(
        self: &Arc<Self>,
        submission: Submission,
        page: AuditedIngestPage,
        backend: Arc<dyn IngestBackend>,
        timeout: Duration,
        lease: Arc<dyn Send + Sync>,
    ) -> Result<Receipt, V1Error> {
        let mut tasks = self.tasks.lock().await;
        while tasks.try_join_next().is_some() {}
        let mut state = self.state.clone().lock_owned().await;
        if state.unavailable || self.closed.load(Ordering::SeqCst) {
            return Err(unavailable());
        }
        let observer = self.observer();
        observer.ingest_register_read();
        let now = self.now()?;
        let old = state
            .entries
            .get(&submission.id)
            .filter(|entry| !expired(entry, now));
        if let Some(entry) = old.filter(|entry| {
            entry.body_sha256 == submission.body_sha256 && entry.delivery == Delivery::Acknowledged
        }) {
            return Ok(receipt(entry));
        }
        let owner = self.clone();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tasks.spawn(async move {
            let dispatch = Dispatch {
                page,
                backend,
                timeout,
                lease,
                observer,
            };
            let result = AssertUnwindSafe(owner.transact(&mut state, submission, now, dispatch))
                .catch_unwind()
                .await;
            let result = match result {
                Ok(result) => result,
                Err(_) => {
                    state.unavailable = true;
                    Err(unavailable())
                }
            };
            let _ = sender.send(result);
        });
        drop(tasks);
        receiver.await.unwrap_or_else(|_| Err(unavailable()))
    }

    /// Retains the writer through recorded publication, one dispatch and durable acknowledgement.
    async fn transact(
        &self,
        state: &mut RegisterState,
        submission: Submission,
        now: i64,
        dispatch: Dispatch,
    ) -> Result<Receipt, V1Error> {
        let mut candidate = state.entries.clone();
        candidate.retain(|_, entry| !expired(entry, now));
        let previous = candidate.get(&submission.id);
        let retry = previous.is_some_and(|entry| entry.body_sha256 == submission.body_sha256);
        let entry = if retry {
            previous.expect("matched recorded entry").clone()
        } else {
            let version = next_version(previous)?;
            submission.into_entry(version)
        };
        candidate.insert(entry.id.clone(), entry.clone());
        let recorded = encode(&candidate)?;
        let mut acknowledged = candidate.clone();
        acknowledged
            .get_mut(&entry.id)
            .expect("current entry")
            .delivery = Delivery::Acknowledged;
        let completed = encode(&acknowledged)?;
        reserve(&candidate, &recorded, &completed)?;
        if !retry {
            self.persist(
                state,
                &recorded,
                dispatch.observer.clone(),
                dispatch.lease.clone(),
            )
            .await?;
            state.entries = candidate;
        }
        self.stage(IngestStage::BeforeDispatch).await?;
        dispatch.observer.ingest_backend_enter();
        let acknowledged_by_backend = AssertUnwindSafe(async {
            tokio::time::timeout(
                dispatch.timeout,
                dispatch
                    .backend
                    .ingest(dispatch.page.with_fetch_time_ms(entry.fetch_time_ms)),
            )
            .await
        })
        .catch_unwind()
        .await;
        if !matches!(
            acknowledged_by_backend,
            Ok(Ok(Ok(IngestAcknowledgement::Acknowledged)))
        ) {
            return Err(unavailable());
        }
        self.persist(state, &completed, dispatch.observer, dispatch.lease.clone())
            .await?;
        state.entries = acknowledged;
        self.stage(IngestStage::AfterAcknowledgement).await?;
        Ok(receipt(&entry))
    }

    async fn stage(&self, stage: IngestStage) -> Result<(), V1Error> {
        let disk = self.disk.clone();
        tokio::task::spawn_blocking(move || disk.stage(stage))
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())
    }

    async fn persist(
        &self,
        state: &mut RegisterState,
        bytes: &[u8],
        observer: Arc<dyn Observer>,
        lease: Arc<dyn Send + Sync>,
    ) -> Result<(), V1Error> {
        let disk = self.disk.clone();
        let bytes = bytes.to_vec();
        observer.ingest_register_write();
        let result = tokio::task::spawn_blocking(move || {
            let _lease = lease;
            let mut renamed = false;
            let outcome =
                std::panic::catch_unwind(AssertUnwindSafe(|| disk.persist(&bytes, &mut renamed)));
            (renamed, outcome)
        })
        .await;
        match result {
            Ok((_, Ok(Ok(())))) => Ok(()),
            Ok((renamed, Ok(Err(_)))) => {
                if renamed {
                    state.unavailable = true;
                }
                Err(unavailable())
            }
            _ => {
                state.unavailable = true;
                Err(unavailable())
            }
        }
    }
}

struct Dispatch {
    page: AuditedIngestPage,
    backend: Arc<dyn IngestBackend>,
    timeout: Duration,
    lease: Arc<dyn Send + Sync>,
    observer: Arc<dyn Observer>,
}

impl Submission {
    fn into_entry(self, version: u64) -> Entry {
        Entry {
            id: self.id,
            canonical_url: self.canonical_url,
            body_sha256: self.body_sha256,
            version,
            received_at: self.received_at,
            retrieved_at: self.retrieved_at,
            fetch_time_ms: self.fetch_time_ms,
            source: self.source,
            admission: Admission::Admitted,
            delivery: Delivery::Recorded,
        }
    }
}

fn receipt(entry: &Entry) -> Receipt {
    Receipt {
        version: entry.version,
        received_at: entry.received_at,
    }
}

fn next_version(previous: Option<&Entry>) -> Result<u64, V1Error> {
    previous
        .map_or(Some(1), |entry| entry.version.checked_add(1))
        .ok_or_else(capacity)
}

fn unavailable() -> V1Error {
    V1Error::failure(V1Failure::IngestUnavailable)
}

fn capacity() -> V1Error {
    V1Error::failure(V1Failure::IngestCapacity)
}

/// Computes the content key from the supplied decoded HTML bytes without normalization.
pub(super) fn digest(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn deadline(entry: &Entry) -> Option<i64> {
    let age = i64::try_from(TTL.as_secs()).ok()?;
    let deadline = entry.received_at.checked_add(age)?;
    chrono::DateTime::from_timestamp(deadline, 0).map(|_| deadline)
}

fn expired(entry: &Entry, now: i64) -> bool {
    deadline(entry).is_none_or(|deadline| now >= deadline)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    format_version: u64,
    entries: Vec<Entry>,
}

fn validate_snapshot(snapshot: &Snapshot, now: i64) -> io::Result<()> {
    if snapshot.format_version != 1
        || snapshot.entries.len() > MAX_INGEST_ENTRIES
        || !snapshot
            .entries
            .windows(2)
            .all(|pair| pair[0].id < pair[1].id)
    {
        return Err(io::Error::other("invalid ingest snapshot"));
    }
    for entry in &snapshot.entries {
        validate_entry(entry)?;
        if entry.received_at > now {
            return Err(io::Error::other("future ingest receipt"));
        }
    }
    Ok(())
}

fn validate_entry(entry: &Entry) -> io::Result<()> {
    let invalid = || io::Error::other("invalid ingest entry");
    for (bound, value) in [
        (IngestBound::Url, entry.canonical_url.len() as i128),
        (IngestBound::Timestamp, entry.received_at.into()),
        (IngestBound::Timestamp, entry.retrieved_at.into()),
        (IngestBound::FetchTime, entry.fetch_time_ms.into()),
    ] {
        validate_bound(bound, value).map_err(|_| invalid())?;
    }
    validate_source(&entry.source).map_err(|_| invalid())?;
    // Body digests and document identifiers share the same 64-byte lowercase hexadecimal grammar.
    DocumentId::parse(&entry.body_sha256).map_err(|_| invalid())?;
    let (url, id) = canonical_identity(&entry.canonical_url).map_err(|_| invalid())?;
    if url != entry.canonical_url
        || id != entry.id
        || entry.version == 0
        || entry.retrieved_at > entry.received_at
        || deadline(entry).is_none()
    {
        return Err(invalid());
    }
    Ok(())
}

fn encode(entries: &BTreeMap<DocumentId, Entry>) -> Result<Vec<u8>, V1Error> {
    let snapshot = Snapshot {
        format_version: 1,
        entries: entries.values().cloned().collect(),
    };
    let mut bytes = serde_json::to_vec(&snapshot).map_err(|_| unavailable())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn reserve(
    entries: &BTreeMap<DocumentId, Entry>,
    recorded: &[u8],
    completed: &[u8],
) -> Result<(), V1Error> {
    if entries.len() > MAX_INGEST_ENTRIES
        || recorded.len() > MAX_INGEST_REGISTER_BYTES
        || completed.len() > MAX_INGEST_REGISTER_BYTES
    {
        return Err(capacity());
    }
    Ok(())
}

struct Shared {
    owner: Weak<SuppressionStore>,
    register: Weak<IngestRegister>,
    configuration: Vec<u8>,
}

static SHARED: OnceLock<StdMutex<Vec<Shared>>> = OnceLock::new();

/// Associates one register with an existing suppression owner without extending dead lifetimes.
pub(super) fn for_store(
    config: &ApiConfig,
    owner: &Arc<SuppressionStore>,
    seams: Option<IngestSeams>,
) -> anyhow::Result<Arc<IngestRegister>> {
    let mut settings = config.v1.clone();
    settings.suppression_store_path = owner.disk.path.clone();
    settings.validate(&[])?;
    let configuration = serde_json::to_vec(&settings)?;
    let mut shared = SHARED
        .get_or_init(|| StdMutex::new(Vec::new()))
        .lock()
        .map_err(|_| io::Error::other("ingest resource registry unavailable"))?;
    shared.retain(|entry| entry.owner.strong_count() > 0 && entry.register.strong_count() > 0);
    for entry in shared.iter() {
        if entry
            .owner
            .upgrade()
            .is_some_and(|prior| Arc::ptr_eq(&prior, owner))
        {
            let register = entry.register.upgrade().ok_or_else(unavailable)?;
            let matches = seams.as_ref().is_none_or(|seams| {
                Arc::ptr_eq(&seams.clock, &register.seams.clock)
                    && Arc::ptr_eq(&seams.hooks, &register.seams.hooks)
                    && Arc::ptr_eq(&seams.compliance_hooks, &register.seams.compliance_hooks)
            });
            anyhow::ensure!(
                entry.configuration == configuration && matches,
                "inconsistent ingest resource configuration"
            );
            return Ok(register);
        }
    }
    let register = Arc::new(IngestRegister::open(
        &owner.disk.path,
        seams.unwrap_or_default(),
    )?);
    shared.push(Shared {
        owner: Arc::downgrade(owner),
        register: Arc::downgrade(&register),
        configuration,
    });
    Ok(register)
}
