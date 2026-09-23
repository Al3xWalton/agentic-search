//! Supplies private HTTP/index fixtures, independent disk observations and owned fault barriers.
//! Assertions inspect work and filesystem evidence before headers, response content and status.

use axum::{
    body::{to_bytes, Body},
    http::{HeaderMap, Request},
    Router,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs, io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
        Arc, Condvar, Mutex,
    },
};
use stract::{
    api::v1::{
        self,
        compliance_adapter::ComplianceSeams,
        ingest_register::{IngestHooks, IngestSeams, IngestStage},
        AuditedIngestPage, IngestAcknowledgement, IngestBackendFailure, Observer, V1Resources,
        V1State,
    },
    compliance::{
        disk::{ComplianceHooks, ComplianceStage},
        model::{Entropy, SystemEntropy},
    },
    config::ApiConfig,
    crawler::politeness::ManualClock,
    searcher::{SearchQuery, SearchResult},
};
use tower::ServiceExt;

/// Actual observer work counts; backend calls and disk stages are also counted independently.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    /// Authentication attempts.
    pub auth: usize,
    /// Fixed-buffer verifier calls.
    pub verifier: usize,
    /// JSON decoder entries.
    pub decode: usize,
    /// Authenticated ingest handler entries.
    pub enter: usize,
    /// Actual indexer audit entries.
    pub audit: usize,
    /// Register lookups under its writer.
    pub read: usize,
    /// Snapshot transaction attempts.
    pub write: usize,
    /// Backend boundary entries.
    pub backend: usize,
    /// Expiry sweep considerations.
    pub sweep: usize,
    /// Delete handler entries.
    pub delete: usize,
    /// Search result attribution constructions.
    pub construct: usize,
    /// Compliance journal appends.
    pub journal: usize,
    /// Existing source handler entries.
    pub source: usize,
    /// Existing search backend entries.
    pub search: usize,
}

/// Counts actual production observer hooks without reading any request content.
#[derive(Default)]
pub struct Probe {
    counts: Mutex<Counts>,
    verifier_lengths: Mutex<Vec<(usize, usize)>>,
    permits: AtomicUsize,
    auth_pause: Mutex<Option<Arc<AuthPause>>>,
}

impl Probe {
    /// Returns a stable value snapshot.
    pub fn counts(&self) -> Counts {
        *self.counts.lock().unwrap()
    }
    /// Starts a new observation interval after all prior work has joined.
    pub fn reset(&self) {
        *self.counts.lock().unwrap() = Counts::default();
        self.permits.store(0, SeqCst);
    }
    /// Returns the number of actually acquired listener permits.
    pub fn permits(&self) -> usize {
        self.permits.load(SeqCst)
    }
    /// Proves every verifier invocation used the required fixed-width buffers.
    pub fn fixed_verifiers(&self) {
        assert!(self
            .verifier_lengths
            .lock()
            .unwrap()
            .iter()
            .all(|pair| *pair == (32, 32)));
    }
}

impl Observer for Probe {
    fn admission_acquired(&self) {
        self.permits.fetch_add(1, SeqCst);
    }
    fn source_enter(&self) {
        self.counts.lock().unwrap().source += 1;
    }
    fn backend_enter(&self) {
        self.counts.lock().unwrap().search += 1;
    }
    fn authentication_attempt(&self) {
        self.counts.lock().unwrap().auth += 1;
        let pause = self.auth_pause.lock().unwrap().take();
        if let Some(pause) = pause {
            pause.reached.notify_one();
            let mut blocked = pause.blocked.lock().unwrap();
            while *blocked {
                blocked = pause.release.wait(blocked).unwrap();
            }
        }
    }
    fn authentication_verifier(&self, expected: usize, actual: usize) {
        self.counts.lock().unwrap().verifier += 1;
        self.verifier_lengths
            .lock()
            .unwrap()
            .push((expected, actual));
    }
    fn json_decode(&self) {
        self.counts.lock().unwrap().decode += 1;
    }
    fn ingest_enter(&self) {
        self.counts.lock().unwrap().enter += 1;
    }
    fn ingest_audit(&self) {
        self.counts.lock().unwrap().audit += 1;
    }
    fn ingest_register_read(&self) {
        self.counts.lock().unwrap().read += 1;
    }
    fn ingest_register_write(&self) {
        self.counts.lock().unwrap().write += 1;
    }
    fn ingest_backend_enter(&self) {
        self.counts.lock().unwrap().backend += 1;
    }
    fn ingest_sweep(&self) {
        self.counts.lock().unwrap().sweep += 1;
    }
    fn delete_enter(&self) {
        self.counts.lock().unwrap().delete += 1;
    }
    fn attribution_construct(&self, _: &v1::suppression::DocumentId) {
        self.counts.lock().unwrap().construct += 1;
    }
    fn compliance_journal_write(&self) {
        self.counts.lock().unwrap().journal += 1;
    }
}

struct AuthPause {
    blocked: Mutex<bool>,
    release: Condvar,
    reached: tokio::sync::Notify,
}

/// Owns a stalled unauthorised request and releases both causal barriers before joining it.
pub struct StalledIngest {
    pause: Arc<AuthPause>,
    release_body: tokio::sync::watch::Sender<bool>,
    body_started: Arc<tokio::sync::Notify>,
    worker: Option<std::thread::JoinHandle<Observed>>,
    /// Independent body-poll observations, including the first stalled poll.
    pub polls: Arc<AtomicUsize>,
}

impl StalledIngest {
    /// Starts the request on its own runtime so the verifier pause cannot block the control.
    pub fn start(fixture: &Fixture) -> Self {
        let pause = Arc::new(AuthPause {
            blocked: Mutex::new(true),
            release: Condvar::new(),
            reached: tokio::sync::Notify::new(),
        });
        *fixture.probe.auth_pause.lock().unwrap() = Some(pause.clone());
        let (release_body, mut released) = tokio::sync::watch::channel(false);
        let body_started = Arc::new(tokio::sync::Notify::new());
        let signal = body_started.clone();
        let polls = Arc::new(AtomicUsize::new(0));
        let count = polls.clone();
        let stream = futures::stream::once(async move {
            count.fetch_add(1, SeqCst);
            signal.notify_one();
            while !*released.borrow_and_update() {
                if released.changed().await.is_err() {
                    break;
                }
            }
            Ok::<_, io::Error>(axum::body::Bytes::new())
        });
        let mut request = fixture.request(
            "PUT",
            &path("https://example.com/page"),
            Body::from_stream(stream),
        );
        request.headers_mut().remove("authorization");
        let router = fixture.router(true);
        let worker = std::thread::spawn(move || runtime().block_on(send(router, request)));
        Self {
            pause,
            release_body,
            body_started,
            worker: Some(worker),
            polls,
        }
    }

    /// Waits for either the actual auth boundary or the actual body poll, without a timing race.
    pub async fn started(&self) {
        tokio::select! {
            () = self.pause.reached.notified() => {},
            () = self.body_started.notified() => {},
        }
    }

    fn release(&self) {
        *self.pause.blocked.lock().unwrap() = false;
        self.pause.release.notify_all();
        let _ = self.release_body.send(true);
    }

    /// Releases both barriers and joins before any response assertion is made.
    pub fn finish(mut self) -> Observed {
        self.release();
        self.worker.take().unwrap().join().unwrap()
    }
}

impl Drop for StalledIngest {
    fn drop(&mut self) {
        self.release();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct Fault {
    stage: IngestStage,
    occurrence: usize,
    fail: bool,
}

/// Observes real I/O stages and can fail or pause one selected occurrence.
#[derive(Default)]
pub struct Hooks {
    stages: Mutex<Vec<IngestStage>>,
    fault: Mutex<Option<Fault>>,
    blocked: Mutex<bool>,
    release: Condvar,
    reached: tokio::sync::Notify,
    /// Shared hardening's actual safe-before-open counter.
    pub opens: AtomicUsize,
    /// Injects uncertainty only at the existing rules directory-sync boundary.
    pub rules_fail: AtomicBool,
    timer_waits: AtomicUsize,
    timer_changed: tokio::sync::Notify,
    timer_deadlines: Mutex<Vec<(u64, u64)>>,
}

impl Hooks {
    /// Returns actual scheduler starts and deadlines in the order their waits were polled.
    pub fn timer_deadlines(&self) -> Vec<(u64, u64)> {
        self.timer_deadlines.lock().unwrap().clone()
    }
    /// Waits for a scheduler continuation so an omitted sweep is observed without a timeout.
    pub async fn wait_for_timer(&self, count: usize) {
        loop {
            let changed = self.timer_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.timer_waits.load(SeqCst) >= count {
                return;
            }
            changed.await;
        }
    }
    /// Clears completed observations and disarms faults.
    pub fn reset(&self) {
        self.stages.lock().unwrap().clear();
        *self.fault.lock().unwrap() = None;
    }
    /// Returns the ordered actual-stage trace.
    pub fn stages(&self) -> Vec<IngestStage> {
        self.stages.lock().unwrap().clone()
    }
    /// Fails one actual operation result on its selected one-based occurrence.
    pub fn fail(&self, stage: IngestStage, occurrence: usize) {
        self.reset();
        *self.fault.lock().unwrap() = Some(Fault {
            stage,
            occurrence,
            fail: true,
        });
    }
    /// Pauses a real blocking stage; the returned guard releases it during unwinding too.
    pub fn pause(self: &Arc<Self>, stage: IngestStage, occurrence: usize) -> ReleaseIo {
        self.reset();
        *self.blocked.lock().unwrap() = true;
        *self.fault.lock().unwrap() = Some(Fault {
            stage,
            occurrence,
            fail: false,
        });
        ReleaseIo(self.clone())
    }
}

struct SchedulerClock {
    clock: Arc<ManualClock>,
    hooks: Arc<Hooks>,
}
impl stract::crawler::politeness::Clock for SchedulerClock {
    fn utc(&self) -> chrono::DateTime<chrono::Utc> {
        self.clock.utc()
    }
    fn ticks(&self) -> u64 {
        self.clock.ticks()
    }
    fn wait_until(&self, deadline: u64) -> stract::crawler::politeness::WaitFuture<'_> {
        Box::pin(async move {
            self.hooks
                .timer_deadlines
                .lock()
                .unwrap()
                .push((self.clock.ticks(), deadline));
            self.hooks.timer_waits.fetch_add(1, SeqCst);
            self.hooks.timer_changed.notify_waiters();
            self.clock.wait_until(deadline).await;
        })
    }
}

impl IngestHooks for Hooks {
    fn at(&self, stage: IngestStage) -> io::Result<()> {
        let occurrence = {
            let mut stages = self.stages.lock().unwrap();
            stages.push(stage);
            stages.iter().filter(|item| **item == stage).count()
        };
        let selected = self
            .fault
            .lock()
            .unwrap()
            .as_ref()
            .filter(|fault| fault.stage == stage && fault.occurrence == occurrence)
            .map(|fault| fault.fail);
        match selected {
            Some(true) => Err(io::Error::other("synthetic ingest operation failure")),
            Some(false) => {
                self.reached.notify_one();
                let mut blocked = self.blocked.lock().unwrap();
                while *blocked {
                    blocked = self.release.wait(blocked).unwrap();
                }
                Ok(())
            }
            None => Ok(()),
        }
    }
}

impl ComplianceHooks for Hooks {
    fn at(&self, _: ComplianceStage) -> io::Result<()> {
        self.opens.fetch_add(1, SeqCst);
        Ok(())
    }
}

impl stract::compliance::rules::RulesHooks for Hooks {
    fn at(&self, stage: stract::compliance::rules::RulesStage) -> io::Result<()> {
        if stage == stract::compliance::rules::RulesStage::SyncDirectory
            && self.rules_fail.load(SeqCst)
        {
            return Err(io::Error::other("synthetic rules sync failure"));
        }
        Ok(())
    }
}

/// Releases a paused real filesystem worker on explicit completion or assertion unwinding.
pub struct ReleaseIo(Arc<Hooks>);
impl ReleaseIo {
    /// Waits for a causal stage signal, without timing guesses.
    pub async fn reached(&self) {
        self.0.reached.notified().await;
    }
}
impl Drop for ReleaseIo {
    fn drop(&mut self) {
        *self.0.blocked.lock().unwrap() = false;
        self.0.release.notify_all();
    }
}

/// Backend outcome controls, independent of production Observer counts.
#[derive(Clone, Copy)]
pub enum Mode {
    /// Explicit acknowledgement.
    Success,
    /// Closed delivery failure.
    Failure,
    /// A panicking adapter, caught at the transaction boundary.
    Panic,
    /// Never completes without the production dispatch timeout.
    Pending,
}

/// Records actual RPC calls and reads the real snapshot on backend entry.
pub struct Backend {
    /// Independent backend invocation count.
    pub calls: AtomicUsize,
    mode: AtomicUsize,
    hold: AtomicBool,
    reached: tokio::sync::Notify,
    resume: tokio::sync::Notify,
    /// Actual snapshot observations on entry; malformed/missing bytes become Null, never panic.
    pub observed: Mutex<Vec<Value>>,
    /// Actual payload fetch durations observed before any delivery outcome.
    pub fetch_times: Mutex<Vec<u64>>,
    snapshot: PathBuf,
    index: Mutex<Option<Arc<tokio::sync::RwLock<stract::index::Index>>>>,
}

impl Backend {
    fn new(snapshot: PathBuf) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            mode: AtomicUsize::new(0),
            hold: AtomicBool::new(false),
            reached: Default::default(),
            resume: Default::default(),
            observed: Default::default(),
            fetch_times: Default::default(),
            snapshot,
            index: Mutex::new(None),
        }
    }
    /// Selects the next outcome without replacing the adapter or state.
    pub fn mode(&self, mode: Mode) {
        self.mode.store(mode as usize, SeqCst);
    }
    /// Pauses the next backend call after its independent observation.
    pub fn pause(self: &Arc<Self>) -> ReleaseBackend {
        self.hold.store(true, SeqCst);
        ReleaseBackend(self.clone())
    }
    async fn ingest(
        &self,
        page: AuditedIngestPage,
    ) -> Result<IngestAcknowledgement, IngestBackendFailure> {
        self.calls.fetch_add(1, SeqCst);
        let observed = fs::read(&self.snapshot)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or(Value::Null);
        self.observed.lock().unwrap().push(observed);
        let input = page.into_indexable_webpage();
        self.fetch_times.lock().unwrap().push(input.fetch_time_ms);
        if self.hold.load(SeqCst) {
            self.reached.notify_one();
            self.resume.notified().await;
        }
        match self.mode.load(SeqCst) {
            1 => return Err(IngestBackendFailure::Unavailable),
            2 => panic!("synthetic backend panic"),
            3 => return std::future::pending().await,
            _ => {}
        }
        let index = self.index.lock().unwrap().clone();
        if let Some(index) = index {
            let mut index = index.write().await;
            let mut webpage = stract::webpage::Webpage::from(
                stract::webpage::Html::parse(&input.body, &input.url).unwrap(),
            );
            webpage.fetch_time_ms = input.fetch_time_ms;
            webpage.host_centrality = 100.0;
            webpage.inserted_at = chrono::DateTime::from_timestamp(1_790_000_000, 0).unwrap();
            index.insert(&webpage).unwrap();
            index.commit().unwrap();
        }
        Ok(IngestAcknowledgement::Acknowledged)
    }
}

/// Releases an owned async backend barrier even on assertion failure.
pub struct ReleaseBackend(Arc<Backend>);
impl ReleaseBackend {
    /// Waits until the first backend call has observed durable metadata.
    pub async fn reached(&self) {
        self.0.reached.notified().await;
    }
}
impl Drop for ReleaseBackend {
    fn drop(&mut self) {
        self.0.hold.store(false, SeqCst);
        self.0.resume.notify_one();
    }
}

/// Retains one complete production resource bundle and its private test directory.
pub struct Fixture {
    /// Shared production state used by both composers.
    pub state: Arc<V1State>,
    /// Observer counters.
    pub probe: Arc<Probe>,
    /// Independent persistence stage observations.
    pub hooks: Arc<Hooks>,
    /// Independent RPC adapter and controls.
    pub backend: Arc<Backend>,
    /// Manually controlled UTC and maintenance clock.
    pub clock: Arc<ManualClock>,
    /// Runtime-generated credential, never a fixture literal.
    pub token: String,
    /// Validated startup configuration.
    pub config: ApiConfig,
    routers: std::sync::OnceLock<(Router, Router)>,
    directory: file_store::temp::TempDir,
}

impl Fixture {
    /// Opens an isolated production owner before entering the async test runtime.
    pub fn new() -> Self {
        Self::configured(|_| {})
    }
    /// Changes only startup settings; every production validator still runs.
    pub fn configured(change: impl FnOnce(&mut ApiConfig)) -> Self {
        Self::configured_at(change, 1_790_000_000)
    }
    /// Opens production owners at an explicit initial UTC second for elapsed-day witnesses.
    pub fn at(timestamp: i64) -> Self {
        Self::configured_at(|_| {}, timestamp)
    }
    fn configured_at(change: impl FnOnce(&mut ApiConfig), timestamp: i64) -> Self {
        let directory = stract::gen_temp_dir().unwrap();
        let root = directory.as_ref().join("private");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut config: ApiConfig =
            toml::from_str(include_str!("../../../../configs/api.toml")).unwrap();
        config.v1.suppression_store_path = root.join("suppression.json");
        let mut entropy = [0u8; 32];
        SystemEntropy.fill(&mut entropy).unwrap();
        let token = entropy
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let token_path = root.join("admin.token");
        fs::write(&token_path, &token).unwrap();
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
        config.compliance.admin_token_file = Some(token_path);
        change(&mut config);
        let clock = Arc::new(ManualClock::new(
            chrono::DateTime::from_timestamp(timestamp, 0).unwrap(),
        ));
        let probe = Arc::new(Probe::default());
        let hooks = Arc::new(Hooks::default());
        let backend = Arc::new(Backend::new(
            root.join("suppression.json.ingest/snapshot.json"),
        ));
        let state = open_state(&config, &clock, &probe, &hooks, &backend, None);
        hooks.reset();
        Self {
            state,
            probe,
            hooks,
            backend,
            clock,
            token,
            config,
            directory,
            routers: Default::default(),
        }
    }

    /// Returns the private API metadata root, excluding the separate fixture index.
    pub fn root(&self) -> &Path {
        self.config.v1.suppression_store_path.parent().unwrap()
    }
    /// Returns the authoritative snapshot path.
    pub fn snapshot_path(&self) -> PathBuf {
        self.root().join("suppression.json.ingest/snapshot.json")
    }
    /// Decodes fixture-controlled snapshot bytes for independent metadata assertions.
    pub fn snapshot(&self) -> Value {
        serde_json::from_slice(&fs::read(self.snapshot_path()).unwrap()).unwrap()
    }
    /// Clones the same router/semaphore for concurrent request observations.
    pub fn router(&self, management: bool) -> Router {
        let (public, private) = self.routers.get_or_init(|| {
            (
                v1::compose_api(Router::new(), self.state.clone()),
                v1::compose_management(self.state.clone()),
            )
        });
        if management {
            private.clone()
        } else {
            public.clone()
        }
    }
    /// Builds a request with the real runtime-generated management credential.
    pub fn request(&self, method: &str, path: &str, body: impl Into<Body>) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", self.token))
            .body(body.into())
            .unwrap()
    }
    /// Sends valid synthetic input through the actual management composer.
    pub async fn put(&self, input: &Value) -> Observed {
        let path = path(input["url"].as_str().unwrap());
        send(
            self.router(true),
            self.request("PUT", &path, serde_json::to_vec(input).unwrap()),
        )
        .await
    }
    /// Drains started transactions, retaining maintenance ownership until its stop completes.
    pub async fn shutdown(&self) {
        self.state.ingest_register().shutdown().await;
        self.state.store().shutdown().await;
        self.state.compliance().shutdown().await;
    }
    /// Reopens the same files after all old owners have been drained and dropped.
    pub fn reopen(self) -> Self {
        self.reopen_after(|_| {})
    }
    /// Edits fixture-owned persisted bytes only while no owner is alive.
    pub fn reopen_after(self, edit: impl FnOnce(&Path)) -> Self {
        let Self {
            state,
            probe,
            hooks,
            backend,
            clock,
            token,
            config,
            directory,
            routers,
        } = self;
        drop(routers);
        drop(state);
        edit(config.v1.suppression_store_path.parent().unwrap());
        probe.reset();
        hooks.reset();
        backend.calls.store(0, SeqCst);
        let state = open_state(&config, &clock, &probe, &hooks, &backend, None);
        hooks.reset();
        Self {
            state,
            probe,
            hooks,
            backend,
            clock,
            token,
            config,
            directory,
            routers: Default::default(),
        }
    }
    /// Reuses opened owners while changing only the search adapter for synthetic candidate order.
    pub fn search_backend(&mut self, backend: Arc<dyn v1::SearchBackend>) {
        self.routers.take();
        let resources = V1Resources::with_store(&self.config, self.state.store()).unwrap();
        let ingest = self.backend.clone();
        self.state = Arc::new(
            V1State::from_resources(&self.config, backend, &resources)
                .with_ingest_backend(Arc::new(move |page| {
                    let ingest = ingest.clone();
                    async move { ingest.ingest(page).await }
                }))
                .with_observer(self.probe.clone()),
        );
    }
    /// Installs one actual index shared by the ingest writer and local searcher.
    pub async fn real_index(
        &mut self,
    ) -> Arc<
        stract::searcher::api::ApiSearcher<
            stract::searcher::LocalSearchClient,
            stract::webgraph::Webgraph,
        >,
    > {
        let mut index = stract::index::Index::open(self.directory.as_ref().join("index")).unwrap();
        index.set_shard_id(stract::inverted_index::ShardId::Backbone(0));
        index.inverted_index.prepare_writer().unwrap();
        let index = Arc::new(tokio::sync::RwLock::new(index));
        *self.backend.index.lock().unwrap() = Some(index.clone());
        let local = stract::searcher::LocalSearcher::builder(index).build();
        let mut config = stract::searcher::api::Config {
            agent_query_planning: true,
            ..Default::default()
        };
        config.widgets.calculator_fetch_currencies_exchange = false;
        config.widgets.thesaurus_paths.clear();
        let searcher = Arc::new(
            stract::searcher::api::ApiSearcher::new(
                stract::searcher::LocalSearchClient::from(local),
                None,
                stract::bangs::Bangs::empty(),
                config,
            )
            .await,
        );
        let api = searcher.clone();
        self.search_backend(Arc::new(move |query: SearchQuery| {
            let api = api.clone();
            async move { api.search(&query).await }
        }));
        searcher
    }
}

fn open_state(
    config: &ApiConfig,
    clock: &Arc<ManualClock>,
    probe: &Arc<Probe>,
    hooks: &Arc<Hooks>,
    backend: &Arc<Backend>,
    search: Option<Arc<dyn v1::SearchBackend>>,
) -> Arc<V1State> {
    let resources = V1Resources::with_ingest_seams(
        config,
        ComplianceSeams {
            clock: clock.clone(),
            rules_hooks: hooks.clone(),
            ..Default::default()
        },
        IngestSeams {
            clock: Arc::new(SchedulerClock {
                clock: clock.clone(),
                hooks: hooks.clone(),
            }),
            hooks: hooks.clone(),
            compliance_hooks: hooks.clone(),
        },
    )
    .unwrap();
    let backend = backend.clone();
    let search =
        search.unwrap_or_else(|| Arc::new(|_: SearchQuery| async { Ok(search_result(&[])) }));
    Arc::new(
        V1State::from_resources(config, search, &resources)
            .with_observer(probe.clone())
            .with_ingest_backend(Arc::new(move |page| {
                let backend = backend.clone();
                async move { backend.ingest(page).await }
            })),
    )
}

/// Builds the six-field synthetic request; no content is loaded from the network.
pub fn input(url: &str) -> Value {
    let body = concat!(
        "<html><head><title>Example page</title></head><body><main><p>",
        "Orchard apples are grown with careful pruning and regular watering. ",
        "The fruit harvest includes varied trees and a plentiful crop of delicious produce.",
        "</p></main></body></html>"
    );
    json!({"url":url,"body":body,"fetch_time_ms":100,"retrieved_at":1_789_999_999_i64,
        "source":"engine.fetch","x_robots_tag":[]})
}

/// Independently hashes bytes with the pinned cryptographic implementation.
pub fn digest(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Returns the route for a valid canonical source identity.
pub fn path(url: &str) -> String {
    format!(
        "/v1/documents/{}",
        v1::suppression::canonical_identity(url).unwrap().1.as_str()
    )
}

/// Captures response bytes without unwrapping an observed mutant's JSON shape.
pub struct Observed {
    /// Numeric wire status, asserted last.
    pub status: u16,
    /// Actual response headers.
    pub headers: HeaderMap,
    /// Exact response bytes.
    pub bytes: Vec<u8>,
}

impl Observed {
    /// Pins the unchanged bodyless, unauthenticated suppression acknowledgement.
    pub fn success_delete(&self) {
        headers(self);
        let value = self.value();
        assert_eq!(value["version"], "v1");
        assert_eq!(value["suppressed"], true);
        assert_eq!(value.as_object().map(|object| object.len()), Some(3));
        assert_eq!(self.status, 200);
    }
    /// Decodes only after work and contract headers have been asserted by the witness.
    pub fn value(&self) -> Value {
        serde_json::from_slice(&self.bytes).unwrap_or(Value::Null)
    }
    /// Checks the fixed owned error envelope and numeric status after caller work assertions.
    pub fn error(&self, code: &str, reason: Option<&str>, status: u16) {
        headers(self);
        let value = self.value();
        assert_eq!(value["version"], "v1");
        assert_eq!(value.as_object().map(|object| object.len()), Some(2));
        assert_eq!(value["error"]["code"], code);
        assert_eq!(
            value["error"].as_object().map(|object| object.len()),
            Some(if reason.is_some() { 3 } else { 2 })
        );
        if let Some(reason) = reason {
            assert_eq!(value["error"]["reason"], reason);
        } else {
            assert!(value["error"].get("reason").is_none());
        }
        assert_eq!(self.status, status);
    }
    /// Checks the exact successful envelope and positive document version.
    pub fn success(&self, version: u64) -> Value {
        headers(self);
        let value = self.value();
        assert_eq!(value["version"], "v1");
        assert_eq!(value.as_object().map(|object| object.len()), Some(2));
        assert_eq!(
            value["document"]
                .as_object()
                .map(|object| object.keys().map(String::as_str).collect::<Vec<_>>()),
            Some(vec![
                "accepted_at",
                "canonical_url",
                "domain",
                "id",
                "title",
                "version"
            ])
        );
        assert_eq!(value["document"]["version"], version);
        assert_eq!(self.status, 200);
        value
    }
}

/// Checks exactly one copy of all three inherited v1 headers.
pub fn headers(response: &Observed) {
    let revision = env!("AVA_SEARCH_REVISION");
    let source = if revision == "unknown" {
        env!("CARGO_PKG_REPOSITORY").to_owned()
    } else {
        format!("{}/tree/{revision}", env!("CARGO_PKG_REPOSITORY"))
    };
    for (name, value) in [
        ("source-offer", source.as_str()),
        ("x-api-version", "v1"),
        ("reports-and-requests", "/v1/reports"),
    ] {
        assert_eq!(
            response.headers.get_all(name).iter().count(),
            1,
            "one {name}"
        );
        assert_eq!(response.headers[name], value);
    }
}

/// Executes one request through the given real production composition.
pub async fn send(router: Router, request: Request<Body>) -> Observed {
    let response = router.oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 16_777_216)
        .await
        .unwrap()
        .to_vec();
    Observed {
        status,
        headers,
        bytes,
    }
}

/// Records private file bytes, mode, inode and modification time independently of observer hooks.
pub fn tree(root: &Path) -> BTreeMap<PathBuf, (String, u32, u64, i64, i64)> {
    let mut result = BTreeMap::new();
    fn walk(
        root: &Path,
        here: &Path,
        output: &mut BTreeMap<PathBuf, (String, u32, u64, i64, i64)>,
    ) {
        for entry in fs::read_dir(here).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                walk(root, &path, output);
            } else {
                output.insert(
                    path.strip_prefix(root).unwrap().into(),
                    (
                        digest(&fs::read(&path).unwrap()),
                        metadata.mode(),
                        metadata.ino(),
                        metadata.mtime(),
                        metadata.mtime_nsec(),
                    ),
                );
            }
        }
    }
    walk(root, root, &mut result);
    result
}

/// Supplies nonvalidating candidate DTOs for ordering and collapse witnesses.
pub fn search_result(pages: &[(&str, &str, &str)]) -> SearchResult {
    let pages = pages
        .iter()
        .map(|(url, title, domain)| {
            json!({
                "title":title,"url":url,"site":domain,"domain":domain,"prettyUrl":url,
                "snippet":{"date":null,"text":{"fragments":[]}},
                "richSnippet":null,"rankingSignals":null,"structuredData":null,
                "likelyHasAds":false,"likelyHasPaywall":false
            })
        })
        .collect::<Vec<_>>();
    SearchResult::Websites(
        serde_json::from_value(json!({
            "webpages":pages,"numHits":{"_type":"exact","value":pages.len()},
            "searchDurationMs":1,"hasMoreResults":true
        }))
        .unwrap(),
    )
}

/// Creates a current-thread test runtime so startup opens remain outside async blocking contexts.
pub fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Pads a valid JSON value outside strings to an exact complete-wire byte size.
pub fn wire(value: &Value, length: usize) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    assert!(bytes.len() <= length);
    bytes.resize(length, b' ');
    bytes
}

/// Creates a counted chunk stream; a sentinel after overflow must never be polled.
pub fn chunks(parts: Vec<Vec<u8>>) -> (Body, Arc<AtomicUsize>) {
    let polls = Arc::new(AtomicUsize::new(0));
    let seen = polls.clone();
    let stream = futures::stream::iter(parts.into_iter().map(move |bytes| {
        seen.fetch_add(1, SeqCst);
        Ok::<_, io::Error>(axum::body::Bytes::from(bytes))
    }));
    (Body::from_stream(stream), polls)
}

/// Captures actual tracing from startup, HTTP and blocking workers in this test executable.
pub struct TraceCapture {
    bytes: Arc<Mutex<Vec<u8>>>,
    start: usize,
}
struct TraceWriter(Arc<Mutex<Vec<u8>>>);
impl io::Write for TraceWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl TraceCapture {
    /// Marks the start without clearing observations owned by another concurrent witness.
    pub fn new() -> Self {
        static OUTPUT: std::sync::OnceLock<Arc<Mutex<Vec<u8>>>> = std::sync::OnceLock::new();
        let bytes = OUTPUT
            .get_or_init(|| {
                let bytes = Arc::new(Mutex::new(Vec::new()));
                let writer = bytes.clone();
                let subscriber = tracing_subscriber::fmt()
                    .without_time()
                    .with_ansi(false)
                    .with_max_level(tracing::Level::TRACE)
                    .with_writer(move || TraceWriter(writer.clone()))
                    .finish();
                tracing::subscriber::set_global_default(subscriber).unwrap();
                bytes
            })
            .clone();
        let start = bytes.lock().unwrap().len();
        Self { bytes, start }
    }
    /// Returns the captured log text for marker absence checks, without printing it.
    pub fn text(&self) -> String {
        String::from_utf8(self.bytes.lock().unwrap()[self.start..].to_vec()).unwrap()
    }
}

/// Retains a child paused before exec and releases/reaps it during parent unwinding as well.
pub struct PausedChild {
    channel: Option<std::os::unix::net::UnixStream>,
    worker: Option<std::thread::JoinHandle<io::Result<std::process::ExitStatus>>>,
}

impl PausedChild {
    /// Pauses an owned CLI child using only async-signal-safe I/O in pre_exec.
    pub fn start() -> io::Result<Self> {
        use std::{
            io::Read,
            os::{fd::AsRawFd, unix::process::CommandExt},
            process::{Command, Stdio},
        };
        let (parent, child) = std::os::unix::net::UnixStream::pair()?;
        let raw = child.as_raw_fd();
        let worker = std::thread::spawn(move || {
            let mut command = Command::new(env!("CARGO_BIN_EXE_stract"));
            command
                .arg("--help")
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            // # Safety
            // Only async-signal-safe I/O accesses the live inherited descriptor before exec.
            unsafe {
                command.pre_exec(move || {
                    if libc::write(raw, [1u8].as_ptr().cast(), 1) != 1 {
                        return Err(io::Error::last_os_error());
                    }
                    if libc::read(raw, [0u8].as_mut_ptr().cast(), 1) != 1 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let result = command.spawn();
            drop(child);
            result?.wait()
        });
        let mut paused = Self {
            channel: Some(parent),
            worker: Some(worker),
        };
        paused.channel.as_mut().unwrap().read_exact(&mut [0u8])?;
        Ok(paused)
    }
    fn release(&mut self) {
        use std::io::Write;
        if let Some(mut channel) = self.channel.take() {
            let _ = channel.write_all(&[1u8]);
        }
    }
    /// Releases and reaps the owned child before returning its status.
    pub fn finish(mut self) -> io::Result<std::process::ExitStatus> {
        self.release();
        self.worker
            .take()
            .unwrap()
            .join()
            .map_err(|_| io::Error::other("child owner panicked"))?
    }
}

impl Drop for PausedChild {
    fn drop(&mut self) {
        self.release();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
