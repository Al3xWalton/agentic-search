//! Provides isolated synthetic compliance fixtures and independent canonical journal encoders.
//! Fixture roots follow the configured external TMPDIR and contain no real reports or credentials.
//! This module supplies synthetic fixtures to the HTTP/clock/contract harness and the
//! persistence/crash/hardening harness. Observe counters and store state, then exact-once
//! contract headers, then body/content/code, and finally numeric HTTP status.

#![deny(missing_docs)]

use chrono::{DateTime, Utc};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use stract::{
    compliance::{disk::NoHooks, journal::Journal, listed::ListedMetadata},
    config::compliance::{ComplianceConfig, ValidatedComplianceConfig},
    crawler::politeness::ManualClock,
};

/// A private case root and fixed UTC source retained for the fixture's complete lifetime.
pub struct DomainFixture {
    /// Validated isolated sibling paths and literal default policy.
    pub config: ValidatedComplianceConfig,
    /// Injected controllable UTC source; tests never sleep to meet statutory thresholds.
    pub clock: Arc<ManualClock>,
    _directory: file_store::temp::TempDir,
}
impl Default for DomainFixture {
    fn default() -> Self {
        Self::new()
    }
}
impl DomainFixture {
    /// Creates an isolated default configuration at a fixed September 2026 instant.
    pub fn new() -> Self {
        let directory = stract::gen_temp_dir().unwrap();
        let config = ComplianceConfig::default()
            .validate(&directory.as_ref().join("private/suppression.json"))
            .unwrap();
        Self {
            config,
            clock: Arc::new(ManualClock::new(utc("2026-09-18T12:00:00Z"))),
            _directory: directory,
        }
    }
    /// Opens the real journal and its lifetime lock, panicking on an unexpected refusal.
    pub fn journal(&self) -> Journal {
        Journal::open(&self.config, self.clock.clone(), Arc::new(NoHooks)).unwrap()
    }
    /// Opens actual independent case/rules owners before entering an async fixture runtime.
    pub fn store(&self) -> Arc<stract::compliance::tickets::ComplianceStore> {
        self.store_with_hooks(Arc::new(NoHooks))
    }

    /// Opens genuine owners with instrumentation only at their actual persistence stages.
    pub fn store_with_hooks(
        &self,
        hooks: Arc<dyn stract::compliance::disk::ComplianceHooks>,
    ) -> Arc<stract::compliance::tickets::ComplianceStore> {
        self.try_store_with_hooks(hooks).unwrap()
    }

    /// Observes startup refusal at the caller instead of hiding it in fixture unwraps.
    pub fn try_store(
        &self,
    ) -> stract::compliance::Result<Arc<stract::compliance::tickets::ComplianceStore>> {
        self.try_store_with_hooks(Arc::new(NoHooks))
    }

    /// Opens owners fallibly with the same instrumentation and production startup arguments.
    pub fn try_store_with_hooks(
        &self,
        hooks: Arc<dyn stract::compliance::disk::ComplianceHooks>,
    ) -> stract::compliance::Result<Arc<stract::compliance::tickets::ComplianceStore>> {
        use stract::compliance::{
            model::SystemEntropy,
            rules::NoRulesHooks,
            tickets::{ComplianceStore, NoObserver},
        };
        ComplianceStore::open(
            &self.config,
            self.clock.clone(),
            Arc::new(SystemEntropy),
            hooks,
            Arc::new(NoRulesHooks),
            Arc::new(NoObserver),
            false,
        )
        .map(Arc::new)
    }
    /// Returns one private journal file path for deliberate corruption fixtures.
    pub fn path(&self, name: &str) -> PathBuf {
        self.config.journal_dir().join(name)
    }
    /// Writes one genuine aggregate system event without introducing ticket personal data.
    pub fn list_row(&self, journal: &mut Journal) {
        journal
            .record_list_access(&ListedMetadata {
                version: "synthetic.1".into(),
                url_count: 1,
                host_count: 1,
            })
            .unwrap();
    }
}

/// Creates a bounded Tokio runtime for HTTP and owned transaction fixtures.
pub fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// Captures process tracing across request, startup and blocking transaction threads.
pub struct TraceCapture {
    bytes: Arc<std::sync::Mutex<Vec<u8>>>,
    start: usize,
}
impl Default for TraceCapture {
    fn default() -> Self {
        Self::new()
    }
}
struct TraceWriter(Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for TraceWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl TraceCapture {
    /// Installs one process subscriber and marks this fixture's beginning without deleting other
    /// logs.
    pub fn new() -> Self {
        static OUTPUT: std::sync::OnceLock<Arc<std::sync::Mutex<Vec<u8>>>> =
            std::sync::OnceLock::new();
        let bytes = OUTPUT
            .get_or_init(|| {
                let bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
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
    /// Returns all actual log bytes since construction; callers never print private markers.
    pub fn text(&self) -> String {
        String::from_utf8(self.bytes.lock().unwrap()[self.start..].to_vec()).unwrap()
    }
}

/// Constructs reserved-example personal data in memory, with no real contact or report.
pub fn intake(
    category: stract::compliance::model::IntakeKind,
) -> stract::compliance::model::Intake {
    use stract::compliance::model::{
        Asset, Contact, ContactMethod, DocumentKey, Intake, IntakeKind, ReportFields, RequesterType,
    };
    let assets = if matches!(
        category,
        IntakeKind::DataProtectionComplaint | IntakeKind::OnlineSafetyComplaint
    ) {
        Vec::new()
    } else {
        let url = format!("https://{}.example.test/item", "synthetic");
        let key = DocumentKey::parse(&digest(url.as_bytes())).unwrap();
        vec![Asset::new(url, key).unwrap()]
    };
    Intake {
        report: ReportFields {
            contact: Contact {
                method: ContactMethod::Email,
                address: "synthetic@example.test".into(),
            },
            description: "Synthetic private narrative".into(),
            requester_type: RequesterType::AffectedPerson,
            nonessential_opt_out: true,
        },
        assets,
        category,
    }
}

/// Constructs a synthetic operator delivery attestation; no message is sent.
pub fn delivery() -> stract::compliance::model::Delivery {
    stract::compliance::model::Delivery {
        channel: stract::compliance::model::DeliveryChannel::ManualApi,
        reference: "synthetic-ref".into(),
    }
}

/// Fails one armed occurrence of a genuine persistence stage, after successful owner creation.
pub struct FailOnce {
    /// Selected actual stage.
    pub stage: stract::compliance::disk::ComplianceStage,
    /// Remaining selected-stage occurrences before failure; zero leaves hooks inert.
    pub remaining: std::sync::atomic::AtomicUsize,
}
impl stract::compliance::disk::ComplianceHooks for FailOnce {
    fn at(&self, stage: stract::compliance::disk::ComplianceStage) -> std::io::Result<()> {
        use std::sync::atomic::Ordering::SeqCst;
        if stage == self.stage {
            let previous = self
                .remaining
                .fetch_update(SeqCst, SeqCst, |count| count.checked_sub(1));
            if previous == Ok(1) {
                return Err(std::io::Error::other("synthetic stage failure"));
            }
        }
        Ok(())
    }
}

/// Finite actual HTTP/domain observations without request text or credentials.
#[derive(Default)]
pub struct FileCounts {
    /// Actual operating-system open boundaries.
    pub opens: std::sync::atomic::AtomicUsize,
    /// Actual personal or journal decode boundaries.
    pub decodes: std::sync::atomic::AtomicUsize,
    /// Actual personal/journal/rules write boundaries.
    pub writes: std::sync::atomic::AtomicUsize,
    /// Rules Decode, Open, Write, SyncFile, Rename and SyncDirectory counts.
    pub rules: [std::sync::atomic::AtomicUsize; 6],
}
impl stract::compliance::disk::ComplianceHooks for FileCounts {
    fn at(&self, stage: stract::compliance::disk::ComplianceStage) -> std::io::Result<()> {
        use stract::compliance::disk::ComplianceStage as S;
        let count = match stage {
            S::BeforeOpen => Some(&self.opens),
            S::BeforeDecode => Some(&self.decodes),
            S::BeforePayloadWrite | S::AfterJournalSync | S::AfterRulesSync => Some(&self.writes),
            _ => None,
        };
        if let Some(count) = count {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }
}
impl stract::compliance::rules::RulesHooks for FileCounts {
    fn at(&self, stage: stract::compliance::rules::RulesStage) -> std::io::Result<()> {
        use stract::compliance::rules::RulesStage as S;
        let index = match stage {
            S::Decode => 0,
            S::Open => 1,
            S::Write => 2,
            S::SyncFile => 3,
            S::Rename => 4,
            S::SyncDirectory => 5,
        };
        self.rules[index].fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

/// Finite actual HTTP/domain observations without request text or credentials.
#[derive(Default)]
pub struct Probe {
    /// JSON decoding attempts after admission and authentication.
    pub decodes: std::sync::atomic::AtomicUsize,
    /// Validated-capability projection lookups.
    pub lookups: std::sync::atomic::AtomicUsize,
    /// Actual journal append attempts.
    pub writes: std::sync::atomic::AtomicUsize,
    /// Paid backend calls after both serving-availability checks.
    pub backend: std::sync::atomic::AtomicUsize,
    /// Attributed DTO construction for an allowed retrieved result.
    pub attribution: std::sync::atomic::AtomicUsize,
    /// Authentication attempts before administration extraction.
    pub authentication: std::sync::atomic::AtomicUsize,
    /// Actual verifier buffer lengths, with no compared bytes retained.
    pub verifier: std::sync::Mutex<Vec<(usize, usize)>>,
    /// Holds a retrieved response before its live serving-rule read.
    pub hold_assembly: std::sync::atomic::AtomicBool,
    /// Signals that retrieval completed at the production observation seam.
    pub assembly_reached: tokio::sync::Notify,
    /// Releases a held response after a concurrent rule transaction completes.
    pub assembly_resume: tokio::sync::Notify,
}
impl stract::api::v1::Observer for Probe {
    fn before_assembly(&self) -> futures::future::BoxFuture<'_, ()> {
        Box::pin(async move {
            if self.hold_assembly.load(std::sync::atomic::Ordering::SeqCst) {
                self.assembly_reached.notify_one();
                self.assembly_resume.notified().await;
            }
        })
    }
    fn json_decode(&self) {
        self.decodes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    fn compliance_lookup(&self) {
        self.lookups
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    fn compliance_journal_write(&self) {
        self.writes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    fn backend_enter(&self) {
        self.backend
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    fn attribution_construct(&self, _: &stract::api::v1::suppression::DocumentId) {
        self.attribution
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    fn authentication_attempt(&self) {
        self.authentication
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    fn authentication_verifier(&self, expected: usize, presented: usize) {
        self.verifier.lock().unwrap().push((expected, presented));
    }
}

/// Real composed routers with isolated owners and a runtime-generated synthetic bearer.
pub struct HttpFixture {
    /// Retains the private temporary root and injected UTC clock.
    pub domain: DomainFixture,
    /// Real API state shared by both listener compositions.
    pub state: Arc<stract::api::v1::V1State>,
    /// Actual bounded lifecycle counters.
    pub probe: Arc<Probe>,
    /// Runtime-generated bearer retained only in this private fixture.
    pub token: String,
}
impl Default for HttpFixture {
    fn default() -> Self {
        Self::new()
    }
}
impl HttpFixture {
    /// Opens the real production builders before entering an async runtime.
    pub fn new() -> Self {
        Self::configured(|_| {})
    }

    /// Opens real owners with an explicit valid configuration mutation for boundary fixtures.
    pub fn configured(change: impl FnOnce(&mut stract::config::ApiConfig)) -> Self {
        Self::instrumented(change, |_| {})
    }

    /// Installs observations on actual persistence stages while retaining production owners.
    pub fn instrumented(
        change: impl FnOnce(&mut stract::config::ApiConfig),
        configure_seams: impl FnOnce(&mut stract::api::v1::compliance_adapter::ComplianceSeams),
    ) -> Self {
        use std::os::unix::fs::PermissionsExt;
        use stract::{
            api::v1::{compliance_adapter::ComplianceSeams, V1Resources, V1State},
            compliance::model::{Entropy, SystemEntropy},
        };
        let mut domain = DomainFixture::new();
        let mut config: stract::config::ApiConfig =
            toml::from_str(include_str!("../../../../configs/api.toml")).unwrap();
        let parent = domain.config.store_dir().parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        config.v1.suppression_store_path = parent.join("suppression.json");
        let token_path = parent.join("admin.token");
        let mut bytes = [0u8; 32];
        SystemEntropy.fill(&mut bytes).unwrap();
        let token = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        fs::write(&token_path, &token).unwrap();
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
        config.compliance.admin_token_file = Some(token_path);
        change(&mut config);
        domain.config = config
            .compliance
            .validate(&config.v1.suppression_store_path)
            .unwrap();
        let mut seams = ComplianceSeams {
            clock: domain.clock.clone(),
            ..ComplianceSeams::default()
        };
        configure_seams(&mut seams);
        let resources = V1Resources::with_compliance_seams(&config, seams).unwrap();
        let probe = Arc::new(Probe::default());
        let backend = Arc::new(|_: stract::searcher::SearchQuery| async { Ok(search_result()) });
        let state = Arc::new(
            V1State::from_resources(&config, backend, &resources).with_observer(probe.clone()),
        );
        Self {
            domain,
            state,
            probe,
            token,
        }
    }

    /// Drops actual owners and reopens their persisted files after the caller has joined started
    /// work.
    pub fn reopen(self) -> Self {
        self.reopen_instrumented(|_| {})
    }

    /// Reopens actual persisted owners with fresh startup observations and entropy instrumentation.
    pub fn reopen_instrumented(
        self,
        configure_seams: impl FnOnce(&mut stract::api::v1::compliance_adapter::ComplianceSeams),
    ) -> Self {
        self.reopen_after(|_| {}, configure_seams)
    }

    /// Performs fixture-owned offline maintenance only after all live owners have been dropped.
    pub fn reopen_after(
        self,
        maintenance: impl FnOnce(&mut DomainFixture),
        configure_seams: impl FnOnce(&mut stract::api::v1::compliance_adapter::ComplianceSeams),
    ) -> Self {
        use stract::api::v1::{compliance_adapter::ComplianceSeams, V1Resources, V1State};
        let Self {
            mut domain,
            state,
            probe,
            token,
        } = self;
        drop(state);
        maintenance(&mut domain);
        let mut config: stract::config::ApiConfig =
            toml::from_str(include_str!("../../../../configs/api.toml")).unwrap();
        config.v1.suppression_store_path = domain
            .config
            .store_dir()
            .parent()
            .unwrap()
            .join("suppression.json");
        config.compliance = domain.config.settings().clone();
        let mut seams = ComplianceSeams {
            clock: domain.clock.clone(),
            ..ComplianceSeams::default()
        };
        configure_seams(&mut seams);
        let resources = V1Resources::with_compliance_seams(&config, seams).unwrap();
        let backend = Arc::new(|_: stract::searcher::SearchQuery| async { Ok(search_result()) });
        let state = Arc::new(
            V1State::from_resources(&config, backend, &resources).with_observer(probe.clone()),
        );
        Self {
            domain,
            state,
            probe,
            token,
        }
    }

    /// Reopens an isolated legacy owner with real filesystem-stage instrumentation.
    /// Call after joining started case work and outside the async runtime, like production startup.
    pub fn reopen_with_legacy_hooks(
        self,
        hooks: Arc<dyn stract::api::v1::suppression::StoreHooks>,
    ) -> Self {
        use stract::api::v1::{suppression::SuppressionStore, V1Resources, V1State};
        let Self {
            domain,
            state,
            probe,
            token,
        } = self;
        drop(state);
        let mut config: stract::config::ApiConfig =
            toml::from_str(include_str!("../../../../configs/api.toml")).unwrap();
        config.v1.suppression_store_path = domain
            .config
            .store_dir()
            .parent()
            .unwrap()
            .join("suppression.json");
        config.compliance = domain.config.settings().clone();
        let store = Arc::new(
            SuppressionStore::open_with_hooks(&config.v1.suppression_store_path, hooks).unwrap(),
        );
        let resources = V1Resources::with_store(&config, store).unwrap();
        let backend = Arc::new(|_: stract::searcher::SearchQuery| async { Ok(search_result()) });
        let state = Arc::new(
            V1State::from_resources(&config, backend, &resources).with_observer(probe.clone()),
        );
        Self {
            domain,
            state,
            probe,
            token,
        }
    }

    /// Sends through the actual public or management composition and captures exact JSON bytes.
    pub async fn send(
        &self,
        management: bool,
        method: &str,
        path: &str,
        body: Value,
        authorised: bool,
    ) -> Observed {
        let mut builder = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if authorised {
            builder = builder.header("authorization", format!("Bearer {}", self.token));
        }
        let bytes = if body.is_null() {
            Vec::new()
        } else {
            serde_json::to_vec(&body).unwrap()
        };
        self.raw(
            management,
            builder.body(axum::body::Body::from(bytes)).unwrap(),
        )
        .await
    }

    /// Sends an exact synthetic transport request, including duplicate headers and chunked bodies.
    pub async fn raw(
        &self,
        management: bool,
        request: axum::http::Request<axum::body::Body>,
    ) -> Observed {
        use std::sync::atomic::Ordering::SeqCst;
        use tower::ServiceExt;
        let path = request.uri().path().to_owned();
        let method = request.method().clone();
        let before = tree(self.domain.config.store_dir());
        let writes = self.probe.writes.load(SeqCst);
        let concurrent_assembly = self.probe.hold_assembly.load(SeqCst);
        let app = if management {
            stract::api::v1::compose_management(self.state.clone())
        } else {
            stract::api::v1::compose_api(axum::Router::new(), self.state.clone())
        };
        let response = app.oneshot(request).await.unwrap();
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 1_048_576)
            .await
            .unwrap()
            .to_vec();
        let mut observed = Observed {
            status,
            headers,
            value: Value::Null,
            bytes,
        };
        if path.starts_with("/v1/") || path == "/v1" {
            // These actual transport observations precede all caller-level body and status checks.
            // Started persistence failures are checked explicitly by their fault-specific
            // witnesses.
            let read_only = method == axum::http::Method::GET
                || method == axum::http::Method::HEAD
                || path == "/v1/search"
                || path == "/v1/compliance/queue"
                || path.ends_with("/read");
            if (read_only && !concurrent_assembly)
                || matches!(status, 400 | 401 | 404 | 405 | 409 | 413 | 415)
            {
                assert_eq!(tree(self.domain.config.store_dir()), before);
                assert_eq!(self.probe.writes.load(SeqCst), writes);
            }
            contract_headers(&observed);
        }
        if !observed.bytes.is_empty() {
            observed.value = serde_json::from_slice(&observed.bytes).unwrap();
            if path.starts_with("/v1/") || path == "/v1" {
                assert_eq!(observed.value["version"], "v1");
                if let Some(error) = observed.value.get("error") {
                    assert_eq!(observed.value.as_object().unwrap().len(), 2);
                    assert_eq!(error.as_object().unwrap().len(), 2);
                    assert!(error["code"].is_string() && error["message"].is_string());
                }
            }
        }
        observed
    }
}

/// Captured synthetic response, without Debug to avoid accidental capability or personal dumps.
pub struct Observed {
    /// Numeric HTTP status.
    pub status: u16,
    /// Actual response headers.
    pub headers: axum::http::HeaderMap,
    /// Parsed owned JSON envelope.
    pub value: Value,
    /// Exact body for indistinguishability and preservation assertions.
    pub bytes: Vec<u8>,
}

/// Captures a direct response after caller effect checks, validating headers before decoding JSON.
pub async fn contract_response(response: axum::response::Response) -> Observed {
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1_048_576)
        .await
        .unwrap()
        .to_vec();
    let mut observed = Observed {
        status,
        headers,
        value: Value::Null,
        bytes,
    };
    contract_headers(&observed);
    if !observed.bytes.is_empty() {
        observed.value = serde_json::from_slice(&observed.bytes).unwrap();
        assert_eq!(observed.value["version"], "v1");
    }
    observed
}

/// Checks each outer contract header exactly once, before body and numeric status assertions.
pub fn contract_headers(response: &Observed) {
    for (name, value) in [
        ("x-api-version", "v1"),
        ("reports-and-requests", "/v1/reports"),
    ] {
        assert_eq!(response.headers.get_all(name).iter().count(), 1);
        assert_eq!(response.headers[name], value);
    }
    assert_eq!(response.headers.get_all("source-offer").iter().count(), 1);
    let revision = env!("AVA_SEARCH_REVISION");
    let expected = if revision == "unknown" {
        env!("CARGO_PKG_REPOSITORY").into()
    } else {
        format!("{}/tree/{revision}", env!("CARGO_PKG_REPOSITORY"))
    };
    assert_eq!(response.headers["source-offer"], expected);
}

/// Checks a successful observation after the transport's real counter/store observations.
pub fn successful_response(response: Observed) {
    contract_headers(&response);
    if response.bytes.is_empty() {
        assert_eq!(response.value, Value::Null);
    } else {
        assert_eq!(response.value["version"], "v1");
        assert!(response.value.get("error").is_none());
    }
    assert_eq!(response.status, 200);
}

/// Pins a literal refusal code after real effects, exact headers and closed envelope checks.
pub fn rejected_response(response: Observed, code: &str, status: u16) {
    contract_headers(&response);
    assert_eq!(response.value["error"]["code"], code);
    assert_eq!(response.value.as_object().unwrap().len(), 2);
    assert_eq!(response.value["error"].as_object().unwrap().len(), 2);
    assert_eq!(response.status, status);
}

/// Counts real full-width entropy draws while delegating to the production random source.
#[derive(Default)]
pub struct CountingEntropy {
    /// Actual requested buffer lengths; no random bytes are retained or printed.
    pub widths: std::sync::Mutex<Vec<usize>>,
}
impl stract::compliance::model::Entropy for CountingEntropy {
    fn fill(&self, bytes: &mut [u8]) -> stract::compliance::Result<()> {
        self.widths.lock().unwrap().push(bytes.len());
        stract::compliance::model::SystemEntropy.fill(bytes)
    }
}

/// Counts actual bounded decode stages at cold startup.
#[derive(Default)]
pub struct StartupCounts {
    /// Head, journal row and personal payload decodes.
    pub compliance: std::sync::atomic::AtomicUsize,
    /// Persisted rules snapshot decodes.
    pub rules: std::sync::atomic::AtomicUsize,
}
impl stract::compliance::disk::ComplianceHooks for StartupCounts {
    fn at(&self, stage: stract::compliance::disk::ComplianceStage) -> std::io::Result<()> {
        if stage == stract::compliance::disk::ComplianceStage::BeforeDecode {
            self.compliance
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }
}
impl stract::compliance::rules::RulesHooks for StartupCounts {
    fn at(&self, stage: stract::compliance::rules::RulesStage) -> std::io::Result<()> {
        if stage == stract::compliance::rules::RulesStage::Decode {
            self.rules.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }
}

/// Complete synthetic common request object; booleans and all nested keys are explicit.
pub fn report() -> Value {
    serde_json::json!({"contact":{"method":"email","address":"synthetic@example.test"},
        "description":"Synthetic private narrative",
            "requester_type":"affected_person",
            "nonessential_opt_out":true})
}

/// Creates a private synthetic hash-only feed adjacent to, never inside, a serving or journal root.
pub fn configure_list(config: &mut stract::config::ApiConfig, urls: &[String], hosts: &[String]) {
    use std::os::unix::fs::PermissionsExt;
    let mut urls = urls
        .iter()
        .map(|url| digest(url.as_bytes()))
        .collect::<Vec<_>>();
    urls.sort();
    let mut hosts = hosts
        .iter()
        .map(|host| digest(host.as_bytes()))
        .collect::<Vec<_>>();
    hosts.sort();
    let path = config
        .v1
        .suppression_store_path
        .parent()
        .unwrap()
        .join("synthetic-list.json");
    fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({"format_version":1,
        "version":"synthetic.1",
        "url_hashes":urls,
        "host_hashes":hosts}))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    config.compliance.listed_hashes_file = Some(path);
}

fn search_result() -> stract::searcher::SearchResult {
    let urls = [
        format!("https://{}.example.test/item", "synthetic"),
        format!("https://{}.example.test/item", "unrelated"),
        format!("https://{}.example.test/item", "host-listed"),
    ];
    let pages = urls
        .iter()
        .map(|url| {
            serde_json::json!({"title":"Synthetic result","url":url,
        "site":"example.test",
            "domain":"example.test",
            "prettyUrl":url,
            "snippet":{"date":null,
            "text":{"fragments":[]}},
        "richSnippet":null,
            "rankingSignals":null,
            "structuredData":null,
            "likelyHasAds":false,
            "likelyHasPaywall":false})
        })
        .collect::<Vec<_>>();
    stract::searcher::SearchResult::Websites(
        serde_json::from_value(serde_json::json!({"webpages":pages,
        "numHits":{"_type":"exact","value":3},"searchDurationMs":1,"hasMoreResults":false}))
        .unwrap(),
    )
}

/// Parses a literal UTC timestamp without calling production deadline arithmetic.
pub fn utc(text: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(text)
        .unwrap()
        .with_timezone(&Utc)
}

/// Reads fixture JSON without altering its bytes or filesystem permissions.
pub fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

/// Writes compact JSON plus one LF to an already owned fixture file.
pub fn write_json(path: &Path, value: &Value) {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    fs::write(path, bytes).unwrap();
}

/// Produces an independent SHA-256 hex vector, without calling the production digest helper.
pub fn digest(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Hashes every current private file and its mode for exact no-write assertions.
pub fn tree(root: &Path) -> std::collections::BTreeMap<PathBuf, (String, u32)> {
    use std::os::unix::fs::PermissionsExt;
    fn walk(
        root: &Path,
        current: &Path,
        result: &mut std::collections::BTreeMap<PathBuf, (String, u32)>,
    ) {
        if !current.exists() {
            return;
        }
        for entry in fs::read_dir(current).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                walk(root, &path, result);
            } else {
                result.insert(
                    path.strip_prefix(root).unwrap().into(),
                    (
                        digest(&fs::read(&path).unwrap()),
                        metadata.permissions().mode(),
                    ),
                );
            }
        }
    }
    let mut result = std::collections::BTreeMap::new();
    walk(root, root, &mut result);
    result
}

/// Encodes the literal ordered row contract, independently of the production serializer.
pub fn encoded_row(row: &Value, signed: bool) -> Vec<u8> {
    let fields = [
        "format_version",
        "sequence",
        "previous_hash",
        "at",
        "received_at",
        "event",
        "ticket_id",
        "route",
        "requester_type",
        "state",
        "actor",
        "decision",
        "reason_code",
        "policy_version",
        "asset_ids",
        "payload_sequence",
        "commitment",
        "intent_sequence",
        "effective_at",
        "related_ticket_id",
        "record_ref",
        "list_version",
        "url_count",
        "host_count",
        "quarantined_bytes",
        "quarantine_hash",
    ];
    let mut pairs = fields
        .iter()
        .map(|field| format!("{}:{}", serde_json::to_string(field).unwrap(), row[*field]))
        .collect::<Vec<_>>();
    if signed {
        pairs.push(format!("\"hash\":{}", row["hash"]));
    }
    format!("{{{}}}{}", pairs.join(","), if signed { "\n" } else { "" }).into_bytes()
}

/// Recomputes a deliberately changed fixture row's digest using the independently encoded bytes.
pub fn rehash(row: &mut Value) {
    let mut input = b"AVA619-JOURNAL-v1\0".to_vec();
    input.extend(encoded_row(row, false));
    row["hash"] = Value::String(digest(&input));
}

/// Updates a fixture checkpoint to refer to an independently encoded row and byte length.
pub fn checkpoint(row: &Value, length: usize) -> Vec<u8> {
    format!(
        "{{\"format_version\":1,\"sequence\":{},\"hash\":{},\"byte_length\":{length}}}\n",
        row["sequence"], row["hash"]
    )
    .into_bytes()
}
