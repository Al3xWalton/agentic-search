// SPDX-License-Identifier: AGPL-3.0-only
//! Synthetic production-router witnesses for permanent legacy retirement.
//! Owned indexes and loopback services exercise serving; no external assets are used.

use super::*;
use axum::{body::to_bytes, http::Request};
use serde_json::{json, Value};
use std::{path::Path, time::Duration};
use tower::ServiceExt;

const DELETED: &str = "a30810149588dba56ba802dcd755787ba916ff0362ae7c0be3a0de4a2aa66b03";
const BLOCKED: &str = "d2f997dbefe73456eafaecd53c64330a18c53dd44818e8f4a9aeb5b40b05532e";
const ALLOWED: &str = "02a962af645644114931287f08a52a685ef73d16d02c9974a4f6e18f9517ee24";

// Fixture errors must never disclose captured request or credential values.
fn must<T, E>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(_) => panic!("FIXTURE_OPERATION"),
    }
}

// Parsing a TOML template preserves optional values without serializing ApiConfig.
fn config(root: &Path) -> ApiConfig {
    let mut config: ApiConfig = must(toml::from_str(include_str!(
        "../../../../configs/eval/api-off.toml"
    )));
    config.v1.suppression_store_path = root.join("serving/suppression.json");
    config.compliance.store_dir = Some(root.join("cases"));
    config.compliance.records_dir = Some(root.join("records"));
    use std::os::unix::fs::PermissionsExt;
    must(std::fs::set_permissions(
        root,
        std::fs::Permissions::from_mode(0o700),
    ));
    let token = root.join("admin.token");
    must(std::fs::write(&token, "a".repeat(64)));
    must(std::fs::set_permissions(
        &token,
        std::fs::Permissions::from_mode(0o600),
    ));
    config.compliance.admin_token_file = Some(token);
    config
}

// The fixture needs counters without registering an unrelated metrics publication.
fn counters() -> Counters {
    Counters {
        search_counter_success: Default::default(),
        search_counter_fail: Default::default(),
        explore_counter: Default::default(),
        daily_active_users: must(user_count::UserCount::new()),
    }
}

// Each dedicated word selects exactly one independently identified page.
fn index(root: &Path) -> crate::index::Index {
    let mut index = must(crate::index::Index::open(root));
    index.set_shard_id(crate::inverted_index::ShardId::Backbone(0));
    must(index.prepare_writer());
    for (path, word) in [
        ("deleted", "cedar"),
        ("blocked", "maple"),
        ("allowed", "birch"),
    ] {
        let html = format!(
            "<html><head><title>Synthetic {word}</title>\
             <meta name=\"description\" content=\"Synthetic {word} body with enough words \
             for a deterministic complete search snippet.\"></head>\
             <body><p>Synthetic {word} body</p></body></html>"
        );
        let html = must(crate::webpage::Html::parse(
            &html,
            &format!("https://fixture.test/{path}"),
        ));
        must(index.insert(&crate::webpage::Webpage::from(html)));
    }
    must(index.commit());
    index
}

// An owned task retains its cluster and is always cancelled before fixture teardown.
struct ServiceFixture {
    cluster: Arc<Cluster>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ServiceFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// The native server cannot inherit a reservation, so only address collisions are retried.
async fn service(root: &Path) -> ServiceFixture {
    use crate::distributed::member::{Member, Service};
    use crate::entrypoint::search_server::SearchService;
    let index = Arc::new(tokio::sync::RwLock::new(index(root)));
    for _ in 0..16 {
        let reserved = must(std::net::TcpListener::bind("127.0.0.1:0"));
        let host = must(reserved.local_addr());
        let gossip = must(std::net::UdpSocket::bind("127.0.0.1:0"));
        let gossip_addr = must(gossip.local_addr());
        drop(gossip);
        let shard = crate::inverted_index::ShardId::Backbone(0);
        let cluster = Arc::new(must(
            Cluster::join(
                Member::new(Service::Searcher { host, shard }),
                gossip_addr,
                vec![],
            )
            .await,
        ));
        let config = must(toml::from_str(&format!(
            "host = '{host}'\ngossip_addr = '{gossip_addr}'\nindex_path = 'unused'\nshard = 0\n"
        )));
        let service =
            must(SearchService::new_from_existing(config, cluster.clone(), index.clone()).await);
        drop(reserved);
        match service.bind(host).await {
            Ok(server) => {
                let task = tokio::spawn(async move {
                    loop {
                        must(server.accept().await);
                    }
                });
                return ServiceFixture { cluster, task };
            }
            Err(crate::distributed::sonic::Error::IO(e))
                if e.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(_) => panic!("FIXTURE_BIND"),
        }
    }
    panic!("FIXTURE_BIND_EXHAUSTED")
}

// A complete v1 value is independent of the production attribution mapper.
fn expected(word: &str, path: &str, id: &str) -> Value {
    let snippet = format!(
        "Synthetic {word} body with enough words for a deterministic complete search snippet."
    );
    json!({"version":"v1","results":[{"id":id,
        "url":format!("https://fixture.test/{path}"),"domain":"fixture.test",
        "title":format!("Synthetic {word}"),"snippet":snippet}],
        "page":0,"num_results":10,"has_more_results":false})
}

// Explicit fields witness the supported request rather than relying on changing defaults.
fn query(word: &str) -> Vec<u8> {
    must(serde_json::to_vec(
        &json!({"query":word,"page":0,"num_results":10,
        "country":"unknown","adult_verified":false,"scholarly":false}),
    ))
}

// Both existing timing fields are captured explicitly; all other values are independent.
fn legacy_expected(word: &str, path: &str, duration: u64, stage_ms: u64) -> Value {
    let mut page = json!({"title":format!("Synthetic {word}"),
        "url":format!("https://fixture.test/{path}"),"site":"fixture.test",
        "domain":"fixture.test","prettyUrl":format!("https://fixture.test › {path}"),
        "snippet":{"date":null,"text":{"fragments":[
            {"kind":"normal","text":"Synthetic "},{"kind":"highlighted","text":word},
            {"kind":"normal","text":
                " body with enough words for a deterministic complete search snippet."}]}},
        "planStage":"strict","richSnippet":null,"rankingSignals":null,"structuredData":null,
        "likelyHasAds":false,"likelyHasPaywall":false});
    if cfg!(feature = "return_body") {
        page["body"] = Value::Null;
    }
    let fields = [
        "title",
        "body",
        "stemmed_title",
        "stemmed_body",
        "all_body",
        "url",
        "url_no_tokenizer",
        "site_no_tokenizer",
        "domain_no_tokenizer",
        "domain_name_no_tokenizer",
        "description",
        "clean_body_bigrams",
        "title_bigrams",
        "clean_body_trigrams",
        "title_trigrams",
    ];
    let terms = fields
        .map(|field| format!("should:{field}:TERM(\"{word}\")"))
        .join(",");
    json!({"_type":"websites","webpages":[page],
        "numHits":{"_type":"exact","value":1},"searchDurationMs":duration,
        "hasMoreResults":false,"queryPlan":{"version":1,"mode":"strict_only",
            "numHitsScope":"single_stage","stages":[{"id":"strict","elapsedMs":stage_ms,
                "addedCount":1,"returnedCount":1,"producedResults":true,
                "hitCount":{"_type":"exact","value":1},"minimumShouldMatch":null,
                "renderedQuery":format!("BOOL({terms})"),"rewrittenQuery":word,
                "terms":[{"kind":"literal","occur":"must","text":word,"weight":1}]}]}})
}

// Whole wire observations retain headers and bytes, including empty fallback and HEAD bodies.
struct Observed {
    status: u16,
    headers: axum::http::HeaderMap,
    bytes: Vec<u8>,
}

// Deadlines are fixture failures, never mutation kills.
async fn observe(
    app: Router,
    method: &str,
    path: &str,
    body: Body,
    headers: &[(&str, &str)],
) -> Observed {
    let mut input = Request::builder().method(method).uri(path);
    for (key, value) in headers {
        input = input.header(*key, *value);
    }
    let input = must(input.body(body));
    let response = must(must(
        tokio::time::timeout(Duration::from_secs(5), app.oneshot(input)).await,
    ));
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = must(to_bytes(response.into_body(), 4 * 1024 * 1024).await).to_vec();
    Observed {
        status,
        headers,
        bytes,
    }
}

// Expected bytes are independent of the handler's constant and never echo input.
const REFUSAL: &[u8] = br#"{"error":{"code":"legacy_api_retired","message":"Use the v1 API"}}"#;
const EMPTY: &[u8] =
    br#"{"version":"v1","results":[],"page":0,"num_results":10,"has_more_results":false}"#;

// Exact header equality catches compression, CORS, redirects, versioning and HEAD length drift.
fn refused(actual: &Observed, head: bool, marker: &str) {
    let body = if head { &[][..] } else { REFUSAL };
    let mut headers = axum::http::HeaderMap::new();
    for (key, value) in [
        ("content-type", "application/json".to_owned()),
        ("cache-control", "no-store".to_owned()),
        (
            "source-offer",
            crate::source_metadata::embedded().source_url,
        ),
        ("content-length", body.len().to_string()),
    ] {
        headers.insert(
            axum::http::HeaderName::from_static(key),
            must(value.parse()),
        );
    }
    assert!(
        actual.status == 410 && actual.headers == headers && actual.bytes == body,
        "{marker}"
    );
}

// Contract headers and the complete successful value are asserted independently.
fn v1_value(actual: &Observed, expected: Value, marker: &str) {
    assert!(
        actual.status == 200
            && serde_json::from_slice::<Value>(&actual.bytes).ok() == Some(expected),
        "{marker}"
    );
    assert!(
        actual
            .headers
            .get("content-type")
            .is_some_and(|v| v == "application/json")
            && actual
                .headers
                .get("reports-and-requests")
                .is_some_and(|v| v == "/v1/reports")
            && actual
                .headers
                .get("x-api-version")
                .is_some_and(|v| v == "v1")
            && actual
                .headers
                .get("source-offer")
                .is_some_and(|v| v == crate::source_metadata::embedded().source_url.as_str()),
        "V1_HEADERS"
    );
}

// The same public composition carries independently loaded metadata routers in production.
fn policy(config: &ApiConfig) -> Router {
    merge_policy_egress(
        must(crawler_policy::router(
            config.crawler_policy_config_path.as_deref(),
        )),
        must(egress::router(
            config.egress_file_path.as_deref(),
            config.egress_trusted_keys_path.as_deref(),
        )),
    )
}

// Counting wraps actual retrieval and never replaces filtering, attribution or serialization.
async fn local_backend(
    root: &Path,
    calls: Arc<std::sync::atomic::AtomicUsize>,
) -> Arc<dyn v1::SearchBackend> {
    use crate::searcher::{distributed::LocalSearchClient, LocalSearcher};
    let local = LocalSearcher::builder(Arc::new(tokio::sync::RwLock::new(index(root)))).build();
    let mut settings = crate::searcher::api::Config::default();
    settings.widgets.calculator_fetch_currencies_exchange = false;
    settings.widgets.thesaurus_paths.clear();
    let searcher: ApiSearcher<LocalSearchClient, crate::webgraph::Webgraph> = ApiSearcher::new(
        LocalSearchClient::from(local),
        None,
        Bangs::empty(),
        settings,
    )
    .await;
    let searcher = Arc::new(searcher);
    Arc::new(move |query: crate::searcher::SearchQuery| {
        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let searcher = searcher.clone();
        async move { searcher.search(&query).await }
    })
}

// The existing observer holds the real response after retrieval, immediately before live guards.
#[derive(Default)]
struct Assembly {
    hold: std::sync::atomic::AtomicBool,
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
impl v1::Observer for Assembly {
    fn before_assembly(&self) -> futures::future::BoxFuture<'_, ()> {
        Box::pin(async {
            if self.hold.swap(false, std::sync::atomic::Ordering::SeqCst) {
                self.reached.notify_one();
                self.release.notified().await;
            }
        })
    }
}

// Real persistence hooks create uncertain final guards without a production test switch.
#[derive(Default)]
struct Fault(std::sync::atomic::AtomicBool);
impl v1::suppression::StoreHooks for Fault {
    fn at(&self, stage: v1::suppression::StoreStage) -> std::io::Result<()> {
        if stage == v1::suppression::StoreStage::SyncDirectory
            && self.0.load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(std::io::Error::other("synthetic uncertainty"));
        }
        Ok(())
    }
}
impl crate::compliance::rules::RulesHooks for Fault {
    fn at(&self, stage: crate::compliance::rules::RulesStage) -> std::io::Result<()> {
        if stage == crate::compliance::rules::RulesStage::SyncDirectory
            && self.0.load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(std::io::Error::other("synthetic uncertainty"));
        }
        Ok(())
    }
}

// Owned directories outlive all store handles and the indexed backend.
struct Fixture {
    app: Router,
    management: Router,
    state: Arc<v1::V1State>,
    calls: Arc<std::sync::atomic::AtomicUsize>,
    assembly: Arc<Assembly>,
    fault: Arc<Fault>,
    _root: file_store::temp::TempDir,
}

impl Fixture {
    // A fixed clock pins report bytes; only the separate suppression-fault case needs with_store.
    async fn new(suppression_fault: bool) -> Self {
        let root = must(crate::gen_temp_dir());
        let config = config(root.as_ref());
        let policy = policy(&config);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let backend = local_backend(&root.as_ref().join("index"), calls.clone()).await;
        let assembly = Arc::new(Assembly::default());
        let fault = Arc::new(Fault::default());
        let hooks = fault.clone();
        let observer = assembly.clone();
        let state = must(
            tokio::task::spawn_blocking(move || {
                let resources = if suppression_fault {
                    let store = Arc::new(must(v1::suppression::SuppressionStore::open_with_hooks(
                        &config.v1.suppression_store_path,
                        hooks,
                    )));
                    must(v1::V1Resources::with_store(&config, store))
                } else {
                    resources(&config, hooks)
                };
                Arc::new(
                    v1::V1State::from_resources(&config, backend, &resources)
                        .with_observer(observer),
                )
            })
            .await,
        );
        Self {
            app: compose_public(policy, state.clone()),
            management: v1::compose_management(state.clone()),
            state,
            calls,
            assembly,
            fault,
            _root: root,
        }
    }

    // Capture every response through the real public router.
    async fn search(&self, word: &str) -> Observed {
        observe(
            self.app.clone(),
            "POST",
            "/v1/search",
            Body::from(query(word)),
            &[("content-type", "application/json")],
        )
        .await
    }

    // An explicit management operation supplies the suppression update.
    async fn delete(&self) -> Observed {
        observe(
            self.management.clone(),
            "DELETE",
            &format!("/v1/documents/{DELETED}"),
            Body::empty(),
            &[],
        )
        .await
    }

    // Healthy controls use a document independent of both kinds of update.
    async fn allowed(&self, marker: &str) {
        v1_value(
            &self.search("birch").await,
            expected("birch", "allowed", ALLOWED),
            marker,
        );
    }

    // Pending store transactions finish before temporary paths are removed.
    async fn close(self) {
        self.state.store().shutdown().await;
        self.state.compliance().shutdown().await;
        self.state.ingest_register().shutdown().await;
    }
}

// A fixed clock makes every field except the captured random ticket independently predictable.
fn resources(config: &ApiConfig, hooks: Arc<Fault>) -> v1::V1Resources {
    let time = must(chrono::DateTime::parse_from_rfc3339("2026-09-18T12:00:00Z"))
        .with_timezone(&chrono::Utc);
    must(v1::V1Resources::with_compliance_seams(
        config,
        v1::compliance_adapter::ComplianceSeams {
            clock: Arc::new(crate::crawler::politeness::ManualClock::new(time)),
            rules_hooks: hooks,
            ..Default::default()
        },
    ))
}

// Admission is driven through the actual report route, with the full acknowledgement pinned.
async fn admit(app: Router) -> String {
    let report = json!({"urls":["https://fixture.test/blocked"],
        "suspected_illegality":"Synthetic evidence",
        "report":{"contact":{"method":"email","address":"synthetic@example.test"},
            "description":"Synthetic fixture", "requester_type":"affected_person",
            "nonessential_opt_out":true}});
    let actual = observe(
        app,
        "POST",
        "/v1/reports/illegal-content",
        Body::from(must(serde_json::to_vec(&report))),
        &[("content-type", "application/json")],
    )
    .await;
    let value: Value = must(serde_json::from_slice(&actual.bytes));
    let id = value["ticket_id"].as_str().expect("RULE_TICKET").to_owned();
    v1_value(
        &actual,
        json!({"version":"v1","ticket_id":id,
        "status_path":format!("/v1/reports/status/{id}"),"received_at":1789732800i64,
        "acknowledged_at":1789732800i64,
        "indicative_timeframe":"We will review this report as soon as possible",
        "possible_outcomes":["deindexed","no_action"],"nonessential_opt_out":true}),
        "RULE_REPORT",
    );
    id
}

// The synthetic bearer is sent only to the in-process authenticated management route.
async fn decision(management: Router, id: &str) -> Observed {
    observe(
        management,
        "POST",
        &format!("/v1/compliance/tickets/{id}/decision"),
        Body::from(must(serde_json::to_vec(&json!({"actor":"reviewer",
            "decision":{"kind":"granted","reasons":"Synthetic ground",
                "delivery":{"channel":"manual_api","reference":"synthetic"}}})))),
        &[
            ("content-type", "application/json"),
            ("authorization", &format!("Bearer {}", "a".repeat(64))),
        ],
    )
    .await
}

// No rules file is fabricated; the real decision path must return its entire acknowledgement.
async fn block(fixture: &Fixture) {
    let id = admit(fixture.app.clone()).await;
    v1_value(
        &decision(fixture.management.clone(), &id).await,
        json!({"version":"v1","ticket_id":id,"state":"actioned",
            "recorded_at":1789732800i64,"notice":{"text":"Synthetic ground","remedies":[]}}),
        "RULE_DECISION",
    );
}

// Both witnesses share intake; only regressions assert that backend work is absent.
async fn beta(fixture: &Fixture, word: &str, check_calls: bool) -> Observed {
    let before = fixture.calls.load(std::sync::atomic::Ordering::SeqCst);
    let actual = observe(
        fixture.app.clone(),
        "POST",
        "/beta/api/search",
        Body::from(must(serde_json::to_vec(
            &json!({"query":word,"numResults":10,
            "flattenResponse":true}),
        ))),
        &[("content-type", "application/json")],
    )
    .await;
    assert!(
        !check_calls || fixture.calls.load(std::sync::atomic::Ordering::SeqCst) == before,
        "BETA_NO_BACKEND"
    );
    actual
}

// The deletion-only case cannot be hidden by a global rule for the same document.
async fn suppress(fixture: &Fixture) {
    v1_value(
        &fixture.search("cedar").await,
        expected("cedar", "deleted", DELETED),
        "W01_VISIBLE",
    );
    v1_value(
        &fixture.delete().await,
        json!({"version":"v1","id":DELETED,"suppressed":true}),
        "W01_ACK",
    );
    let hidden = fixture.search("cedar").await;
    assert!(hidden.status == 200 && hidden.bytes == EMPTY, "W01_DELETE");
}

#[tokio::test]
async fn w01_legacy_search_closed() {
    let fixture = Fixture::new(false).await;
    suppress(&fixture).await;
    refused(&beta(&fixture, "cedar", true).await, false, "W01_BETA");
    fixture.allowed("W01_ALLOWED").await;
    v1_value(
        &fixture.search("maple").await,
        expected("maple", "blocked", BLOCKED),
        "W01_RULE_VISIBLE",
    );
    block(&fixture).await;
    let hidden = fixture.search("maple").await;
    assert!(hidden.status == 200 && hidden.bytes == EMPTY, "W01_RULES");
    refused(&beta(&fixture, "maple", true).await, false, "W01_BETA");
    fixture.allowed("W01_ALLOWED").await;
    fixture.close().await;
}

// The complete old inventory includes roots, arbitrary tails, malformed image input and assets.
const RETIRED_PATHS: &[&str] = &[
    "/beta/api/entity_image",
    "/beta",
    "/beta/",
    "/improvement",
    "/improvement/",
    "/beta/api/search",
    "/beta/api/search/widget",
    "/beta/api/search/sidebar",
    "/beta/api/search/spellcheck",
    "/beta/api/autosuggest",
    "/beta/api/autosuggest/browser",
    "/beta/api/webgraph/host/similar",
    "/beta/api/webgraph/host/knows",
    "/beta/api/webgraph/host/ingoing",
    "/beta/api/webgraph/host/outgoing",
    "/beta/api/webgraph/page/ingoing",
    "/beta/api/webgraph/page/outgoing",
    "/beta/api/hosts/export",
    "/beta/api/explore/export",
    "/beta/api/docs/swagger",
    "/beta/api/docs/openapi.json",
    "/beta/api/docs/swagger/swagger-ui.css",
    "/beta/unknown/tail",
    "/improvement/unknown/tail",
    "/improvement/store",
    "/improvement/click?qid=x&click=1",
    "/beta/api/entity_image?entity=x&width=4294967295&height=4294967295",
    "/beta/api/entity_image?width=bad&height=%FF",
];

#[tokio::test]
async fn w02_beta_inventory() {
    let fixture = Fixture::new(false).await;
    for (path_index, path) in RETIRED_PATHS.iter().enumerate() {
        for (method_index, method) in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
            .into_iter()
            .enumerate()
        {
            let actual = observe(fixture.app.clone(), method, path, Body::from("{bad"), &[]).await;
            refused(
                &actual,
                method == "HEAD",
                &format!("W02_RETIRED_{path_index}_{method_index}"),
            );
        }
    }
    for headers in [
        vec![
            ("origin", "https://fixture.test"),
            ("access-control-request-method", "POST"),
        ],
        vec![("accept-encoding", "gzip")],
    ] {
        refused(
            &observe(
                fixture.app.clone(),
                "OPTIONS",
                "/beta/api/search",
                Body::empty(),
                &headers,
            )
            .await,
            false,
            "W02_RETIRED_PREFLIGHT",
        );
        refused(
            &observe(
                fixture.app.clone(),
                "GET",
                "/improvement/store",
                Body::empty(),
                &headers,
            )
            .await,
            false,
            "W02_RETIRED_ENCODING",
        );
    }
    for path in [
        "/betamax",
        "/improvements",
        "/Beta/api/search",
        "/%62eta/api/search",
        "/%69mprovement/store",
        "/beta%2Fapi/search",
    ] {
        let actual = observe(fixture.app.clone(), "GET", path, Body::empty(), &[]).await;
        assert!(
            actual.status == 404 && actual.bytes.is_empty(),
            "W02_NEAR_PREFIX"
        );
    }
    source_control(fixture.app.clone(), "/v1/source", true).await;
    publication(fixture.app.clone()).await;
    fixture.close().await;
}

// The stream increments only on an actual body poll, including its final EOF.
fn counted(chunks: Vec<Vec<u8>>, polls: Arc<std::sync::atomic::AtomicUsize>) -> Body {
    let mut chunks = chunks.into_iter();
    Body::from_stream(futures::stream::poll_fn(move |_| {
        polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::task::Poll::Ready(chunks.next().map(Ok::<_, std::io::Error>))
    }))
}

// Store regression and diagnostic use exactly this same public intake operation.
async fn store(app: Router, bytes: Vec<u8>) -> (Observed, usize) {
    let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let actual = observe(
        app,
        "POST",
        "/improvement/store",
        counted(vec![bytes], polls.clone()),
        &[("content-type", "application/json")],
    )
    .await;
    (actual, polls.load(std::sync::atomic::Ordering::SeqCst))
}

// The historical million-byte query is serialized, so its exact query length is unambiguous.
fn megabyte() -> Vec<u8> {
    must(serde_json::to_vec(&json!({"query":"x".repeat(1_000_000),
        "urls":["https://example.test/a"]})))
}

#[tokio::test]
async fn w03_megabyte_query_closed() {
    let fixture = Fixture::new(false).await;
    fixed_control().await;
    let mut bodies = vec![megabyte(), vec![], b"{bad".to_vec()];
    for size in [0, 1, 1_048_576] {
        bodies.push(must(serde_json::to_vec(&json!({"query":"x".repeat(size),
            "urls":["https://example.test/a"]}))));
    }
    bodies.push(must(serde_json::to_vec(&json!({"query":"x",
        "urls":[format!("https://example.test/{}", "a".repeat(100_000))]}))));
    bodies.push(must(serde_json::to_vec(&json!({"query":"x",
        "urls":vec!["https://example.test/a";10_001]}))));
    for bytes in bodies {
        let (actual, polls) = store(fixture.app.clone(), bytes).await;
        refused(&actual, false, "W03_REFUSAL");
        assert!(polls == 0, "W03_UNREAD");
    }
    refused(
        &observe(
            fixture.app.clone(),
            "POST",
            "/improvement/click?qid=x&click=1",
            Body::from("x"),
            &[],
        )
        .await,
        false,
        "W03_REFUSAL",
    );
    fixture.allowed("W03_ALLOWED").await;
    fixture.close().await;
}

#[tokio::test]
async fn w04_no_body_poll() {
    let fixture = Fixture::new(false).await;
    let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let chunks = vec![b"a".to_vec(), b"bc".to_vec(), b"d".to_vec()];
    let bytes = must(to_bytes(counted(chunks, polls.clone()), 1024).await);
    assert!(
        bytes.as_ref() == b"abcd" && polls.load(std::sync::atomic::Ordering::SeqCst) > 0,
        "W04_COUNTER_CONTROL"
    );
    for length in [None, Some("1"), Some("9000000")] {
        polls.store(0, std::sync::atomic::Ordering::SeqCst);
        let headers = length
            .map(|v| vec![("content-length", v)])
            .unwrap_or_default();
        let actual = observe(
            fixture.app.clone(),
            "POST",
            "/improvement/store",
            counted(vec![vec![b'x'; 1024]; 1024], polls.clone()),
            &headers,
        )
        .await;
        assert!(
            polls.load(std::sync::atomic::Ordering::SeqCst) == 0,
            "W04_UNREAD"
        );
        refused(&actual, false, "W04_CONTRACT");
    }
    for _ in 0..10_001 {
        let (actual, polls) = store(fixture.app.clone(), vec![b'x']).await;
        assert!(polls == 0, "W04_UNREAD");
        refused(&actual, false, "W04_CONTRACT");
    }
    let pending = (0..32).map(|_| store(fixture.app.clone(), vec![b'x'; 1_000_000]));
    for (actual, polls) in futures::future::join_all(pending).await {
        assert!(polls == 0, "W04_UNREAD");
        refused(&actual, false, "W04_CONTRACT");
    }
    polls.store(0, std::sync::atomic::Ordering::SeqCst);
    let chunks = query("birch").chunks(3).map(|c| c.to_vec()).collect();
    let actual = observe(
        fixture.app.clone(),
        "POST",
        "/v1/search",
        counted(chunks, polls.clone()),
        &[("content-type", "application/json")],
    )
    .await;
    v1_value(
        &actual,
        expected("birch", "allowed", ALLOWED),
        "W04_V1_STREAM",
    );
    assert!(
        polls.load(std::sync::atomic::Ordering::SeqCst) > 0,
        "W04_V1_POLLED"
    );
    fixture.close().await;
}

#[tokio::test]
async fn w05_v1_rules_live() {
    let fixture = Fixture::new(false).await;
    fixture.allowed("W05_ALLOWED").await;
    v1_value(
        &fixture.search("maple").await,
        expected("maple", "blocked", BLOCKED),
        "W05_VISIBLE",
    );
    block(&fixture).await;
    let actual = fixture.search("maple").await;
    assert!(actual.status == 200 && actual.bytes == EMPTY, "W05_RULES");
    suppress(&fixture).await;
    refused(&beta(&fixture, "maple", true).await, false, "W05_BETA");
    fixture.allowed("W05_ALLOWED").await;
    fixture.close().await;
}

#[tokio::test]
async fn w07_router_startup_retirement() {
    let root = must(crate::gen_temp_dir());
    let service = service(&root.as_ref().join("index")).await;
    let mut config = config(root.as_ref());
    config.host = must("0.0.0.0:57300".parse());
    let startup = config.clone();
    let resources = must(
        tokio::task::spawn_blocking(move || resources(&startup, Arc::new(Fault::default()))).await,
    );
    config.query_store_db = Some(crate::config::QueryStoreConfig {
        host: "127.0.0.1".into(),
        username: "x".into(),
        password: "x".into(),
    });
    let rejected = must(
        tokio::time::timeout(
            Duration::from_secs(30),
            router(&config, counters(), service.cluster.clone(), &resources),
        )
        .await,
    );
    assert!(
        rejected
            .err()
            .is_some_and(|e| e.to_string() == "query_store_db has been retired"),
        "W07_ROUTER_REJECTS"
    );
    config.query_store_db = None;
    let (app, state) = must(must(
        tokio::time::timeout(
            Duration::from_secs(30),
            router(&config, counters(), service.cluster.clone(), &resources),
        )
        .await,
    ));
    let actual = observe(
        app.clone(),
        "POST",
        "/v1/search",
        Body::from(query("birch")),
        &[("content-type", "application/json")],
    )
    .await;
    v1_value(
        &actual,
        expected("birch", "allowed", ALLOWED),
        "W07_ROUTER_VISIBLE",
    );
    refused(
        &observe(app, "POST", "/beta/api/search", Body::empty(), &[]).await,
        false,
        "W07_ROUTER_RETIRED",
    );
    state.compliance().shutdown().await;
    state.store().shutdown().await;
}

// Independent expected metadata is built only from the embedded public build identity.
async fn source_control(app: Router, path: &str, versioned: bool) {
    let metadata = crate::source_metadata::embedded();
    let mut expected = json!({"licence":"AGPL-3.0-only","source_url":metadata.source_url,
        "revision":metadata.revision,"revision_source":metadata.revision_source});
    if versioned {
        expected["version"] = json!("v1");
    }
    let actual = observe(app, "GET", path, Body::empty(), &[]).await;
    assert!(
        actual.status == 200
            && serde_json::from_slice::<Value>(&actual.bytes).ok() == Some(expected),
        "SOURCE_CONTROL"
    );
}

// Exact complete path items preserve all v1 operations, references and listener annotations.
async fn publication(app: Router) {
    let actual = observe(
        app.clone(),
        "GET",
        "/api/docs/openapi.json",
        Body::empty(),
        &[],
    )
    .await;
    let bytes = must(serde_json::to_vec(&docs::published_openapi()));
    if let Some(path) = std::env::var_os("PUBLISHED_OPENAPI_ARTIFACT") {
        must(std::fs::write(path, &bytes));
    } else {
        assert!(
            bytes == include_bytes!("../../tests/fixtures/api_v1/published-openapi.json"),
            "W08_PUBLISHED"
        );
    }
    assert!(
        actual.status == 200
            && actual.bytes == bytes
            && actual
                .headers
                .get("source-offer")
                .is_some_and(|v| v == crate::source_metadata::embedded().source_url.as_str()),
        "W08_PUBLISHED"
    );
    let doc: Value = must(serde_json::from_slice(&actual.bytes));
    let v1: Value = must(serde_json::from_slice(include_bytes!(
        "../../tests/fixtures/api_v1/v1-openapi.json"
    )));
    assert!(
        must(serde_json::to_value(v1::openapi())) == v1,
        "W08_V1_GOLDEN"
    );
    let mut paths = v1["paths"].as_object().unwrap().clone();
    for path in [
        "/.well-known/ava-search-source",
        "/.well-known/ava-search-crawler",
        "/.well-known/ava-search-egress.json",
    ] {
        let item = doc["paths"][path].as_object().expect("W08_WELL_KNOWN");
        assert!(item.len() == 1 && item.contains_key("get"), "W08_PUBLISHED");
        paths.insert(path.into(), Value::Object(item.clone()));
    }
    assert!(
        doc["paths"] == Value::Object(paths) && doc["paths"].as_object().unwrap().len() == 28,
        "W08_PUBLISHED"
    );
    let operations = doc["paths"]
        .as_object()
        .unwrap()
        .values()
        .map(|p| p.as_object().unwrap().len())
        .sum::<usize>();
    assert!(operations == 29, "W08_PUBLISHED");
    for text in [
        "Source-Offer",
        "AGPL-3.0-only",
        "/.well-known/ava-search-source",
        "/.well-known/ava-search-crawler",
        "/.well-known/ava-search-egress.json",
        "410",
    ] {
        assert!(
            doc["info"]["description"].as_str().unwrap().contains(text),
            "W08_PUBLISHED"
        );
    }
    let egress = &doc["paths"]["/.well-known/ava-search-egress.json"]["get"];
    assert!(
        egress["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
            ["signature_base64"]
            .is_object(),
        "W08_PUBLISHED"
    );
    assert!(docs::historical_beta_matches_golden(), "W08_BETA_GOLDEN");
    for path in ["/beta/api/docs/openapi.json", "/beta/api/docs/swagger"] {
        refused(
            &observe(app.clone(), "GET", path, Body::empty(), &[]).await,
            false,
            "W08_RETIRED_DOCS",
        );
    }
    for path in ["/api/docs/swagger/", "/api/docs/swagger/swagger-ui.css"] {
        let actual = observe(app.clone(), "GET", path, Body::empty(), &[]).await;
        assert!(
            actual.status == 200 && !actual.bytes.is_empty(),
            "W08_SWAGGER"
        );
    }
}

#[tokio::test]
async fn w08_publication() {
    let fixture = Fixture::new(false).await;
    publication(fixture.app.clone()).await;
    fixture.close().await;
}

// Tombstone audits inspect items, not a counter claiming that removed storage is empty.
fn audit_storage() {
    for source in [
        include_str!("improvement.rs"),
        include_str!("../improvement.rs"),
        include_str!("../leaky_queue.rs"),
    ] {
        let tail: Vec<_> = source
            .lines()
            .skip(15)
            .filter(|line| !line.trim().is_empty())
            .collect();
        assert!(
            !tail.is_empty() && tail.iter().all(|line| line.starts_with("//!")),
            "W09_NO_STORE"
        );
    }
    let source = include_str!("mod.rs");
    for token in [
        "ImprovementEvent",
        "StoredQuery",
        "improvement_queue",
        "query_store_queue",
        "LeakyQueue",
        "store_improvements_loop",
        "scylla::",
        "post(improvement::",
    ] {
        assert!(!source.contains(token), "W09_NO_STORE");
    }
    let gone = include_str!("retired.rs");
    assert!(
        gone.contains("async fn gone(method: Method) -> Response")
            && !gone.contains("State<")
            && !gone.contains("to_bytes("),
        "W09_NO_STORE"
    );
}

#[tokio::test]
async fn w09_removed_storage() {
    let fixture = Fixture::new(false).await;
    let metrics = metrics_router(Default::default());
    for path in [
        "/improvement/store",
        "/improvement/click",
        "/beta/api/search",
    ] {
        for app in [fixture.management.clone(), metrics.clone()] {
            let actual = observe(app, "POST", path, Body::from(megabyte()), &[]).await;
            assert!(
                actual.status == 404 && actual.bytes.is_empty(),
                "W09_NO_STORE"
            );
        }
        refused(
            &observe(
                fixture.app.clone(),
                "POST",
                path,
                Body::from(megabyte()),
                &[],
            )
            .await,
            false,
            "W09_NO_STORE",
        );
    }
    let management = observe(
        fixture.management.clone(),
        "POST",
        "/v1/search",
        Body::empty(),
        &[],
    )
    .await;
    assert!(management.status == 404 && management.bytes
        == br#"{"version":"v1","error":{"code":"not_found","message":"The route was not found"}}"#,
        "W09_MANAGEMENT");
    source_control(fixture.app.clone(), "/.well-known/ava-search-source", false).await;
    source_control(metrics, "/.well-known/ava-search-source", false).await;
    source_control(fixture.management.clone(), "/v1/source", true).await;
    fixture.allowed("W09_ALLOWED").await;
    audit_storage();
    fixture.close().await;
}

// Four separate fixtures prevent one denial mechanism from masking another.
async fn concurrent_gate(rule: bool, unavailable: bool) {
    let fixture = Fixture::new(!rule && unavailable).await;
    fixture.allowed("W11_CONTROL").await;
    let word = if rule { "maple" } else { "cedar" };
    let id = if rule {
        Some(admit(fixture.app.clone()).await)
    } else {
        None
    };
    fixture
        .assembly
        .hold
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let app = fixture.app.clone();
    let pending = tokio::spawn(async move {
        observe(
            app,
            "POST",
            "/v1/search",
            Body::from(query(word)),
            &[("content-type", "application/json")],
        )
        .await
    });
    must(tokio::time::timeout(Duration::from_secs(5), fixture.assembly.reached.notified()).await);
    fixture
        .fault
        .0
        .store(unavailable, std::sync::atomic::Ordering::SeqCst);
    let update = if let Some(id) = id.as_deref() {
        decision(fixture.management.clone(), id).await
    } else {
        fixture.delete().await
    };
    if unavailable {
        unavailable_response(&update, rule);
    } else if let Some(id) = id {
        v1_value(
            &update,
            json!({"version":"v1","ticket_id":id,"state":"actioned",
            "recorded_at":1789732800i64,"notice":{"text":"Synthetic ground","remedies":[]}}),
            "W11_DECISION",
        );
    } else {
        v1_value(
            &update,
            json!({"version":"v1","id":DELETED,"suppressed":true}),
            "W11_DELETE",
        );
    }
    fixture.assembly.release.notify_one();
    let actual = must(must(
        tokio::time::timeout(Duration::from_secs(5), pending).await,
    ));
    if unavailable {
        unavailable_response(&actual, rule);
    } else {
        assert!(actual.status == 200 && actual.bytes == EMPTY, "W11_FINAL");
        fixture.allowed("W11_CONTROL").await;
    }
    fixture.close().await;
}

// Closed error bytes prove unavailability without partial results after retrieval.
fn unavailable_response(actual: &Observed, rule: bool) {
    let bytes: &[u8] = if rule {
        concat!(
            r#"{"version":"v1","error":{"code":"rules_unavailable","message":""#,
            r#"The serving rules are unavailable"}}"#
        )
        .as_bytes()
    } else {
        concat!(
            r#"{"version":"v1","error":{"code":"suppression_unavailable","message":""#,
            r#"The suppression store is unavailable"}}"#
        )
        .as_bytes()
    };
    assert!(actual.status == 503 && actual.bytes == bytes, "W11_FINAL");
}

#[tokio::test]
async fn w11_final_gates() {
    for rule in [false, true] {
        for unavailable in [false, true] {
            concurrent_gate(rule, unavailable).await;
        }
    }
    let healthy = Fixture::new(false).await;
    healthy.allowed("W11_RECOVERY_CONTROL").await;
    healthy.close().await;
}

#[tokio::test]
async fn w12_config_and_features() {
    for source in [
        include_str!("../../../../configs/api.toml"),
        include_str!("../../../../configs/eval/api-off.toml"),
        include_str!("../../../../configs/eval/api-on.toml"),
    ] {
        let mut config: ApiConfig = must(toml::from_str(source));
        assert!(
            config.query_store_db.is_none() && config.ensure_query_store_retired().is_ok(),
            "W12_CONFIG"
        );
        for mode in [
            crate::config::compliance::DeploymentMode::Local,
            crate::config::compliance::DeploymentMode::Hosted,
        ] {
            config.compliance.deployment_mode = mode;
            for host in ["127.0.0.1", "0.0.0.0", ""] {
                for credential in ["", "x"] {
                    config.query_store_db = Some(crate::config::QueryStoreConfig {
                        host: host.into(),
                        username: credential.into(),
                        password: credential.into(),
                    });
                    assert!(
                        config
                            .ensure_query_store_retired()
                            .err()
                            .is_some_and(|e| e.to_string() == "query_store_db has been retired"),
                        "W12_CONFIG"
                    );
                }
            }
        }
    }
    let fixture = Fixture::new(false).await;
    fixture.allowed("W12_V1").await;
    source_control(fixture.app.clone(), "/v1/source", true).await;
    for method in ["OPTIONS", "HEAD", "POST"] {
        refused(
            &observe(
                fixture.app.clone(),
                method,
                "/improvement/store",
                Body::empty(),
                &[
                    ("origin", "https://fixture.test"),
                    ("access-control-request-method", "POST"),
                ],
            )
            .await,
            method == "HEAD",
            "W12_CONFIG",
        );
    }
    fixture.close().await;
}

// A separate fixed backend checks the brief's literal cedar wire fixture without timing fields.
async fn fixed_control() {
    let root = must(crate::gen_temp_dir());
    let config = config(root.as_ref());
    let backend = Arc::new(|_: crate::searcher::SearchQuery| async {
        let page = must(serde_json::from_value(json!({"title":"Synthetic cedar",
            "url":"https://fixture.test/allowed","site":"fixture.test","domain":"fixture.test",
            "prettyUrl":"https://fixture.test › allowed","snippet":{"date":null,
                "text":{"fragments":[{"kind":"normal","text":"Synthetic cedar body"}]}},
            "body":null,"richSnippet":null,"rankingSignals":null,"structuredData":null,
            "likelyHasAds":false,"likelyHasPaywall":false})));
        Ok(crate::searcher::SearchResult::Websites(
            crate::searcher::WebsitesResult {
                webpages: vec![page],
                num_hits: crate::collector::approx_count::Count::Exact(1),
                search_duration_ms: 0,
                has_more_results: false,
                spell_correction: None,
                query_plan: None,
            },
        ))
    });
    let state = must(
        tokio::task::spawn_blocking(move || {
            Arc::new(v1::V1State::from_resources(
                &config,
                backend,
                &resources(&config, Arc::new(Fault::default())),
            ))
        })
        .await,
    );
    let actual = observe(
        compose_public(Router::new(), state.clone()),
        "POST",
        "/v1/search",
        Body::from(concat!(
            r#"{"query":"cedar","page":0,"num_results":10,"country":"unknown","#,
            r#""adult_verified":false,"scholarly":false}"#
        )),
        &[("content-type", "application/json")],
    )
    .await;
    v1_value(
        &actual,
        json!({"version":"v1","results":[{"id":ALLOWED,
        "url":"https://fixture.test/allowed","domain":"fixture.test","title":"Synthetic cedar",
        "snippet":"Synthetic cedar body"}],"page":0,"num_results":10,"has_more_results":false}),
        "FIXED_V1_CONTROL",
    );
    state.compliance().shutdown().await;
}

#[tokio::test]
#[ignore = "Gate-2 defect replay; expected red on the fixed tree"]
async fn legacy_search_is_outside_suppression_and_rules_gate() {
    let fixture = Fixture::new(false).await;
    suppress(&fixture).await;
    let actual = beta(&fixture, "cedar", false).await;
    let value = serde_json::from_slice::<Value>(&actual.bytes).ok();
    let duration = value.as_ref().and_then(|v| v["searchDurationMs"].as_u64());
    let stage = value
        .as_ref()
        .and_then(|v| v["queryPlan"]["stages"][0]["elapsedMs"].as_u64());
    fixture.close().await;
    assert!(
        actual.status == 200
            && duration.is_some()
            && stage
                .zip(duration)
                .is_some_and(|(stage, total)| stage <= total)
            && value
                == Some(legacy_expected(
                    "cedar",
                    "deleted",
                    duration.unwrap_or(0),
                    stage.unwrap_or(0)
                )),
        "DEFECT_SB01_LEGACY_SUCCESS"
    );
}

#[tokio::test]
#[ignore = "Gate-2 defect replay; expected red on the fixed tree"]
async fn query_store_accepts_a_megabyte_query_before_queuing() {
    let fixture = Fixture::new(false).await;
    let (actual, _) = store(fixture.app.clone(), megabyte()).await;
    let uuid = std::str::from_utf8(&actual.bytes)
        .ok()
        .and_then(|s| uuid::Uuid::parse_str(s).ok());
    fixture.close().await;
    assert!(
        actual.status == 200 && uuid.is_some_and(|id| actual.bytes == id.to_string().as_bytes()),
        "DEFECT_SB02_STORE_SUCCESS"
    );
}
