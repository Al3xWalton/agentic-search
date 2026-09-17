//! Exercises the production v1 boundary with counted adapters and real synthetic retrieval fixtures.
//! No external service, index schema, legacy handler or inherited fixture is changed by these tests.

#[path = "support/query_index.rs"]
#[allow(
    dead_code,
    reason = "The immutable shared fixture exposes helpers used by other integration targets"
)]
mod query_index;

mod contracts {
    use axum::{
        body::{to_bytes, Body},
        http::{HeaderMap, Request},
        response::{IntoResponse, Response},
        routing::get,
        Router,
    };
    use serde_json::{json, Value};
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
        Arc, Mutex,
    };
    use stract::{
        api::v1::{
            self,
            dto::Country,
            error::{V1Error, V1Failure},
            search::ServingContext,
            suppression::DocumentId,
            Observer, SearchBackend, V1State,
        },
        config::ApiConfig,
        searcher::{SearchQuery, SearchResult},
    };
    use tokio::sync::Notify;
    use tower::ServiceExt;

    #[derive(Default)]
    struct Probe {
        directory: Mutex<Option<file_store::temp::TempDir>>,
        decode: AtomicUsize,
        backend: AtomicUsize,
        source: AtomicUsize,
        deletes: AtomicUsize,
        delete_reached: Notify,
        construction: AtomicUsize,
        contexts: Mutex<Vec<(DocumentId, ServingContext)>>,
        hold: AtomicBool,
        reached: Notify,
        resume: Notify,
    }
    impl Observer for Probe {
        fn delete_enter(&self) {
            self.deletes.fetch_add(1, SeqCst);
            self.delete_reached.notify_one();
        }
        fn json_decode(&self) {
            self.decode.fetch_add(1, SeqCst);
        }
        fn backend_enter(&self) {
            self.backend.fetch_add(1, SeqCst);
        }
        fn source_enter(&self) {
            self.source.fetch_add(1, SeqCst);
        }
        fn attribution_construct(&self, _: &DocumentId) {
            self.construction.fetch_add(1, SeqCst);
        }
        fn serving_context(&self, id: &DocumentId, context: &ServingContext) {
            self.contexts.lock().unwrap().push((id.clone(), *context));
        }
        fn before_assembly(&self) -> futures::future::BoxFuture<'_, ()> {
            Box::pin(async move {
                if self.hold.load(SeqCst) {
                    self.reached.notify_one();
                    self.resume.notified().await;
                }
            })
        }
    }
    fn config() -> ApiConfig {
        toml::from_str(include_str!("../../../configs/api.toml")).unwrap()
    }
    fn page(url: &str) -> Value {
        json!({"title":"synthetic","url":url,"site":"fixture.test","domain":"fixture.test","prettyUrl":url,"snippet":{"date":null,"text":{"fragments":[]}},"richSnippet":null,"rankingSignals":null,"structuredData":null,"likelyHasAds":false,"likelyHasPaywall":false})
    }
    fn result(urls: &[&str]) -> SearchResult {
        SearchResult::Websites(serde_json::from_value(json!({"webpages":urls.iter().map(|u|page(u)).collect::<Vec<_>>(),"numHits":{"_type":"exact","value":urls.len()},"searchDurationMs":1,"hasMoreResults":false})).unwrap())
    }
    fn state(
        config: &ApiConfig,
        probe: Arc<Probe>,
        backend: Arc<dyn SearchBackend>,
    ) -> Arc<V1State> {
        let directory = stract::gen_temp_dir().unwrap();
        let mut config = config.clone();
        config.v1.suppression_store_path = directory.as_ref().join("private/suppression.json");
        *probe.directory.lock().unwrap() = Some(directory);
        Arc::new(
            V1State::initialize(&config, backend)
                .unwrap()
                .with_observer(probe),
        )
    }
    fn fixture_with(config: &ApiConfig) -> (Arc<V1State>, Arc<Probe>) {
        let probe = Arc::new(Probe::default());
        let backend = Arc::new(|_: SearchQuery| async {
            Ok(result(&[
                "https://example.com/",
                "https://example.com/a?b=2&a=1",
            ]))
        });
        (state(config, probe.clone(), backend), probe)
    }
    fn fixture() -> (Arc<V1State>, Arc<Probe>) {
        fixture_with(&config())
    }
    fn public(state: Arc<V1State>) -> Router {
        v1::compose_api(Router::new(), state)
    }
    fn management(state: Arc<V1State>) -> Router {
        v1::compose_management(state)
    }
    fn request(method: &str, path: &str, body: impl Into<Body>) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .body(body.into())
            .unwrap()
    }
    async fn send(app: Router, method: &str, path: &str, body: impl Into<Body>) -> Response {
        app.oneshot(request(method, path, body)).await.unwrap()
    }
    struct Observed {
        headers: HeaderMap,
        value: Value,
        bytes: Vec<u8>,
        status: u16,
    }
    async fn observe(response: Response) -> Observed {
        let headers = response.headers().clone();
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap()
            .to_vec();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Observed {
            headers,
            value,
            bytes,
            status,
        }
    }
    fn contract(response: &Observed) {
        assert_eq!(response.headers.get_all("source-offer").iter().count(), 1);
        assert_eq!(response.headers["source-offer"], expected_source());
        assert_eq!(response.headers["x-api-version"], "v1");
        assert_eq!(response.value["version"], "v1");
    }
    fn expected_source() -> String {
        let revision = env!("AVA_SEARCH_REVISION");
        if revision == "unknown" {
            env!("CARGO_PKG_REPOSITORY").into()
        } else {
            format!("{}/tree/{revision}", env!("CARGO_PKG_REPOSITORY"))
        }
    }

    use std::{
        io,
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        path::PathBuf,
        sync::Condvar,
    };
    use stract::api::v1::suppression::{
        canonical_identity, StoreHooks, StoreStage, SuppressionStore,
    };

    #[derive(Default)]
    struct Hooks {
        writes: AtomicUsize,
        decodes: AtomicUsize,
        fail: Mutex<Option<StoreStage>>,
        block: Mutex<Option<StoreStage>>,
        entered: Notify,
        released: (Mutex<bool>, Condvar),
    }
    impl StoreHooks for Hooks {
        fn at(&self, stage: StoreStage) -> io::Result<()> {
            if stage == StoreStage::Open {
                self.writes.fetch_add(1, SeqCst);
            }
            if stage == StoreStage::Decode {
                self.decodes.fetch_add(1, SeqCst);
            }
            if *self.block.lock().unwrap() == Some(stage) {
                self.entered.notify_one();
                let mut released = self.released.0.lock().unwrap();
                while !*released {
                    released = self.released.1.wait(released).unwrap();
                }
            }
            if *self.fail.lock().unwrap() == Some(stage) {
                return Err(io::Error::other("SECRET injected store path"));
            }
            Ok(())
        }
    }
    impl Hooks {
        fn release(&self) {
            *self.released.0.lock().unwrap() = true;
            self.released.1.notify_all();
        }
    }
    struct ReleaseHook(Arc<Hooks>);
    impl Drop for ReleaseHook {
        fn drop(&mut self) {
            self.0.release();
        }
    }
    async fn durable_timeout(stage: StoreStage, abort: bool) {
        let mut config = config();
        config.v1.request_timeout_ms = if abort { 60_000 } else { 25 };
        config.v1.max_concurrent_requests = Some(1);
        let fixture = persistent_with(config);
        *fixture.hooks.block.lock().unwrap() = Some(stage);
        let _release = ReleaseHook(fixture.hooks.clone());
        let removed = id("https://example.com/");
        let path = format!("/v1/documents/{}", removed.as_str());
        let app = management(fixture.state.clone());
        let pending_app = app.clone();
        let pending_path = path.clone();
        let task =
            tokio::spawn(
                async move { send(pending_app, "DELETE", &pending_path, Body::empty()).await },
            );
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            fixture.hooks.entered.notified(),
        )
        .await
        .unwrap();
        if abort {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        } else {
            let response = observe(watchdog(async { task.await.unwrap() }).await).await;
            error(&response, "request_timeout", 504);
        }
        let polls = Arc::new(AtomicUsize::new(0));
        let response = observe(
            send(
                app.clone(),
                "DELETE",
                &path,
                stream(vec![vec![b'x']], polls.clone()),
            )
            .await,
        )
        .await;
        assert_eq!(polls.load(SeqCst), 0);
        assert_eq!(fixture.hooks.writes.load(SeqCst), 1);
        error(&response, "overloaded", 503);
        let source = observe(
            send(
                public(fixture.state.clone()),
                "GET",
                "/v1/source",
                Body::empty(),
            )
            .await,
        )
        .await;
        contract(&source);
        assert_eq!(source.status, 200);
        fixture.hooks.release();
        fixture.state.store().shutdown().await;
        assert_eq!(fixture.state.store().generation().await, 1);
        let response = observe(send(app, "DELETE", &path, Body::empty()).await).await;
        assert_eq!(fixture.hooks.writes.load(SeqCst), 1);
        ack(&response, &removed);
        let response = observe(
            send(
                public(fixture.state.clone()),
                "POST",
                "/v1/search",
                r#"{"query":"compiler"}"#,
            )
            .await,
        )
        .await;
        work(&fixture.probe, 1, 1, 1);
        assert_eq!(fixture.probe.construction.load(SeqCst), 2);
        contract(&response);
        assert_eq!(response.value["results"].as_array().unwrap().len(), 2);
    }
    async fn cancellation_before_transaction() {
        let mut config = config();
        config.v1.max_concurrent_requests = Some(2);
        let fixture = persistent_with(config);
        *fixture.hooks.block.lock().unwrap() = Some(StoreStage::Write);
        let _release = ReleaseHook(fixture.hooks.clone());
        let removed = id("https://example.com/");
        let app = management(fixture.state.clone());
        let pending = app.clone();
        let path = format!("/v1/documents/{}", removed.as_str());
        let first =
            tokio::spawn(async move { send(pending, "DELETE", &path, Body::empty()).await });
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            fixture.hooks.entered.notified(),
        )
        .await
        .unwrap();
        let path = format!("/v1/documents/{}", id_for_unknown().as_str());
        let second = tokio::spawn(async move { send(app, "DELETE", &path, Body::empty()).await });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while fixture.probe.deletes.load(SeqCst) < 2 {
                fixture.probe.delete_reached.notified().await;
            }
        })
        .await
        .unwrap();
        second.abort();
        assert!(second.await.unwrap_err().is_cancelled());
        fixture.hooks.release();
        ack(&observe(first.await.unwrap()).await, &removed);
        fixture.state.store().shutdown().await;
        assert_eq!(fixture.hooks.writes.load(SeqCst), 1);
        let snapshot: Value =
            serde_json::from_slice(&std::fs::read(&fixture.path).unwrap()).unwrap();
        assert_eq!(snapshot["ids"], json!([removed.as_str()]));
    }
    struct Persistent {
        state: Arc<V1State>,
        probe: Arc<Probe>,
        hooks: Arc<Hooks>,
        path: PathBuf,
        _directory: file_store::temp::TempDir,
    }
    fn persistent_with(mut config: ApiConfig) -> Persistent {
        let directory = stract::gen_temp_dir().unwrap();
        config.v1.suppression_store_path = directory.as_ref().join("private/suppression.json");
        let path = config.v1.suppression_store_path.clone();
        let hooks = Arc::new(Hooks::default());
        let store = Arc::new(SuppressionStore::open_with_hooks(&path, hooks.clone()).unwrap());
        hooks.writes.store(0, SeqCst);
        let resources = v1::V1Resources::with_store(&config, store).unwrap();
        let probe = Arc::new(Probe::default());
        let backend = Arc::new(|_: SearchQuery| async {
            Ok(result(&[
                "https://example.com/",
                "https://example.com/a?b=2&a=1",
                "https://other.test/",
            ]))
        });
        let state = Arc::new(
            V1State::from_resources(&config, backend, &resources).with_observer(probe.clone()),
        );
        Persistent {
            state,
            probe,
            hooks,
            path,
            _directory: directory,
        }
    }
    fn persistent() -> Persistent {
        persistent_with(config())
    }
    fn id(url: &str) -> DocumentId {
        canonical_identity(url).unwrap().1
    }
    async fn delete(state: Arc<V1State>, id: &DocumentId) -> Observed {
        observe(
            send(
                management(state),
                "DELETE",
                &format!("/v1/documents/{}", id.as_str()),
                Body::empty(),
            )
            .await,
        )
        .await
    }
    fn ack(response: &Observed, id: &DocumentId) {
        contract(response);
        assert_eq!(
            response.value,
            json!({"version":"v1","id":id.as_str(),"suppressed":true})
        );
        assert_eq!(response.status, 200);
    }

    #[tokio::test]
    async fn delete_is_idempotent_without_second_store_write() {
        let fixture = persistent();
        let id = id("https://example.com/");
        let first = delete(fixture.state.clone(), &id).await;
        assert_eq!(fixture.hooks.writes.load(SeqCst), 1);
        work(&fixture.probe, 0, 0, 0);
        ack(&first, &id);
        let bytes = std::fs::read(&fixture.path).unwrap();
        let meta = std::fs::metadata(&fixture.path).unwrap();
        let second = delete(fixture.state.clone(), &id).await;
        assert_eq!(fixture.hooks.writes.load(SeqCst), 1);
        assert_eq!(std::fs::read(&fixture.path).unwrap(), bytes);
        let repeated = std::fs::metadata(&fixture.path).unwrap();
        assert_eq!(
            (repeated.ino(), repeated.mtime(), repeated.mtime_nsec()),
            (meta.ino(), meta.mtime(), meta.mtime_nsec())
        );
        ack(&second, &id);
        assert_eq!(first.bytes, second.bytes);
        let unknown = id_for_unknown();
        let response = delete(fixture.state.clone(), &unknown).await;
        assert_eq!(fixture.hooks.writes.load(SeqCst), 2);
        ack(&response, &unknown);
        let source = observe(
            send(
                management(fixture.state.clone()),
                "GET",
                "/v1/source",
                Body::empty(),
            )
            .await,
        )
        .await;
        assert_eq!(fixture.hooks.writes.load(SeqCst), 2);
        work(&fixture.probe, 0, 0, 1);
        contract(&source);
        assert_eq!(source.status, 200);
        fixture.state.store().shutdown().await;
    }
    fn id_for_unknown() -> DocumentId {
        id("https://never-indexed.invalid/")
    }

    fn write_private(path: &std::path::Path, bytes: &[u8]) {
        use std::io::Write;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }
    fn private_path(directory: &file_store::temp::TempDir) -> PathBuf {
        let parent = directory.as_ref().join("private");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        parent.join("suppression.json")
    }
    fn invalid_snapshot(bytes: &[u8]) {
        let directory = stract::gen_temp_dir().unwrap();
        let path = private_path(&directory);
        write_private(&path, bytes);
        assert!(SuppressionStore::open(&path).is_err());
    }
    fn unsafe_files() {
        for lock in [false, true] {
            for kind in ["symlink", "hardlink", "directory"] {
                let directory = stract::gen_temp_dir().unwrap();
                let path = private_path(&directory);
                let selected = if lock {
                    path.with_file_name("suppression.json.lock")
                } else {
                    path.clone()
                };
                let other = path.with_file_name("other");
                write_private(&other, b"{}");
                match kind {
                    "symlink" => std::os::unix::fs::symlink(&other, &selected).unwrap(),
                    "hardlink" => std::fs::hard_link(&other, &selected).unwrap(),
                    _ => std::fs::create_dir(&selected).unwrap(),
                }
                assert!(
                    SuppressionStore::open(&path).is_err(),
                    "accepted {kind} lock={lock}"
                );
            }
        }
        let directory = stract::gen_temp_dir().unwrap();
        let real = directory.as_ref().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = directory.as_ref().join("link");
        std::os::unix::fs::symlink(real, &link).unwrap();
        assert!(SuppressionStore::open(&link.join("snapshot")).is_err());
    }
    async fn failure_stage(stage: StoreStage) {
        let fixture = persistent();
        let before = std::fs::read(&fixture.path).unwrap();
        *fixture.hooks.fail.lock().unwrap() = Some(stage);
        let removed = id("https://example.com/");
        let response = delete(fixture.state.clone(), &removed).await;
        assert_eq!(fixture.hooks.writes.load(SeqCst), 1);
        assert_eq!(fixture.state.store().generation().await, 0);
        error(&response, "suppression_unavailable", 503);
        *fixture.hooks.fail.lock().unwrap() = None;
        let search = observe(
            send(
                public(fixture.state.clone()),
                "POST",
                "/v1/search",
                r#"{"query":"compiler"}"#,
            )
            .await,
        )
        .await;
        work(
            &fixture.probe,
            1,
            usize::from(stage != StoreStage::SyncDirectory),
            0,
        );
        if stage == StoreStage::SyncDirectory {
            assert_ne!(std::fs::read(&fixture.path).unwrap(), before);
            error(&search, "suppression_unavailable", 503);
            let again = delete(fixture.state.clone(), &removed).await;
            assert_eq!(fixture.hooks.writes.load(SeqCst), 1);
            error(&again, "suppression_unavailable", 503);
        } else {
            assert_eq!(std::fs::read(&fixture.path).unwrap(), before);
            contract(&search);
            assert_eq!(search.value["results"].as_array().unwrap().len(), 3);
            let retry = delete(fixture.state.clone(), &removed).await;
            assert_eq!(fixture.hooks.writes.load(SeqCst), 2);
            ack(&retry, &removed);
        }
        fixture.state.store().shutdown().await;
        let path = fixture.path.clone();
        drop(fixture.state);
        assert!(SuppressionStore::open(&path).is_ok());
    }

    #[tokio::test]
    async fn store_failures_fail_closed_and_preserve_integrity() {
        missing_policy_prevents_store_startup();
        durable_timeout(StoreStage::Write, true).await;
        durable_timeout(StoreStage::SyncDirectory, true).await;
        cancellation_before_transaction().await;
        for bytes in [
            b"{".as_slice(),
            br#"{"format_version":2,"ids":[]}"#,
            br#"{"format_version":1,"ids":[],"extra":true}"#,
            br#"{"format_version":1,"ids":[]}garbage"#,
        ] {
            invalid_snapshot(bytes);
        }
        let a = "0".repeat(64);
        let b = "1".repeat(64);
        for ids in [vec![a.clone(), a.clone()], vec![b, a], vec!["A".repeat(64)]] {
            invalid_snapshot(json!({"format_version":1,"ids":ids}).to_string().as_bytes());
        }
        unsafe_files();
        let fixture = persistent();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "contracts::store_lock_child",
                "--nocapture",
            ])
            .env("V1_STORE_LOCK_PATH", &fixture.path)
            .output()
            .unwrap();
        println!("{}", String::from_utf8_lossy(&child.stdout));
        assert!(
            child.status.success(),
            "{}",
            String::from_utf8_lossy(&child.stderr)
        );
        for stage in [
            StoreStage::Open,
            StoreStage::Write,
            StoreStage::SyncFile,
            StoreStage::Rename,
            StoreStage::SyncDirectory,
        ] {
            failure_stage(stage).await;
        }
        let directory = stract::gen_temp_dir().unwrap();
        let path = private_path(&directory);
        let leftover = path.with_file_name("suppression.json.leftover.tmp");
        write_private(&leftover, b"uncommitted garbage");
        let store = SuppressionStore::open(&path).unwrap();
        assert_eq!(store.generation().await, 0);
        assert_eq!(std::fs::read(&leftover).unwrap(), b"uncommitted garbage");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"{\"format_version\":1,\"ids\":[]}\n"
        );
    }

    #[test]
    #[ignore = "Invoked in a separate process only by the store lock ownership witness"]
    fn store_lock_child() {
        let path = PathBuf::from(std::env::var_os("V1_STORE_LOCK_PATH").unwrap());
        assert!(SuppressionStore::open(&path).is_err());
        println!("LOCK588 pid={} contention=rejected", std::process::id());
    }

    fn missing_policy_prevents_store_startup() {
        let directory = stract::gen_temp_dir().unwrap();
        let mut config = config();
        config.crawler_policy_config_path = Some(directory.as_ref().join("missing-policy.toml"));
        config.v1.suppression_store_path = directory.as_ref().join("private/suppression.json");
        assert!(v1::V1Resources::load(&config).is_err());
        assert!(!config.v1.suppression_store_path.exists());
    }

    async fn listen(
        app: Router,
    ) -> (
        String,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (send, receive) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = receive.await;
                })
                .await
                .unwrap();
        });
        (base, send, task)
    }
    async fn network(response: reqwest::Response) -> Observed {
        let status = response.status().as_u16();
        let mut headers = HeaderMap::new();
        for (name, value) in response.headers() {
            headers.append(
                axum::http::HeaderName::from_bytes(name.as_str().as_bytes()).unwrap(),
                axum::http::HeaderValue::from_bytes(value.as_bytes()).unwrap(),
            );
        }
        let bytes = response.bytes().await.unwrap().to_vec();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Observed {
            status,
            headers,
            bytes,
            value,
        }
    }

    #[tokio::test]
    async fn management_is_isolated_and_delete_is_not_an_existence_oracle() {
        let fixture = persistent();
        let (state, _index) = real_state(&fixture).await;
        let (api, stop_api, api_task) = listen(public(state.clone())).await;
        let (admin, stop_admin, admin_task) = listen(management(state)).await;
        let client = reqwest::Client::new();
        let known = id("https://a.test/");
        let unknown = id_for_unknown();
        let response = network(
            client
                .delete(format!("{api}/v1/documents/{}", known.as_str()))
                .send()
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(fixture.hooks.writes.load(SeqCst), 0);
        work(&fixture.probe, 0, 0, 0);
        error(&response, "not_found", 404);
        for (count, id) in [(1, &known), (2, &unknown), (2, &known)] {
            let response = network(
                client
                    .delete(format!("{admin}/v1/documents/{}", id.as_str()))
                    .send()
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(fixture.hooks.writes.load(SeqCst), count);
            work(&fixture.probe, 0, 0, 0);
            ack(&response, id);
        }
        for path in ["/v1/documents", "/v1/documents/abc", "/v1/autosuggest"] {
            let response = network(client.get(format!("{api}{path}")).send().await.unwrap()).await;
            assert_eq!(fixture.hooks.writes.load(SeqCst), 2);
            work(&fixture.probe, 0, 0, 0);
            error(&response, "not_found", 404);
        }
        for (count, base) in [(1, &api), (2, &admin)] {
            let response = network(
                client
                    .get(format!("{base}/v1/source"))
                    .send()
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(fixture.hooks.writes.load(SeqCst), 2);
            work(&fixture.probe, 0, 0, count);
            contract(&response);
            assert_eq!(response.status, 200);
        }
        stop_api.send(()).unwrap();
        stop_admin.send(()).unwrap();
        api_task.await.unwrap();
        admin_task.await.unwrap();
        fixture.state.store().shutdown().await;
    }

    #[tokio::test]
    async fn store_size_is_bounded_before_decode_and_write() {
        const EXPECTED_CAP: usize = 16_777_216;
        let directory = stract::gen_temp_dir().unwrap();
        let path = private_path(&directory);
        let mut bytes = b"{\"format_version\":1,\"ids\":[]}".to_vec();
        bytes.resize(EXPECTED_CAP, b' ');
        write_private(&path, &bytes);
        let hooks = Arc::new(Hooks::default());
        let store = SuppressionStore::open_with_hooks(&path, hooks.clone()).unwrap();
        assert_eq!(hooks.decodes.load(SeqCst), 1);
        drop(store);
        bytes.push(b' ');
        write_private(&path, &bytes);
        hooks.decodes.store(0, SeqCst);
        let loaded = SuppressionStore::open_with_hooks(&path, hooks.clone());
        assert_eq!(
            hooks.decodes.load(SeqCst),
            0,
            "oversized data reached decoder"
        );
        assert!(loaded.is_err());
        drop(loaded);
        let count = (EXPECTED_CAP - 30) / 67;
        let ids = (0..count).map(|n| format!("{n:064x}")).collect::<Vec<_>>();
        let mut bytes = serde_json::to_vec(&json!({"format_version":1,"ids":ids})).unwrap();
        bytes.push(b'\n');
        assert!(bytes.len() <= EXPECTED_CAP);
        assert!(bytes.len() + 67 > EXPECTED_CAP);
        write_private(&path, &bytes);
        let store = Arc::new(SuppressionStore::open_with_hooks(&path, hooks.clone()).unwrap());
        hooks.writes.store(0, SeqCst);
        let resources = v1::V1Resources::with_store(&config(), store).unwrap();
        let probe = Arc::new(Probe::default());
        let backend = Arc::new(|_: SearchQuery| async { Ok(result(&[])) });
        let state =
            Arc::new(V1State::from_resources(&config(), backend, &resources).with_observer(probe));
        let new = DocumentId::parse(&"f".repeat(64)).unwrap();
        let response = delete(state.clone(), &new).await;
        assert_eq!(hooks.writes.load(SeqCst), 0);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(state.store().generation().await, 0);
        error(&response, "suppression_unavailable", 503);
        let repeat = DocumentId::parse(&"0".repeat(64)).unwrap();
        let response = delete(state.clone(), &repeat).await;
        assert_eq!(hooks.writes.load(SeqCst), 0);
        ack(&response, &repeat);
        state.store().shutdown().await;
    }

    async fn real_state(fixture: &Persistent) -> (Arc<V1State>, file_store::temp::TempDir) {
        let docs = [
            ("https://a.test/", "cedar", "cedar synthetic one"),
            ("https://b.test/", "cedar", "cedar synthetic two"),
            ("https://c.test/", "cedar", "cedar synthetic three"),
        ];
        let (searcher, directory) = super::query_index::searcher(&docs, true).await;
        let searcher = Arc::new(searcher);
        let backend = Arc::new(move |query: SearchQuery| {
            let searcher = searcher.clone();
            async move { searcher.search(&query).await }
        });
        let resources = v1::V1Resources::with_store(&config(), fixture.state.store()).unwrap();
        (
            Arc::new(
                V1State::from_resources(&config(), backend, &resources)
                    .with_observer(fixture.probe.clone()),
            ),
            directory,
        )
    }

    #[tokio::test]
    async fn suppressed_ids_never_enter_attributed_results() {
        let fixture = persistent();
        let (state, _index) = real_state(&fixture).await;
        let initial = observe(
            send(
                public(state.clone()),
                "POST",
                "/v1/search",
                r#"{"query":"cedar"}"#,
            )
            .await,
        )
        .await;
        work(&fixture.probe, 1, 1, 0);
        assert_eq!(fixture.probe.construction.load(SeqCst), 3);
        contract(&initial);
        let removed =
            DocumentId::parse(initial.value["results"][1]["id"].as_str().unwrap()).unwrap();
        let expected = initial.value["results"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|page| page["id"] != removed.as_str())
            .cloned()
            .collect::<Vec<_>>();
        let response = delete(state.clone(), &removed).await;
        assert_eq!(fixture.hooks.writes.load(SeqCst), 1);
        ack(&response, &removed);
        let mut calls = 1;
        for country in ["UK", "unknown", "non-UK"] {
            for adult in [false, true] {
                let before = fixture.probe.construction.load(SeqCst);
                let response = observe(
                    send(
                        public(state.clone()),
                        "POST",
                        "/v1/search",
                        json!({"query":"cedar","country":country,"adult_verified":adult})
                            .to_string(),
                    )
                    .await,
                )
                .await;
                calls += 1;
                work(&fixture.probe, calls, calls, 0);
                assert_eq!(fixture.probe.construction.load(SeqCst) - before, 2);
                contract(&response);
                assert_eq!(response.value["results"], json!(expected));
                assert_eq!(
                    response.value["has_more_results"],
                    initial.value["has_more_results"]
                );
                assert_eq!(response.value["num_results"], 20);
                assert_eq!(response.status, 200);
            }
        }
        fixture.state.store().shutdown().await;
    }

    #[tokio::test]
    async fn suppression_survives_store_restart() {
        let fixture = persistent();
        let removed = id("https://example.com/");
        let response = delete(fixture.state.clone(), &removed).await;
        assert_eq!(fixture.hooks.writes.load(SeqCst), 1);
        ack(&response, &removed);
        fixture.state.store().shutdown().await;
        let path = fixture.path.clone();
        drop(fixture.state);
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            bytes,
            format!(
                "{{\"format_version\":1,\"ids\":[\"{}\"]}}\n",
                removed.as_str()
            )
            .as_bytes()
        );
        let store = Arc::new(SuppressionStore::open(&path).unwrap());
        let resources = v1::V1Resources::with_store(&config(), store).unwrap();
        let probe = Arc::new(Probe::default());
        let backend = Arc::new(|_: SearchQuery| async {
            Ok(result(&["https://example.com/", "https://other.test/"]))
        });
        let state = Arc::new(
            V1State::from_resources(&config(), backend, &resources).with_observer(probe.clone()),
        );
        let response = observe(
            send(
                public(state),
                "POST",
                "/v1/search",
                r#"{"query":"compiler"}"#,
            )
            .await,
        )
        .await;
        work(&probe, 1, 1, 0);
        assert_eq!(probe.construction.load(SeqCst), 1);
        contract(&response);
        assert_eq!(response.value["results"][0]["url"], "https://other.test/");
        assert_eq!(response.status, 200);
        let fresh = persistent();
        let response = observe(
            send(
                public(fresh.state),
                "POST",
                "/v1/search",
                r#"{"query":"compiler"}"#,
            )
            .await,
        )
        .await;
        work(&fresh.probe, 1, 1, 0);
        contract(&response);
        assert_eq!(response.value["results"].as_array().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn delete_between_retrieval_and_assembly_suppresses_inflight_search() {
        let fixture = persistent();
        let removed = id("https://example.com/");
        let prior = observe(
            send(
                public(fixture.state.clone()),
                "POST",
                "/v1/search",
                r#"{"query":"compiler"}"#,
            )
            .await,
        )
        .await;
        work(&fixture.probe, 1, 1, 0);
        assert_eq!(fixture.probe.construction.load(SeqCst), 3);
        contract(&prior);
        fixture.probe.hold.store(true, SeqCst);
        let app = public(fixture.state.clone());
        let search = tokio::spawn(async move {
            send(app, "POST", "/v1/search", r#"{"query":"compiler"}"#).await
        });
        fixture.probe.reached.notified().await;
        assert_eq!(fixture.probe.backend.load(SeqCst), 2);
        assert_eq!(fixture.probe.construction.load(SeqCst), 3);
        let response = delete(fixture.state.clone(), &removed).await;
        assert_eq!(fixture.state.store().generation().await, 1);
        assert_eq!(fixture.hooks.writes.load(SeqCst), 1);
        ack(&response, &removed);
        fixture.probe.resume.notify_one();
        let response = observe(search.await.unwrap()).await;
        assert_eq!(fixture.probe.construction.load(SeqCst), 5);
        contract(&response);
        assert!(response.value["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|page| page["id"] != removed.as_str()));
        assert_eq!(response.status, 200);
        assert!(prior.value["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|page| page["id"] == removed.as_str()));
        fixture.state.store().shutdown().await;
    }
    fn work(probe: &Probe, decode: usize, backend: usize, source: usize) {
        assert_eq!(probe.decode.load(SeqCst), decode, "JSON decode boundary");
        assert_eq!(probe.backend.load(SeqCst), backend, "backend boundary");
        assert_eq!(probe.source.load(SeqCst), source, "source boundary");
    }
    fn error(response: &Observed, code: &str, status: u16) {
        contract(response);
        assert_eq!(response.value["error"]["code"], code);
        assert_eq!(response.status, status);
    }

    #[tokio::test]
    async fn successes_have_version_and_source_offer() {
        management_successes().await;
        let (state, probe) = fixture();
        let response = observe(
            send(
                v1::api_router(state.clone()),
                "POST",
                "/search",
                r#"{"query":"compiler"}"#,
            )
            .await,
        )
        .await;
        work(&probe, 1, 1, 0);
        contract(&response);
        assert_eq!(response.value.as_object().unwrap().len(), 5);
        assert_eq!(response.value["results"][0].as_object().unwrap().len(), 5);
        assert_eq!(
            response.value["results"][0]["id"],
            "0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7"
        );
        assert_eq!(response.status, 200);
        let response = observe(send(public(state), "GET", "/v1/source", Body::empty()).await).await;
        work(&probe, 1, 1, 1);
        contract(&response);
        let source = expected_source();
        for (field, expected) in [
            ("licence", "AGPL-3.0-only"),
            ("source_url", source.as_str()),
            ("revision", env!("AVA_SEARCH_REVISION")),
            ("revision_source", env!("AVA_SEARCH_REVISION_SOURCE")),
        ] {
            assert_eq!(response.value[field], expected);
        }
        assert_eq!(response.status, 200);
    }

    async fn typed_error_case(failure: V1Error, code: Value, message: String, status: u16) {
        let entered = Arc::new(AtomicUsize::new(0));
        let inside = entered.clone();
        let routes = Router::new().route(
            "/case",
            get(move || {
                let failure = failure.clone();
                inside.fetch_add(1, SeqCst);
                async move { failure }
            }),
        );
        let response = observe(
            send(
                v1::finish_v1_router(routes, &config().v1),
                "GET",
                "/case",
                Body::empty(),
            )
            .await,
        )
        .await;
        assert_eq!(entered.load(SeqCst), 1);
        contract(&response);
        assert_eq!(response.value["error"]["code"], code);
        assert_eq!(response.value["error"]["message"], message);
        assert!(!response.bytes.windows(6).any(|part| part == b"SECRET"));
        assert_eq!(response.status, status);
    }

    #[tokio::test]
    async fn every_error_code_has_its_status_and_safe_message() {
        use stract::{query::planner::bounds::InputError::*, searcher::wire::QueryServiceError};
        for input in [
            InvalidRequest,
            RequestTooLarge,
            EmptyQuery,
            QueryTooLong,
            TooManyTerms,
            TermTooLong,
            PhraseTooLong,
            EmptyPhrase,
            InvalidQuotes,
            InvalidOperator,
            InvalidQuerySyntax,
            TooManyOperators,
            NoSearchableTerms,
            ForbiddenCharacter,
            ExcessiveRepetition,
            InvalidResultCount,
            InvalidPage,
            PlanTooComplex,
            PreferencesTooLarge,
        ] {
            typed_error_case(
                V1Error::input(input),
                serde_json::to_value(input).unwrap(),
                input.to_string(),
                if input == RequestTooLarge { 413 } else { 400 },
            )
            .await;
        }
        use QueryServiceError::*;
        for service in [
            NoShards,
            TooManyShards,
            BudgetExhausted,
            ProtocolUnavailable,
            InvalidPlan,
            SchemaMismatch,
            ShardFailed,
            RetrievalFailed,
            WorkerFailed,
        ] {
            typed_error_case(
                V1Error::service(service),
                serde_json::to_value(service).unwrap(),
                service.to_string(),
                503,
            )
            .await;
        }
        local_error_codes().await;
        positive_search_and_source().await;
    }

    async fn positive_search_and_source() {
        let (state, probe) = fixture();
        let app = public(state);
        let source = observe(send(app.clone(), "GET", "/v1/source", Body::empty()).await).await;
        work(&probe, 0, 0, 1);
        contract(&source);
        assert_eq!(source.status, 200);
        let search =
            observe(send(app, "POST", "/v1/search", r#"{"query":"compiler"}"#).await).await;
        work(&probe, 1, 1, 1);
        contract(&search);
        assert_eq!(search.value["results"].as_array().unwrap().len(), 2);
        assert_eq!(search.status, 200);
    }

    async fn local_error_codes() {
        use V1Failure::*;
        for (failure, code, message, status) in [
            (
                InvalidDocumentId,
                "invalid_document_id",
                "The document identifier is invalid",
                400,
            ),
            (NotFound, "not_found", "The route was not found", 404),
            (
                NoBangTarget,
                "no_bang_target",
                "No bang target was found",
                404,
            ),
            (
                MethodNotAllowed,
                "method_not_allowed",
                "The method is not allowed",
                405,
            ),
            (
                UnsupportedMediaType,
                "unsupported_media_type",
                "The request content type is unsupported",
                415,
            ),
            (
                InternalError,
                "internal_error",
                "The request could not be completed",
                500,
            ),
            (
                InvalidResult,
                "invalid_result",
                "The search result is invalid",
                500,
            ),
            (Overloaded, "overloaded", "The service is busy", 503),
            (
                SuppressionUnavailable,
                "suppression_unavailable",
                "The suppression store is unavailable",
                503,
            ),
            (
                RequestTimeout,
                "request_timeout",
                "The request timed out",
                504,
            ),
        ] {
            typed_error_case(
                V1Error::failure(failure),
                json!(code),
                message.into(),
                status,
            )
            .await;
        }
        typed_error_case(
            V1Error::from_error(anyhow::anyhow!("SECRET path/query/peer")),
            json!("internal_error"),
            "The request could not be completed".into(),
            500,
        )
        .await;
    }

    #[tokio::test]
    async fn panic_and_bare_status_are_versioned_errors() {
        for status in [200, 302, 400, 404, 405, 413, 415, 500, 503, 504] {
            let entered = Arc::new(AtomicUsize::new(0));
            let inside = entered.clone();
            let routes = Router::new().route(
                "/case",
                get(move || {
                    inside.fetch_add(1, SeqCst);
                    async move {
                        (
                            axum::http::StatusCode::from_u16(status).unwrap(),
                            [
                                ("location", "SECRET"),
                                ("allow", "GET"),
                                ("source-offer", "SECRET"),
                            ],
                            "SECRET",
                        )
                            .into_response()
                    }
                }),
            );
            let response = observe(
                send(
                    v1::finish_v1_router(routes, &config().v1),
                    "GET",
                    "/case",
                    Body::empty(),
                )
                .await,
            )
            .await;
            assert_eq!(entered.load(SeqCst), 1);
            contract(&response);
            assert!(!String::from_utf8_lossy(&response.bytes).contains("SECRET"));
            assert!(response.headers.get("location").is_none());
            let (code, expected) = match status {
                400 => ("invalid_request", 400),
                404 => ("not_found", 404),
                405 => ("method_not_allowed", 405),
                413 => ("request_too_large", 413),
                415 => ("unsupported_media_type", 415),
                504 => ("request_timeout", 504),
                _ => ("internal_error", 500),
            };
            error(&response, code, expected);
            if status == 405 {
                assert_eq!(response.headers["allow"], "GET");
            }
        }
        let calls = Arc::new(AtomicUsize::new(0));
        for middleware_panic in [false, true] {
            let inside = calls.clone();
            let mut routes = Router::new().route("/panic", get(move || { inside.fetch_add(1, SeqCst); async move { panic!("SECRET handler"); #[allow(unreachable_code, reason = "Fixture deliberately unwinds before producing its typed response")] axum::http::StatusCode::OK } }));
            if middleware_panic {
                routes = routes.layer(axum::middleware::from_fn(
                    |_: axum::extract::Request, _: axum::middleware::Next| async {
                        panic!("SECRET middleware");
                        #[allow(
                            unreachable_code,
                            reason = "Fixture deliberately unwinds inside pre-handler middleware"
                        )]
                        axum::http::StatusCode::OK.into_response()
                    },
                ));
            }
            let response = observe(
                send(
                    v1::finish_v1_router(routes, &config().v1),
                    "GET",
                    "/panic",
                    Body::empty(),
                )
                .await,
            )
            .await;
            assert_eq!(calls.load(SeqCst), 1);
            error(&response, "internal_error", 500);
        }
        let probe = Arc::new(Probe::default());
        let backend = Arc::new(|_: SearchQuery| async {
            panic!("SECRET production adapter");
            #[allow(
                unreachable_code,
                reason = "Panic-only adapter has the same result type as production"
            )]
            Ok(result(&[]))
        });
        let app = public(state(&config(), probe.clone(), backend));
        let response =
            observe(send(app, "POST", "/v1/search", r#"{"query":"compiler"}"#).await).await;
        work(&probe, 1, 1, 0);
        error(&response, "internal_error", 500);
        positive_search_and_source().await;
    }

    #[tokio::test]
    async fn fallbacks_methods_and_head_keep_contract_headers() {
        management_fallbacks().await;
        let (state, probe) = fixture();
        let app = public(state);
        for (method, path, code, status) in [
            ("GET", "/v1", "not_found", 404),
            ("GET", "/v1/", "not_found", 404),
            ("GET", "/v1/missing", "not_found", 404),
            ("GET", "/v1/autosuggest", "not_found", 404),
            ("GET", "/v1/search", "method_not_allowed", 405),
            ("OPTIONS", "/v1/source", "method_not_allowed", 405),
            ("POST", "/v1/source", "method_not_allowed", 405),
            ("DELETE", "/v1/documents/abc", "not_found", 404),
        ] {
            let response = observe(send(app.clone(), method, path, Body::empty()).await).await;
            work(&probe, 0, 0, 0);
            assert!(
                response.headers.contains_key("source-offer"),
                "{method} {path}"
            );
            error(&response, code, status);
        }
        let head = observe(send(app.clone(), "HEAD", "/v1/source", Body::empty()).await).await;
        work(&probe, 0, 0, 0);
        assert!(head.bytes.is_empty());
        assert_eq!(head.headers.get_all("source-offer").iter().count(), 1);
        assert_eq!(head.headers["source-offer"], expected_source());
        assert_eq!(head.headers["x-api-version"], "v1");
        assert_eq!(head.status, 405);
        for (method, path) in [("POST", "/v1/source"), ("DELETE", "/v1/search")] {
            let response = observe(send(app.clone(), method, path, "x").await).await;
            work(&probe, 0, 0, 0);
            error(&response, "method_not_allowed", 405);
        }
        let legacy = observe(send(app.clone(), "GET", "/beta/api/nope", Body::empty()).await).await;
        work(&probe, 0, 0, 0);
        assert!(legacy.bytes.is_empty());
        assert!(legacy.headers.get("x-api-version").is_none());
        assert_eq!(legacy.status, 404);
        let source = observe(send(app, "GET", "/v1/source", Body::empty()).await).await;
        work(&probe, 0, 0, 1);
        contract(&source);
        assert_eq!(source.status, 200);
    }

    fn stream(chunks: Vec<Vec<u8>>, polls: Arc<AtomicUsize>) -> Body {
        let mut chunks = std::collections::VecDeque::from(chunks);
        Body::from_stream(futures::stream::poll_fn(move |_| {
            polls.fetch_add(1, SeqCst);
            std::task::Poll::Ready(chunks.pop_front().map(Ok::<_, std::io::Error>))
        }))
    }

    async fn management_successes() {
        let fixture = persistent();
        let removed = id_for_unknown();
        let response = delete(fixture.state.clone(), &removed).await;
        assert_eq!(fixture.hooks.writes.load(SeqCst), 1);
        work(&fixture.probe, 0, 0, 0);
        ack(&response, &removed);
        let inner = management(fixture.state.clone()).layer(axum::middleware::map_response(
            |mut response: Response| async {
                response
                    .headers_mut()
                    .insert("source-offer", "conflicting-inner-offer".parse().unwrap());
                response
            },
        ));
        let response = observe(
            send(
                v1::finish_v1_router(inner, &config().v1),
                "GET",
                "/v1/source",
                Body::empty(),
            )
            .await,
        )
        .await;
        assert_eq!(fixture.hooks.writes.load(SeqCst), 1);
        work(&fixture.probe, 0, 0, 1);
        contract(&response);
        assert_eq!(response.status, 200);
    }
    async fn management_fallbacks() {
        let fixture = persistent();
        let app = management(fixture.state.clone());
        for (method, path, code, status) in [
            ("GET", "/v1", "not_found", 404),
            ("GET", "/v1/", "not_found", 404),
            ("GET", "/v1/missing", "not_found", 404),
            ("POST", "/v1/search", "not_found", 404),
            ("OPTIONS", "/v1/source", "method_not_allowed", 405),
        ] {
            let response = observe(send(app.clone(), method, path, Body::empty()).await).await;
            assert_eq!(fixture.hooks.writes.load(SeqCst), 0);
            work(&fixture.probe, 0, 0, 0);
            error(&response, code, status);
        }
        let source = observe(send(app, "GET", "/v1/source", Body::empty()).await).await;
        assert_eq!(fixture.hooks.writes.load(SeqCst), 0);
        work(&fixture.probe, 0, 0, 1);
        contract(&source);
        assert_eq!(source.status, 200);
    }
    async fn management_body_cap() {
        let fixture = persistent();
        let app = management(fixture.state.clone());
        let removed = id_for_unknown();
        let path = format!("/v1/documents/{}", removed.as_str());
        for (method, path) in [
            ("DELETE", path.as_str()),
            ("GET", "/v1/source"),
            ("POST", "/v1/missing"),
            ("GET", path.as_str()),
        ] {
            let polls = Arc::new(AtomicUsize::new(0));
            let response = observe(
                send(
                    app.clone(),
                    method,
                    path,
                    stream(
                        vec![vec![b' '; 32_768], vec![b' '; 32_769], vec![b'!']],
                        polls.clone(),
                    ),
                )
                .await,
            )
            .await;
            assert_eq!(polls.load(SeqCst), 2);
            assert_eq!(fixture.hooks.writes.load(SeqCst), 0);
            work(&fixture.probe, 0, 0, 0);
            error(&response, "request_too_large", 413);
        }
        let response = delete(fixture.state.clone(), &removed).await;
        assert_eq!(fixture.hooks.writes.load(SeqCst), 1);
        ack(&response, &removed);
    }
    async fn management_request_shapes() {
        let fixture = persistent();
        let app = management(fixture.state.clone());
        for raw in [
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
            format!("%61{}", "a".repeat(63)),
            "%2e%2e".into(),
        ] {
            let response = observe(
                send(
                    app.clone(),
                    "DELETE",
                    &format!("/v1/documents/{raw}"),
                    Body::empty(),
                )
                .await,
            )
            .await;
            assert_eq!(fixture.hooks.writes.load(SeqCst), 0);
            assert_eq!(fixture.probe.deletes.load(SeqCst), 0);
            work(&fixture.probe, 0, 0, 0);
            error(&response, "invalid_document_id", 400);
        }
        let removed = id_for_unknown();
        let path = format!("/v1/documents/{}", removed.as_str());
        for (method, path) in [("DELETE", path.as_str()), ("GET", "/v1/source")] {
            for body in ["x", "larger"] {
                let response = observe(send(app.clone(), method, path, body).await).await;
                assert_eq!(fixture.hooks.writes.load(SeqCst), 0);
                assert_eq!(fixture.probe.deletes.load(SeqCst), 0);
                work(&fixture.probe, 0, 0, 0);
                error(&response, "invalid_request", 400);
            }
            let response =
                observe(send(app.clone(), method, &format!("{path}?x=1"), Body::empty()).await)
                    .await;
            assert_eq!(fixture.hooks.writes.load(SeqCst), 0);
            assert_eq!(fixture.probe.deletes.load(SeqCst), 0);
            work(&fixture.probe, 0, 0, 0);
            error(&response, "invalid_request", 400);
        }
        let response =
            observe(send(app, "DELETE", &format!("{path}/extra"), Body::empty()).await).await;
        assert_eq!(fixture.hooks.writes.load(SeqCst), 0);
        assert_eq!(fixture.probe.deletes.load(SeqCst), 0);
        work(&fixture.probe, 0, 0, 0);
        error(&response, "not_found", 404);
        let response = delete(fixture.state.clone(), &removed).await;
        assert_eq!(fixture.hooks.writes.load(SeqCst), 1);
        ack(&response, &removed);
        let (state, probe) = fixture_with(&config());
        let mut req = request("POST", "/v1/search", r#"{"query":"compiler"}"#);
        req.headers_mut().remove("content-type");
        let response = observe(public(state).oneshot(req).await.unwrap()).await;
        work(&probe, 0, 0, 0);
        error(&response, "unsupported_media_type", 415);
    }

    #[tokio::test]
    async fn chunked_body_cap_precedes_parse_and_work_on_every_route() {
        management_body_cap().await;
        let (state, probe) = fixture();
        let app = public(state);
        let base = r#"{"query":"compiler"}"#;
        let exact = format!("{base}{}", " ".repeat(65_536 - base.len()));
        let valid = observe(send(app.clone(), "POST", "/v1/search", exact.clone()).await).await;
        work(&probe, 1, 1, 0);
        contract(&valid);
        assert_eq!(valid.status, 200);
        for (method, path) in [
            ("POST", "/v1/search"),
            ("GET", "/v1/source"),
            ("DELETE", "/v1/documents/abc"),
            ("POST", "/v1/missing"),
            ("GET", "/v1/search"),
        ] {
            let polls = Arc::new(AtomicUsize::new(0));
            let body = stream(
                vec![vec![b' '; 32_768], vec![b' '; 32_769], vec![b'!']],
                polls.clone(),
            );
            let mut req = request(method, path, body);
            req.headers_mut()
                .insert("content-length", "1".parse().unwrap());
            let response = observe(app.clone().oneshot(req).await.unwrap()).await;
            assert_eq!(polls.load(SeqCst), 2, "overflow must stop before sentinel");
            work(&probe, 1, 1, 0);
            error(&response, "request_too_large", 413);
        }
        let response = observe(send(app.clone(), "POST", "/v1/search", exact + " ").await).await;
        work(&probe, 1, 1, 0);
        error(&response, "request_too_large", 413);
        let response = observe(send(app, "GET", "/v1/source", Body::empty()).await).await;
        work(&probe, 1, 1, 1);
        contract(&response);
        assert_eq!(response.status, 200);
    }

    async fn query_case(query: String, code: Option<&str>) {
        let (state, probe) = fixture();
        let response = observe(
            send(
                public(state),
                "POST",
                "/v1/search",
                json!({"query":query}).to_string(),
            )
            .await,
        )
        .await;
        work(&probe, 1, usize::from(code.is_none()), 0);
        if let Some(code) = code {
            error(&response, code, 400);
        } else {
            contract(&response);
            assert_eq!(response.status, 200);
        }
    }
    fn words(prefix: &str, count: usize) -> String {
        (0..count)
            .map(|i| format!("{prefix}{i}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[tokio::test]
    async fn query_bounds_precede_backend_work() {
        let bytes = format!(
            "{} {} {} {}",
            "a".repeat(1024),
            "b".repeat(1023),
            "c".repeat(1023),
            "d".repeat(1023)
        );
        assert_eq!(bytes.len(), 4096);
        query_case(bytes.clone(), None).await;
        query_case(bytes + "z", Some("query_too_long")).await;
        for (good, bad, code) in [
            (words("term", 32), words("term", 33), "too_many_terms"),
            ("å".repeat(1024), "å".repeat(1025), "term_too_long"),
            (
                format!("\"{}\"", words("term", 32)),
                format!("\"{}\"", words("term", 33)),
                "phrase_too_long",
            ),
            (
                format!("compiler {}", words("site:host", 8)),
                format!("compiler {}", words("site:host", 9)),
                "too_many_operators",
            ),
            (
                ["word"; 8].join(" "),
                ["word"; 9].join(" "),
                "excessive_repetition",
            ),
        ] {
            query_case(good, None).await;
            query_case(bad, Some(code)).await;
        }
        for (query, code) in [
            ("", "empty_query"),
            (" ", "empty_query"),
            ("\t", "forbidden_character"),
            ("compiler\u{200b}", "forbidden_character"),
            ("\"compiler", "invalid_quotes"),
            ("\"\"", "empty_phrase"),
            ("site:", "invalid_operator"),
            ("!docs compiler", "invalid_query_syntax"),
        ] {
            query_case(query.into(), Some(code)).await;
        }
    }

    #[tokio::test]
    async fn result_counts_zero_and_101_are_rejected_before_work() {
        for count in [0, 101, 300, 1, 20, 100] {
            let (state, probe) = fixture();
            let good = (1..=100).contains(&count);
            let response = observe(
                send(
                    public(state),
                    "POST",
                    "/v1/search",
                    json!({"query":"compiler","num_results":count}).to_string(),
                )
                .await,
            )
            .await;
            work(&probe, 1, usize::from(good), 0);
            if good {
                contract(&response);
                assert_eq!(response.value["num_results"], count);
                assert_eq!(response.status, 200);
            } else {
                error(&response, "invalid_result_count", 400);
            }
        }
        let (state, probe) = fixture();
        let response = observe(
            send(
                public(state),
                "POST",
                "/v1/search",
                r#"{"query":"compiler"}"#,
            )
            .await,
        )
        .await;
        work(&probe, 1, 1, 0);
        contract(&response);
        assert_eq!(response.value["num_results"], 20);
        assert_eq!(response.status, 200);
    }

    #[tokio::test]
    async fn page_depth_and_overflow_are_rejected_before_work() {
        let (state, probe) = fixture();
        let response = observe(
            send(
                public(state),
                "POST",
                "/v1/search",
                json!({"query":"compiler", "page":u64::MAX, "num_results":2}).to_string(),
            )
            .await,
        )
        .await;
        work(&probe, 1, 0, 0);
        error(&response, "invalid_page", 400);
        for page in [0, 99, 100, u64::MAX, u64::MAX / 100 + 1] {
            let (state, probe) = fixture();
            let good = page <= 99;
            let response = observe(
                send(
                    public(state),
                    "POST",
                    "/v1/search",
                    json!({"query":"compiler","num_results":100,"page":page}).to_string(),
                )
                .await,
            )
            .await;
            work(&probe, 1, usize::from(good), 0);
            if good {
                contract(&response);
                assert_eq!(response.value["page"], page);
                assert_eq!(response.status, 200);
            } else {
                error(&response, "invalid_page", 400);
            }
        }
        use stract::query::planner::bounds::{validate_numbers, InputError};
        assert_eq!(
            validate_numbers(usize::MAX, 2, true),
            Err(InputError::InvalidPage)
        );
        assert_eq!(
            validate_numbers(usize::MAX / 2, 2, true),
            Err(InputError::InvalidPage)
        );
        assert_eq!(validate_numbers(99, 100, true), Ok(9900));
    }

    struct DropCount(Arc<AtomicUsize>);
    impl Drop for DropCount {
        fn drop(&mut self) {
            self.0.fetch_add(1, SeqCst);
        }
    }
    async fn watchdog(future: impl std::future::Future<Output = Response>) -> Response {
        tokio::time::timeout(std::time::Duration::from_secs(2), future)
            .await
            .expect("v1 deadline did not fire within the named witness watchdog")
    }

    #[tokio::test]
    async fn timeout_covers_body_search_and_source_without_leaking_permits() {
        durable_timeout(StoreStage::Write, false).await;
        let mut config = config();
        config.v1.request_timeout_ms = 25;
        config.v1.max_concurrent_requests = Some(1);
        let probe = Arc::new(Probe::default());
        let dropped = Arc::new(AtomicUsize::new(0));
        let inside = dropped.clone();
        let backend = Arc::new(move |_: SearchQuery| {
            let guard = DropCount(inside.clone());
            async move {
                let _guard = guard;
                std::future::pending().await
            }
        });
        let app = public(state(&config, probe.clone(), backend));
        let response = observe(
            watchdog(send(
                app.clone(),
                "POST",
                "/v1/search",
                r#"{"query":"compiler"}"#,
            ))
            .await,
        )
        .await;
        work(&probe, 1, 1, 0);
        assert_eq!(dropped.load(SeqCst), 1);
        error(&response, "request_timeout", 504);
        let response = observe(send(app.clone(), "GET", "/v1/source", Body::empty()).await).await;
        work(&probe, 1, 1, 1);
        contract(&response);
        assert_eq!(response.status, 200);
        let polls = Arc::new(AtomicUsize::new(0));
        let inside = polls.clone();
        let body = Body::from_stream(futures::stream::poll_fn(move |_| {
            inside.fetch_add(1, SeqCst);
            std::task::Poll::<Option<Result<Vec<u8>, std::io::Error>>>::Pending
        }));
        let response = observe(watchdog(send(app.clone(), "POST", "/v1/search", body)).await).await;
        assert!(polls.load(SeqCst) > 0);
        work(&probe, 1, 1, 1);
        error(&response, "request_timeout", 504);
        let response = observe(send(app, "GET", "/v1/source", Body::empty()).await).await;
        work(&probe, 1, 1, 2);
        contract(&response);
        assert_eq!(response.status, 200);
        let entered = Arc::new(AtomicUsize::new(0));
        let inside = entered.clone();
        let slow = Router::new().route(
            "/source",
            get(move || {
                inside.fetch_add(1, SeqCst);
                async { std::future::pending::<Response>().await }
            }),
        );
        let response = observe(
            watchdog(send(
                v1::finish_v1_router(slow, &config.v1),
                "GET",
                "/source",
                Body::empty(),
            ))
            .await,
        )
        .await;
        assert_eq!(entered.load(SeqCst), 1);
        error(&response, "request_timeout", 504);
    }

    #[tokio::test]
    async fn concurrency_rejects_before_polling_body_or_starting_work() {
        durable_timeout(StoreStage::SyncDirectory, false).await;
        let mut config = config();
        config.v1.max_concurrent_requests = Some(1);
        let probe = Arc::new(Probe::default());
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let (inside, resume) = (entered.clone(), release.clone());
        let backend = Arc::new(move |_: SearchQuery| {
            let (inside, resume) = (inside.clone(), resume.clone());
            async move {
                inside.notify_one();
                resume.notified().await;
                Ok(result(&[]))
            }
        });
        let panic_calls = Arc::new(AtomicUsize::new(0));
        let calls = panic_calls.clone();
        let routes = Router::new()
            .route("/search", axum::routing::post(v1::search::route))
            .route("/source", get(v1::source::route))
            .route(
                "/panic",
                get(move || {
                    calls.fetch_add(1, SeqCst);
                    permit_panic()
                }),
            )
            .with_state(state(&config, probe.clone(), backend));
        let app = Router::new().nest("/v1", v1::finish_v1_router(routes, &config.v1));
        let first_app = app.clone();
        let first = tokio::spawn(async move {
            send(first_app, "POST", "/v1/search", r#"{"query":"compiler"}"#).await
        });
        entered.notified().await;
        for (method, path) in [("POST", "/v1/search"), ("GET", "/v1/source")] {
            let polls = Arc::new(AtomicUsize::new(0));
            let response = observe(
                send(
                    app.clone(),
                    method,
                    path,
                    stream(vec![vec![b'x']], polls.clone()),
                )
                .await,
            )
            .await;
            assert_eq!(polls.load(SeqCst), 0);
            work(&probe, 1, 1, 0);
            error(&response, "overloaded", 503);
        }
        release.notify_one();
        let response = observe(first.await.unwrap()).await;
        work(&probe, 1, 1, 0);
        contract(&response);
        assert_eq!(response.status, 200);
        let polls = Arc::new(AtomicUsize::new(0));
        let response = observe(
            send(
                app.clone(),
                "GET",
                "/v1/panic",
                stream(vec![], polls.clone()),
            )
            .await,
        )
        .await;
        assert_eq!(polls.load(SeqCst), 1);
        assert_eq!(panic_calls.load(SeqCst), 1);
        work(&probe, 1, 1, 0);
        error(&response, "internal_error", 500);
        let response =
            observe(send(app, "GET", "/v1/source", stream(vec![], polls.clone())).await).await;
        assert_eq!(polls.load(SeqCst), 2);
        assert_eq!(panic_calls.load(SeqCst), 1);
        work(&probe, 1, 1, 1);
        contract(&response);
        assert_eq!(response.status, 200);
    }

    async fn permit_panic() -> Response {
        panic!("fixture handler unwinds while holding the only admission permit");
    }

    async fn content_encoding_values_reject_before_body() {
        let fixture = persistent();
        let app = public(fixture.state.clone());
        let admin = management(fixture.state.clone());
        let path = format!("/v1/documents/{}", id_for_unknown().as_str());
        for values in [
            ["identity", "gzip"],
            ["gzip", "identity"],
            ["identity", "identity"],
        ] {
            for (router, method, path) in [
                (app.clone(), "POST", "/v1/search"),
                (admin.clone(), "DELETE", path.as_str()),
            ] {
                let polls = Arc::new(AtomicUsize::new(0));
                let body = stream(vec![br#"{"query":"compiler"}"#.to_vec()], polls.clone());
                let mut req = request(method, path, body);
                for value in values {
                    req.headers_mut()
                        .append("content-encoding", value.parse().unwrap());
                }
                let response = observe(router.oneshot(req).await.unwrap()).await;
                assert_eq!(polls.load(SeqCst), 0, "{values:?} {method} {path}");
                assert_eq!(fixture.probe.deletes.load(SeqCst), 0);
                assert_eq!(fixture.hooks.writes.load(SeqCst), 0);
                work(&fixture.probe, 0, 0, 0);
                error(&response, "unsupported_media_type", 415);
            }
        }
        for (index, value) in ["identity", "IdEnTiTy"].into_iter().enumerate() {
            let polls = Arc::new(AtomicUsize::new(0));
            let body = stream(vec![br#"{"query":"compiler"}"#.to_vec()], polls.clone());
            let mut req = request("POST", "/v1/search", body);
            req.headers_mut()
                .insert("content-encoding", value.parse().unwrap());
            let response = observe(app.clone().oneshot(req).await.unwrap()).await;
            assert_eq!(polls.load(SeqCst), 2);
            assert_eq!(fixture.probe.deletes.load(SeqCst), 0);
            assert_eq!(fixture.hooks.writes.load(SeqCst), 0);
            work(&fixture.probe, index + 1, index + 1, 0);
            contract(&response);
            assert_eq!(response.status, 200);
        }
    }

    #[tokio::test]
    async fn request_shape_and_document_ids_reject_before_work() {
        management_request_shapes().await;
        content_encoding_values_reject_before_body().await;
        for body in [
            "{",
            r#"{"query":4}"#,
            r#"{"query":"compiler","query":"other"}"#,
            r#"{"Query":"compiler"}"#,
            r#"{"query":"compiler","optic":"x"}"#,
            r#"{"query":"compiler","page":null}"#,
            r#"{"query":"compiler","num_results":null}"#,
            r#"{"query":"compiler","country":null}"#,
            r#"{"query":"compiler","country":"uk"}"#,
            r#"{"query":"compiler","num_results":-1}"#,
            r#"{"query":"compiler","num_results":1.1}"#,
            r#"{"query":"compiler","page":18446744073709551616}"#,
        ] {
            let (state, probe) = fixture();
            let response = observe(send(public(state), "POST", "/v1/search", body).await).await;
            work(&probe, 1, 0, 0);
            error(&response, "invalid_request", 400);
        }
        for (header, value) in [
            ("content-type", "text/plain"),
            ("content-type", ""),
            ("content-encoding", "gzip"),
        ] {
            let (state, probe) = fixture();
            let mut req = request("POST", "/v1/search", r#"{"query":"compiler"}"#);
            req.headers_mut().insert(
                axum::http::HeaderName::from_bytes(header.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
            let response = observe(public(state).oneshot(req).await.unwrap()).await;
            work(&probe, 0, 0, 0);
            error(&response, "unsupported_media_type", 415);
        }
        for path in ["/v1/search?", "/v1/source?x=1", "/v1/missing?"] {
            let (state, probe) = fixture();
            let response = observe(send(public(state), "POST", path, Body::empty()).await).await;
            work(&probe, 0, 0, 0);
            error(&response, "invalid_request", 400);
        }
        for body in ["x", "larger"] {
            let (state, probe) = fixture();
            let response = observe(send(public(state), "GET", "/v1/source", body).await).await;
            work(&probe, 0, 0, 0);
            error(&response, "invalid_request", 400);
        }
        let (state, probe) = fixture();
        let response = observe(
            send(
                public(state),
                "POST",
                "/v1/search",
                r#"{"query":"compiler","adult_verified":null}"#,
            )
            .await,
        )
        .await;
        work(&probe, 1, 1, 0);
        contract(&response);
        assert_eq!(response.status, 200);
    }

    #[tokio::test]
    async fn uk_unknown_and_adult_defaults_reach_the_suppression_seam() {
        let (state, probe) = fixture();
        let removed = id("https://example.com/");
        ack(&delete(state.clone(), &removed).await, &removed);
        let app = public(state);
        let mut calls = 0;
        for country in [None, Some("UK"), Some("unknown"), Some("non-UK")] {
            for adult in [
                None,
                Some(Value::Null),
                Some(json!(false)),
                Some(json!(true)),
            ] {
                let mut request = json!({"query":"compiler"});
                if let Some(country) = country {
                    request["country"] = json!(country);
                }
                if let Some(adult) = &adult {
                    request["adult_verified"] = adult.clone();
                }
                let response =
                    observe(send(app.clone(), "POST", "/v1/search", request.to_string()).await)
                        .await;
                calls += 1;
                work(&probe, calls, calls, 0);
                assert_eq!(probe.construction.load(SeqCst), calls);
                assert!(response.value["results"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|page| page["id"] != removed.as_str()));
                let expected = ServingContext {
                    country: match country {
                        Some("UK") => Country::Uk,
                        Some("non-UK") => Country::NonUk,
                        _ => Country::Unknown,
                    },
                    uk_measures: true,
                    is_child: adult != Some(json!(true)),
                };
                assert_eq!(probe.contexts.lock().unwrap().last().unwrap().1, expected);
                contract(&response);
                assert!(!response.value["results"].as_array().unwrap().is_empty());
                assert_eq!(response.status, 200);
            }
        }
    }

    fn legacy_projection(value: &mut Value) {
        match value {
            Value::Object(map) => {
                map.remove("searchDurationMs");
                map.remove("elapsedMs");
                map.remove("rankingSignals");
                if let Some(Value::Object(snippet)) = map.get_mut("snippet") {
                    snippet.remove("date");
                }
                for child in map.values_mut() {
                    legacy_projection(child);
                }
            }
            Value::Array(items) => {
                for item in items {
                    legacy_projection(item);
                }
            }
            _ => {}
        }
    }
    async fn legacy_result(request: stract::api::search::ValidatedSearchRequest) -> Response {
        assert_eq!(request.query.query, "compiler");
        assert_eq!(request.query.num_results, 2);
        let result = result(&["https://e.test/a", "https://e.test/b"]);
        if request.flatten_result {
            axum::Json(stract::api::search::ApiSearchResult::from(result)).into_response()
        } else {
            axum::Json(result).into_response()
        }
    }
    #[tokio::test]
    async fn beta_search_fixture_is_unchanged_from_base() {
        let app = Router::new().route("/beta/api/search", axum::routing::post(legacy_result));
        let mut projections = serde_json::Map::new();
        let mut statuses = Vec::new();
        for (name, flattened) in [("tagged", false), ("flattened", true)] {
            let response = observe(
                send(
                    app.clone(),
                    "POST",
                    "/beta/api/search",
                    json!({"query":"compiler","numResults":2,"flattenResponse":flattened})
                        .to_string(),
                )
                .await,
            )
            .await;
            let mut value = response.value;
            legacy_projection(&mut value);
            assert!(value.get("version").is_none());
            assert!(!serde_json::to_string(&value).unwrap().contains("\"id\":"));
            statuses.push(response.status);
            projections.insert(name.into(), value);
        }
        assert_eq!(
            serde_json::to_vec(&projections).unwrap(),
            include_bytes!("fixtures/api_v1/beta-search.json")
        );
        assert_eq!(statuses, [200, 200]);
    }

    #[tokio::test]
    async fn serving_policy_is_loaded_and_validated_before_listening() {
        let directory = stract::gen_temp_dir().unwrap();
        let path = directory.as_ref().join("policy.toml");
        let template = stract::crawler::policy::template().unwrap();
        let text = toml::to_string(template.get()).unwrap();
        std::fs::write(&path, &text).unwrap();
        let loaded = stract::config::ingestion::IngestionPolicy::load(&path).unwrap();
        assert_eq!(
            serde_json::to_value(&loaded.get().exclusions.serving).unwrap(),
            serde_json::to_value(&template.get().exclusions.serving).unwrap()
        );
        let mut config = config();
        config.crawler_policy_config_path = Some(path.clone());
        let (state, probe) = fixture_with(&config);
        let response = observe(
            send(
                public(state),
                "POST",
                "/v1/search",
                r#"{"query":"compiler"}"#,
            )
            .await,
        )
        .await;
        work(&probe, 1, 1, 0);
        assert!(probe
            .contexts
            .lock()
            .unwrap()
            .iter()
            .all(|(_, ctx)| ctx.uk_measures && ctx.is_child));
        contract(&response);
        assert_eq!(response.status, 200);
        for (old, new) in [
            (
                "uk_or_unknown_measures = true",
                "uk_or_unknown_measures = false",
            ),
            (
                "missing_adult_is_child = true",
                "missing_adult_is_child = false",
            ),
            (
                "non_uk_policy = \"same-as-uk\"",
                "non_uk_policy = \"other\"",
            ),
        ] {
            assert!(text.contains(old));
            std::fs::write(&path, text.replace(old, new)).unwrap();
            assert!(V1State::initialize(
                &config,
                Arc::new(|_: SearchQuery| async { Ok(result(&[])) })
            )
            .is_err());
        }
        std::fs::remove_file(&path).unwrap();
        assert!(V1State::initialize(
            &config,
            Arc::new(|_: SearchQuery| async { Ok(result(&[])) })
        )
        .is_err());
    }

    #[test]
    fn ids_survive_process_and_shard_changes() {
        let executable = std::env::current_exe().unwrap();
        let mut maps = Vec::new();
        let mut pids = Vec::new();
        for shard in [0, 7] {
            let child = std::process::Command::new(&executable)
                .args([
                    "--ignored",
                    "--exact",
                    "contracts::id_process_child",
                    "--nocapture",
                ])
                .env("V1_ID_CHILD", shard.to_string())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let pid = child.id();
            let output = child.wait_with_output().unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            println!(
                "child shard={shard} pid={pid} reaped=true status={}\n{stdout}",
                output.status
            );
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(stdout.contains(&format!("PROCESS588 {pid} {shard}")));
            pids.push(pid);
            maps.push(
                stdout
                    .lines()
                    .find_map(|line| line.strip_prefix("IDS588 "))
                    .unwrap()
                    .to_owned(),
            );
        }
        assert_ne!(pids[0], pids[1]);
        assert_eq!(maps[0], maps[1]);
        let expected = json!({"https://example.com/":"0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7","https://example.com/a?b=2&a=1":"9e1b7931d74ecb77efdde8e79ca52c2b63da671a086a011e1c949e9da31640be"});
        assert_eq!(serde_json::from_str::<Value>(&maps[0]).unwrap(), expected);
    }

    #[tokio::test]
    #[ignore = "Re-executed sequentially by ids_survive_process_and_shard_changes with a child marker"]
    async fn id_process_child() {
        let shard: u64 = std::env::var("V1_ID_CHILD").unwrap().parse().unwrap();
        println!("PROCESS588 {} {shard}", std::process::id());
        let mut docs = [
            ("https://example.com/", "cedar", "cedar synthetic document"),
            (
                "https://example.com/a?b=2&a=1",
                "cedar",
                "cedar second synthetic document",
            ),
        ];
        if shard == 7 {
            docs.reverse();
        }
        let (local, _directory) = super::query_index::local_on_shard(
            &docs,
            |_, page| page.host_centrality = 1.0,
            Default::default(),
            stract::inverted_index::ShardId::Backbone(shard),
        );
        let searcher =
            Arc::new(super::query_index::api(local, true, stract::bangs::Bangs::empty()).await);
        let backend = Arc::new(move |mut query: SearchQuery| {
            let searcher = searcher.clone();
            async move {
                query.signal_coefficients = stract::ranking::SignalCoefficients::new(
                    stract::ranking::SignalEnum::all().map(|signal| (signal, 0.0)),
                );
                searcher.search(&query).await
            }
        });
        let probe = Arc::new(Probe::default());
        let app = public(state(&config(), probe.clone(), backend));
        let response = observe(send(app, "POST", "/v1/search", r#"{"query":"cedar"}"#).await).await;
        work(&probe, 1, 1, 0);
        assert_eq!(probe.construction.load(SeqCst), 2);
        contract(&response);
        let map = response.value["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|page| (page["url"].as_str().unwrap().to_owned(), page["id"].clone()))
            .collect::<serde_json::Map<_, _>>();
        assert_eq!(
            map["https://example.com/"],
            "0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7"
        );
        assert_eq!(
            map["https://example.com/a?b=2&a=1"],
            "9e1b7931d74ecb77efdde8e79ca52c2b63da671a086a011e1c949e9da31640be"
        );
        assert_eq!(response.status, 200);
        println!("IDS588 {}", serde_json::to_string(&map).unwrap());
    }
}
