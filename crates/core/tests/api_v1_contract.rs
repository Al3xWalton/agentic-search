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
        decode: AtomicUsize,
        backend: AtomicUsize,
        source: AtomicUsize,
        construction: AtomicUsize,
        contexts: Mutex<Vec<(DocumentId, ServingContext)>>,
        hold: AtomicBool,
        reached: Notify,
        resume: Notify,
    }
    impl Observer for Probe {
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
        Arc::new(
            V1State::initialize(config, backend)
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
    }

    #[tokio::test]
    async fn fallbacks_methods_and_head_keep_contract_headers() {
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
        assert_eq!(head.headers["source-offer"], expected_source());
        assert_eq!(head.headers["x-api-version"], "v1");
        assert_eq!(head.status, 405);
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

    #[tokio::test]
    async fn chunked_body_cap_precedes_parse_and_work_on_every_route() {
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
        let response = observe(send(app, "POST", "/v1/search", exact + " ").await).await;
        work(&probe, 1, 1, 0);
        error(&response, "request_too_large", 413);
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
                vec!["word"; 8].join(" "),
                vec!["word"; 9].join(" "),
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
        let app = public(state(&config, probe.clone(), backend));
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
        let response = observe(send(app, "GET", "/v1/source", Body::empty()).await).await;
        work(&probe, 1, 1, 1);
        contract(&response);
        assert_eq!(response.status, 200);
    }

    #[tokio::test]
    async fn request_shape_and_document_ids_reject_before_work() {
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
            assert_eq!(response.status, 200);
            projections.insert(name.into(), value);
        }
        assert_eq!(
            serde_json::to_vec(&projections).unwrap(),
            include_bytes!("fixtures/api_v1/beta-search.json")
        );
    }

    #[tokio::test]
    async fn serving_policy_is_loaded_and_validated_before_listening() {
        let directory = stract::gen_temp_dir().unwrap();
        let path = directory.as_ref().join("policy.toml");
        let template = stract::crawler::policy::template().unwrap();
        let text = toml::to_string(template.get()).unwrap();
        std::fs::write(&path, &text).unwrap();
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
