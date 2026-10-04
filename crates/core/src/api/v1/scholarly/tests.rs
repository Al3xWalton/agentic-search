//! Exercises provider production paths against owned synthetic loopback services.

use super::*;
use crate::api::v1::{self, SearchBackend, V1Resources, V1State};
use crate::config::{papers::PaperProviderConfig, ApiConfig};
use axum::{
    body::{to_bytes, Body},
    http::{HeaderMap, Request},
    Router,
};
use serde_json::{json, Value};
use std::{
    cell::RefCell,
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering::SeqCst},
        Mutex,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Notify,
};
use tower::ServiceExt;

const OPENALEX: &[u8] = include_bytes!("../../../../tests/fixtures/papers/openalex-page.json");
const HTTP: &[u8] = include_bytes!("../../../../tests/fixtures/papers/http-page.json");
const OA_EMPTY: &[u8] = include_bytes!("../../../../tests/fixtures/papers/openalex-empty.json");
const HTTP_EMPTY: &[u8] = include_bytes!("../../../../tests/fixtures/papers/http-empty.json");
const EXPECTED: &[u8] = include_bytes!("../../../../tests/fixtures/papers/openalex-expected.json");

thread_local! {
    static ORIGIN: RefCell<Option<url::Url>> = const { RefCell::new(None) };
    static TLS: RefCell<Option<(std::net::SocketAddr, bool)>> = const { RefCell::new(None) };
    static SEND_FAULT: RefCell<Option<reqwest::Error>> = const { RefCell::new(None) };
    static PARSE_FAULT: RefCell<Option<serde_json::Error>> = const { RefCell::new(None) };
}

/// Injects the real reqwest error before the production mapper, without a separate error path.
pub(super) fn send_fault(
    result: Result<reqwest::Response, reqwest::Error>,
) -> Result<reqwest::Response, reqwest::Error> {
    SEND_FAULT.with(|fault| fault.borrow_mut().take().map_or(result, Err))
}

/// Injects the real decoder error at the production mapping expression.
pub(super) fn parse_fault(
    result: Result<Value, serde_json::Error>,
) -> Result<Value, serde_json::Error> {
    PARSE_FAULT.with(|fault| fault.borrow_mut().take().map_or(result, Err))
}

/// Observes whether a concurrent delete could enter the real gate before serialization finishes.
pub(in crate::api::v1) fn serialization_gate(state: &V1State) {
    assert!(
        state.store.state.try_write().is_err(),
        "W11 serialization gate held"
    );
}

// Full generated values catch schema drift beyond the individual field assertions.
#[test]
fn w32_openapi_identity() {
    use utoipa::OpenApi;
    let document = must(serde_json::to_value(v1::openapi()));
    let golden = value(include_bytes!(
        "../../../../tests/fixtures/api_v1/v1-openapi.json"
    ));
    assert!(document == golden, "W32 generated v1 identity");
    let schemas = &document["components"]["schemas"];
    let request = &schemas["V1SearchRequest"]["properties"]["scholarly"];
    assert!(
        request["type"] == "boolean" && request["default"] == false,
        "W32 request flag"
    );
    let metadata = &schemas["V1ScholarlyAttribution"];
    assert!(
        metadata["properties"].as_object().unwrap().len() == 8
            && metadata["required"].as_array().unwrap().len() == 8
            && metadata["additionalProperties"] == false,
        "W32 closed attribution"
    );
    let license = &metadata["properties"]["metadata_license"];
    assert!(
        license["enum"] == json!(["CC0-1.0"])
            && !license["enum"]
                .as_array()
                .unwrap()
                .contains(&json!("CC0-1x0")),
        "W32 exact license schema"
    );
    let pattern = metadata["properties"]["openalex_id"]["pattern"]
        .as_str()
        .unwrap();
    let pattern = must(regex::Regex::new(pattern));
    assert!(
        pattern.is_match("https://openalex.org/W9999000001")
            && !pattern.is_match("https://openalexXorg/W9999000001"),
        "W32 exact identity schema"
    );
    let description = document["paths"]["/v1/search"]["post"]["description"]
        .as_str()
        .unwrap();
    assert!(
        description.contains("Scholarly bound violations return 400 invalid_request."),
        "W32 scholarly input error documentation"
    );
    assert!(
        schemas["V1ErrorCode"]["enum"].as_array().unwrap().len() == 48
            && schemas["V1ErrorCode"]["enum"]
                .as_array()
                .unwrap()
                .contains(&json!("scholarly_unavailable")),
        "W32 exact error inventory"
    );
    let beta = include_bytes!("../../../../tests/fixtures/api_v1/beta-openapi.json");
    let search = include_bytes!("../../../../tests/fixtures/api_v1/beta-search.json");
    assert!(
        crate::compliance::model::sha256(&[beta])
            == "deedc24f5f55173a61ee05497266c5a8cb2ab345a8abde01550a0d2b9fd70a94",
        "W32 beta schema hash"
    );
    assert!(
        crate::compliance::model::sha256(&[search])
            == "d7319b5d5370c084a277c0b735c0a79c03f5352d009c46e6d62ae888f71b6183",
        "W32 beta response hash"
    );
    assert!(
        must(serde_json::to_value(crate::api::docs::BetaApiDoc::openapi())) == value(beta),
        "W32 generated beta identity"
    );
}

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Capture {
    // Keep all candidate diagnostics private in memory, including deliberately leaking mutants.
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        must(self.0.lock()).extend_from_slice(bytes);
        Ok(bytes.len())
    }
    // In-memory captures need no external flush.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// Both the scoped future and the stock immutable filter are exercised via the log facade bridge.
#[tokio::test]
async fn w29_redaction_transport() {
    use tracing_subscriber::{prelude::*, util::SubscriberInitExt};
    for filtered in [false, true] {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let sink = Capture(bytes.clone());
        let capture = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .without_time()
            .with_writer(move || sink.clone())
            .finish();
        let guard = capture
            .with(tracing_subscriber::filter::filter_fn(move |metadata| {
                !filtered || transport_log_allowed(metadata)
            }))
            .set_default();
        async {
            log::debug!(target:"paper_fixture", "bridge-positive");
        }
        .await;
        for http in [false, true] {
            let key = must(String::from_utf8(credential(http)));
            let encoded: String = url::form_urlencoded::byte_serialize(key.as_bytes()).collect();
            let mut url = must(url::Url::parse("https://reflection.example/private"));
            url.query_pairs_mut().append_pair("secret", &key);
            let mut spec = ResponseSpec::json(302, b"synthetic reflection");
            spec.headers.push(("Location".into(), url.to_string()));
            unavailable(
                &roundtrip(http, spec, paper_request()).await.0,
                "W29 redirect mapping",
            );
            let mut wrong = ResponseSpec::json(401, br#"{"error":"unauthenticated"}"#);
            wrong.headers.push(("x-reflected".into(), key.clone()));
            unavailable(
                &roundtrip(http, wrong, paper_request()).await.0,
                "W29 credential mapping",
            );
            invalid(
                &roundtrip(http, ResponseSpec::json(200, b"{"), paper_request())
                    .await
                    .0,
                "W29 decoder mapping",
            );
            redaction_failures(http).await;
            let captured = must(bytes.lock());
            for needle in [
                &key,
                &encoded,
                "Synthetic Cedar",
                "reflection.example/private",
                "http.secret",
                "openalex.secret",
            ] {
                assert!(
                    !captured
                        .windows(needle.len())
                        .any(|w| w == needle.as_bytes()),
                    "W29 transport redaction"
                );
            }
        }
        assert!(
            must(bytes.lock())
                .windows(b"bridge-positive".len())
                .any(|w| w == b"bridge-positive"),
            "W29 facade positive control"
        );
        drop(guard);
    }
}

// Natural send, malformed-header, truncated-read and deadline errors use the captured real path.
async fn redaction_failures(http: bool) {
    for raw in [
        b"invalid HTTP\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
          Content-Length: 300\r\nConnection: close\r\n\r\n{"
            .as_slice(),
    ] {
        let mut spec = ResponseSpec::json(200, HTTP_EMPTY);
        spec.raw = Some(raw.to_vec());
        unavailable(
            &roundtrip(http, spec, paper_request()).await.0,
            "W29 natural failure",
        );
    }
    let root = must(crate::gen_temp_dir());
    let server = Server::new(ResponseSpec::json(200, HTTP_EMPTY)).await;
    let adapter = provider(root.as_ref(), &server, http);
    server.finish().await;
    assert!(
        matches!(
            adapter
                .search(must(PaperQuery::try_new("Synthetic Cedar".into(), 0, 2)))
                .await,
            Err(PaperProviderError::Unavailable)
        ),
        "W29 connection failure"
    );
    let mut spec = ResponseSpec::json(200, HTTP_EMPTY);
    spec.header_delay = Duration::from_secs(1);
    let server = Server::new(spec).await;
    let budgets = transport::Budgets {
        header: Duration::from_millis(30),
        ..Default::default()
    };
    let client = must(transport::client(budgets));
    let result = transport::isolated(transport::exchange(
        client.get(server.endpoint()),
        budgets,
        http,
    ))
    .await;
    assert!(
        matches!(result, Err(PaperProviderError::Deadline)),
        "W29 timeout failure"
    );
    server.finish().await;
}

// Natural and injected failures hit the same actual send/decoder mappings and have no source chain.
#[tokio::test]
async fn w30_real_failure_mapping() {
    use std::error::Error;
    let budgets = transport::Budgets::default();
    let client = must(transport::client(budgets));
    let listener = must(TcpListener::bind("127.0.0.1:0").await);
    let addr = must(listener.local_addr());
    drop(listener);
    let failure = transport::exchange(
        client.get(format!("http://{addr}/v1/search")),
        budgets,
        true,
    )
    .await
    .err()
    .unwrap();
    assert!(
        failure == PaperProviderError::Unavailable && failure.source().is_none(),
        "W30 natural send"
    );
    let error = client.get("not a URL").build().err().unwrap();
    SEND_FAULT.with(|v| *v.borrow_mut() = Some(error));
    let server = Server::new(ResponseSpec::json(200, HTTP_EMPTY)).await;
    let failure = transport::exchange(client.get(server.endpoint()), budgets, true)
        .await
        .err()
        .unwrap();
    assert!(
        failure == PaperProviderError::Unavailable,
        "W30 actual send mapper"
    );
    server.finish().await;
    let error = serde_json::from_slice::<Value>(b"{").err().unwrap();
    PARSE_FAULT.with(|v| *v.borrow_mut() = Some(error));
    assert!(
        matches!(
            transport::parse(HTTP_EMPTY),
            Err(PaperProviderError::InvalidResponse)
        ),
        "W30 actual parse mapper"
    );
    assert!(
        matches!(
            transport::parse(b"{"),
            Err(PaperProviderError::InvalidResponse)
        ),
        "W30 natural parser"
    );
    let mut spec = ResponseSpec::json(200, HTTP_EMPTY);
    spec.raw = Some(b"invalid HTTP\r\n\r\n".to_vec());
    unavailable(
        &roundtrip(true, spec, paper_request()).await.0,
        "W30 malformed HTTP",
    );
}

// Opaque debug and immutable filters must survive trace-level user configuration.
#[tokio::test]
async fn w31_logging_and_debug() {
    use tracing_subscriber::{prelude::*, util::SubscriberInitExt};
    let main = include_str!("../../../main.rs");
    let main = main.split_once("fn main() -> Result<()> {").unwrap().1;
    let subscriber = main.split_once(".init();").unwrap().0;
    assert!(
        subscriber.contains(".with(tracing_subscriber::filter::filter_fn(")
            && subscriber.contains("stract::api::v1::scholarly::transport_log_allowed,"),
        "W31 stock binary transport filter"
    );
    let root = must(crate::gen_temp_dir());
    let path = root.as_ref().join("private-secret-canary");
    private_file(&path, &credential(true));
    let secret = must(crate::config::papers::test_secret(&path, true));
    assert!(
        format!("{secret:?}") == "Secret { .. }" && format!("{secret}") == "Secret { .. }",
        "W31 opaque secret"
    );
    assert!(must(secret.header()).is_sensitive(), "W31 sensitive header");
    opaque_provider_values(&path);
    let config = PaperProviderConfig::Http {
        endpoint: "https://private.example/v1/search".into(),
        bearer_token_file: path,
    };
    assert!(
        format!("{config:?}") == "PaperProviderConfig { .. }",
        "W31 opaque config"
    );
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let sink = Capture(bytes.clone());
    let capture = tracing_subscriber::fmt()
        .with_env_filter("trace")
        .without_time()
        .with_ansi(false)
        .with_writer(move || sink.clone())
        .finish()
        .with(tracing_subscriber::filter::filter_fn(transport_log_allowed));
    let guard = capture.set_default();
    log::debug!(target:"reqwest::fixture", "transport-private-canary");
    tracing::info!(target:"paper_fixture", "application-positive");
    drop(guard);
    let bytes = must(bytes.lock());
    assert!(
        !bytes
            .windows(b"transport-private-canary".len())
            .any(|w| w == b"transport-private-canary")
            && bytes
                .windows(b"application-positive".len())
                .any(|w| w == b"application-positive"),
        "W31 immutable filter"
    );
    for source in [
        include_str!("../../../config/papers.rs"),
        include_str!("transport.rs"),
        include_str!("openalex.rs"),
        include_str!("http.rs"),
    ] {
        for token in [
            ".unwrap(",
            ".expect(",
            "panic!(",
            "assert!(",
            "unreachable!(",
            "#[tracing::instrument]",
        ] {
            assert!(!source.contains(token), "W31 production panic redaction");
        }
    }
}

// Debug output for actual built-in instances must remain independent of private inputs.
fn opaque_provider_values(path: &Path) {
    let secret = must(crate::config::papers::test_secret(path, true));
    let http = must(super::http::HttpProvider::new(
        "https://private.example/v1/search",
        secret,
    ));
    let secret = must(crate::config::papers::test_secret(path, false));
    let openalex = must(super::openalex::OpenAlex::new(secret));
    let query = must(PaperQuery::try_new("private query".into(), 0, 1));
    let page = must(PaperPage::try_new(Vec::new(), None));
    assert!(
        format!("{http:?}") == "HttpProvider { .. }"
            && format!("{openalex:?}") == "OpenAlex { .. }"
            && format!("{query:?}") == "PaperQuery { .. }"
            && format!("{page:?}") == "PaperPage { .. }",
        "W31 opaque provider values"
    );
}

// Escape expansion and exact-cap acceptance are measured at the actual capped output writer.
#[tokio::test]
async fn w36_output_bounds() {
    let hit: AttributedResult = must(serde_json::from_value(value(HTTP)["results"][0].clone()));
    let size = must(serde_json::to_vec(&hit)).len();
    assert!(validate_hit_size(&hit, size).is_ok(), "W36 hit exact cap");
    assert!(
        validate_hit_size(&hit, size - 1).is_err(),
        "W36 hit overflow"
    );
    for text in ["plain", "\"\\\n\t", "🦀"] {
        let expected = must(serde_json::to_vec(text));
        for excess in [false, true] {
            let cap = expected.len() - usize::from(excess);
            let response = v1::error::bounded_success(&text, cap);
            let status = response.status().as_u16();
            let bytes = must(to_bytes(response.into_body(), 1024).await);
            if excess {
                assert!(
                    status == 500
                        && bytes.as_ref()
                            == b"{\"version\":\"v1\",\"error\":\
                    {\"code\":\"invalid_result\",\"message\":\"The search result is invalid\"}}",
                    "W36 exact overflow error"
                );
            } else {
                assert!(
                    status == 200 && bytes.as_ref() == expected,
                    "W36 exact output cap"
                );
            }
        }
    }
}

#[derive(Default)]
struct ContextProbe {
    serving: Mutex<Vec<v1::search::ServingContext>>,
    rules: Mutex<Vec<crate::compliance::rules::RuleContext>>,
}
impl v1::Observer for ContextProbe {
    // Observe the actual context used for every independently hashed known link.
    fn serving_context(
        &self,
        _id: &v1::suppression::DocumentId,
        context: &v1::search::ServingContext,
    ) {
        must(self.serving.lock()).push(*context);
    }
    // Observe the actual compliance context immediately before the rules call.
    fn compliance_context(&self, context: &crate::compliance::rules::RuleContext) {
        must(self.rules.lock()).push(*context);
    }
}

// Original Unicode text, caller page/count and conservative local context survive both adapters.
#[tokio::test]
async fn w37_original_context() {
    for http in [false, true] {
        let root = must(crate::gen_temp_dir());
        let mut body = if http { value(HTTP) } else { value(OPENALEX) };
        if http {
            body["next_page"] = json!(8);
        }
        let server = Server::new(ResponseSpec::json(200, body.to_string().as_bytes())).await;
        let provider = provider(root.as_ref(), &server, http);
        let state = provider_state(root.as_ref(), provider).await;
        let probe = Arc::new(ContextProbe::default());
        let state = Arc::new(must(Arc::try_unwrap(state)).with_observer(probe.clone()));
        let query = "Élodie + Cedar & ? #";
        let reply = send(
            state,
            json!({"query":query,"page":7,"num_results":3,"scholarly":true}),
        )
        .await;
        let value = value(&reply.bytes);
        assert!(
            reply.status == 200 && value["page"] == 7 && value["num_results"] == 3,
            "W37 local echoes"
        );
        assert!(
            !must(probe.serving.lock()).is_empty()
                && must(probe.serving.lock()).iter().all(|c| {
                    c.country == v1::dto::Country::Unknown && c.is_child && c.uk_measures
                }),
            "W37 original serving context"
        );
        assert!(
            !must(probe.rules.lock()).is_empty()
                && must(probe.rules.lock()).iter().all(|c| {
                    c.country == crate::compliance::rules::RuleCountry::Unknown
                        && c.is_child
                        && c.uk_measures
                }),
            "W37 original rule context"
        );
        {
            let requests = must(server.requests.lock());
            let sent = if http {
                value_from_body(&requests[0].body)
            } else {
                let url = must(url::Url::parse(&format!(
                    "http://fixture.test{}",
                    requests[0].path
                )));
                url.query_pairs()
                    .find(|(key, _)| key == "search")
                    .unwrap()
                    .1
                    .into_owned()
            };
            assert!(sent == query, "W37 original query bytes");
        }
        server.finish().await;
    }
}

// Extract only synthetic fixture query bytes without formatting the surrounding request.
fn value_from_body(bytes: &[u8]) -> String {
    value(bytes)["query"].as_str().unwrap().to_owned()
}

/// Substitutes only the destination in test builds, preserving transport policy.
pub(super) fn openalex_origin(production: url::Url) -> url::Url {
    ORIGIN.with(|value| value.borrow().clone().unwrap_or(production))
}

/// Installs fixture trust and resolution while retaining certificate and hostname verification.
pub(super) fn configure_client(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    TLS.with(|tls| {
        let Some((addr, trust)) = *tls.borrow() else {
            return builder;
        };
        let builder = builder
            .resolve(TEST_TLS_HOST, addr)
            .resolve(TEST_TLS_WRONG_HOST, addr);
        if trust {
            builder
                .tls_built_in_root_certs(false)
                .add_root_certificate(must(reqwest::Certificate::from_der(TEST_TLS_CA_DER)))
        } else {
            builder
        }
    })
}

// The owned blocking server uses only the sealed identity; the client keeps its real TLS policy.
fn tls_server() -> (
    std::net::SocketAddr,
    Arc<AtomicUsize>,
    std::thread::JoinHandle<()>,
) {
    use std::io::{Read, Write};
    let listener = must(std::net::TcpListener::bind("127.0.0.1:0"));
    let addr = must(listener.local_addr());
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let task = std::thread::spawn(move || {
        let identity = must(native_tls::Identity::from_pkcs12(
            TEST_TLS_IDENTITY_P12,
            TEST_TLS_IDENTITY_PASSPHRASE,
        ));
        let acceptor = must(native_tls::TlsAcceptor::new(identity));
        must(listener.set_nonblocking(true));
        let end = std::time::Instant::now() + Duration::from_secs(3);
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= end {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return,
            }
        };
        must(stream.set_nonblocking(false));
        must(stream.set_read_timeout(Some(Duration::from_secs(2))));
        must(stream.set_write_timeout(Some(Duration::from_secs(2))));
        let Ok(mut stream) = acceptor.accept(stream) else {
            return;
        };
        let mut bytes = Vec::new();
        while !bytes.windows(4).any(|w| w == b"\r\n\r\n") && bytes.len() < 40_000 {
            let mut chunk = [0; 1024];
            let Ok(n) = stream.read(&mut chunk) else {
                return;
            };
            if n == 0 {
                return;
            }
            bytes.extend_from_slice(&chunk[..n]);
        }
        count.fetch_add(1, SeqCst);
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
            Content-Length: {}\r\nConnection: close\r\n\r\n",
            HTTP_EMPTY.len()
        );
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(HTTP_EMPTY);
        let _ = stream.flush();
    });
    (addr, calls, task)
}

// Certificate rejection is causal: only the supplied test root permits the valid reserved hostname.
async fn tls_cases() {
    assert!(!TEST_TLS_LEAF_DER.is_empty(), "W20 sealed leaf");
    for (trust, host, accepted) in [
        (false, TEST_TLS_HOST, false),
        (true, TEST_TLS_HOST, true),
        (true, TEST_TLS_WRONG_HOST, false),
    ] {
        let (addr, calls, task) = tls_server();
        TLS.with(|v| *v.borrow_mut() = Some((addr, trust)));
        let budgets = transport::Budgets::default();
        let client = must(transport::client(budgets));
        TLS.with(|v| *v.borrow_mut() = None);
        let result = transport::exchange(
            client.get(format!("https://{host}:{}/v1/search", addr.port())),
            budgets,
            true,
        )
        .await;
        must(task.join());
        assert!(
            result.is_ok() == accepted && calls.load(SeqCst) == usize::from(accepted),
            "W20 TLS verification trust={trust} accepted={accepted} result={} calls={}",
            result.is_ok(),
            calls.load(SeqCst)
        );
    }
}

// Proxy variables are changed only in a fresh child before any reqwest client exists there.
async fn proxy_child() {
    let proxy = Server::new(ResponseSpec::json(200, HTTP_EMPTY)).await;
    let upstream = Server::new(ResponseSpec::json(200, HTTP_EMPTY)).await;
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        std::env::set_var(key, format!("http://{}", proxy.addr));
    }
    for key in ["NO_PROXY", "no_proxy"] {
        std::env::remove_var(key);
    }
    let root = must(crate::gen_temp_dir());
    let provider = provider(root.as_ref(), &upstream, true);
    let reply = send(
        provider_state(root.as_ref(), provider).await,
        paper_request(),
    )
    .await;
    assert!(
        reply.status == 200 && upstream.count() == 1 && proxy.count() == 0,
        "W20 no proxy"
    );
    upstream.finish().await;
    proxy.finish().await;
}

// Cleartext exceptions use parsed literal address semantics; HTTPS never disables verification.
#[tokio::test]
async fn w20_endpoint_tls() {
    if std::env::var_os("PAPER_PROXY_CHILD").is_some() {
        proxy_child().await;
        return;
    }
    for url in [
        "http://127.0.0.1:3019/v1/search",
        "http://[::1]:3019/v1/search",
        "https://papers.example/v1/search",
    ] {
        assert!(transport::endpoint(url).is_ok(), "W20 allowed endpoint");
    }
    for url in [
        "http://localhost/v1/search",
        "http://192.0.2.1/v1/search",
        "http://0.0.0.0/v1/search",
        "http://[::]/v1/search",
        "http://[::ffff:127.0.0.1]/v1/search",
        "http://127.1/v1/search",
        "https://user:pass@papers.example/v1/search",
        "https://user@papers.example/v1/search",
        "https://:pass@papers.example/v1/search",
        "https://papers.example/v1/search?q=1",
        "https://papers.example/v1/search#x",
        "https://papers.example/wrong",
    ] {
        assert!(transport::endpoint(url).is_err(), "W20 refused endpoint");
    }
    tls_cases().await;
    let output = must(
        std::process::Command::new(must(std::env::current_exe()))
            .args([
                "api::v1::scholarly::tests::w20_endpoint_tls",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("PAPER_PROXY_CHILD", "1")
            .output(),
    );
    assert!(output.status.success(), "W20 child proxy policy");
}

// Await real fixture arrival without racing a policy write against request extraction.
async fn arrived(server: &Server, count: usize) {
    let ready = tokio::time::timeout(Duration::from_secs(3), async {
        while server.count() < count {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(ready.is_ok(), "paper fixture arrival");
}

// Use the actual serialized persistence operation rather than directly inserting a suppression ID.
async fn suppress(state: &V1State, url: &str) {
    let id = must(v1::suppression::canonical_identity(url)).1;
    let permit = must(
        Arc::new(tokio::sync::Semaphore::new(1))
            .acquire_owned()
            .await,
    );
    must(state.store.suppress(id, Arc::new(permit)).await);
}

// A completed delete during provider I/O must precede every later assembly.
#[tokio::test]
async fn w10_live_suppression() {
    let root = must(crate::gen_temp_dir());
    let release = Arc::new(Notify::new());
    let mut spec = ResponseSpec::json(200, HTTP);
    spec.release = Some(release.clone());
    let server = Server::new(spec).await;
    let provider = provider(root.as_ref(), &server, true);
    let state = provider_state(root.as_ref(), provider).await;
    let request = tokio::spawn(send(state.clone(), paper_request()));
    arrived(&server, 1).await;
    assert!(
        state.store.state.try_write().is_ok(),
        "W10 no gate during network"
    );
    suppress(&state, "https://openalex.org/W9999000001").await;
    release.notify_waiters();
    let reply = must(request.await);
    let mut expected = value(EXPECTED);
    expected["results"].as_array_mut().unwrap().remove(0);
    expected["results"][0]["scholarly"]["snapshot_date"] = json!("2026-09-01");
    assert!(
        reply.status == 200 && value(&reply.bytes) == expected,
        "W10 current suppression"
    );
    server.finish().await;
}

struct RulesFault(std::sync::atomic::AtomicBool);
impl crate::compliance::rules::RulesHooks for RulesFault {
    // Fail at the real post-rename uncertainty boundary, which marks the serving owner unavailable.
    fn at(&self, stage: crate::compliance::rules::RulesStage) -> std::io::Result<()> {
        if self.0.load(SeqCst) && stage == crate::compliance::rules::RulesStage::SyncDirectory {
            Err(std::io::Error::other("synthetic rules fault"))
        } else {
            Ok(())
        }
    }
}

// Install through the actual rule writer so its live health and synchronization are exercised.
async fn fail_rules(state: Arc<V1State>) {
    must(
        tokio::task::spawn_blocking(move || {
            use crate::compliance::{
                model::{DocumentKey, Ground, TicketId},
                rules::RuleDelta,
            };
            let id = must(v1::suppression::canonical_identity(
                "https://openalex.org/W9999000001",
            ))
            .1;
            let delta = RuleDelta::Install {
                ticket: must(TicketId::parse(&"1".repeat(64))),
                documents: vec![must(DocumentKey::parse(id.as_str()))],
                ground: Ground::IllegalContent,
                effective_at: 1_700_000_000,
                sequence: 1,
                names: Vec::new(),
            };
            let rules = state.compliance.rules();
            let prepared = must(rules.prepare_delta(&delta));
            assert!(rules.commit(prepared).is_err(), "W11 real rules failure");
        })
        .await,
    );
}

// Store and rules health are rechecked after network completion, not only before paid work.
#[tokio::test]
async fn w11_gate_races() {
    for rules_fail in [false, true] {
        let root = must(crate::gen_temp_dir());
        let release = Arc::new(Notify::new());
        let mut spec = ResponseSpec::json(200, HTTP);
        spec.release = Some(release.clone());
        let server = Server::new(spec).await;
        let provider = provider(root.as_ref(), &server, true);
        let config = config(root.as_ref());
        let fault = Arc::new(RulesFault(std::sync::atomic::AtomicBool::new(false)));
        let startup_fault = fault.clone();
        let state = must(
            tokio::task::spawn_blocking(move || {
                let seams = v1::compliance_adapter::ComplianceSeams {
                    rules_hooks: startup_fault,
                    ..Default::default()
                };
                let resources = must(V1Resources::with_compliance_seams(&config, seams))
                    .with_paper_provider(provider);
                Arc::new(V1State::from_resources(
                    &config,
                    web(Arc::new(AtomicUsize::new(0))),
                    &resources,
                ))
            })
            .await,
        );
        let request = tokio::spawn(send(state.clone(), paper_request()));
        arrived(&server, 1).await;
        if rules_fail {
            fault.0.store(true, SeqCst);
            fail_rules(state.clone()).await;
        } else {
            state.store.state.write().await.unavailable = true;
        }
        release.notify_waiters();
        let reply = must(request.await);
        let (code, message) = if rules_fail {
            ("rules_unavailable", "The serving rules are unavailable")
        } else {
            (
                "suppression_unavailable",
                "The suppression store is unavailable",
            )
        };
        closed(&reply, 503, code, message, "W11 final health recheck");
        server.finish().await;
    }
    let root = must(crate::gen_temp_dir());
    let server = Server::new(ResponseSpec::json(200, HTTP)).await;
    let state = provider_state(root.as_ref(), provider(root.as_ref(), &server, true)).await;
    assert!(
        send(state, paper_request()).await.status == 200,
        "W11 serialized control"
    );
    server.finish().await;
}

// Four permits are shared by two independently attached states, and cancellation returns capacity.
#[tokio::test]
async fn w28_admission_cleanup() {
    let root = must(crate::gen_temp_dir());
    let release = Arc::new(Notify::new());
    let mut spec = ResponseSpec::json(200, HTTP_EMPTY);
    spec.release = Some(release.clone());
    let server = Server::new(spec).await;
    let provider = provider(root.as_ref(), &server, true);
    let config = config(root.as_ref());
    let states = must(
        tokio::task::spawn_blocking(move || {
            let resources = must(V1Resources::load(&config)).with_paper_provider(provider);
            [0, 1].map(|_| {
                Arc::new(V1State::from_resources(
                    &config,
                    web(Arc::new(AtomicUsize::new(0))),
                    &resources,
                ))
            })
        })
        .await,
    );
    let mut requests = Vec::new();
    for i in 0..4 {
        requests.push(tokio::spawn(send(states[i % 2].clone(), paper_request())));
    }
    arrived(&server, 4).await;
    let fifth = tokio::time::timeout(
        Duration::from_millis(150),
        send(states[1].clone(), paper_request()),
    )
    .await;
    assert!(fifth.is_ok(), "W28 no waiting queue");
    unavailable(&must(fifth), "W28 fifth refusal");
    assert!(server.count() == 4, "W28 shared admission");
    let cancelled = requests.pop().unwrap();
    cancelled.abort();
    let _ = cancelled.await;
    assert!(
        states[0].papers.admission.available_permits() == 1,
        "W28 cancellation release"
    );
    requests.push(tokio::spawn(send(states[0].clone(), paper_request())));
    arrived(&server, 5).await;
    release.notify_waiters();
    for request in requests {
        assert!(must(request.await).status == 200, "W28 completion");
    }
    assert!(
        states[1].papers.admission.available_permits() == 4,
        "W28 success release"
    );
    server.finish().await;
    drop(states);
    let server = Server::new(ResponseSpec::json(401, br#"{"error":"unauthenticated"}"#)).await;
    let provider = self::provider(root.as_ref(), &server, true);
    let state = provider_state(root.as_ref(), provider).await;
    unavailable(
        &send(state.clone(), paper_request()).await,
        "W28 provider error",
    );
    assert!(
        state.papers.admission.available_permits() == 4,
        "W28 error release"
    );
    assert!(server.count() == 1, "W28 error request count");
    server.finish().await;
}

// Each known URL is checked with its own ID, independently of the chosen display URL.
#[tokio::test]
async fn w35_known_link_policy() {
    let links = [
        "https://openalex.org/W9999000001",
        "https://doi.org/10.5555/synthetic.0001",
        "https://repository.example/record/1",
    ];
    for url in links {
        for listing in 0..3 {
            let listed = listing != 0;
            let root = must(crate::gen_temp_dir());
            let server = Server::new(ResponseSpec::json(200, HTTP)).await;
            let provider = provider(root.as_ref(), &server, true);
            let mut config = config(root.as_ref());
            if listed {
                use std::os::unix::fs::PermissionsExt;
                must(std::fs::set_permissions(
                    root.as_ref(),
                    std::fs::Permissions::from_mode(0o700),
                ));
                let path = root.as_ref().join("listed.json");
                let id = must(v1::suppression::canonical_identity(url)).1;
                let host = must(url::Url::parse(url)).host_str().unwrap().to_owned();
                let host_hash = crate::compliance::model::sha256(&[host.as_bytes()]);
                private_file(
                    &path,
                    json!({"format_version":1,"version":"synthetic",
                    "url_hashes":if listing == 1 {vec![id.as_str()]} else {vec![]},
                    "host_hashes":if listing == 2 {vec![host_hash.as_str()]} else {vec![]}})
                    .to_string()
                    .as_bytes(),
                );
                config.compliance.listed_hashes_file = Some(path);
            }
            let state = must(
                tokio::task::spawn_blocking(move || {
                    let resources = must(V1Resources::load(&config)).with_paper_provider(provider);
                    Arc::new(V1State::from_resources(
                        &config,
                        web(Arc::new(AtomicUsize::new(0))),
                        &resources,
                    ))
                })
                .await,
            );
            let probe = Arc::new(ContextProbe::default());
            let state = Arc::new(must(Arc::try_unwrap(state)).with_observer(probe.clone()));
            if !listed {
                suppress(&state, url).await;
            }
            let reply = send(state, paper_request()).await;
            let expected_count = usize::from(listing != 2 || url != links[0]);
            assert!(
                reply.status == 200
                    && value(&reply.bytes)["results"].as_array().unwrap().len() == expected_count
                    && (expected_count == 0
                        || value(&reply.bytes)["results"][0]["url"]
                            == links[0].replace("0001", "0002")),
                "W35 own-link denial"
            );
            assert!(server.count() == 1, "W35 no refill");
            assert!(
                must(probe.serving.lock())
                    .iter()
                    .all(|c| c.is_child && c.country == v1::dto::Country::Unknown),
                "W35 original child context"
            );
            assert!(
                must(probe.rules.lock())
                    .iter()
                    .all(|c| c.is_child
                        && c.country == crate::compliance::rules::RuleCountry::Unknown),
                "W35 original rule context"
            );
            server.finish().await;
        }
    }
    reversible_paper_rules().await;
}

// Never let a failing fixture decoder or I/O operation print untrusted content or a secret path.
fn must<T, E>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(_) => panic!("paper fixture operation"),
    }
}

// Every provider response must observe deadline expiry and durable rule reversal locally.
async fn reversible_paper_rules() {
    use crate::compliance::{
        model::{DocumentKey, Ground, TicketId},
        rules::RuleDelta,
    };
    let root = must(crate::gen_temp_dir());
    let server = Server::new(ResponseSpec::json(200, HTTP)).await;
    let provider = provider(root.as_ref(), &server, true);
    let config = config(root.as_ref());
    let clock = Arc::new(crate::crawler::politeness::ManualClock::new(must(
        crate::compliance::clock::instant(100),
    )));
    let seams = v1::compliance_adapter::ComplianceSeams {
        clock: clock.clone(),
        ..Default::default()
    };
    let state = must(
        tokio::task::spawn_blocking(move || {
            let resources = must(V1Resources::with_compliance_seams(&config, seams))
                .with_paper_provider(provider);
            Arc::new(V1State::from_resources(
                &config,
                web(Arc::new(AtomicUsize::new(0))),
                &resources,
            ))
        })
        .await,
    );
    let id = must(v1::suppression::canonical_identity(
        "https://repository.example/record/1",
    ))
    .1;
    let ticket = must(TicketId::parse(&"2".repeat(64)));
    let install = RuleDelta::Install {
        ticket: ticket.clone(),
        documents: vec![must(DocumentKey::parse(id.as_str()))],
        ground: Ground::IllegalContent,
        effective_at: 101,
        sequence: 1,
        names: Vec::new(),
    };
    for (delta, observations) in [
        (install, vec![(0, 2), (1_000, 1)]),
        (RuleDelta::Remove { ticket }, vec![(0, 2)]),
    ] {
        let current = state.clone();
        must(
            tokio::task::spawn_blocking(move || {
                let rules = current.compliance.rules();
                let prepared = must(rules.prepare_delta(&delta));
                must(rules.commit(prepared));
            })
            .await,
        );
        for (advance, count) in observations {
            must(clock.advance(advance));
            let reply = send(state.clone(), paper_request()).await;
            let mut expected = value(EXPECTED);
            for hit in expected["results"].as_array_mut().unwrap() {
                hit["scholarly"]["snapshot_date"] = json!("2026-09-01");
            }
            if count == 1 {
                expected["results"].as_array_mut().unwrap().remove(0);
            }
            assert!(
                reply.status == 200 && value(&reply.bytes) == expected,
                "W35 deadline expiry and reversal"
            );
        }
    }
    assert!(server.count() == 3, "W35 one retrieval per page");
    server.finish().await;
}

// Expected JSON is decoded independently of the production provider parser.
fn value(bytes: &[u8]) -> Value {
    must(serde_json::from_slice(bytes))
}

// Runtime credentials are synthetic and never copied from configuration outside this fixture.
fn credential(http: bool) -> Vec<u8> {
    if http {
        [b'a'; 64].to_vec()
    } else {
        [b"synthetic-".as_slice(), b"key+&?#"].concat()
    }
}

// Explicit permissions prove the real loader's descriptor checks rather than bypassing them.
fn private_file(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    must(std::fs::write(path, bytes));
    must(std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(0o600),
    ));
}

// Each state retains its directory owner until all requests and resource owners have been dropped.
fn config(root: &Path) -> ApiConfig {
    let mut config: ApiConfig = must(toml::from_str(include_str!(
        "../../../../../../configs/api.toml"
    )));
    config.v1.suppression_store_path = root.join("serving/suppression.json");
    config
}

// The web control is visibly nonempty, so absence of fallback cannot hide an empty backend.
fn web(counter: Arc<AtomicUsize>) -> Arc<dyn SearchBackend> {
    Arc::new(move |_: crate::searcher::SearchQuery| {
        counter.fetch_add(1, SeqCst);
        async {
            Ok(crate::searcher::SearchResult::Websites(must(
                serde_json::from_value(json!({
                    "webpages":[{"title":"Synthetic web control",
                    "url":"https://web.example/control",
                    "site":"web.example","domain":"web.example","prettyUrl":"web.example/control",
                    "snippet":{"date":null,"text":{"fragments":[]}},"richSnippet":null,
                    "rankingSignals":null,"structuredData":null,"likelyHasAds":false,
                    "likelyHasPaywall":false}],"numHits":{"_type":"exact","value":1},
                    "searchDurationMs":0,"hasMoreResults":false
                })),
            )))
        }
    })
}

// Match startup's resource construction off the runtime thread before the real state handoff.
async fn state(config: ApiConfig, backend: Arc<dyn SearchBackend>) -> Arc<V1State> {
    must(
        tokio::task::spawn_blocking(move || Arc::new(must(V1State::initialize(&config, backend))))
            .await,
    )
}

struct Reply {
    status: u16,
    bytes: Vec<u8>,
    headers: HeaderMap,
}

// Exercise the finished production router, including ownership normalization and contract headers.
async fn send(state: Arc<V1State>, body: Value) -> Reply {
    let router = v1::compose_api(Router::new(), state);
    let request = must(
        Request::builder()
            .method("POST")
            .uri("/v1/search")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string())),
    );
    let response = must(router.oneshot(request).await);
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = must(to_bytes(response.into_body(), MAX_PAPER_RESPONSE_BYTES + 1).await).to_vec();
    Reply {
        status,
        bytes,
        headers,
    }
}

// Pin complete compact local envelopes, never individual fields or arbitrary upstream text.
fn closed(reply: &Reply, status: u16, code: &str, message: &str, marker: &str) {
    let expected = format!(
        "{{\"version\":\"v1\",\"error\":{{\"code\":\"{code}\",\"message\":\"{message}\"}}}}"
    );
    assert!(
        reply.status == status && reply.bytes == expected.as_bytes(),
        "{marker}"
    );
    assert!(
        reply
            .headers
            .get("x-api-version")
            .is_some_and(|v| v == "v1"),
        "{marker}"
    );
    assert!(
        reply.headers.get_all("source-offer").iter().count() == 1,
        "{marker}"
    );
}

// One source for the exact unavailable envelope used by all transport witnesses.
fn unavailable(reply: &Reply, marker: &str) {
    closed(
        reply,
        503,
        "scholarly_unavailable",
        "The scholarly provider is unavailable",
        marker,
    );
}

// One source for the exact invalid-provider-response envelope.
fn invalid(reply: &Reply, marker: &str) {
    closed(
        reply,
        500,
        "invalid_result",
        "The search result is invalid",
        marker,
    );
}

#[derive(Clone)]
struct ResponseSpec {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    chunk: usize,
    header_delay: Duration,
    chunk_delay: Duration,
    authority: Option<Vec<u8>>,
    raw: Option<Vec<u8>>,
    release: Option<Arc<Notify>>,
}

impl ResponseSpec {
    // The same chunked fixture supports exact-limit, trickle and truncated-body variations.
    fn json(status: u16, body: &[u8]) -> Self {
        Self {
            status,
            body: body.to_vec(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            chunk: 8192,
            header_delay: Duration::ZERO,
            chunk_delay: Duration::ZERO,
            authority: None,
            raw: None,
            release: None,
        }
    }
}

struct Wire {
    method: String,
    path: String,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

impl Wire {
    // Preserve duplicate header values so tests can detect accidental credential duplication.
    fn header(&self, name: &str) -> Vec<&[u8]> {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_slice())
            .collect()
    }
}

struct Server {
    addr: std::net::SocketAddr,
    requests: Arc<Mutex<Vec<Wire>>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Server {
    // Literal loopback is the only fixture destination; each connection task has a finite owner.
    async fn new(spec: ResponseSpec) -> Self {
        let listener = must(TcpListener::bind("127.0.0.1:0").await);
        let addr = must(listener.local_addr());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let received = requests.clone();
        let task = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    connection = listener.accept() => {
                        let Ok((stream, _)) = connection else { break; };
                        let (spec, received) = (spec.clone(), received.clone());
                        children.spawn(async move { serve(stream, spec, received).await; });
                    }
                    _ = children.join_next(), if !children.is_empty() => {}
                }
            }
        });
        Self {
            addr,
            requests,
            task: Some(task),
        }
    }
    // Complete endpoints are selected only by trusted startup configuration.
    fn endpoint(&self) -> String {
        format!("http://{}/v1/search", self.addr)
    }
    // Request counts remain content-free even when a mutant forwards a bad credential.
    fn count(&self) -> usize {
        must(self.requests.lock()).len()
    }
    // Explicit joins keep normal paths free of detached fixture work.
    async fn finish(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for Server {
    // Panic paths must also close the listener and abort its owned connection set.
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

// Read only the fixture's bounded request, then independently enforce the configured credential.
async fn serve(
    mut stream: tokio::net::TcpStream,
    mut spec: ResponseSpec,
    received: Arc<Mutex<Vec<Wire>>>,
) {
    let Some(wire) = read_wire(&mut stream).await else {
        return;
    };
    if let Some(token) = &spec.authority {
        let expected = [b"Bearer ".as_slice(), token].concat();
        if wire.header("authorization") != vec![expected.as_slice()] {
            spec.status = 401;
            spec.body = br#"{"error":"unauthenticated"}"#.to_vec();
        }
    }
    must(received.lock()).push(wire);
    if let Some(release) = spec.release {
        release.notified().await;
    }
    tokio::time::sleep(spec.header_delay).await;
    if let Some(raw) = spec.raw {
        let _ = stream.write_all(&raw).await;
        return;
    }
    let mut head = format!("HTTP/1.1 {} Fixture\r\n", spec.status);
    for (key, value) in spec.headers {
        head.push_str(&format!("{key}: {value}\r\n"));
    }
    head.push_str("Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
    if stream.write_all(head.as_bytes()).await.is_err() {
        return;
    }
    for chunk in spec.body.chunks(spec.chunk) {
        tokio::time::sleep(spec.chunk_delay).await;
        if stream
            .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
            .await
            .is_err()
            || stream.write_all(chunk).await.is_err()
            || stream.write_all(b"\r\n").await.is_err()
        {
            return;
        }
    }
    let _ = stream.write_all(b"0\r\n\r\n").await;
}

// A fixture framing error reports a fixed marker and never prints received request bytes.
async fn read_wire(stream: &mut tokio::net::TcpStream) -> Option<Wire> {
    let mut bytes = Vec::new();
    let boundary = loop {
        if let Some(pos) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
            break pos + 4;
        }
        let mut chunk = [0; 1024];
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 || bytes.len() + n > 40_000 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..n]);
    };
    let head = std::str::from_utf8(&bytes[..boundary]).ok()?;
    let mut lines = head.split("\r\n");
    let mut start = lines.next()?.split_whitespace();
    let method = start.next()?.to_owned();
    let path = start.next()?.to_owned();
    let headers: Vec<_> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.to_owned(), value.trim().as_bytes().to_vec()))
        .collect();
    let length = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| std::str::from_utf8(v).ok())
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    if length > MAX_PROVIDER_REQUEST_BYTES {
        return None;
    }
    while bytes.len() < boundary + length {
        let mut chunk = [0; 1024];
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..n]);
    }
    Some(Wire {
        method,
        path,
        headers,
        body: bytes[boundary..boundary + length].to_vec(),
    })
}

// Build both actual adapters through the public configuration seam, never a canned result adapter.
fn provider(root: &Path, server: &Server, http: bool) -> Arc<dyn PaperProvider> {
    let path = root.join(if http {
        "http.secret"
    } else {
        "openalex.secret"
    });
    private_file(&path, &credential(http));
    if http {
        must(
            PaperProviderConfig::Http {
                endpoint: server.endpoint(),
                bearer_token_file: path,
            }
            .build(),
        )
    } else {
        ORIGIN.with(|v| {
            *v.borrow_mut() = Some(must(url::Url::parse(&format!(
                "http://{}/works",
                server.addr
            ))))
        });
        let built = PaperProviderConfig::Openalex { api_key_file: path }.build();
        ORIGIN.with(|v| *v.borrow_mut() = None);
        must(built)
    }
}

// Embedded providers still pass through production admission and serving gates.
async fn provider_state(root: &Path, provider: Arc<dyn PaperProvider>) -> Arc<V1State> {
    let config = config(root);
    must(
        tokio::task::spawn_blocking(move || {
            let resources = must(V1Resources::load(&config)).with_paper_provider(provider);
            Arc::new(V1State::from_resources(
                &config,
                web(Arc::new(AtomicUsize::new(0))),
                &resources,
            ))
        })
        .await,
    )
}

// Common end-to-end exchange returns only the final local response and a bounded observed count.
async fn roundtrip(http: bool, spec: ResponseSpec, request: Value) -> (Reply, usize) {
    let root = must(crate::gen_temp_dir());
    let server = Server::new(spec).await;
    let provider = provider(root.as_ref(), &server, http);
    let state = provider_state(root.as_ref(), provider).await;
    let reply = send(state.clone(), request).await;
    let count = server.count();
    drop(state);
    server.finish().await;
    (reply, count)
}

// Every connector witness shares exactly the same real route request shape.
fn paper_request() -> Value {
    json!({"query":"Synthetic Cedar","num_results":2,"scholarly":true})
}

// Old configurations must remain network-idle and have no implicit paper destination.
#[test]
fn w01_default_config() {
    let sample = include_str!("../../../../../../configs/api.toml");
    for text in [sample, sample.split("[v1]").next().unwrap()] {
        let config: ApiConfig = must(toml::from_str(text));
        assert!(config.v1.paper_provider.is_none(), "W01 default provider");
        assert!(
            must(Resources::load(&config)).provider.is_none(),
            "W01 idle resources"
        );
    }
    assert!(
        crate::config::v1::V1ApiConfig::default()
            .paper_provider
            .is_none(),
        "W01 default"
    );
}

// Both closed variants reject extra, mixed, missing and inline-secret fields before construction.
#[test]
fn w02_config_variants() {
    for good in [
        r#"kind="openalex"
api_key_file="synthetic.key""#,
        r#"kind="http"
endpoint="https://papers.example/v1/search"
bearer_token_file="synthetic.token""#,
    ] {
        assert!(
            toml::from_str::<PaperProviderConfig>(good).is_ok(),
            "W02 variant"
        );
        for extra in [
            "extra=1",
            "api_key='private'",
            "budget=1",
            "token='private'",
        ] {
            assert!(
                toml::from_str::<PaperProviderConfig>(&format!("{good}\n{extra}")).is_err(),
                "W02 unknown fields"
            );
        }
    }
    for bad in [
        "kind='unknown'",
        "kind='openalex'",
        "api_key_file='missing-kind'",
        "kind='openalex'\napi_key_file='a'\nbearer_token_file='b'",
        "kind='http'\nendpoint='https://papers.example/v1/search'",
        "kind='http'\nbearer_token_file='a'",
        concat!(
            "kind='http'\nendpoint='https://papers.example/v1/search'\n",
            "bearer_token_file='a'\napi_key_file='b'"
        ),
    ] {
        assert!(
            toml::from_str::<PaperProviderConfig>(bad).is_err(),
            "W02 closed configuration"
        );
    }
    let root = must(crate::gen_temp_dir());
    let path = root.as_ref().join("invalid-config");
    for text in ["private = [", "[v1]\nrequest_timeout_ms=0"] {
        private_file(&path, text.as_bytes());
        let err = crate::config::papers::read_api_config(&path).err().unwrap();
        assert!(
            err.to_string() == "Paper provider configuration is invalid",
            "W02 fixed error"
        );
    }
}

// Private descriptors, exact payload syntax and a one-byte-over read are exercised through build.
#[test]
fn w03_secret_files() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let root = must(crate::gen_temp_dir());
    let path = root.as_ref().join("credential");
    for http in [false, true] {
        let build = || {
            if http {
                PaperProviderConfig::Http {
                    endpoint: "http://127.0.0.1:9/v1/search".into(),
                    bearer_token_file: path.clone(),
                }
                .build()
            } else {
                PaperProviderConfig::Openalex {
                    api_key_file: path.clone(),
                }
                .build()
            }
        };
        let cap = if http { 64 } else { 1024 };
        for bytes in [vec![b'a'; cap], [vec![b'a'; cap], vec![b'\n']].concat()] {
            private_file(&path, &bytes);
            assert!(build().is_ok(), "W03 exact cap");
        }
        let mut bad = vec![
            Vec::new(),
            vec![b'a'; cap + 1],
            b"bad\r\n".to_vec(),
            b"two\nlines".to_vec(),
            b"white space".to_vec(),
            vec![0],
            [vec![b'a'; cap], b"\ntail".to_vec()].concat(),
        ];
        if http {
            bad.extend([vec![b'A'; 64], vec![b'a'; 63], vec![b'g'; 64]]);
        }
        for bytes in bad {
            private_file(&path, &bytes);
            assert!(build().is_err(), "W03 credential syntax");
        }
        private_file(&path, &credential(http));
        // Inject at the real descriptor observation because unprivileged fixtures cannot chown.
        crate::config::papers::PAPER_OWNER.with(|v| v.set(Some(u32::MAX)));
        let foreign = build().is_err();
        crate::config::papers::PAPER_OWNER.with(|v| v.set(None));
        assert!(foreign, "W03 descriptor owner");
        must(std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(0o644),
        ));
        assert!(build().is_err(), "W03 private mode");
        private_file(&path, &credential(http));
        let alias = root.as_ref().join("alias");
        must(std::fs::hard_link(&path, &alias));
        assert!(build().is_err(), "W03 single link");
        must(std::fs::remove_file(&alias));
        must(std::fs::rename(&path, &alias));
        must(symlink(&alias, &path));
        assert!(build().is_err(), "W03 no symlink");
        must(std::fs::remove_file(&path));
        must(std::fs::remove_file(&alias));
        must(std::fs::create_dir(&path));
        assert!(build().is_err(), "W03 regular descriptor");
        must(std::fs::remove_dir(&path));
        fifo_secret(&path, &credential(http), &build);
    }
}

// Keep a read descriptor open after writing so a regular-file bypass sees valid FIFO payload bytes.
fn fifo_secret(
    path: &Path,
    bytes: &[u8],
    build: &impl Fn() -> Result<Arc<dyn PaperProvider>, PaperProviderError>,
) {
    use std::{
        io::Write,
        os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    };
    let name = must(std::ffi::CString::new(path.as_os_str().as_bytes()));
    // The NUL-terminated owned name remains valid throughout the call.
    assert!(
        unsafe { libc::mkfifo(name.as_ptr(), 0o600) } == 0,
        "W03 FIFO fixture"
    );
    let mut writer = must(
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path),
    );
    must(writer.write_all(bytes));
    let reader = must(
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path),
    );
    drop(writer);
    assert!(build().is_err(), "W03 regular file gate");
    drop(reader);
    must(std::fs::remove_file(path));
}

// Every real constructor must retain the selected provider through the exact attachment expression.
#[tokio::test]
async fn w04_startup_wiring() {
    for constructor in 0..4 {
        let root = must(crate::gen_temp_dir());
        let server = Server::new(ResponseSpec::json(200, HTTP_EMPTY)).await;
        let mut config = config(root.as_ref());
        let token = root.as_ref().join("token");
        private_file(&token, &credential(true));
        config.v1.paper_provider = Some(PaperProviderConfig::Http {
            endpoint: server.endpoint(),
            bearer_token_file: token,
        });
        let (first, second) = must(
            tokio::task::spawn_blocking(move || {
                let resources = must(match constructor {
                    0 => V1Resources::load(&config),
                    1 => V1Resources::with_store(
                        &config,
                        Arc::new(must(v1::suppression::SuppressionStore::open(
                            &config.v1.suppression_store_path,
                        ))),
                    ),
                    2 => V1Resources::with_compliance_seams(&config, Default::default()),
                    _ => V1Resources::with_ingest_seams(
                        &config,
                        Default::default(),
                        Default::default(),
                    ),
                });
                let backend = web(Arc::new(AtomicUsize::new(0)));
                let make = || {
                    Arc::new(
                        V1State::from_resources(&config, backend.clone(), &resources)
                            .with_ingest_backend(Arc::new(|_: v1::AuditedIngestPage| async {
                                Err(v1::IngestBackendFailure::Unavailable)
                            })),
                    )
                };
                (make(), make())
            })
            .await,
        );
        assert!(
            Arc::ptr_eq(&first.papers, &second.papers)
                && Arc::ptr_eq(&first.papers.admission, &second.papers.admission),
            "W04 shared owner"
        );
        let (Some(a), Some(b)) = (&first.papers.provider, &second.papers.provider) else {
            panic!("W04 provider retained");
        };
        assert!(Arc::ptr_eq(a, b), "W04 provider identity");
        assert!(
            send(first, paper_request()).await.status == 200 && server.count() == 1,
            "W04 real startup routing"
        );
        assert!(
            send(second, paper_request()).await.status == 200 && server.count() == 2,
            "W04 second state routing"
        );
        server.finish().await;
    }
    let source = include_str!("../../mod.rs");
    let attach = source
        .split("fn attach_v1(")
        .nth(1)
        .unwrap()
        .split("\n}")
        .next()
        .unwrap();
    assert!(
        attach.contains("v1::V1State::from_resources(config, backend, v1_resources)"),
        "W04 actual attachment pin"
    );
    let root = must(crate::gen_temp_dir());
    let mut config = config(root.as_ref());
    config.v1.paper_provider = Some(PaperProviderConfig::Openalex {
        api_key_file: root.as_ref().join("missing-secret"),
    });
    let result = crate::entrypoint::api::run(config).await;
    assert!(
        result.err().is_some_and(|e| e.is::<PaperProviderError>()),
        "W04 before cluster"
    );
}

// A real local index and ApiSearcher control excludes canned response camouflage.
async fn local_web(root: &Path, calls: Arc<AtomicUsize>) -> Arc<dyn SearchBackend> {
    use crate::searcher::{
        api::{ApiSearcher, Config},
        distributed::LocalSearchClient,
        LocalSearcher,
    };
    let mut index = must(crate::index::Index::open(root));
    index.set_shard_id(crate::inverted_index::ShardId::Backbone(0));
    must(index.prepare_writer());
    for suffix in ["a", "b", "c"] {
        let html = "<html><head><title>Synthetic cedar experiment</title></head>\
            <body>synthetic cedar experiment and independent fixture vocabulary</body></html>";
        let parsed = must(crate::webpage::Html::parse(
            html,
            &format!("https://web.example/{suffix}"),
        ));
        must(index.insert(&crate::webpage::Webpage::from(parsed)));
    }
    must(index.commit());
    let local = LocalSearcher::builder(Arc::new(tokio::sync::RwLock::new(index))).build();
    let mut config = Config::default();
    config.widgets.calculator_fetch_currencies_exchange = false;
    config.widgets.thesaurus_paths.clear();
    let searcher: ApiSearcher<LocalSearchClient, crate::webgraph::Webgraph> = ApiSearcher::new(
        LocalSearchClient::from(local),
        None,
        crate::bangs::Bangs::empty(),
        config,
    )
    .await;
    let searcher = Arc::new(searcher);
    Arc::new(move |query: crate::searcher::SearchQuery| {
        calls.fetch_add(1, SeqCst);
        assert!(
            !query.return_ranking_signals
                && !query.return_structured_data
                && query.return_body.is_none(),
            "W06 web query defaults"
        );
        let searcher = searcher.clone();
        async move { searcher.search(&query).await }
    })
}

// Missing and false flags compare complete bytes across all three real startup configurations.
#[tokio::test]
async fn w06_web_identity() {
    let index = must(crate::gen_temp_dir());
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = local_web(index.as_ref(), calls.clone()).await;
    let oa = Server::new(ResponseSpec::json(200, OPENALEX)).await;
    let http = Server::new(ResponseSpec::json(200, HTTP)).await;
    let mut roots = Vec::new();
    let mut states = Vec::new();
    for kind in 0..3 {
        let root = must(crate::gen_temp_dir());
        let mut config = config(root.as_ref());
        let secret = root.as_ref().join("secret");
        private_file(&secret, &credential(kind == 2));
        config.v1.paper_provider = match kind {
            1 => Some(PaperProviderConfig::Openalex {
                api_key_file: secret,
            }),
            2 => Some(PaperProviderConfig::Http {
                endpoint: http.endpoint(),
                bearer_token_file: secret,
            }),
            _ => None,
        };
        let backend = backend.clone();
        let origin = must(url::Url::parse(&format!("http://{}/works", oa.addr)));
        let state = must(
            tokio::task::spawn_blocking(move || {
                ORIGIN.with(|v| *v.borrow_mut() = Some(origin));
                let state = Arc::new(must(V1State::initialize(&config, backend)));
                ORIGIN.with(|v| *v.borrow_mut() = None);
                state
            })
            .await,
        );
        roots.push(root);
        states.push(state);
    }
    for (query, page) in [
        ("cedar", 0),
        ("cedar", 1),
        ("unfindablefixtureword", 0),
        ("\"cedar experiment\"", 0),
        ("site:web.example cedar", 0),
    ] {
        let request = json!({"query":query,"page":page,"num_results":1});
        let baseline = send(states[0].clone(), request.clone()).await;
        assert!(baseline.status == 200, "W06 real web success");
        if query == "cedar" {
            assert!(
                !value(&baseline.bytes)["results"]
                    .as_array()
                    .unwrap()
                    .is_empty(),
                "W06 real positive hits"
            );
        }
        for state in &states {
            for explicit in [false, true] {
                let mut body = request.clone();
                if explicit {
                    body["scholarly"] = json!(false);
                }
                let reply = send(state.clone(), body).await;
                assert!(
                    reply.status == baseline.status && reply.bytes == baseline.bytes,
                    "W06 identical web bytes"
                );
                for header in [
                    "source-offer",
                    "x-api-version",
                    "reports-and-requests",
                    "content-type",
                ] {
                    assert!(
                        reply.headers.get(header) == baseline.headers.get(header),
                        "W06 stable headers"
                    );
                }
                assert!(
                    value(&reply.bytes)["results"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|hit| hit.get("scholarly").is_none()),
                    "W06 web shape"
                );
            }
        }
    }
    assert!(
        oa.count() == 0 && http.count() == 0 && calls.load(SeqCst) > 0,
        "W06 off path idle"
    );
    for state in &states[1..] {
        assert!(
            send(state.clone(), paper_request()).await.status == 200,
            "W06 configured provider active"
        );
    }
    assert!(oa.count() == 1 && http.count() == 1, "W06 activated once");
    drop(states);
    drop(roots);
    oa.finish().await;
    http.finish().await;
}

// Missing providers must preserve owned errors and never call a visibly nonempty web backend.
#[tokio::test]
async fn w05_unavailable_route() {
    let root = must(crate::gen_temp_dir());
    let calls = Arc::new(AtomicUsize::new(0));
    let state = state(config(root.as_ref()), web(calls.clone())).await;
    let reply = send(state.clone(), paper_request()).await;
    unavailable(&reply, "W05 unavailable");
    assert!(calls.load(SeqCst) == 0, "W05 no fallback");
    let reply = send(state, json!({"query":"synthetic"})).await;
    assert!(
        reply.status == 200 && value(&reply.bytes)["results"].as_array().unwrap().len() == 1,
        "W05 web control"
    );
}

// Both public construction and actual HTTP extraction enforce the paper input bounds.
#[tokio::test]
async fn w07_request_bounds() {
    let root = must(crate::gen_temp_dir());
    let calls = Arc::new(AtomicUsize::new(0));
    let state = state(config(root.as_ref()), web(calls.clone())).await;
    for (query, page, count, valid) in [
        ("a".into(), 0, 0, false),
        ("a".into(), 0, 1, true),
        ("a".into(), 98, 20, true),
        ("a".into(), 99, 20, true),
        ("a".into(), 100, 20, false),
        ("a".into(), 0, 21, false),
        ("a".repeat(4096), 0, 1, true),
        ("a".repeat(4097), 0, 1, false),
        (vec!["a"; 64].join(" "), 0, 1, true),
        (vec!["a"; 65].join(" "), 0, 1, false),
        ("?!".into(), 0, 1, false),
        ("a\0".into(), 0, 1, false),
    ] {
        assert!(
            PaperQuery::try_new(query.clone(), page, count).is_ok() == valid,
            "W07 Rust bounds"
        );
        let response = send(
            state.clone(),
            json!({"query":query,"page":page,
            "num_results":count,"scholarly":true}),
        )
        .await;
        if valid {
            unavailable(&response, "W07 route bounds");
        } else {
            closed(
                &response,
                400,
                "invalid_request",
                "The search request is invalid",
                "W07 route bounds",
            );
        }
    }
    for bad in [Value::Null, json!(1), json!("true")] {
        let response = send(state.clone(), json!({"query":"a","scholarly":bad})).await;
        closed(
            &response,
            400,
            "invalid_request",
            "The search request is invalid",
            "W07 strict boolean",
        );
    }
    let response = send(
        state.clone(),
        json!({"query":"a","scholarly":true,"provider":"http"}),
    )
    .await;
    closed(
        &response,
        400,
        "invalid_request",
        "The search request is invalid",
        "W07 extra field",
    );
    assert!(calls.load(SeqCst) == 0, "W07 before work");
    assert!(
        send(state, json!({"query":"a","num_results":100}))
            .await
            .status
            == 200,
        "W07 web count"
    );
}

struct Custom {
    calls: Arc<AtomicUsize>,
    result: Result<(), PaperProviderError>,
    hits: usize,
    next: Option<u16>,
}

impl PaperProvider for Custom {
    // Internal malformed pages deliberately bypass construction to witness the route's own check.
    fn search(&self, query: PaperQuery) -> BoxFuture<'_, Result<PaperPage, PaperProviderError>> {
        self.calls.fetch_add(1, SeqCst);
        Box::pin(async move {
            self.result?;
            assert!(query.query() == "Synthetic Cedar", "W08 original query");
            assert!(
                query.page() == 0 && query.num_results() == 2,
                "W08 original numbers"
            );
            let hit: AttributedResult = if self.hits == 0 {
                must(AttributedResult::try_new(
                    "https://web.example/",
                    "web.example",
                    "Title",
                    "",
                ))
            } else {
                must(serde_json::from_value(value(HTTP)["results"][0].clone()))
            };
            Ok(PaperPage {
                results: vec![hit; self.hits.max(1)],
                next_page: self.next,
            })
        })
    }
}

// Trusted providers still face the route's count/hint boundary and all fixed failure mappings.
#[tokio::test]
async fn w08_provider_seam() {
    for failure in [
        None,
        Some(PaperProviderError::Configuration),
        Some(PaperProviderError::InvalidRequest),
        Some(PaperProviderError::Unavailable),
        Some(PaperProviderError::InvalidResponse),
        Some(PaperProviderError::Deadline),
    ] {
        let root = must(crate::gen_temp_dir());
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(Custom {
            calls: calls.clone(),
            result: failure.map_or(Ok(()), Err),
            hits: 1,
            next: Some(1),
        });
        let reply = send(
            provider_state(root.as_ref(), provider).await,
            paper_request(),
        )
        .await;
        match failure {
            None => assert!(
                reply.status == 200
                    && value(&reply.bytes)
                        == json!({"version":"v1", "results":[
                        value(HTTP)["results"][0].clone()
                    ], "has_more_results":true, "page":0, "num_results":2}),
                "W08 provider success"
            ),
            Some(PaperProviderError::InvalidResponse) => invalid(&reply, "W08 invalid response"),
            Some(PaperProviderError::Deadline) => closed(
                &reply,
                504,
                "request_timeout",
                "The request timed out",
                "W08 deadline",
            ),
            _ => unavailable(&reply, "W08 closed failure"),
        }
        assert!(calls.load(SeqCst) == 1, "W08 once");
    }
    for (hits, next) in [(3, Some(1)), (1, Some(2)), (0, None)] {
        let root = must(crate::gen_temp_dir());
        let provider = Arc::new(Custom {
            calls: Arc::new(AtomicUsize::new(0)),
            result: Ok(()),
            hits,
            next,
        });
        invalid(
            &send(
                provider_state(root.as_ref(), provider).await,
                paper_request(),
            )
            .await,
            "W08 route validation",
        );
    }
    let web = must(AttributedResult::try_new(
        "https://web.example/",
        "web.example",
        "Title",
        "",
    ));
    assert!(
        PaperPage::try_new(vec![web], None).is_err(),
        "W08 attribution required"
    );
}

// Full DTO roundtrips preserve ordered names and truthful live/snapshot provenance.
#[tokio::test]
async fn w09_attribution_roundtrip() {
    let expected = value(EXPECTED);
    for hit in expected["results"].as_array().unwrap() {
        let decoded: AttributedResult = must(serde_json::from_value(hit.clone()));
        assert!(
            must(serde_json::to_value(decoded)) == *hit,
            "W09 whole roundtrip"
        );
    }
    for year in [1, 1901, 2026, 9999] {
        let mut hit = value(HTTP)["results"][0].clone();
        hit["scholarly"]["publication_year"] = json!(year);
        assert!(
            serde_json::from_value::<AttributedResult>(hit).is_ok(),
            "W09 broader years"
        );
    }
    let (reply, _) = roundtrip(false, ResponseSpec::json(200, OPENALEX), paper_request()).await;
    assert!(
        reply.status == 200 && value(&reply.bytes) == expected,
        "W09 live snapshot"
    );
    let web = must(AttributedResult::try_new(
        "https://web.example/",
        "web.example",
        "Title",
        "",
    ));
    let web = must(serde_json::to_value(web));
    assert!(
        web.as_object().unwrap().len() == 5 && web.get("scholarly").is_none(),
        "W09 web shape"
    );
}

// The real OpenAlex adapter and local router must equal a wholly independent expected value.
#[tokio::test]
async fn w12_openalex_mapping() {
    let (reply, count) = roundtrip(false, ResponseSpec::json(200, OPENALEX), paper_request()).await;
    assert!(
        reply.status == 200 && value(&reply.bytes) == value(EXPECTED),
        "W12 whole response"
    );
    assert!(count == 1, "W12 once");
}

// Count boundaries and terminal pages are independent of local filtering and remote result count.
#[tokio::test]
async fn w13_openalex_paging() {
    for page in [0, 98, 99] {
        for (count, expected) in [
            (0, false),
            ((page + 1) * 3, false),
            ((page + 1) * 3 + 1, page < 99),
        ] {
            let mut body = value(OA_EMPTY);
            body["meta"]["count"] = json!(count);
            let root = must(crate::gen_temp_dir());
            let server = Server::new(ResponseSpec::json(200, body.to_string().as_bytes())).await;
            let provider = provider(root.as_ref(), &server, false);
            let reply = send(
                provider_state(root.as_ref(), provider).await,
                json!({"query":"cedar","page":page,"num_results":3,"scholarly":true}),
            )
            .await;
            assert!(
                reply.status == 200 && value(&reply.bytes)["has_more_results"] == expected,
                "W13 count boundary"
            );
            {
                let requests = must(server.requests.lock());
                assert!(requests.len() == 1, "W13 once");
                let url = must(url::Url::parse(&format!(
                    "http://fixture.test{}",
                    requests[0].path
                )));
                let pairs: std::collections::BTreeMap<_, _> =
                    url.query_pairs().into_owned().collect();
                assert!(
                    pairs.get("page") == Some(&(page + 1).to_string())
                        && pairs.get("per_page") == Some(&"3".to_string()),
                    "W13 wire paging"
                );
            }
            server.finish().await;
        }
    }
}

// Bearer transport and decoded query pairs are pinned independently, including reserved characters.
#[tokio::test]
async fn w14_openalex_key() {
    let root = must(crate::gen_temp_dir());
    let mut spec = ResponseSpec::json(200, OA_EMPTY);
    spec.authority = Some(credential(false));
    let server = Server::new(spec).await;
    let provider = provider(root.as_ref(), &server, false);
    let query = "Cedar + & ? # É";
    let reply = send(
        provider_state(root.as_ref(), provider).await,
        json!({"query":query,"num_results":3,"page":4,"scholarly":true}),
    )
    .await;
    assert!(reply.status == 200, "W14 correct credential");
    {
        let requests = must(server.requests.lock());
        assert!(requests.len() == 1, "W14 once");
        let wire = &requests[0];
        let url = must(url::Url::parse(&format!(
            "http://fixture.test{}",
            wire.path
        )));
        let pairs: Vec<_> = url.query_pairs().into_owned().collect();
        assert!(
            pairs
                == vec![
                    ("search".into(), query.into()),
                    ("per_page".into(), "3".into()),
                    ("page".into(), "5".into())
                ],
            "W14 exact query pairs"
        );
        let bearer = [b"Bearer ".as_slice(), &credential(false)].concat();
        assert!(
            wire.header("authorization") == vec![bearer.as_slice()]
                && wire.method == "GET"
                && wire.body.is_empty(),
            "W14 header only credential"
        );
    }
    server.finish().await;
    let mut wrong = ResponseSpec::json(200, OA_EMPTY);
    wrong.authority = Some(b"different-valid-synthetic-key".to_vec());
    let (reply, count) = roundtrip(false, wrong, paper_request()).await;
    unavailable(&reply, "W14 wrong valid key");
    assert!(count == 1, "W14 no retry");
}

// OpenAlex non-200 responses have no media precondition, but every body remains bounded.
#[tokio::test]
async fn w15_openalex_errors() {
    for status in [400, 401, 403, 404, 429, 500, 503] {
        let mut spec = ResponseSpec::json(status, b"synthetic reflected provider prose");
        spec.headers.clear();
        let (reply, count) = roundtrip(false, spec, paper_request()).await;
        unavailable(&reply, "W15 exact non-success");
        assert!(count == 1, "W15 no retry");
    }
    let (reply, count) = roundtrip(false, ResponseSpec::json(200, b"{"), paper_request()).await;
    invalid(&reply, "W15 invalid success");
    assert!(count == 1, "W15 malformed once");
}

// The compatible-service request contains exactly the documented method, headers and three keys.
#[tokio::test]
async fn w16_http_request() {
    let root = must(crate::gen_temp_dir());
    let server = Server::new(ResponseSpec::json(200, HTTP_EMPTY)).await;
    let provider = provider(root.as_ref(), &server, true);
    let reply = send(
        provider_state(root.as_ref(), provider).await,
        json!({"query":"Cedar É & ?","page":7,"num_results":3,"scholarly":true,
            "country":"UK","adult_verified":false}),
    )
    .await;
    assert!(reply.status == 200, "W16 success");
    {
        let requests = must(server.requests.lock());
        assert!(requests.len() == 1, "W16 once");
        let request = &requests[0];
        assert!(
            request.method == "POST" && request.path == "/v1/search",
            "W16 method path"
        );
        assert!(request.body == br#"{"query":"Cedar "#.iter().copied().chain(
        "É & ?\",\"page\":7,\"num_results\":3}".bytes()).collect::<Vec<_>>(), "W16 exact body");
        let expected = [b"Bearer ".as_slice(), &credential(true)].concat();
        assert!(
            request.header("authorization") == vec![expected.as_slice()],
            "W16 one bearer"
        );
        assert!(
            request.header("content-type") == vec![b"application/json".as_slice()]
                && request.header("accept") == vec![b"application/json".as_slice()]
                && request.header("accept-encoding") == vec![b"identity".as_slice()],
            "W16 media"
        );
    }
    server.finish().await;
}

// Independent full values include every identity, null, ordered author and prefilter page hint.
#[tokio::test]
async fn w17_http_whole_response() {
    for fixture in [HTTP, HTTP_EMPTY] {
        let (reply, count) =
            roundtrip(true, ResponseSpec::json(200, fixture), paper_request()).await;
        let upstream = value(fixture);
        let expected = json!({"version":"v1","results":upstream["results"],"page":0,
            "num_results":2,"has_more_results":!upstream["next_page"].is_null()});
        assert!(
            reply.status == 200 && value(&reply.bytes) == expected,
            "W17 whole response"
        );
        let ordered = format!(
            "{{\"version\":\"v1\",\"results\":{},\"page\":0,\"num_results\":2,\
            \"has_more_results\":{}}}",
            must(serde_json::to_string(&must(serde_json::from_value::<
                Vec<AttributedResult>,
            >(
                upstream["results"].clone()
            )))),
            !upstream["next_page"].is_null()
        );
        assert!(
            reply.bytes == ordered.as_bytes() && count == 1,
            "W17 compact local envelope"
        );
    }
    for hint in [json!(2), json!(100), json!(true), json!(1.5)] {
        let mut bad = value(HTTP_EMPTY);
        bad["next_page"] = hint;
        let (reply, _) = roundtrip(
            true,
            ResponseSpec::json(200, bad.to_string().as_bytes()),
            paper_request(),
        )
        .await;
        invalid(&reply, "W17 exact hint relation");
    }
}

// A valid different token tests forwarding and closed mapping beside a positive control.
#[tokio::test]
async fn w18_wrong_bearer() {
    for correct in [true, false] {
        let mut spec = ResponseSpec::json(200, HTTP_EMPTY);
        spec.authority = Some(if correct {
            credential(true)
        } else {
            vec![b'b'; 64]
        });
        let (reply, count) = roundtrip(true, spec, paper_request()).await;
        if correct {
            assert!(reply.status == 200, "W18 correct bearer");
        } else {
            unavailable(&reply, "W18 wrong valid bearer");
        }
        assert!(count == 1, "W18 once");
    }
}

// All nine known errors require the exact one-key body, including 404 and 405.
#[tokio::test]
async fn w19_http_errors() {
    for (status, name) in [
        (400, "invalid-request"),
        (401, "unauthenticated"),
        (413, "body-too-large"),
        (429, "busy"),
        (503, "unavailable"),
        (504, "deadline"),
        (500, "internal"),
        (404, "not-found"),
        (405, "method-not-allowed"),
    ] {
        let body = format!("{{\"error\":\"{name}\"}}");
        let (reply, count) = roundtrip(
            true,
            ResponseSpec::json(status, body.as_bytes()),
            paper_request(),
        )
        .await;
        if status == 504 {
            closed(
                &reply,
                504,
                "request_timeout",
                "The request timed out",
                "W19 deadline",
            );
        } else {
            unavailable(&reply, "W19 exact error");
        }
        assert!(
            count == 1 && reply.headers.get("retry-after").is_none(),
            "W19 once local headers"
        );
        for bad in [
            br#"{"error":"wrong"}"#.to_vec(),
            format!("{{\"error\":\"{name}\",\"extra\":null}}").into_bytes(),
            format!("{{\"error\":\"{name}\",\"error\":\"{name}\"}}").into_bytes(),
        ] {
            let (reply, _) =
                roundtrip(true, ResponseSpec::json(status, &bad), paper_request()).await;
            invalid(&reply, "W19 reject mismatched error");
        }
    }
}

// Both connectors reject malformed JSON through their real decoder and map transport truncation.
#[tokio::test]
async fn w24_malformed_json() {
    for http in [false, true] {
        for bad in [
            vec![0xff],
            b"{".to_vec(),
            b"{} {}".to_vec(),
            b"[]".to_vec(),
            br#"{"results":[],"results":[],"next_page":null}"#.to_vec(),
        ] {
            let (reply, _) = roundtrip(http, ResponseSpec::json(200, &bad), paper_request()).await;
            invalid(&reply, "W24 malformed body");
        }
        let mut spec = ResponseSpec::json(200, &[]);
        spec.raw = Some(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
            Content-Length: 80\r\nConnection: close\r\n\r\n{"
                .to_vec(),
        );
        unavailable(
            &roundtrip(http, spec, paper_request()).await.0,
            "W24 truncated framing",
        );
    }
    let (reply, _) = roundtrip(
        true,
        ResponseSpec::json(200, br#"{"results":[],"next_page":null,"extra":0}"#),
        paper_request(),
    )
    .await;
    invalid(&reply, "W24 strict HTTP keys");
    let (reply, _) = roundtrip(
        false,
        ResponseSpec::json(200, br#"{"meta":{"count":0,"count":0},"results":[]}"#),
        paper_request(),
    )
    .await;
    invalid(&reply, "W24 duplicate known key");
}

// Ignored OpenAlex fields share the same depth and token budget as domain fields.
#[tokio::test]
async fn w25_json_complexity() {
    for (depth, valid) in [(32, true), (33, false)] {
        let nested = format!("{}0{}", "[".repeat(depth - 1), "]".repeat(depth - 1));
        let body = format!("{{\"meta\":{{\"count\":0}},\"results\":[],\"ignored\":{nested}}}");
        assert!(
            transport::parse(body.as_bytes()).is_ok() == valid,
            "W25 depth boundary"
        );
        let (reply, _) = roundtrip(
            false,
            ResponseSpec::json(200, body.as_bytes()),
            paper_request(),
        )
        .await;
        assert!(
            reply.status == if valid { 200 } else { 500 },
            "W25 ignored depth"
        );
    }
    for (count, valid) in [
        (MAX_PROVIDER_JSON_TOKENS - 13, true),
        (MAX_PROVIDER_JSON_TOKENS - 12, false),
    ] {
        let body = format!(
            "{{\"meta\":{{\"count\":0}},\"results\":[],\"noise\":[{}]}}",
            vec!["0"; count].join(",")
        );
        assert!(
            transport::parse(body.as_bytes()).is_ok() == valid,
            "W25 token boundary"
        );
        let reply = roundtrip(
            false,
            ResponseSpec::json(200, body.as_bytes()),
            paper_request(),
        )
        .await
        .0;
        assert!(
            reply.status == if valid { 200 } else { 500 },
            "W25 ignored token boundary"
        );
    }
    for (key, count) in [("results", 21), ("authors", 101)] {
        let array = format!("[{}]", vec!["null"; count].join(","));
        let body = if key == "results" {
            format!("{{\"results\":{array}}}")
        } else {
            format!("{{\"results\":[{{\"scholarly\":{{\"authors\":{array}}}}}]}}")
        };
        assert!(
            transport::parse(body.as_bytes()).is_err(),
            "W25 early array cap"
        );
    }
}

// Strict HTTP rejects whole pages, while precisely the documented OpenAlex defects drop records.
#[tokio::test]
async fn w26_record_bounds() {
    for (count, accepted) in [(100, true), (101, false)] {
        let bytes = must(serde_json::to_vec(&vec!["Name"; count]));
        let mut decoder = serde_json::Deserializer::from_slice(&bytes);
        assert!(
            v1::dto::paper_authors(&mut decoder).is_ok() == accepted,
            "W26 author allocation boundary"
        );
    }
    for (pointer, bad) in [
        ("/title", json!(null)),
        ("/title", json!(" ")),
        ("/title", json!("x".repeat(501))),
        ("/title", json!("🦀".repeat(501))),
        ("/publication_year", json!(null)),
        ("/publication_year", json!(0)),
        ("/publication_year", json!(10000)),
        ("/publication_year", json!(u64::MAX)),
        ("/publication_year", json!(-1)),
        ("/doi", json!("https://doi.org/10.5555/")),
        ("/doi", json!(42)),
        ("/best_oa_location/pdf_url", json!([])),
        ("/best_oa_location/pdf_url", json!("file:///synthetic")),
        ("/authorships/0/author/display_name", json!("x".repeat(257))),
        (
            "/primary_location/source/display_name",
            json!("x".repeat(257)),
        ),
        ("/primary_location/source/display_name", json!(" ")),
        (
            "/authorships",
            json!(vec![json!({"author":{"display_name":"Name"}}); 101]),
        ),
    ] {
        let mut body = value(OPENALEX);
        *body["results"][0].pointer_mut(pointer).unwrap() = bad;
        let (reply, count) = roundtrip(
            false,
            ResponseSpec::json(200, body.to_string().as_bytes()),
            paper_request(),
        )
        .await;
        let mut expected = value(EXPECTED);
        expected["results"].as_array_mut().unwrap().remove(0);
        assert!(
            reply.status == 200 && value(&reply.bytes) == expected && count == 1,
            "W26 OpenAlex drop"
        );
    }
    for (pointer, bad) in [
        ("/title", json!("x".repeat(501))),
        ("/scholarly/authors", json!(vec!["Name"; 101])),
        ("/scholarly/authors/0", json!("x".repeat(257))),
        ("/scholarly/venue", json!("🦀".repeat(257))),
        ("/scholarly/publication_year", json!(10000)),
    ] {
        let mut body = value(HTTP);
        *body["results"][0].pointer_mut(pointer).unwrap() = bad;
        assert!(
            serde_json::from_value::<AttributedResult>(body["results"][0].clone()).is_err(),
            "W26 direct DTO limits"
        );
        invalid(
            &roundtrip(
                true,
                ResponseSpec::json(200, body.to_string().as_bytes()),
                paper_request(),
            )
            .await
            .0,
            "W26 HTTP whole rejection",
        );
    }
    let mut body = value(HTTP);
    body["results"][0]["title"] = json!("🦀".repeat(500));
    body["results"][0]["scholarly"]["authors"] = json!(vec!["🦀".repeat(256); 100]);
    let reply = roundtrip(
        true,
        ResponseSpec::json(200, body.to_string().as_bytes()),
        paper_request(),
    )
    .await
    .0;
    assert!(reply.status == 200, "W26 exact Unicode bounds");
    record_link_bounds().await;
}

// Exact URL budgets and identity budgets remain independent of title and author constraints.
async fn record_link_bounds() {
    for (field, prefix, cap) in [
        ("doi", "https://doi.org/10.5555/", 2048),
        ("oa_url", "https://repository.example/", 2048),
        ("openalex_id", "https://openalex.org/W9999", 64),
    ] {
        for excess in [0, 1] {
            let mut body = value(HTTP);
            let link = format!("{prefix}{}", "1".repeat(cap + excess - prefix.len()));
            body["results"][0]["scholarly"][field] = json!(link);
            if field == "openalex_id" {
                body["results"][0]["url"] = json!(link);
                body["results"][0]["id"] =
                    json!(must(v1::suppression::canonical_identity(&link)).1.as_str());
            }
            let reply = roundtrip(
                true,
                ResponseSpec::json(200, body.to_string().as_bytes()),
                paper_request(),
            )
            .await
            .0;
            assert!(
                reply.status == if excess == 0 { 200 } else { 500 },
                "W26 link boundary"
            );
        }
    }
}

// Every redirect code must stop at the first server, even when Location reflects authentication.
#[tokio::test]
async fn w21_redirects() {
    for http in [false, true] {
        let destination = Server::new(ResponseSpec::json(200, HTTP_EMPTY)).await;
        for status in [301, 302, 303, 307, 308] {
            let mut spec = ResponseSpec::json(status, b"synthetic redirect");
            let key = must(String::from_utf8(credential(http)));
            spec.headers.push((
                "Location".into(),
                format!("{}?reflected={key}", destination.endpoint()),
            ));
            let (reply, count) = roundtrip(http, spec, paper_request()).await;
            unavailable(&reply, "W21 redirect refusal");
            assert!(
                count == 1 && destination.count() == 0,
                "W21 no second request"
            );
        }
        destination.finish().await;
    }
}

// Observed bytes, including small chunks and error bodies, enforce the exact cumulative cap.
#[tokio::test]
async fn w22_body_bounds() {
    for http in [false, true] {
        for status in [200, 401] {
            for excess in [0, 1] {
                let base = if status == 401 {
                    br#"{"error":"unauthenticated"}"#.as_slice()
                } else if http {
                    HTTP_EMPTY
                } else {
                    OA_EMPTY
                };
                let mut bytes = base.to_vec();
                bytes.resize(MAX_PROVIDER_BODY_BYTES + excess, b' ');
                let mut spec = ResponseSpec::json(status, &bytes);
                spec.chunk = 4096;
                let server = Server::new(spec).await;
                let budgets = transport::Budgets::default();
                let client = must(transport::client(budgets));
                let result =
                    transport::exchange(client.get(server.endpoint()), budgets, http).await;
                if excess == 0 {
                    assert!(
                        result.is_ok_and(|r| r.body.len() == MAX_PROVIDER_BODY_BYTES),
                        "W22 exact cumulative cap"
                    );
                } else {
                    let expected = if !http && status != 200 {
                        PaperProviderError::Unavailable
                    } else {
                        PaperProviderError::InvalidResponse
                    };
                    assert!(result.err() == Some(expected), "W22 cumulative overflow");
                }
                assert!(server.count() == 1, "W22 no retry");
                server.finish().await;
            }
        }
    }
    let mut spec = ResponseSpec::json(200, HTTP_EMPTY);
    spec.raw = Some(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
        Content-Length: 400\r\nConnection: close\r\n\r\n{}"
            .to_vec(),
    );
    unavailable(
        &roundtrip(true, spec, paper_request()).await.0,
        "W22 overstated length",
    );
}

// Phase deadlines remain distinguishable from the longer transport and route backstops.
#[tokio::test]
async fn w23_deadlines() {
    let budgets = transport::Budgets {
        connect: Duration::from_millis(100),
        header: Duration::from_millis(300),
        idle: Duration::from_millis(100),
        total: Duration::from_secs(1),
    };
    for phase in ["headers", "idle", "trickle", "connect"] {
        let mut spec = ResponseSpec::json(200, &[b' '; 100]);
        match phase {
            "headers" => spec.header_delay = Duration::from_secs(2),
            "idle" => spec.chunk_delay = Duration::from_secs(2),
            "trickle" => {
                spec.chunk = 1;
                spec.chunk_delay = Duration::from_millis(50);
            }
            _ => {}
        }
        let server = Server::new(spec).await;
        let client = must(transport::client(budgets));
        let endpoint = if phase == "connect" {
            format!("https://{}/v1/search", server.addr)
        } else {
            server.endpoint()
        };
        let start = std::time::Instant::now();
        let result = transport::exchange(client.get(endpoint), budgets, true).await;
        let elapsed = start.elapsed().as_secs_f64();
        assert!(
            matches!(result, Err(PaperProviderError::Deadline)),
            "W23 deadline identity"
        );
        let valid = match phase {
            "headers" => elapsed < 0.6,
            "idle" => elapsed < 0.5,
            "trickle" => (1.0..1.5).contains(&elapsed),
            _ => elapsed < 0.3,
        };
        assert!(valid, "W23 phase deadline window");
        server.finish().await;
    }
    route_timeout_cleanup().await;
}

// The outer v1 timeout drops the actual provider future and releases its shared permit.
async fn route_timeout_cleanup() {
    let root = must(crate::gen_temp_dir());
    let mut spec = ResponseSpec::json(200, HTTP_EMPTY);
    spec.header_delay = Duration::from_secs(1);
    let server = Server::new(spec).await;
    let provider = provider(root.as_ref(), &server, true);
    let mut config = config(root.as_ref());
    config.v1.request_timeout_ms = 50;
    let state = must(
        tokio::task::spawn_blocking(move || {
            let resources = must(V1Resources::load(&config)).with_paper_provider(provider);
            Arc::new(V1State::from_resources(
                &config,
                web(Arc::new(AtomicUsize::new(0))),
                &resources,
            ))
        })
        .await,
    );
    closed(
        &send(state.clone(), paper_request()).await,
        504,
        "request_timeout",
        "The request timed out",
        "W23 outer timeout",
    );
    assert!(
        state.papers.admission.available_permits() == 4 && server.count() == 1,
        "W23 cancellation capacity"
    );
    server.finish().await;
}

// Header caps count duplicate values and byte lengths; encoding is never silently decoded.
#[tokio::test]
async fn w27_headers_encoding() {
    for http in [false, true] {
        let body = if http { HTTP_EMPTY } else { OA_EMPTY };
        let mut cases = vec![
            vec![],
            vec![("Content-Type".into(), "text/plain".into())],
            vec![(
                "Content-Type".into(),
                "application/json; charset=utf-8; extra=x".into(),
            )],
        ];
        for encoding in ["gzip", "deflate", "br", "unknown"] {
            cases.push(vec![
                ("Content-Type".into(), "application/json".into()),
                ("Content-Encoding".into(), encoding.into()),
            ]);
        }
        cases.push(vec![("Content-Type".into(), "application/json".into()); 2]);
        cases.push(vec![
            ("Content-Type".into(), "application/json".into()),
            ("Content-Encoding".into(), "identity".into()),
            ("Content-Encoding".into(), "identity".into()),
        ]);
        for headers in cases {
            let mut spec = ResponseSpec::json(200, body);
            spec.headers = headers;
            invalid(
                &roundtrip(http, spec, paper_request()).await.0,
                "W27 media refusal",
            );
        }
        for (extra, valid) in [(29, true), (30, false)] {
            let mut spec = ResponseSpec::json(200, body);
            spec.headers
                .extend(vec![("x-count".into(), "a".into()); extra]);
            let reply = roundtrip(http, spec, paper_request()).await.0;
            assert!(
                reply.status == if valid { 200 } else { 500 },
                "W27 header count"
            );
        }
        for (length, valid) in [(16_311, true), (16_312, false)] {
            let mut spec = ResponseSpec::json(200, body);
            spec.headers.push(("x-fill".into(), "a".repeat(length)));
            let reply = roundtrip(http, spec, paper_request()).await.0;
            assert!(
                reply.status == if valid { 200 } else { 500 },
                "W27 header bytes"
            );
        }
    }
}

// No identity, URL, snippet or licence supplied by a remote service is trusted without validation.
#[tokio::test]
async fn w33_forged_identity() {
    for (pointer, bad) in [
        ("/id", json!("0".repeat(64))),
        ("/domain", json!("foreign.example")),
        (
            "/scholarly/openalex_id",
            json!("https://openalex.org/W9999000003"),
        ),
        (
            "/scholarly/openalex_id",
            json!("https://openalex.org/W9999x"),
        ),
        ("/scholarly/doi", json!("http://doi.org/10.5555/synthetic")),
        (
            "/scholarly/oa_url",
            json!("https://user:pass@repository.example/a"),
        ),
        ("/scholarly/oa_url", json!("file:///synthetic")),
        (
            "/scholarly/oa_url",
            json!("https://repository.example/a#fragment"),
        ),
        ("/scholarly/metadata_license", json!("CC0")),
    ] {
        let mut body = value(HTTP);
        *body["results"][0].pointer_mut(pointer).unwrap() = bad;
        invalid(
            &roundtrip(
                true,
                ResponseSpec::json(200, body.to_string().as_bytes()),
                paper_request(),
            )
            .await
            .0,
            "W33 forged result",
        );
    }
}

// Required nullable keys cannot disappear, and a present null attribution cannot masquerade as web.
#[tokio::test]
async fn w34_required_nulls() {
    for key in ["doi", "oa_url", "venue", "snapshot_date"] {
        let mut hit = value(HTTP)["results"][0].clone();
        hit["scholarly"][key] = Value::Null;
        assert!(
            serde_json::from_value::<AttributedResult>(hit.clone()).is_ok(),
            "W34 explicit null"
        );
        hit["scholarly"].as_object_mut().unwrap().remove(key);
        assert!(
            serde_json::from_value::<AttributedResult>(hit).is_err(),
            "W34 required key"
        );
    }
    let mut body = value(HTTP);
    body["results"][0]["scholarly"]["snapshot_date"] = Value::Null;
    invalid(
        &roundtrip(
            true,
            ResponseSpec::json(200, body.to_string().as_bytes()),
            paper_request(),
        )
        .await
        .0,
        "W34 HTTP snapshot",
    );
    for body in [
        json!({"results":[]}),
        json!({"results":[],"next_page":true}),
    ] {
        invalid(
            &roundtrip(
                true,
                ResponseSpec::json(200, body.to_string().as_bytes()),
                paper_request(),
            )
            .await
            .0,
            "W34 required hint",
        );
    }
    let web = must(AttributedResult::try_new(
        "https://web.example/",
        "web.example",
        "Title",
        "",
    ));
    let mut web = must(serde_json::to_value(web));
    assert!(
        serde_json::from_value::<AttributedResult>(web.clone()).is_ok(),
        "W34 web omission"
    );
    web["scholarly"] = Value::Null;
    assert!(
        serde_json::from_value::<AttributedResult>(web).is_err(),
        "W34 nonnull attribution"
    );
}

// Abstract/full-text metadata stays inert and cannot become excerpts or another fetch.
#[tokio::test]
async fn w38_metadata_only() {
    let mut body = value(OPENALEX);
    body["results"][0]["content_urls"] = json!({"pdf":"https://content.example/private.pdf"});
    let (reply, count) = roundtrip(
        false,
        ResponseSpec::json(200, body.to_string().as_bytes()),
        paper_request(),
    )
    .await;
    assert!(
        reply.status == 200 && value(&reply.bytes) == value(EXPECTED) && count == 1,
        "W38 metadata only"
    );
    let mut body = value(HTTP);
    body["results"][0]["snippet"] = json!("synthetic unlicensed excerpt");
    assert!(
        serde_json::from_value::<AttributedResult>(body["results"][0].clone()).is_err(),
        "W38 DTO excerpt refusal"
    );
    invalid(
        &roundtrip(
            true,
            ResponseSpec::json(200, body.to_string().as_bytes()),
            paper_request(),
        )
        .await
        .0,
        "W38 excerpt refusal",
    );
}

// Abstract words must remain inert even when they coincide with protocol array names.
#[tokio::test]
async fn w43_structural_array_caps() {
    let mut body = value(OPENALEX);
    body["results"][0]["abstract_inverted_index"] = json!({
        "results": (0..25).collect::<Vec<_>>(),
        "authors": (25..145).collect::<Vec<_>>()
    });
    let (reply, count) = roundtrip(
        false,
        ResponseSpec::json(200, body.to_string().as_bytes()),
        paper_request(),
    )
    .await;
    assert!(
        reply.status == 200 && value(&reply.bytes) == value(EXPECTED) && count == 1,
        "W43 abstract words preserve complete page"
    );
}

// Unknown error bodies obey the same byte cap without acquiring a success-validation failure.
#[tokio::test]
async fn w44_oversized_unavailable() {
    for http in [false, true] {
        let (reply, count) = roundtrip(
            http,
            ResponseSpec::json(502, &vec![b'x'; 4_194_305]),
            paper_request(),
        )
        .await;
        unavailable(&reply, "W44 oversized non-200 unavailable");
        assert!(count == 1, "W44 exactly one request");
    }
}

// Percent encoding can exceed the service limit even when the local plain-text query is valid.
#[tokio::test]
async fn w41_openalex_url_limit() {
    let mut request = paper_request();
    request["query"] = json!("é".repeat(1000));
    let (reply, count) = roundtrip(false, ResponseSpec::json(200, OA_EMPTY), request).await;
    unavailable(&reply, "W41 local URL refusal");
    assert!(count == 0, "W41 no outbound work");
}

// The connector's independent service window guard is tested below the stronger public page bound.
#[tokio::test]
async fn w42_openalex_window() {
    let root = must(crate::gen_temp_dir());
    let server = Server::new(ResponseSpec::json(200, OA_EMPTY)).await;
    let provider = provider(root.as_ref(), &server, false);
    let query = PaperQuery {
        query: "synthetic".into(),
        page: 500,
        num_results: 20,
    };
    assert!(
        matches!(
            provider.search(query).await,
            Err(PaperProviderError::Unavailable)
        ),
        "W42 local window refusal"
    );
    assert!(server.count() == 0, "W42 no outbound work");
    server.finish().await;
}
// Synthetic, test-only TLS material for Story #656 W20 (D03 dispatch seal, 2026-10-02).
// NOT a production credential. Reserved test name `paper-provider.test` (RFC 6761 .test).
// Generated offline with OpenSSL 3.6.4; CA and leaf: RSA-2048, SHA-256, validity
// 2019-06-01T00:00:00Z..2125-01-01T00:00:00Z (notBefore precedes 2019-07-01 so macOS's
// 825-day TLS-validity rule does not apply). PKCS#12 uses PBE-SHA1-3DES + SHA-1 MAC so both
// macOS Security.framework and OpenSSL 3 default provider import it.

/// PKCS#12 (DER) identity: leaf key + leaf cert + CA cert.
/// SHA-256 398503392daf333d89990f27438497b30069b62c6f3bc333e006ee0e7a578b82.
pub(super) const TEST_TLS_IDENTITY_P12: &[u8] = &[
    0x30, 0x82, 0x0d, 0xc0, 0x02, 0x01, 0x03, 0x30, 0x82, 0x0d, 0x7e, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x82, 0x0d, 0x6f, 0x04, 0x82, 0x0d, 0x6b, 0x30, 0x82,
    0x0d, 0x67, 0x30, 0x82, 0x07, 0xe7, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07,
    0x06, 0xa0, 0x82, 0x07, 0xd8, 0x30, 0x82, 0x07, 0xd4, 0x02, 0x01, 0x00, 0x30, 0x82, 0x07, 0xcd,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0x30, 0x1c, 0x06, 0x0a, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03, 0x30, 0x0e, 0x04, 0x08, 0x46, 0xaf, 0x4f,
    0x78, 0x8f, 0x8d, 0x91, 0x15, 0x02, 0x02, 0x08, 0x00, 0x80, 0x82, 0x07, 0xa0, 0xed, 0x9a, 0xa4,
    0xcf, 0xa0, 0x72, 0x27, 0x87, 0x94, 0x03, 0x88, 0x33, 0x16, 0x15, 0xb0, 0xa0, 0x23, 0x7f, 0xa7,
    0x6c, 0xc5, 0x14, 0x81, 0x3b, 0x0f, 0xd5, 0xfc, 0x6c, 0xf2, 0x36, 0x74, 0xb6, 0x01, 0x53, 0x9f,
    0x36, 0xc6, 0xa0, 0x78, 0x0d, 0x71, 0x6f, 0x2e, 0x02, 0xa1, 0xd0, 0x3b, 0x53, 0x36, 0x97, 0x45,
    0x11, 0xe4, 0xd4, 0xe2, 0x0c, 0x05, 0xff, 0x29, 0x11, 0xa2, 0x74, 0x22, 0xee, 0xe8, 0xd0, 0xaa,
    0xd4, 0x57, 0xab, 0x90, 0xfb, 0x27, 0x63, 0x5a, 0xa1, 0x71, 0xb0, 0xf8, 0xda, 0x7b, 0x0b, 0xbf,
    0x30, 0x85, 0xd1, 0x46, 0x9c, 0xbb, 0xbe, 0x93, 0x01, 0xd9, 0xf9, 0xa8, 0x01, 0xe8, 0x83, 0x65,
    0x82, 0xfa, 0x0d, 0x99, 0x2f, 0x3c, 0x4a, 0x5a, 0xff, 0x28, 0x3a, 0x63, 0x24, 0x8e, 0xcf, 0xfa,
    0x86, 0x9d, 0xaf, 0xe7, 0xe1, 0x72, 0xa3, 0x74, 0x75, 0x69, 0xd8, 0x1a, 0x70, 0x91, 0x9b, 0x68,
    0x47, 0x1d, 0x76, 0x03, 0x3a, 0x14, 0x9f, 0x58, 0xb4, 0xb3, 0xba, 0xcd, 0xc3, 0xa4, 0x1d, 0x59,
    0x2b, 0x2c, 0xa1, 0xd9, 0x5d, 0x60, 0x4e, 0x49, 0x3a, 0x41, 0xd7, 0x52, 0x8e, 0xd4, 0x42, 0x3c,
    0x82, 0x12, 0x98, 0x6d, 0xfe, 0x3d, 0xba, 0x8b, 0xdc, 0x54, 0x26, 0xa7, 0xd3, 0x13, 0x2e, 0xed,
    0x98, 0xfe, 0xf8, 0x5e, 0x31, 0x76, 0x60, 0x8d, 0x9f, 0x70, 0x72, 0xe4, 0xd2, 0xc0, 0x98, 0x8b,
    0x21, 0x5c, 0x03, 0x4a, 0x03, 0xc7, 0x71, 0x5a, 0xb7, 0x1d, 0xa0, 0xcb, 0x82, 0x8c, 0x78, 0x20,
    0x82, 0xf6, 0x9b, 0x18, 0xd0, 0x5d, 0xb4, 0x3f, 0x68, 0x1a, 0x60, 0x8c, 0xed, 0x1b, 0x86, 0xeb,
    0xde, 0xd7, 0xc2, 0x34, 0xd3, 0x08, 0xdb, 0x90, 0x82, 0x0b, 0xcb, 0xb2, 0xb7, 0xbd, 0x08, 0x1a,
    0xab, 0x02, 0x3b, 0x32, 0xd4, 0x0b, 0xf9, 0x64, 0x7f, 0x10, 0x25, 0xc5, 0x6c, 0x9c, 0xb3, 0x6e,
    0x2b, 0x7e, 0xe5, 0x5f, 0xc6, 0x73, 0x79, 0x7c, 0xc7, 0xe6, 0xfe, 0x94, 0xbc, 0xad, 0x89, 0xa7,
    0xf1, 0x55, 0x34, 0xce, 0x78, 0x82, 0xf9, 0x3a, 0xdf, 0x52, 0x13, 0xce, 0xcf, 0xa0, 0x11, 0x97,
    0xf9, 0xee, 0x5a, 0x88, 0x0f, 0xff, 0x76, 0x29, 0x79, 0x53, 0x09, 0x5c, 0xf9, 0xaa, 0xc8, 0xe8,
    0x71, 0x14, 0xfa, 0xd3, 0x1b, 0x74, 0x75, 0x6f, 0x18, 0x39, 0xd8, 0xd7, 0xb9, 0x50, 0x05, 0x86,
    0x6c, 0x28, 0xb7, 0x3f, 0xfc, 0x6a, 0x1a, 0x31, 0xcc, 0x55, 0xa8, 0x68, 0x4d, 0x7b, 0xa8, 0x9e,
    0x7d, 0x2b, 0x12, 0x8a, 0x98, 0x6a, 0xa8, 0x07, 0x78, 0x94, 0x75, 0x4d, 0xa6, 0x41, 0x0f, 0xb4,
    0x59, 0x85, 0x33, 0x56, 0x4a, 0x5e, 0xfc, 0x13, 0x69, 0x9c, 0x49, 0xed, 0x38, 0xd4, 0xa1, 0xcb,
    0x24, 0xb1, 0xc2, 0x6c, 0xa1, 0x10, 0xe9, 0xaf, 0xd8, 0xa1, 0xf8, 0xc4, 0xce, 0xf8, 0xbf, 0x86,
    0xbc, 0x96, 0x1a, 0x2d, 0xa5, 0xdc, 0x97, 0xea, 0x02, 0xb2, 0xee, 0x50, 0x5f, 0x90, 0xeb, 0xf3,
    0xbb, 0x2d, 0x0f, 0xc0, 0x0f, 0xd2, 0x0f, 0x7a, 0x2e, 0xea, 0x0e, 0x44, 0x51, 0x52, 0x8a, 0xa5,
    0x73, 0x29, 0x86, 0x4f, 0x00, 0xc6, 0xd2, 0x69, 0x57, 0xd4, 0xfd, 0xe7, 0x94, 0x0a, 0xeb, 0xc8,
    0x78, 0x8b, 0xfb, 0x98, 0x62, 0x1a, 0x26, 0xb6, 0xd8, 0x71, 0x91, 0x54, 0xb2, 0xe5, 0x2c, 0xf6,
    0xbd, 0x33, 0xd0, 0x7f, 0x02, 0x49, 0xf8, 0x88, 0x22, 0x66, 0xc7, 0x75, 0x1d, 0x3e, 0xf8, 0xc0,
    0x2c, 0x1d, 0xa2, 0xe1, 0x21, 0xfe, 0x7c, 0x69, 0x1a, 0x7d, 0x8e, 0xd2, 0x12, 0x18, 0xf4, 0x7a,
    0x59, 0x43, 0xe8, 0x58, 0xde, 0xa2, 0x45, 0xe1, 0x0e, 0x9f, 0xc8, 0x1d, 0xc9, 0xee, 0x3e, 0xac,
    0xd3, 0x37, 0xe5, 0x00, 0x34, 0x3f, 0xe7, 0xdb, 0x4f, 0xcc, 0xab, 0x3f, 0xad, 0x46, 0xa2, 0x28,
    0xc8, 0xda, 0x98, 0xbc, 0x2a, 0x62, 0x99, 0x7c, 0x3f, 0x1e, 0x1a, 0x7c, 0xcc, 0xc5, 0x7a, 0x6f,
    0x30, 0x22, 0xc4, 0xab, 0x6f, 0xaa, 0x69, 0x7e, 0xaf, 0x73, 0x51, 0x7d, 0xe6, 0x91, 0x24, 0xdb,
    0x9b, 0x1a, 0x6c, 0xc3, 0xd2, 0x4a, 0xec, 0x7c, 0x8a, 0x95, 0xc0, 0xc9, 0xf8, 0x49, 0xef, 0x1c,
    0x89, 0xac, 0x24, 0x44, 0xdb, 0x24, 0x08, 0x6f, 0xd7, 0x41, 0xb7, 0x28, 0x55, 0xca, 0x78, 0xdc,
    0x19, 0x0e, 0xec, 0xb5, 0x77, 0xed, 0x30, 0x5a, 0x73, 0x78, 0x0e, 0x86, 0xe5, 0x39, 0xff, 0x32,
    0xc9, 0xbe, 0xfc, 0xf1, 0xca, 0x65, 0x39, 0x12, 0x47, 0x7a, 0x8f, 0x75, 0x59, 0xff, 0x57, 0xe1,
    0x47, 0xb7, 0x7b, 0x59, 0xd4, 0xf3, 0xc9, 0x63, 0xa3, 0x79, 0xe0, 0xe5, 0xee, 0xd2, 0xc6, 0xaf,
    0x02, 0x9f, 0x09, 0x47, 0xb6, 0x89, 0xd9, 0xdb, 0x9c, 0x48, 0xb0, 0xd6, 0xb4, 0x68, 0x72, 0x60,
    0x96, 0xfb, 0x31, 0xca, 0x54, 0x3b, 0xa4, 0x0b, 0x53, 0xd6, 0x1c, 0xca, 0xc5, 0x2e, 0x22, 0x90,
    0x88, 0x01, 0x4f, 0x9a, 0xbe, 0xdf, 0xa2, 0x42, 0x96, 0x39, 0x56, 0x13, 0xa2, 0x34, 0xee, 0x87,
    0x96, 0xf7, 0x59, 0xff, 0x1a, 0x4b, 0xda, 0x5c, 0x09, 0x03, 0x90, 0x0e, 0x5b, 0x80, 0x13, 0x23,
    0x34, 0xef, 0xe6, 0x04, 0x47, 0xe4, 0xb7, 0xfa, 0x0f, 0xe4, 0x43, 0xf3, 0xa0, 0x4c, 0x85, 0xac,
    0xd3, 0xb7, 0x9b, 0x6b, 0xdd, 0x7e, 0xb1, 0x84, 0xd1, 0x08, 0x78, 0x82, 0x4c, 0x4c, 0xde, 0x7b,
    0xab, 0xef, 0x54, 0x5e, 0xeb, 0x03, 0x7d, 0x3f, 0xdc, 0xa8, 0x86, 0x1f, 0x28, 0x2d, 0xd5, 0x71,
    0xd0, 0x1f, 0x1c, 0x50, 0xee, 0x41, 0xcb, 0x6f, 0xe0, 0x1a, 0xe0, 0x7b, 0x48, 0xfd, 0xfa, 0x27,
    0x9f, 0xe5, 0x9f, 0x33, 0x0a, 0xfb, 0x1d, 0x51, 0xe9, 0x15, 0x99, 0x04, 0x3c, 0xe9, 0x66, 0x08,
    0x50, 0x03, 0x22, 0xb8, 0xac, 0xb0, 0xf4, 0x9c, 0xf9, 0x70, 0x91, 0xf2, 0x7f, 0x57, 0xa7, 0x97,
    0x11, 0x68, 0xf1, 0x5e, 0x9e, 0x86, 0x80, 0x17, 0x35, 0x37, 0x85, 0x4d, 0x2d, 0x32, 0x0b, 0x0a,
    0xf6, 0x88, 0x9f, 0x38, 0x74, 0x4c, 0x4c, 0xde, 0xf3, 0x73, 0x6b, 0xc0, 0xc6, 0x0d, 0xf9, 0x65,
    0x15, 0xf5, 0x3e, 0xfc, 0x40, 0x79, 0x47, 0xed, 0x99, 0xad, 0x76, 0x57, 0xb2, 0xac, 0x57, 0x8a,
    0x1d, 0xc5, 0x2b, 0xb9, 0xa9, 0x9d, 0x4c, 0x38, 0xda, 0x89, 0xec, 0x36, 0x27, 0xdf, 0xec, 0xeb,
    0x66, 0x43, 0x6f, 0x36, 0xa4, 0x80, 0xed, 0x90, 0x14, 0x02, 0x6c, 0xd0, 0x75, 0x7b, 0x57, 0xbd,
    0xa9, 0xf5, 0x15, 0xe0, 0xd2, 0xed, 0x03, 0x39, 0xff, 0xa7, 0x44, 0xf7, 0x22, 0xdd, 0xe1, 0x79,
    0x3f, 0x9e, 0x22, 0x51, 0xb1, 0x90, 0x15, 0xbe, 0x9f, 0x09, 0xbc, 0xba, 0x1d, 0x51, 0x85, 0x9a,
    0xfa, 0x59, 0xfe, 0xc1, 0xaf, 0x18, 0xdf, 0xf9, 0xfa, 0xd8, 0xb5, 0xc9, 0xad, 0x33, 0x2a, 0x84,
    0x89, 0xd6, 0x16, 0x33, 0xda, 0xb7, 0x0a, 0x9e, 0x10, 0x8a, 0x9a, 0x8d, 0x0f, 0x9e, 0x4a, 0x51,
    0x94, 0x9f, 0x28, 0x70, 0x25, 0xc4, 0x42, 0xf1, 0x62, 0xf7, 0x2c, 0x19, 0xd1, 0x6f, 0xff, 0x0b,
    0xc9, 0x4b, 0x9c, 0xfc, 0x58, 0x17, 0xd1, 0x53, 0xb8, 0x89, 0xae, 0xe1, 0x4b, 0xa0, 0x0b, 0x88,
    0xbd, 0xd7, 0x68, 0xbc, 0xb1, 0x1b, 0x54, 0xe3, 0xa5, 0x20, 0x8f, 0x31, 0xfe, 0x10, 0xdd, 0xe6,
    0xd4, 0xe0, 0x8d, 0xa9, 0xa2, 0xff, 0xd1, 0x33, 0x89, 0xe3, 0xc3, 0xef, 0x80, 0xd8, 0xf1, 0x9c,
    0x3a, 0x60, 0xc3, 0xe5, 0x3a, 0x36, 0x68, 0x16, 0x52, 0x69, 0x79, 0x41, 0x46, 0x8a, 0x4a, 0x8a,
    0x9b, 0xe3, 0x0a, 0xf6, 0xec, 0x53, 0xef, 0x5b, 0x74, 0x0c, 0xfb, 0x06, 0x31, 0x70, 0x4c, 0x38,
    0x7a, 0x0e, 0x91, 0x00, 0x7f, 0x97, 0xca, 0x04, 0x34, 0x16, 0xde, 0x52, 0xb8, 0xe8, 0x02, 0x41,
    0xd4, 0x62, 0xee, 0xe8, 0x15, 0xda, 0xf4, 0x60, 0xcf, 0x10, 0x9a, 0x16, 0xd8, 0xe2, 0xdd, 0x5a,
    0x72, 0xdc, 0x7a, 0x11, 0xd2, 0xd8, 0xe8, 0x5d, 0x5d, 0xbc, 0x75, 0x2f, 0x0f, 0xe7, 0xa4, 0xf7,
    0xd3, 0xe6, 0x17, 0x8f, 0x9e, 0xd2, 0x66, 0xc7, 0x43, 0xd8, 0xcb, 0x6b, 0xfe, 0x8c, 0x57, 0x4f,
    0x2a, 0x09, 0xc5, 0x84, 0xbf, 0x66, 0x02, 0x1c, 0xe3, 0x23, 0x4f, 0x23, 0x11, 0x00, 0x76, 0x6e,
    0x7f, 0x1b, 0x7b, 0x07, 0xd1, 0xf7, 0x19, 0xfc, 0x49, 0xb6, 0x4b, 0x6b, 0x81, 0x12, 0x67, 0x35,
    0xbd, 0x44, 0x68, 0xea, 0xdf, 0x27, 0xf6, 0xd8, 0x07, 0x48, 0x4a, 0x03, 0xf1, 0xe2, 0x96, 0x0c,
    0xe0, 0xa1, 0xf7, 0x03, 0xb1, 0x7a, 0x36, 0x8c, 0x52, 0x4b, 0x57, 0x3a, 0x27, 0xea, 0x85, 0x5a,
    0xe8, 0x07, 0x86, 0xea, 0x60, 0xbd, 0xa2, 0x95, 0x03, 0xff, 0xf7, 0x88, 0xba, 0xcd, 0x8d, 0x15,
    0xe4, 0x73, 0x1e, 0xdf, 0x64, 0x10, 0x9b, 0xb1, 0x79, 0x00, 0x12, 0x50, 0x3e, 0xd9, 0x2f, 0x18,
    0xcc, 0x9a, 0x9b, 0x30, 0xdb, 0xe3, 0xa6, 0x8e, 0xde, 0xee, 0x56, 0x91, 0x28, 0x30, 0x4a, 0xa3,
    0xb9, 0xc8, 0x74, 0xc7, 0xd9, 0x01, 0x30, 0x5b, 0xd5, 0xe6, 0xd0, 0xca, 0x50, 0xb4, 0xd2, 0xba,
    0xb5, 0x41, 0x50, 0x40, 0x67, 0xf9, 0x19, 0xaa, 0xfc, 0xaa, 0xfd, 0xaa, 0xe7, 0x8e, 0x98, 0x3b,
    0xc4, 0xf1, 0x5f, 0xbb, 0x5e, 0x65, 0x0c, 0x67, 0x10, 0x98, 0x8b, 0xca, 0x96, 0x45, 0x6e, 0xf5,
    0x85, 0x8c, 0x94, 0x18, 0x84, 0x45, 0xaa, 0xd9, 0x58, 0xd2, 0x2e, 0x6f, 0x5b, 0x71, 0x76, 0xe6,
    0xc4, 0xd3, 0x55, 0xdc, 0x26, 0x87, 0x14, 0xf8, 0x6b, 0x23, 0xeb, 0xca, 0xfd, 0xf8, 0x46, 0x4d,
    0x5e, 0x1b, 0x0f, 0x0d, 0x7e, 0xda, 0xd0, 0x3c, 0x5f, 0xda, 0xf6, 0x62, 0x3f, 0x15, 0xa3, 0x3b,
    0x96, 0xcf, 0x8c, 0xd1, 0x16, 0xdd, 0x62, 0x60, 0xb7, 0x7f, 0x5a, 0x3f, 0x40, 0x4a, 0xa9, 0x94,
    0xa6, 0x3e, 0x33, 0x2e, 0x73, 0x13, 0x95, 0xa9, 0x25, 0xe2, 0x82, 0xff, 0xa8, 0xa6, 0x69, 0x08,
    0x68, 0x62, 0x13, 0x1d, 0x0b, 0x87, 0xef, 0x83, 0xa2, 0x09, 0xa2, 0xe7, 0x12, 0x10, 0x8e, 0x2d,
    0xf6, 0xdd, 0xe9, 0xd0, 0x58, 0x2e, 0xfb, 0x0b, 0x9d, 0xd2, 0x0a, 0x6a, 0x7f, 0xd7, 0x43, 0x9f,
    0xb3, 0x8c, 0x70, 0x54, 0x68, 0xbe, 0x7d, 0x49, 0x55, 0x3f, 0xe2, 0xd1, 0x50, 0xc1, 0xec, 0x2b,
    0x21, 0xa9, 0xb1, 0xdc, 0x5d, 0xb5, 0x61, 0x8c, 0x47, 0x9d, 0xa8, 0x1b, 0x1e, 0x64, 0x23, 0x28,
    0x52, 0x4d, 0x4b, 0x08, 0x7a, 0x03, 0x49, 0x1e, 0x07, 0x10, 0xe0, 0xc1, 0x3d, 0x3a, 0x88, 0x8f,
    0xae, 0xf5, 0x2d, 0x67, 0x8e, 0xa4, 0xa8, 0xe7, 0xa0, 0xeb, 0x0a, 0x77, 0xdb, 0x71, 0xe7, 0xea,
    0x08, 0x2b, 0xcc, 0xc4, 0xdc, 0x65, 0xc0, 0x0a, 0xdd, 0x18, 0xde, 0x47, 0xcb, 0xa6, 0x87, 0xe4,
    0xd5, 0x35, 0xb8, 0xe2, 0x37, 0xd5, 0xe5, 0x6b, 0xae, 0x73, 0xe9, 0x61, 0x32, 0x6c, 0x86, 0x14,
    0x63, 0xe6, 0x86, 0x76, 0x3b, 0xd6, 0x46, 0xde, 0x3f, 0x30, 0x1f, 0x23, 0x01, 0x1d, 0x2d, 0x55,
    0xf2, 0x80, 0x2f, 0x2f, 0xd8, 0x60, 0xce, 0xfe, 0x86, 0xf3, 0x90, 0x14, 0x26, 0x87, 0x46, 0x21,
    0x03, 0xbd, 0x38, 0xbf, 0x8d, 0x9b, 0x4d, 0x78, 0x11, 0x67, 0x8f, 0x06, 0xad, 0x5e, 0x47, 0xed,
    0xc8, 0xa0, 0xf0, 0x6a, 0x16, 0xe3, 0x8a, 0xc5, 0x07, 0xb6, 0xfa, 0xf6, 0x75, 0xda, 0xb6, 0xb4,
    0x84, 0x99, 0xd8, 0x5e, 0x70, 0x58, 0x7d, 0xe9, 0x9d, 0x34, 0xad, 0xde, 0x29, 0x7e, 0x67, 0xbe,
    0x95, 0xb2, 0xda, 0xb6, 0x64, 0xd6, 0x89, 0xd6, 0xfe, 0x6c, 0x1f, 0xf9, 0xf8, 0x35, 0xf3, 0x79,
    0xbe, 0x97, 0xcd, 0x4a, 0x6e, 0x32, 0xf2, 0x08, 0x6f, 0x58, 0xc8, 0xdb, 0x73, 0x83, 0x50, 0x9a,
    0x5a, 0x71, 0x66, 0xf2, 0xc9, 0x06, 0xcf, 0xdf, 0x8f, 0x5c, 0x31, 0xee, 0x34, 0xac, 0x0e, 0xb2,
    0x61, 0xe7, 0xa5, 0x4b, 0x99, 0xf8, 0xfb, 0xaa, 0x4e, 0xbb, 0xcb, 0x00, 0xba, 0xc9, 0xd2, 0x39,
    0x98, 0x47, 0x3d, 0x81, 0x74, 0x4d, 0xe3, 0xe6, 0x02, 0x8d, 0x33, 0x44, 0x8b, 0xd4, 0x65, 0x67,
    0x43, 0x30, 0x64, 0x59, 0x1b, 0x90, 0x7b, 0xb8, 0x13, 0xd9, 0x93, 0xfd, 0x83, 0x58, 0x06, 0x42,
    0x64, 0x2d, 0xec, 0x22, 0x2c, 0xe3, 0x80, 0x9a, 0x5f, 0xcc, 0x32, 0x9c, 0xa2, 0xf9, 0xe0, 0x61,
    0xad, 0xf6, 0x0b, 0x15, 0x53, 0xe2, 0xde, 0xac, 0x9e, 0x6b, 0x1d, 0x50, 0x6f, 0xc3, 0x82, 0x33,
    0xcd, 0x6d, 0x76, 0x87, 0x0b, 0x2a, 0xd5, 0x80, 0xbb, 0x3a, 0xb3, 0xb7, 0xb5, 0xad, 0xdb, 0x5a,
    0xd5, 0xb4, 0xd0, 0x16, 0x93, 0x3b, 0xbe, 0x8b, 0x2e, 0x87, 0x77, 0x16, 0x9a, 0x6e, 0x39, 0xf7,
    0x5a, 0xe1, 0x1c, 0x05, 0xd5, 0x62, 0xb8, 0xf2, 0x1c, 0x47, 0xcd, 0x9b, 0xd7, 0x26, 0x36, 0x67,
    0x4a, 0x6c, 0x99, 0x63, 0xef, 0x73, 0x16, 0xdc, 0x23, 0x3d, 0xbb, 0x83, 0x06, 0x7d, 0x29, 0xa7,
    0x9d, 0xc4, 0xdc, 0x88, 0xc2, 0x1a, 0xb5, 0xe2, 0x5e, 0x95, 0x1a, 0x61, 0xcc, 0x11, 0x28, 0xb0,
    0x6a, 0xa4, 0xf6, 0x37, 0x25, 0x18, 0x0b, 0x3a, 0x03, 0x9d, 0xcf, 0x0b, 0x0b, 0x18, 0xa1, 0xd3,
    0xbd, 0x79, 0x04, 0xe0, 0x68, 0x68, 0xcb, 0xac, 0x64, 0x17, 0x98, 0xed, 0x57, 0x0d, 0xb7, 0x33,
    0xc9, 0xc4, 0xbf, 0x07, 0x8b, 0x7b, 0x29, 0xcb, 0x06, 0x9a, 0xfc, 0xa2, 0xed, 0x9f, 0x61, 0x82,
    0x7c, 0x6d, 0x2a, 0x23, 0x98, 0x2e, 0x57, 0x31, 0xc8, 0x5f, 0xa4, 0xc0, 0xde, 0x3b, 0x62, 0x89,
    0x4d, 0x90, 0x9c, 0xa0, 0xd5, 0x67, 0xae, 0x99, 0x6d, 0x3b, 0xad, 0x71, 0x62, 0xd7, 0x66, 0x41,
    0x01, 0x3e, 0x2b, 0x1b, 0x7a, 0x4b, 0x99, 0xc5, 0xb7, 0xa6, 0x96, 0x75, 0x4b, 0x1d, 0x50, 0x61,
    0xa3, 0xb8, 0xd9, 0xdd, 0xf8, 0x5c, 0xe2, 0x60, 0xdf, 0xfe, 0xda, 0x9b, 0x57, 0x60, 0x6f, 0x72,
    0xb0, 0x45, 0xed, 0xbd, 0x78, 0x04, 0x59, 0x32, 0x3e, 0x69, 0x4e, 0x7b, 0x19, 0x13, 0x8a, 0x61,
    0xc1, 0x4d, 0x6b, 0x59, 0x97, 0x6a, 0x66, 0x84, 0xc1, 0x39, 0x35, 0x55, 0x7d, 0x65, 0x66, 0x16,
    0x3d, 0xb4, 0x41, 0xeb, 0x1c, 0x24, 0xd1, 0x07, 0x5f, 0x70, 0xb5, 0x22, 0xc1, 0xe0, 0xd8, 0xd9,
    0x94, 0x6d, 0x81, 0x66, 0xcd, 0xe7, 0x71, 0x18, 0x8f, 0xe6, 0xea, 0xc3, 0x9c, 0x99, 0x98, 0xad,
    0x46, 0x95, 0x88, 0xd8, 0x7c, 0xc7, 0xd5, 0x32, 0xc0, 0x81, 0x48, 0xe2, 0x6a, 0x6c, 0xea, 0xd7,
    0xa8, 0x34, 0x2f, 0x1d, 0xee, 0x11, 0xd2, 0x15, 0x50, 0xb8, 0xba, 0xc0, 0x5f, 0x30, 0x82, 0x05,
    0x78, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x82, 0x05, 0x69,
    0x04, 0x82, 0x05, 0x65, 0x30, 0x82, 0x05, 0x61, 0x30, 0x82, 0x05, 0x5d, 0x06, 0x0b, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x02, 0xa0, 0x82, 0x04, 0xee, 0x30, 0x82, 0x04,
    0xea, 0x30, 0x1c, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03, 0x30,
    0x0e, 0x04, 0x08, 0x44, 0xe4, 0xdb, 0xd1, 0x4c, 0xb7, 0xd6, 0xfa, 0x02, 0x02, 0x08, 0x00, 0x04,
    0x82, 0x04, 0xc8, 0xb8, 0x1f, 0xc9, 0x60, 0xe7, 0x1c, 0xad, 0x8e, 0xa4, 0xa2, 0x65, 0x7b, 0xb7,
    0xde, 0x50, 0x4b, 0x0d, 0x48, 0x20, 0xe4, 0xe1, 0x2a, 0x25, 0x29, 0x27, 0x4d, 0x6d, 0x83, 0xcf,
    0xf5, 0x79, 0xd2, 0xd5, 0xa5, 0x82, 0x2a, 0x2e, 0x70, 0x9b, 0x33, 0xc2, 0xc1, 0x29, 0xae, 0x57,
    0x0d, 0xaa, 0x3f, 0xfe, 0x01, 0xe7, 0x04, 0x07, 0x2c, 0xb5, 0x04, 0x91, 0x68, 0x61, 0x19, 0xb6,
    0xaf, 0x33, 0x35, 0x6f, 0xea, 0x17, 0x88, 0x04, 0x7a, 0x75, 0x64, 0x8c, 0x7e, 0x8c, 0xac, 0x3f,
    0xfa, 0xca, 0x4b, 0x08, 0xbe, 0x2c, 0x78, 0x9c, 0xf9, 0x8b, 0x0e, 0x95, 0xe4, 0x05, 0xbc, 0xc4,
    0xfe, 0x79, 0xc5, 0xef, 0x56, 0xde, 0xf0, 0x09, 0x0a, 0x86, 0x96, 0xcc, 0x49, 0xc0, 0x30, 0xf0,
    0x09, 0xbb, 0xe7, 0x97, 0xb8, 0x3c, 0x09, 0xbd, 0xed, 0x50, 0x0b, 0xef, 0x3a, 0xd9, 0xde, 0x60,
    0x24, 0xda, 0x96, 0x35, 0x83, 0xf6, 0xd2, 0x81, 0xfe, 0x86, 0xa8, 0x04, 0xbf, 0xe7, 0x41, 0x7f,
    0x7d, 0xe2, 0x98, 0xdb, 0xce, 0x53, 0x8d, 0x8f, 0x93, 0xa7, 0x19, 0x47, 0x95, 0xba, 0x2e, 0xb0,
    0xaa, 0x8c, 0xbd, 0x98, 0x0d, 0x6c, 0xbe, 0xb8, 0xfb, 0x15, 0xd9, 0xeb, 0x6a, 0xbf, 0x76, 0xe0,
    0xe2, 0xec, 0x0e, 0xca, 0x9a, 0x71, 0xa3, 0x4a, 0x6a, 0x7b, 0xb7, 0x0b, 0x9f, 0x98, 0x4a, 0x81,
    0x27, 0x39, 0x5d, 0x90, 0x35, 0x4d, 0xa9, 0x2e, 0x33, 0xf5, 0x3c, 0x25, 0xb3, 0xdc, 0x38, 0x0a,
    0x87, 0xf9, 0xea, 0x1e, 0x86, 0x86, 0xaa, 0x67, 0x76, 0xc6, 0xd6, 0x9a, 0x7f, 0xf2, 0x04, 0x27,
    0xd1, 0x94, 0x9f, 0xc2, 0x43, 0x99, 0x69, 0x31, 0x50, 0x0a, 0xd7, 0x84, 0xf2, 0xf2, 0xd8, 0x26,
    0xdb, 0x11, 0xb7, 0x45, 0xe9, 0x3d, 0xb8, 0x3c, 0xe3, 0xbf, 0xd8, 0x5e, 0xc9, 0x29, 0x2b, 0x87,
    0x9b, 0xab, 0x3f, 0x46, 0x47, 0x84, 0x04, 0x61, 0x21, 0x5b, 0xa0, 0x7b, 0x14, 0x81, 0x85, 0xd5,
    0xf9, 0x27, 0x5d, 0x2c, 0x08, 0x1e, 0x28, 0x96, 0x7d, 0xfb, 0x46, 0x4e, 0x93, 0x37, 0x5e, 0x87,
    0x51, 0x3b, 0x75, 0x29, 0xe6, 0xc1, 0x36, 0x23, 0x24, 0xaf, 0xdb, 0xdf, 0x36, 0x01, 0xf4, 0x22,
    0xc2, 0x0d, 0x0b, 0x4a, 0x47, 0xa4, 0x74, 0x12, 0x6a, 0x10, 0x5a, 0xeb, 0xb9, 0xcc, 0xfe, 0x00,
    0x55, 0xe3, 0xae, 0xb1, 0x9f, 0x7d, 0x7a, 0x89, 0x84, 0xca, 0x15, 0x08, 0x40, 0x10, 0x40, 0xd2,
    0x53, 0xbd, 0xf6, 0xe1, 0xd7, 0x73, 0xc2, 0x32, 0xfa, 0x86, 0xe1, 0x9a, 0x9a, 0x7d, 0x12, 0x16,
    0xaa, 0x19, 0x2e, 0x37, 0xac, 0xaf, 0x2a, 0x0c, 0xab, 0x5f, 0x68, 0xec, 0xfe, 0x7c, 0xc5, 0x22,
    0x0a, 0xde, 0xbe, 0xb6, 0xe9, 0xeb, 0x89, 0x1f, 0x50, 0x3e, 0x39, 0x4b, 0xd5, 0xf6, 0x20, 0xbe,
    0x3e, 0x13, 0x0d, 0x77, 0x73, 0xd6, 0xac, 0xe0, 0x50, 0x8e, 0x09, 0x00, 0x37, 0x25, 0x3f, 0x69,
    0x22, 0x7f, 0x55, 0x95, 0xb3, 0x54, 0xf1, 0x71, 0x82, 0x5f, 0x06, 0xce, 0xdd, 0x51, 0x55, 0x9e,
    0x75, 0x89, 0xf2, 0x7b, 0x68, 0x03, 0x5c, 0xa0, 0x22, 0xc1, 0x66, 0x4e, 0xfa, 0xa4, 0xdb, 0xe3,
    0x82, 0x66, 0xb2, 0x7a, 0x9d, 0x57, 0x6b, 0x49, 0xa0, 0xbe, 0xf4, 0x0f, 0xa7, 0x47, 0x96, 0x55,
    0xa8, 0x83, 0x26, 0x74, 0x3c, 0x98, 0xea, 0x57, 0xb8, 0x5d, 0x59, 0xdc, 0x63, 0x35, 0x7f, 0x90,
    0xe6, 0x6d, 0x63, 0xd8, 0x27, 0xe9, 0x78, 0x3e, 0xd9, 0x5b, 0xdf, 0x2f, 0xe5, 0x13, 0xf8, 0x5e,
    0x31, 0xfd, 0xc4, 0x91, 0x9b, 0xff, 0xc7, 0xfd, 0xb1, 0xaf, 0x8b, 0x63, 0xca, 0x30, 0x5c, 0x31,
    0x31, 0xd6, 0xa8, 0xba, 0xf6, 0xd1, 0xb6, 0xea, 0x2e, 0xfe, 0x27, 0x4c, 0xfa, 0xed, 0x39, 0x6f,
    0xda, 0xaa, 0x60, 0x09, 0x58, 0x15, 0xcc, 0x97, 0x45, 0x77, 0xea, 0xc4, 0xf0, 0xd2, 0xbd, 0x5e,
    0x86, 0xa4, 0xd8, 0xb0, 0x0a, 0xbf, 0x37, 0x6e, 0x1c, 0x98, 0xfe, 0x36, 0x50, 0x68, 0x17, 0xd4,
    0xea, 0x02, 0xc4, 0x26, 0x05, 0xe3, 0x04, 0x8a, 0x89, 0x7b, 0x24, 0x58, 0x32, 0x94, 0x75, 0x73,
    0x28, 0x44, 0xa2, 0x69, 0x1f, 0x6e, 0x0f, 0x1a, 0xe9, 0x3c, 0xf9, 0xf7, 0xa9, 0xaf, 0x92, 0x1d,
    0xff, 0x8a, 0x0d, 0xe3, 0xf0, 0x0f, 0xc9, 0x6c, 0x4d, 0x10, 0xb1, 0x86, 0xf8, 0x3a, 0xef, 0x71,
    0x5e, 0x4b, 0x50, 0xfb, 0x87, 0x3c, 0x49, 0x16, 0x41, 0x61, 0x57, 0xf3, 0x20, 0xc3, 0xc8, 0x53,
    0xdc, 0xde, 0x64, 0x27, 0xa5, 0x3b, 0xd4, 0xac, 0x3c, 0x26, 0xb1, 0x79, 0xab, 0xf2, 0x7c, 0x47,
    0xf8, 0x45, 0x34, 0x10, 0x0c, 0x12, 0xf5, 0x9e, 0xf4, 0xb3, 0x38, 0xa8, 0x89, 0x3f, 0x60, 0x1f,
    0x75, 0xd0, 0x57, 0x77, 0x09, 0x78, 0x9b, 0x9c, 0xe6, 0xca, 0xd9, 0x65, 0x0b, 0x31, 0x9c, 0xf9,
    0x07, 0x26, 0x0d, 0x14, 0x14, 0x5c, 0x23, 0x89, 0xb9, 0xb4, 0xc9, 0x22, 0x75, 0x27, 0x33, 0x2a,
    0xeb, 0x81, 0xae, 0xcd, 0x77, 0x09, 0x9c, 0xf4, 0x39, 0xa1, 0x33, 0x30, 0xe3, 0x5d, 0x2d, 0x51,
    0x41, 0x07, 0x74, 0x11, 0x56, 0x29, 0x64, 0x93, 0x73, 0x37, 0x61, 0x27, 0xb7, 0xd3, 0x1d, 0xd3,
    0x81, 0x57, 0x61, 0x93, 0x1f, 0xd3, 0xb5, 0x0d, 0xec, 0xc2, 0xe8, 0x00, 0xcb, 0x00, 0xad, 0x0b,
    0x2f, 0x09, 0x95, 0xa2, 0x6b, 0x3d, 0x77, 0x7e, 0x95, 0x73, 0x24, 0x23, 0xf7, 0x7d, 0x1e, 0xdc,
    0xcd, 0xd0, 0x0a, 0x6a, 0xb8, 0xad, 0x5a, 0xfb, 0xde, 0x88, 0x72, 0x96, 0x04, 0x0a, 0x53, 0x54,
    0x5c, 0x9e, 0xb5, 0xab, 0xfc, 0xb2, 0x23, 0x62, 0xc8, 0x00, 0x2a, 0x9d, 0xa4, 0x76, 0x3a, 0xaf,
    0x91, 0x6f, 0xe9, 0x10, 0x77, 0xf0, 0x66, 0xa4, 0x1f, 0x00, 0x5e, 0x92, 0x99, 0x83, 0x48, 0x85,
    0x53, 0x0b, 0xfe, 0x17, 0x68, 0x28, 0xc5, 0x12, 0x0c, 0x1e, 0xd9, 0x66, 0xc5, 0xae, 0x81, 0xde,
    0x43, 0xc0, 0x4e, 0xd6, 0xd3, 0x0a, 0x7a, 0xe5, 0xd6, 0x76, 0x43, 0xce, 0xc9, 0x96, 0xae, 0x1e,
    0xc6, 0x01, 0x7b, 0x5f, 0x55, 0x67, 0xd9, 0xf1, 0x47, 0x93, 0x12, 0xb0, 0x77, 0x0b, 0x45, 0x72,
    0xb6, 0xe6, 0xd3, 0x62, 0x70, 0x53, 0xc3, 0x70, 0x58, 0xf2, 0xaf, 0xfb, 0x45, 0x32, 0x22, 0x2d,
    0x11, 0xc1, 0x05, 0x7e, 0x0d, 0x5f, 0xfa, 0x1f, 0x64, 0xe7, 0x0b, 0x6e, 0xd7, 0xf0, 0xdb, 0x1f,
    0x5b, 0xca, 0x49, 0x6d, 0xb1, 0x7e, 0x0a, 0xac, 0x1d, 0x55, 0x6f, 0xec, 0x06, 0x40, 0x21, 0x6b,
    0x42, 0xc0, 0x32, 0xa5, 0xa3, 0x3c, 0x45, 0x19, 0x77, 0x0a, 0x77, 0x58, 0x74, 0x33, 0xfd, 0xfd,
    0x99, 0x7e, 0x08, 0x23, 0xe1, 0x60, 0x5e, 0xb4, 0xee, 0x03, 0x74, 0xd9, 0xd4, 0x3c, 0xa9, 0x27,
    0x60, 0xd4, 0xc7, 0x9f, 0x10, 0xd2, 0x46, 0x07, 0xc2, 0x43, 0xcc, 0xb2, 0xbc, 0xf4, 0xc7, 0x2f,
    0x02, 0xab, 0x26, 0x2d, 0x1e, 0x38, 0x92, 0x4b, 0x5b, 0x7e, 0x94, 0xbf, 0x90, 0xe1, 0x63, 0x45,
    0xb4, 0x54, 0x73, 0x70, 0xae, 0x71, 0x45, 0x64, 0xe4, 0x4c, 0x78, 0x49, 0x34, 0x7a, 0x05, 0x4b,
    0x1e, 0x75, 0x1d, 0x01, 0xc0, 0xe7, 0xb2, 0x40, 0xaf, 0x02, 0x76, 0xe2, 0x24, 0x43, 0x78, 0x26,
    0xbc, 0xdd, 0xc5, 0x80, 0xbc, 0xf5, 0xfd, 0xea, 0x6f, 0x56, 0x7c, 0xdc, 0x8d, 0x0d, 0x88, 0x28,
    0x3a, 0x3c, 0xde, 0x25, 0x1c, 0x91, 0x81, 0xd6, 0x97, 0xb8, 0xdd, 0xa5, 0x58, 0x17, 0x66, 0xeb,
    0xb2, 0x40, 0xb3, 0x76, 0x99, 0x53, 0x23, 0xdb, 0xaf, 0xd8, 0xe6, 0xf8, 0x84, 0x03, 0x37, 0xcf,
    0xf1, 0x31, 0x5d, 0xd7, 0xbb, 0x5e, 0x07, 0x97, 0x60, 0xa9, 0xe9, 0xc2, 0xfc, 0xb2, 0x73, 0xe1,
    0x48, 0x46, 0xbe, 0xec, 0x2d, 0x67, 0xcc, 0xed, 0x7b, 0x7b, 0x73, 0x4a, 0xeb, 0xa0, 0xc7, 0x1c,
    0x0f, 0x9b, 0xc1, 0x82, 0x49, 0xdf, 0x24, 0x00, 0x6a, 0x4f, 0xd4, 0x9a, 0x1f, 0x0c, 0x3d, 0x6c,
    0x02, 0x60, 0x1d, 0xa5, 0x11, 0xe3, 0x06, 0x1b, 0x9b, 0xeb, 0xc7, 0x1d, 0xd8, 0x02, 0xb0, 0xde,
    0x7f, 0x5c, 0x38, 0x59, 0xd8, 0x03, 0xe4, 0xc8, 0x24, 0x82, 0x95, 0x93, 0x1b, 0x27, 0x31, 0x83,
    0x19, 0x15, 0x8a, 0x85, 0x79, 0x94, 0xce, 0xc7, 0x9e, 0xe3, 0xb8, 0x8c, 0xe5, 0x0f, 0x98, 0xee,
    0x4f, 0xf0, 0xb0, 0x51, 0xa9, 0x64, 0x2d, 0x7d, 0x86, 0x1d, 0x9f, 0xb7, 0xcc, 0x7e, 0x67, 0x6a,
    0x19, 0x03, 0xb5, 0xad, 0xb2, 0x99, 0xe0, 0x82, 0x5e, 0x37, 0xf3, 0xca, 0x91, 0x85, 0x62, 0x32,
    0x24, 0x30, 0xf9, 0x38, 0x7f, 0x75, 0xb3, 0x91, 0xa5, 0x8a, 0xae, 0x08, 0x5a, 0x0e, 0xa3, 0xa6,
    0x4e, 0x72, 0x90, 0x6a, 0x5c, 0x2a, 0xe6, 0x36, 0x4c, 0x66, 0x26, 0x5c, 0x2d, 0x84, 0xe2, 0x82,
    0xee, 0xf7, 0x3d, 0x4b, 0xd5, 0xa7, 0x31, 0x14, 0x98, 0x94, 0x71, 0x9b, 0x81, 0x75, 0x6f, 0x8a,
    0xa7, 0x83, 0xfd, 0x97, 0x15, 0xa6, 0xb4, 0x45, 0x11, 0xfd, 0xd0, 0xf6, 0xb9, 0x65, 0x79, 0xc4,
    0x03, 0xa6, 0xb7, 0x25, 0x8f, 0xb6, 0xc9, 0x6b, 0x76, 0xec, 0xd1, 0x31, 0x5c, 0x30, 0x23, 0x06,
    0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x15, 0x31, 0x16, 0x04, 0x14, 0x22, 0xd9,
    0x7f, 0x95, 0xa7, 0xd0, 0x16, 0xaf, 0x99, 0xd9, 0x36, 0x9b, 0xab, 0x59, 0x03, 0x46, 0xd2, 0xa4,
    0x19, 0x99, 0x30, 0x35, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x14, 0x31,
    0x28, 0x1e, 0x26, 0x00, 0x70, 0x00, 0x61, 0x00, 0x70, 0x00, 0x65, 0x00, 0x72, 0x00, 0x2d, 0x00,
    0x70, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x76, 0x00, 0x69, 0x00, 0x64, 0x00, 0x65, 0x00, 0x72, 0x00,
    0x2e, 0x00, 0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x30, 0x39, 0x30, 0x21, 0x30, 0x09, 0x06,
    0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, 0xd4, 0x46, 0x87, 0xd5, 0x94, 0x50,
    0x9a, 0x35, 0xd8, 0xd8, 0x5f, 0x83, 0xc2, 0x5f, 0x7c, 0x69, 0xea, 0xbe, 0xbb, 0xa3, 0x04, 0x10,
    0x48, 0xa6, 0xf2, 0xdb, 0xc1, 0xa9, 0xd6, 0x36, 0x49, 0x2c, 0x57, 0x56, 0x91, 0xce, 0x3d, 0x74,
    0x02, 0x02, 0x08, 0x00,
];

/// Passphrase for `TEST_TLS_IDENTITY_P12`; synthetic, test-only.
pub(super) const TEST_TLS_IDENTITY_PASSPHRASE: &str = "paper-provider-test-only";

/// Synthetic test CA certificate (DER); private cfg(test) trust root only.
/// SHA-256 1ac2618fbbd48ad812195705df9eb7ad8b056a2299b180668414d74b577e7c5b.
pub(super) const TEST_TLS_CA_DER: &[u8] = &[
    0x30, 0x82, 0x03, 0x6c, 0x30, 0x82, 0x02, 0x54, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x1f,
    0xad, 0x8b, 0x86, 0x0f, 0x49, 0x74, 0x65, 0xc3, 0x9f, 0xd3, 0x69, 0x9a, 0x09, 0x4f, 0xc1, 0xec,
    0x48, 0x30, 0xd1, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
    0x05, 0x00, 0x30, 0x3b, 0x31, 0x39, 0x30, 0x37, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x30, 0x53,
    0x79, 0x6e, 0x74, 0x68, 0x65, 0x74, 0x69, 0x63, 0x20, 0x50, 0x61, 0x70, 0x65, 0x72, 0x20, 0x50,
    0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x20,
    0x28, 0x6e, 0x6f, 0x74, 0x20, 0x61, 0x20, 0x72, 0x65, 0x61, 0x6c, 0x20, 0x43, 0x41, 0x29, 0x30,
    0x20, 0x17, 0x0d, 0x31, 0x39, 0x30, 0x36, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
    0x18, 0x0f, 0x32, 0x31, 0x32, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x5a, 0x30, 0x3b, 0x31, 0x39, 0x30, 0x37, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x30, 0x53, 0x79,
    0x6e, 0x74, 0x68, 0x65, 0x74, 0x69, 0x63, 0x20, 0x50, 0x61, 0x70, 0x65, 0x72, 0x20, 0x50, 0x72,
    0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x20, 0x28,
    0x6e, 0x6f, 0x74, 0x20, 0x61, 0x20, 0x72, 0x65, 0x61, 0x6c, 0x20, 0x43, 0x41, 0x29, 0x30, 0x82,
    0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
    0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xdf,
    0x46, 0x8f, 0xe3, 0x03, 0xab, 0x00, 0x37, 0xed, 0xbb, 0x57, 0xc5, 0x29, 0xb0, 0xea, 0x2f, 0xa6,
    0xe1, 0xef, 0x9a, 0x69, 0x22, 0xcc, 0xdf, 0x8d, 0xc2, 0x70, 0x79, 0xd2, 0xea, 0xe0, 0x7f, 0xcb,
    0x32, 0x07, 0x68, 0xdf, 0x5e, 0x50, 0x84, 0xcf, 0xa5, 0x42, 0x3b, 0x3d, 0xd3, 0xe0, 0xd4, 0x54,
    0x39, 0xa5, 0x21, 0x82, 0xcb, 0x5b, 0x6f, 0x50, 0x41, 0xc4, 0xe5, 0x76, 0xad, 0x33, 0xdf, 0x8a,
    0xe6, 0x0f, 0xa9, 0x96, 0x4c, 0x6c, 0xcd, 0x47, 0x86, 0xff, 0x22, 0xa1, 0xfe, 0x68, 0x5f, 0x1a,
    0xee, 0x67, 0xa9, 0x18, 0x76, 0x5f, 0xa8, 0xa2, 0x30, 0x8a, 0xb6, 0xc6, 0xf8, 0x6b, 0x56, 0x0c,
    0xfd, 0xfc, 0x91, 0x5c, 0x7f, 0x3e, 0x8b, 0xb4, 0x68, 0x13, 0x7e, 0xfa, 0xa0, 0xac, 0x51, 0xd8,
    0xa2, 0xf1, 0xc9, 0xf3, 0xb2, 0xaa, 0xfe, 0x2a, 0x51, 0xb4, 0xfc, 0x9e, 0x24, 0x35, 0x2d, 0x1f,
    0x64, 0xf0, 0xdf, 0xc9, 0xe7, 0x40, 0x1f, 0x3f, 0xc3, 0x99, 0xac, 0x61, 0xa0, 0x84, 0x7c, 0xb6,
    0x29, 0xe2, 0x58, 0x13, 0xfb, 0x3a, 0x39, 0x3f, 0x60, 0x81, 0x23, 0x63, 0x6d, 0xeb, 0x22, 0x11,
    0xdc, 0x79, 0x8e, 0x08, 0x45, 0x3b, 0xcd, 0x30, 0x3e, 0xbf, 0x48, 0x37, 0x37, 0x93, 0x1b, 0xa4,
    0x4a, 0xb5, 0x6f, 0x0e, 0xe8, 0xdf, 0xa4, 0x15, 0xe4, 0x14, 0xa5, 0xaa, 0xc0, 0xe7, 0x7f, 0xea,
    0x8d, 0x2f, 0x92, 0xb7, 0x98, 0x90, 0x60, 0xdb, 0xbe, 0xfb, 0xa2, 0x23, 0x56, 0xf7, 0x8d, 0x0a,
    0xf6, 0xa9, 0xf2, 0xf7, 0x1f, 0xae, 0x53, 0xbc, 0x23, 0x07, 0x43, 0x06, 0x0f, 0x4b, 0x3c, 0x3b,
    0x55, 0x6b, 0x44, 0xa9, 0x4a, 0x35, 0xec, 0x73, 0x42, 0x88, 0xe4, 0xe3, 0x84, 0x18, 0xf5, 0xc1,
    0xfc, 0x7f, 0x9b, 0x9a, 0x10, 0xd1, 0x09, 0xa4, 0x86, 0x9f, 0x9a, 0x3b, 0x53, 0x18, 0x7f, 0x02,
    0x03, 0x01, 0x00, 0x01, 0xa3, 0x66, 0x30, 0x64, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04,
    0x16, 0x04, 0x14, 0xbd, 0xdc, 0xc1, 0xf2, 0x5d, 0x58, 0xac, 0x9a, 0x50, 0x0b, 0x74, 0xdb, 0xe8,
    0x13, 0xf7, 0xd1, 0x66, 0x1e, 0x09, 0x09, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
    0x30, 0x16, 0x80, 0x14, 0xbd, 0xdc, 0xc1, 0xf2, 0x5d, 0x58, 0xac, 0x9a, 0x50, 0x0b, 0x74, 0xdb,
    0xe8, 0x13, 0xf7, 0xd1, 0x66, 0x1e, 0x09, 0x09, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
    0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x06, 0x03,
    0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x0d, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00,
    0x36, 0x77, 0xa4, 0x68, 0x95, 0xff, 0xc7, 0xf8, 0x2b, 0xa2, 0x26, 0x8f, 0x69, 0x1f, 0xe2, 0xa1,
    0x33, 0x8c, 0x39, 0xd4, 0xad, 0x77, 0xb2, 0x7e, 0xaa, 0x42, 0xd3, 0xe1, 0x21, 0x28, 0x97, 0x9f,
    0x7d, 0x77, 0x3c, 0x72, 0x64, 0x55, 0xa4, 0x83, 0xb0, 0x6c, 0x77, 0x2a, 0xc2, 0xcd, 0x78, 0x11,
    0x9b, 0x04, 0x09, 0xd8, 0xd8, 0xef, 0x72, 0x46, 0x00, 0x7b, 0x4c, 0x83, 0x85, 0xec, 0x72, 0xec,
    0xc8, 0xce, 0xe1, 0x9f, 0x54, 0x9c, 0xa4, 0xa4, 0x6c, 0x4f, 0xed, 0x99, 0xe2, 0x52, 0x9b, 0x16,
    0x30, 0xf4, 0x9d, 0xed, 0xd3, 0x89, 0xb1, 0xc2, 0x79, 0xf0, 0x3b, 0x45, 0x89, 0x8a, 0x5a, 0x7d,
    0x8c, 0x08, 0x3b, 0xf9, 0x77, 0x1a, 0xbf, 0x0b, 0xa2, 0x19, 0x13, 0x15, 0xcf, 0xd7, 0x88, 0x3e,
    0xc6, 0x92, 0xd8, 0x5b, 0x3c, 0x7b, 0xa4, 0x03, 0xd1, 0xca, 0x18, 0x74, 0x22, 0x6d, 0x86, 0x83,
    0x35, 0xbc, 0x92, 0x11, 0x98, 0xee, 0x49, 0xd0, 0x46, 0x06, 0xaf, 0x47, 0xfc, 0x19, 0x07, 0xba,
    0x0c, 0xbf, 0xd2, 0x1d, 0x1f, 0xe7, 0xf0, 0x88, 0x48, 0x13, 0x27, 0x1e, 0x98, 0x94, 0xfe, 0xad,
    0xd8, 0xf9, 0xbe, 0x66, 0xb2, 0x3a, 0x2b, 0xb3, 0x9b, 0x86, 0x29, 0x9e, 0xed, 0x77, 0x30, 0x71,
    0x47, 0x28, 0x31, 0x43, 0x4d, 0x28, 0x8a, 0x37, 0xcc, 0x61, 0x5e, 0x53, 0x16, 0x1c, 0xf3, 0xd4,
    0x5c, 0xc4, 0xd0, 0x21, 0xca, 0xbe, 0x6f, 0x5d, 0xd9, 0xb1, 0x24, 0x43, 0x91, 0x6f, 0x9d, 0x8a,
    0x63, 0x06, 0xd6, 0x48, 0xe5, 0x50, 0x36, 0x7c, 0xe5, 0x0e, 0xaf, 0x38, 0x6e, 0x47, 0x14, 0x4d,
    0x4c, 0x3a, 0x92, 0x8a, 0xea, 0xc4, 0xea, 0x7a, 0xd2, 0xd9, 0x18, 0xff, 0x5f, 0x47, 0x70, 0xd3,
    0x61, 0x07, 0xc1, 0x76, 0x5c, 0x58, 0xf9, 0x52, 0xac, 0xa3, 0x3e, 0x57, 0x25, 0x66, 0xdc, 0x15,
];

/// Leaf certificate (DER), SAN DNS:paper-provider.test, EKU serverAuth.
/// SHA-256 345fc75cc8297102630c5870e00fa6e9f7b1b5f234b29fa0a31b1ab7adad68f5.
pub(super) const TEST_TLS_LEAF_DER: &[u8] = &[
    0x30, 0x82, 0x03, 0x6f, 0x30, 0x82, 0x02, 0x57, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x03, 0x5a,
    0x17, 0xe5, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
    0x00, 0x30, 0x3b, 0x31, 0x39, 0x30, 0x37, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x30, 0x53, 0x79,
    0x6e, 0x74, 0x68, 0x65, 0x74, 0x69, 0x63, 0x20, 0x50, 0x61, 0x70, 0x65, 0x72, 0x20, 0x50, 0x72,
    0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x20, 0x28,
    0x6e, 0x6f, 0x74, 0x20, 0x61, 0x20, 0x72, 0x65, 0x61, 0x6c, 0x20, 0x43, 0x41, 0x29, 0x30, 0x20,
    0x17, 0x0d, 0x31, 0x39, 0x30, 0x36, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18,
    0x0f, 0x32, 0x31, 0x32, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
    0x30, 0x1e, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x13, 0x70, 0x61, 0x70,
    0x65, 0x72, 0x2d, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x2e, 0x74, 0x65, 0x73, 0x74,
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
    0x00, 0xb6, 0xf0, 0x84, 0x66, 0xc1, 0x11, 0x62, 0x50, 0x62, 0xd0, 0xdb, 0x6d, 0x17, 0xda, 0xd5,
    0x64, 0xbe, 0x30, 0x7c, 0xb8, 0x9b, 0x28, 0xe3, 0x3d, 0xf2, 0x09, 0xbb, 0x6d, 0x54, 0xab, 0xee,
    0xfc, 0x9c, 0x15, 0xf3, 0xb3, 0x81, 0x4d, 0xee, 0xf8, 0x66, 0x28, 0x71, 0x72, 0xc0, 0x66, 0x3b,
    0xda, 0x7b, 0x6d, 0xf1, 0x26, 0xae, 0xd3, 0xfb, 0x42, 0x57, 0x23, 0x65, 0x00, 0x09, 0x81, 0xc6,
    0x92, 0x3f, 0xc8, 0x57, 0x22, 0xf5, 0x83, 0x5f, 0x73, 0xc2, 0x05, 0x90, 0x3c, 0x23, 0xb2, 0x67,
    0x0d, 0x7f, 0x7b, 0xde, 0x8e, 0xef, 0x96, 0x56, 0x9d, 0xfd, 0xba, 0xac, 0xe3, 0x2b, 0xa2, 0xfc,
    0x5c, 0x74, 0x55, 0x2e, 0xb7, 0x1b, 0x22, 0x7f, 0x40, 0x31, 0x0a, 0xc7, 0x4f, 0xbb, 0x0e, 0x3f,
    0xc0, 0x86, 0x4e, 0x80, 0xae, 0x85, 0x62, 0xe0, 0x77, 0x69, 0xbd, 0x50, 0x0b, 0x92, 0xb6, 0xb7,
    0x5b, 0x80, 0x23, 0x93, 0x0d, 0x0e, 0x1f, 0x61, 0x38, 0x13, 0x89, 0x95, 0xa1, 0x86, 0x94, 0x48,
    0xd7, 0x2c, 0xce, 0xb6, 0x7f, 0xe3, 0xf7, 0xa0, 0x62, 0xe1, 0xb6, 0x4b, 0xcc, 0xf3, 0xe6, 0xf3,
    0xbf, 0x5d, 0x94, 0xc3, 0xf3, 0xe4, 0xef, 0x6c, 0xe9, 0x87, 0xc0, 0xfa, 0x26, 0x95, 0x78, 0x23,
    0xf7, 0xf1, 0x70, 0x3c, 0xa8, 0x91, 0x34, 0x9c, 0xee, 0x8d, 0x9d, 0x82, 0xc2, 0x88, 0x7b, 0x83,
    0x8e, 0x1a, 0x8c, 0x8f, 0xac, 0x2c, 0x57, 0xfb, 0x84, 0x16, 0xc2, 0x55, 0xf8, 0x3d, 0x02, 0x84,
    0xdd, 0x5a, 0xcf, 0xad, 0xb7, 0xa5, 0x32, 0x9c, 0xdb, 0x28, 0x62, 0x79, 0x0c, 0x9f, 0xe5, 0x62,
    0x4e, 0xb0, 0x42, 0x95, 0x0b, 0x1b, 0xe2, 0xcb, 0xf8, 0x7e, 0xc8, 0xee, 0xe6, 0xb0, 0xbd, 0x43,
    0x4c, 0x55, 0x09, 0x3e, 0xb9, 0x4d, 0x69, 0x99, 0xac, 0x8f, 0x4c, 0x9a, 0x35, 0x70, 0xad, 0xa7,
    0x3b, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x81, 0x96, 0x30, 0x81, 0x93, 0x30, 0x0c, 0x06, 0x03,
    0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d,
    0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d,
    0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x30,
    0x1e, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x17, 0x30, 0x15, 0x82, 0x13, 0x70, 0x61, 0x70, 0x65,
    0x72, 0x2d, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x30,
    0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xaf, 0xf8, 0x75, 0x34, 0x01, 0x79,
    0x00, 0x52, 0xb8, 0x66, 0xba, 0x44, 0x4f, 0x48, 0x1b, 0xba, 0x2a, 0x44, 0xd6, 0xad, 0x30, 0x1f,
    0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xbd, 0xdc, 0xc1, 0xf2, 0x5d,
    0x58, 0xac, 0x9a, 0x50, 0x0b, 0x74, 0xdb, 0xe8, 0x13, 0xf7, 0xd1, 0x66, 0x1e, 0x09, 0x09, 0x30,
    0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82,
    0x01, 0x01, 0x00, 0xdc, 0xb6, 0xa3, 0xf9, 0x6b, 0x88, 0xf6, 0xbe, 0x8e, 0xc7, 0x1d, 0x7f, 0x5d,
    0xbe, 0xa4, 0xe1, 0x15, 0xc1, 0xa7, 0xe7, 0x31, 0x75, 0xba, 0xb7, 0x2d, 0xca, 0xf6, 0x9c, 0xbe,
    0x33, 0x66, 0x62, 0xc4, 0x9d, 0xd1, 0x81, 0x0e, 0x7f, 0x69, 0x09, 0xe9, 0xca, 0xa6, 0x0d, 0xbe,
    0x3c, 0x3e, 0x89, 0x7b, 0xa0, 0x01, 0x43, 0x88, 0x35, 0x3d, 0xa2, 0x0f, 0x8b, 0xa6, 0x96, 0xc8,
    0x02, 0x05, 0xe9, 0x8c, 0x12, 0x8b, 0xc2, 0xd9, 0xa7, 0xda, 0x7b, 0x70, 0x8a, 0x9a, 0x35, 0x3b,
    0x33, 0x6c, 0x95, 0x38, 0x24, 0x32, 0x53, 0xf8, 0x9e, 0xe1, 0xde, 0x85, 0x9d, 0x87, 0xc7, 0x17,
    0x65, 0xa6, 0x13, 0x7b, 0xc3, 0xf9, 0xd6, 0x39, 0x2c, 0x71, 0xe9, 0x47, 0x65, 0xf6, 0x70, 0x4a,
    0x2e, 0x27, 0x59, 0x98, 0x1b, 0x49, 0x7f, 0xa7, 0x26, 0x59, 0x1c, 0x2f, 0xc4, 0x1e, 0x70, 0x7e,
    0x9d, 0x4f, 0x31, 0xf0, 0x43, 0x9a, 0x2a, 0x94, 0x57, 0x90, 0xe7, 0x1f, 0xec, 0xb0, 0x21, 0xa4,
    0xfd, 0x51, 0x16, 0x20, 0x59, 0xc8, 0x61, 0xeb, 0x8e, 0xa5, 0x7c, 0xad, 0xa7, 0x43, 0x6f, 0x61,
    0x9a, 0x88, 0xe8, 0xa7, 0xc9, 0x15, 0xd6, 0x54, 0x51, 0x60, 0x10, 0x2a, 0xf6, 0x80, 0xfc, 0xd0,
    0xfc, 0x3b, 0xcb, 0x9d, 0x8f, 0x15, 0x66, 0x29, 0x66, 0x08, 0x2a, 0xb3, 0xb0, 0xfe, 0x66, 0x15,
    0x58, 0x14, 0xd9, 0x06, 0xdc, 0xfa, 0xf9, 0x0e, 0x9c, 0xdd, 0xa6, 0x6f, 0x8f, 0x72, 0x47, 0x4d,
    0x06, 0x92, 0x29, 0x1e, 0xff, 0x69, 0x05, 0x45, 0x10, 0x4c, 0xb7, 0xd2, 0x1a, 0x0d, 0xd3, 0x7a,
    0xd8, 0x76, 0x1f, 0x01, 0x72, 0x4f, 0x0c, 0xd9, 0x1e, 0x69, 0xc1, 0x43, 0xd5, 0x65, 0xa4, 0x90,
    0x67, 0x27, 0x15, 0x4c, 0x68, 0x72, 0xe9, 0x29, 0x7d, 0x86, 0xf4, 0x6f, 0x5c, 0xe2, 0x67, 0x4b,
    0x5e, 0x48, 0x05,
];

/// Reserved hostname bound in the leaf SAN.
pub(super) const TEST_TLS_HOST: &str = "paper-provider.test";

/// A second reserved name absent from the SAN, for the hostname-mismatch case.
pub(super) const TEST_TLS_WRONG_HOST: &str = "wrong-name.test";
