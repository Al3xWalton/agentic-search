// SPDX-License-Identifier: AGPL-3.0-only
//! Exercises stock startup and real loopback search serving with synthetic, owned fixtures.
//! Children use fixed reserved ports, finite readiness and cleanup; no external assets are read.

use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const DELETED: &str = "a30810149588dba56ba802dcd755787ba916ff0362ae7c0be3a0de4a2aa66b03";
const ALLOWED: &str = "02a962af645644114931287f08a52a685ef73d16d02c9974a4f6e18f9517ee24";
const REFUSAL: &[u8] = br#"{"error":{"code":"legacy_api_retired","message":"Use the v1 API"}}"#;
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// Fixture errors never include request bodies, credential values or captured child output.
#[track_caller]
fn must<T, E>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(_) => panic!("STOCK_FIXTURE_OPERATION"),
    }
}

// A child is always killed and reaped before its temporary directories can disappear.
struct OwnedChild {
    child: Child,
    stdout: PathBuf,
    stderr: PathBuf,
    reaped: bool,
}

impl OwnedChild {
    // Logs go to owned files so a full pipe cannot prevent readiness or shutdown.
    fn spawn(root: &Path, command: &str, config: &Path) -> Self {
        let stdout = root.join(format!("{command}.stdout"));
        let stderr = root.join(format!("{command}.stderr"));
        let child = must(
            Command::new(env!("CARGO_BIN_EXE_stract"))
                .arg(command)
                .arg(config)
                .current_dir(root)
                .env("RUST_BACKTRACE", "0")
                .stdout(Stdio::from(must(fs::File::create(&stdout))))
                .stderr(Stdio::from(must(fs::File::create(&stderr))))
                .spawn(),
        );
        Self {
            child,
            stdout,
            stderr,
            reaped: false,
        }
    }

    // Finite polling distinguishes a semantic exit from an unfinished process.
    fn exited(&mut self, deadline: Duration) -> std::process::ExitStatus {
        let start = Instant::now();
        loop {
            if let Some(status) = must(self.child.try_wait()) {
                self.reaped = true;
                return status;
            }
            assert!(start.elapsed() < deadline, "STOCK_EXIT_TIMEOUT");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    // Only the exact owned child handle receives a termination signal.
    fn stop(&mut self) {
        if !self.reaped {
            if must(self.child.try_wait()).is_none() {
                must(self.child.kill());
            }
            self.exited(Duration::from_secs(5));
        }
        println!("OWNED_CHILD_REAPED {}", self.child.id());
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if self.child.try_wait().ok().flatten().is_some() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            panic!("STOCK_REAP_TIMEOUT");
        }
    }
}

// Holding every reservation checks conflicts without identifying or touching another process.
fn ports_free() {
    let tcp: Vec<_> = (57300..=57320)
        .map(|port| must(TcpListener::bind(("127.0.0.1", port))))
        .collect();
    let udp: Vec<_> = (57300..=57320)
        .map(|port| must(UdpSocket::bind(("127.0.0.1", port))))
        .collect();
    assert!(
        tcp.len() == 21 && udp.len() == 21,
        "STOCK_PORT_RESERVATIONS"
    );
}

// Values preserve absent optional fields; the written text is validated as ApiConfig.
fn config(root: &Path) -> toml::Value {
    let mut value: toml::Value = must(toml::from_str(include_str!(
        "../../../configs/eval/api-off.toml"
    )));
    value["gossip_seed_nodes"] = toml::Value::Array(vec!["127.0.0.1:57306".into()]);
    value.as_table_mut().unwrap().insert(
        "v1".into(),
        must(toml::Value::try_from(json!({
        "management_http_host":"127.0.0.1:57312",
        "suppression_store_path":root.join("serving/suppression.json")}))),
    );
    value.as_table_mut().unwrap().insert(
        "compliance".into(),
        must(toml::Value::try_from(json!({
        "store_dir":root.join("cases"),"records_dir":root.join("records")}))),
    );
    value
}

// Validation uses the actual type and never serializes ApiConfig's optional-label array.
fn write_config(root: &Path, value: &toml::Value) -> PathBuf {
    let text = must(toml::to_string(value));
    let _: stract::config::ApiConfig = must(toml::from_str(&text));
    let path = root.join("api.toml");
    must(fs::write(&path, text));
    path
}

// The base probe and stock service use the same independently specified three documents.
fn index(root: &Path) {
    let mut index = must(stract::index::Index::open(root));
    index.set_shard_id(stract::inverted_index::ShardId::Backbone(0));
    must(index.inverted_index.prepare_writer());
    for (path, word) in [
        ("deleted", "cedar"),
        ("blocked", "maple"),
        ("allowed", "birch"),
    ] {
        let source = format!(
            "<html><head><title>Synthetic {word}</title>\
            <meta name=\"description\" content=\"Synthetic {word} body with enough words \
            for a deterministic complete search snippet.\"></head>\
            <body><p>Synthetic {word} body</p></body></html>"
        );
        let html = must(stract::webpage::Html::parse(
            &source,
            &format!("https://fixture.test/{path}"),
        ));
        must(index.insert(&stract::webpage::Webpage::from(html)));
    }
    must(index.commit());
}

// Each one-result response pins attribution independently of the production mapper.
fn expected(word: &str, path: &str, id: &str) -> Value {
    let snippet = format!(
        "Synthetic {word} body with enough words for a deterministic complete search snippet."
    );
    json!({"version":"v1","results":[{"id":id,
        "url":format!("https://fixture.test/{path}"),"domain":"fixture.test",
        "title":format!("Synthetic {word}"),"snippet":snippet}],
        "page":0,"num_results":10,"has_more_results":false})
}

// Body capture retains complete bytes for both JSON and empty listener fallbacks.
struct Observed {
    status: u16,
    headers: reqwest::header::HeaderMap,
    bytes: Vec<u8>,
}

// No ambient proxy or redirect can move a synthetic request away from loopback.
fn client() -> reqwest::Client {
    must(
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build(),
    )
}

// Every real request carries only a fixture body and targets an owned listener.
async fn request(
    client: &reqwest::Client,
    port: u16,
    method: &str,
    path: &str,
    body: Vec<u8>,
) -> Observed {
    let response = client
        .request(
            must(method.parse()),
            format!("http://127.0.0.1:{port}{path}"),
        )
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap_or_else(|error| {
            panic!(
                "STOCK_TRANSPORT store={} connect={} timeout={} body={} request={}",
                path == "/improvement/store",
                error.is_connect(),
                error.is_timeout(),
                error.is_body(),
                error.is_request()
            )
        });
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = must(response.bytes().await).to_vec();
    Observed {
        status,
        headers,
        bytes,
    }
}

// Expect/Continue lets an early refusal arrive before a large sender sees a connection reset.
async fn request_with_continue(path: &'static str, body: Vec<u8>) -> (Observed, usize) {
    must(
        tokio::task::spawn_blocking(move || {
            let stream = must(TcpStream::connect(("127.0.0.1", 57300)));
            must(stream.set_read_timeout(Some(Duration::from_secs(5))));
            must(stream.set_write_timeout(Some(Duration::from_secs(5))));
            let mut reader = BufReader::new(stream);
            let head = format!(
                "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:57300\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\
             Expect: 100-continue\r\nConnection: close\r\n\r\n",
                body.len()
            );
            must(reader.get_mut().write_all(head.as_bytes()));
            let (mut status, mut headers) = response_head(&mut reader);
            let mut sent = 0;
            if status == 100 {
                must(reader.get_mut().write_all(&body));
                sent = body.len();
                (status, headers) = response_head(&mut reader);
            }
            let length = headers
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<usize>().ok())
                .expect("STOCK_RESPONSE_LENGTH");
            assert!(length <= 4 * 1024 * 1024, "STOCK_RESPONSE_BOUND");
            let mut bytes = vec![0; length];
            must(reader.read_exact(&mut bytes));
            (
                Observed {
                    status,
                    headers,
                    bytes,
                },
                sent,
            )
        })
        .await,
    )
}

// A finite header parser preserves the complete response without printing captured values.
fn response_head(reader: &mut BufReader<TcpStream>) -> (u16, reqwest::header::HeaderMap) {
    let mut line = String::new();
    must(reader.read_line(&mut line));
    assert!(line.starts_with("HTTP/1.1 "), "STOCK_HTTP_VERSION");
    let status = must(
        line.split_whitespace()
            .nth(1)
            .expect("STOCK_STATUS")
            .parse(),
    );
    let mut headers = reqwest::header::HeaderMap::new();
    for _ in 0..32 {
        line.clear();
        must(reader.read_line(&mut line));
        assert!(line.len() <= 8192, "STOCK_HEADER_BOUND");
        if line == "\r\n" {
            return (status, headers);
        }
        let (name, value) = line.trim_end().split_once(':').expect("STOCK_HEADER");
        headers.append(
            must(reqwest::header::HeaderName::from_bytes(name.as_bytes())),
            must(reqwest::header::HeaderValue::from_str(value.trim())),
        );
    }
    panic!("STOCK_HEADER_COUNT")
}

// Readiness retries transport refusal only; a served response is asserted immediately.
async fn ready(client: &reqwest::Client, api: &mut OwnedChild, search: &mut OwnedChild) {
    let start = Instant::now();
    loop {
        assert!(
            must(api.child.try_wait()).is_none() && must(search.child.try_wait()).is_none(),
            "STOCK_CHILD_EARLY_EXIT"
        );
        if let Ok(response) = client.get("http://127.0.0.1:57300/v1/source").send().await {
            let status = response.status().as_u16();
            let bytes = must(response.bytes().await);
            assert!(
                status == 200
                    && serde_json::from_slice::<Value>(&bytes).ok() == Some(source_value(true)),
                "W10_READY_SOURCE"
            );
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "STOCK_READINESS_TIMEOUT"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

// Source values are public build metadata, with no timestamps or arbitrary fields masked.
fn source_value(versioned: bool) -> Value {
    let revision = env!("AVA_SEARCH_REVISION");
    let repository = "https://github.com/Al3xWalton/agentic-search";
    let source = if revision == "unknown" {
        repository.into()
    } else {
        format!("{repository}/tree/{revision}")
    };
    let mut value = json!({"licence":"AGPL-3.0-only","source_url":source,
        "revision":revision,"revision_source":env!("AVA_SEARCH_REVISION_SOURCE")});
    if versioned {
        value["version"] = json!("v1");
    }
    value
}

// Whole successful values and standard contract headers must agree on the stock listener.
fn success(actual: &Observed, expected: Value, marker: &str) {
    assert!(
        actual.status == 200
            && serde_json::from_slice::<Value>(&actual.bytes).ok() == Some(expected),
        "{marker}"
    );
    assert!(
        actual
            .headers
            .get("source-offer")
            .is_some_and(|value| value == source_value(false)["source_url"].as_str().unwrap()),
        "W10_SOURCE_HEADER"
    );
}

// Real transport adds a Date header; all retirement contract headers are pinned separately.
fn refused(actual: &Observed) {
    assert!(
        actual.status == 410
            && actual.bytes == REFUSAL
            && actual
                .headers
                .get("content-type")
                .is_some_and(|v| v == "application/json")
            && actual
                .headers
                .get("cache-control")
                .is_some_and(|v| v == "no-store")
            && actual
                .headers
                .get("source-offer")
                .is_some_and(|v| v == source_value(false)["source_url"].as_str().unwrap())
            && !actual.headers.contains_key("location")
            && !actual.headers.contains_key("x-api-version"),
        "W10_REAL_ASSEMBLY"
    );
}

// The fixture's explicit request uses the supported context and bounded pagination.
fn query(word: &str) -> Vec<u8> {
    must(serde_json::to_vec(
        &json!({"query":word,"page":0,"num_results":10,
        "country":"unknown","adult_verified":false,"scholarly":false}),
    ))
}

// Starting actual binaries proves that attach_v1 and startup reach the witnessed composition.
async fn stock_control(root: &Path, value: &toml::Value) {
    ports_free();
    index(&root.join("index"));
    let search_config = root.join("search.toml");
    let source = format!(
        "host = '127.0.0.1:57302'\ngossip_addr = '127.0.0.1:57306'\n\
        gossip_seed_nodes = ['127.0.0.1:57305']\nindex_path = '{}'\nshard = 0\n",
        root.join("index").display()
    );
    let _: stract::config::SearchServerConfig = must(toml::from_str(&source));
    must(fs::write(&search_config, source));
    let mut search = OwnedChild::spawn(root, "search-server", &search_config);
    let mut api = OwnedChild::spawn(root, "api", &write_config(root, value));
    let client = client();
    ready(&client, &mut api, &mut search).await;
    success(
        &request(&client, 57300, "POST", "/v1/search", query("cedar")).await,
        expected("cedar", "deleted", DELETED),
        "W10_REAL_ASSEMBLY",
    );
    success(
        &request(
            &client,
            57312,
            "DELETE",
            &format!("/v1/documents/{DELETED}"),
            vec![],
        )
        .await,
        json!({"version":"v1","id":DELETED,"suppressed":true}),
        "W10_DELETE_ACK",
    );
    success(
        &request(&client, 57300, "POST", "/v1/search", query("cedar")).await,
        json!({"version":"v1","results":[],"page":0,"num_results":10,"has_more_results":false}),
        "W10_DELETE",
    );
    success(
        &request(&client, 57300, "POST", "/v1/search", query("birch")).await,
        expected("birch", "allowed", ALLOWED),
        "W10_ALLOWED",
    );
    retired_routes(&client).await;
    publications(&client).await;
    api.stop();
    search.stop();
    ports_free();
}

// Former operations and listener separation are exercised over real local HTTP.
async fn retired_routes(client: &reqwest::Client) {
    for path in [
        "/beta/api/search",
        "/beta/api/search/widget",
        "/beta/api/search/sidebar",
        "/beta/api/search/spellcheck",
        "/beta/api/entity_image",
        "/beta/api/entity_image?width=bad",
        "/beta/api/autosuggest",
        "/beta/api/autosuggest/browser",
        "/beta/api/docs/swagger",
        "/beta/api/docs/openapi.json",
    ] {
        for method in ["GET", "POST"] {
            refused(&request(client, 57300, method, path, query("cedar")).await);
        }
    }
    let body = must(serde_json::to_vec(&json!({"query":"x".repeat(1_000_000),
        "urls":["https://example.test/a"]})));
    let (actual, sent) = request_with_continue("/improvement/store", body).await;
    refused(&actual);
    assert!(sent == 0, "W10_EXPECT_UNREAD");
    let body = query("birch");
    let length = body.len();
    let (actual, sent) = request_with_continue("/v1/search", body).await;
    success(
        &actual,
        expected("birch", "allowed", ALLOWED),
        "W10_EXPECT_CONTROL",
    );
    assert!(sent == length, "W10_EXPECT_CONTROL");
    for port in [57301, 57312] {
        for path in [
            "/beta/api/search",
            "/improvement/store",
            "/improvement/click",
        ] {
            let actual = request(client, port, "POST", path, vec![]).await;
            assert!(
                actual.status == 404 && actual.bytes.is_empty(),
                "W10_LISTENERS"
            );
        }
    }
}

// Independent complete publication fixtures guard preservation of active metadata routes.
async fn publications(client: &reqwest::Client) {
    for (port, path, versioned) in [
        (57300, "/v1/source", true),
        (57312, "/v1/source", true),
        (57300, "/.well-known/ava-search-source", false),
        (57301, "/.well-known/ava-search-source", false),
    ] {
        success(
            &request(client, port, "GET", path, vec![]).await,
            source_value(versioned),
            "W10_SOURCE",
        );
    }
    let docs = request(client, 57300, "GET", "/api/docs/openapi.json", vec![]).await;
    assert!(
        docs.status == 200
            && docs.bytes == include_bytes!("fixtures/api_v1/published-openapi.json"),
        "W10_DOCS"
    );
    let egress = request(
        client,
        57300,
        "GET",
        "/.well-known/ava-search-egress.json",
        vec![],
    )
    .await;
    assert!(
        egress.status == 503
            && egress.bytes
                == br#"{"status":"pending","detail":"Signed egress inventory is not configured."}"#,
        "W10_EGRESS"
    );
    let markdown = include_str!("../../../CRAWLER_POLICY.md");
    let escaped = markdown
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;");
    let expected = format!(
        concat!(
            "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">",
            "<title>AVA Search crawler policy</title><body><article><pre>{}",
            "</pre></article></body></html>"
        ),
        escaped
    );
    let policy = request(
        client,
        57300,
        "GET",
        "/.well-known/ava-search-crawler",
        vec![],
    )
    .await;
    assert!(
        policy.status == 200 && policy.bytes == expected.as_bytes(),
        "W10_POLICY"
    );
}

#[tokio::test]
async fn w06_stock_startup_retirement() {
    let _serial = SERIAL.lock().await;
    ports_free();
    let root = must(stract::gen_temp_dir());
    let valid = config(root.as_ref());
    for missing_secret in [true, false] {
        let mut value = valid.clone();
        value.as_table_mut().unwrap().insert(
            "query_store_db".into(),
            must(toml::Value::try_from(json!({
            "host":"127.0.0.1:57320","username":"x","password":"x"}))),
        );
        if missing_secret {
            value["v1"].as_table_mut().unwrap().insert(
                "paper_provider".into(),
                must(toml::Value::try_from(json!({
                "kind":"openalex","api_key_file":root.as_ref().join("missing-secret")}))),
            );
        }
        let mut child =
            OwnedChild::spawn(root.as_ref(), "api", &write_config(root.as_ref(), &value));
        let status = child.exited(Duration::from_secs(30));
        assert!(
            status.code() == Some(1)
                && must(fs::read(&child.stdout)).is_empty()
                && must(fs::read(&child.stderr)) == b"Error: query_store_db has been retired\n",
            "W06_BEFORE_RESOURCES"
        );
        assert!(
            !root.as_ref().join("serving").exists()
                && !root.as_ref().join("cases").exists()
                && !root.as_ref().join("records").exists(),
            "W06_NO_RESOURCE_WRITES"
        );
        ports_free();
    }
    stock_control(root.as_ref(), &valid).await;
}

#[tokio::test]
async fn w10_stock_server_retirement() {
    let _serial = SERIAL.lock().await;
    let root = must(stract::gen_temp_dir());
    stock_control(root.as_ref(), &config(root.as_ref())).await;
}
