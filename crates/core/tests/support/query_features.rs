// SPDX-License-Identifier: AGPL-3.0-only
//! Build tiny real graph, host-store, index and English model fixtures for feature contracts.
//! All data is synthetic and owned by returned temporary directories. Fixed multiplicities
//! witness counting and content identity; this module never reads retained assets or labels.

use std::path::{Path, PathBuf};
use stract::{
    eval::features::Arguments,
    index::Index,
    webgraph::{Edge, Node, NodeID},
    webpage::{Html, Webpage},
};

/// Owned native protocol fixtures. Dropping the owner aborts every bounded server task.
pub struct GateServices {
    /// Literal socket of the owned ClusterStatus fixture.
    pub management: String,
    /// Resolved synthetic configs, in backbone shard order.
    pub search_configs: [PathBuf; 2],
    /// Two identities bound to exact synthetic inspect-manifest bytes.
    pub indexes: serde_json::Value,
    /// Mutable membership used to exercise wrong and extra shard sockets.
    pub members: std::sync::Arc<std::sync::Mutex<Vec<(u64, std::net::SocketAddr)>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for GateServices {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

// Sonic exposes neither a bound listener constructor nor its selected local address.
// Retry only the reservation-to-bind race, with a finite number of fresh ports.
async fn native_server<Req: bincode::Decode, Res>() -> (
    std::net::SocketAddr,
    stract::distributed::sonic::Server<Req, Res>,
) {
    use stract::distributed::sonic::{Error, Server};
    for _ in 0..16 {
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = reserved.local_addr().unwrap();
        drop(reserved);
        match Server::bind(socket).await {
            Ok(server) => return (socket, server),
            Err(Error::IO(error)) if error.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(error) => panic!("native fixture bind: {error}"),
        }
    }
    panic!("native fixture bind exhausted 16 port reservations");
}

impl GateServices {
    /// Serve ClusterStatus and exactly the native SizeQuery/retrieve protocol.
    pub async fn start(root: &Path, counts: [u64; 2]) -> Self {
        use serde_json::json;
        type SearchRequest = <SearchService as Service>::Request;
        type ManagementRequest = <ManagementService as Service>::Request;
        use stract::{
            distributed::sonic::service::Service,
            entrypoint::{
                api::{ManagementService, Status},
                search_server::SearchService,
            },
            generic_query::size::SizeResponse,
            inverted_index::ShardId,
            OneOrMany,
        };
        let mut tasks = Vec::new();
        let mut sockets = Vec::new();
        for (ordinal, pages) in counts.into_iter().enumerate() {
            let (socket, server) = native_server::<
                OneOrMany<<SearchService as Service>::Request>,
                OneOrMany<<SearchService as Service>::Response>,
            >()
            .await;
            sockets.push(socket);
            tasks.push(tokio::spawn(async move {
                loop {
                    let Ok(Ok(mut conn)) =
                        tokio::time::timeout(std::time::Duration::from_secs(30), server.accept())
                            .await
                    else {
                        break;
                    };
                    let req = conn.request().await.unwrap();
                    assert!(matches!(
                        req.body(),
                        OneOrMany::One(SearchRequest::SizeQuery(_))
                    ));
                    let fruit = [(ShardId::Backbone(ordinal as u64), SizeResponse { pages })]
                        .into_iter()
                        .collect();
                    req.respond(OneOrMany::One(
                        <SearchService as Service>::Response::SizeQuery(Box::new(Ok(fruit))),
                    ))
                    .await
                    .unwrap();
                    if let Ok(req) = conn.request().await {
                        assert!(matches!(
                            req.body(),
                            OneOrMany::One(SearchRequest::SizeQueryRetrieve(_))
                        ));
                        req.respond(OneOrMany::One(
                            <SearchService as Service>::Response::SizeQueryRetrieve(Box::new(Ok(
                                SizeResponse { pages },
                            ))),
                        ))
                        .await
                        .unwrap();
                    }
                }
            }));
        }
        let members = std::sync::Arc::new(std::sync::Mutex::new(
            sockets
                .iter()
                .enumerate()
                .map(|(i, s)| (i as u64, *s))
                .collect::<Vec<_>>(),
        ));
        let (socket, server) = native_server::<
            OneOrMany<<ManagementService as Service>::Request>,
            OneOrMany<<ManagementService as Service>::Response>,
        >()
        .await;
        let status_members = members.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                let Ok(Ok(mut conn)) =
                    tokio::time::timeout(std::time::Duration::from_secs(30), server.accept()).await
                else {
                    break;
                };
                let req = conn.request().await.unwrap();
                assert!(matches!(
                    req.body(),
                    OneOrMany::One(ManagementRequest::ClusterStatus(_))
                ));
                let members = status_members
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(id, host)| {
                        stract::distributed::member::Member::new(
                            stract::distributed::member::Service::Searcher {
                                host: *host,
                                shard: ShardId::Backbone(*id),
                            },
                        )
                    })
                    .collect();
                req.respond(OneOrMany::One(
                    <ManagementService as Service>::Response::ClusterStatus(Box::new(Status {
                        members,
                    })),
                ))
                .await
                .unwrap();
            }
        }));
        let search_configs = std::array::from_fn(|i| root.join(format!("search-{i}.toml")));
        let mut indexes = Vec::new();
        for (i, path) in search_configs.iter().enumerate() {
            let index = root.parent().unwrap().join(format!("index-{i}"));
            std::fs::create_dir(&index).unwrap();
            std::fs::write(index.join("physical-data"), b"bound synthetic index bytes").unwrap();
            let config = format!(
                "host = {:?}\nindex_path = {:?}\nshard = {i}\n",
                sockets[i].to_string(),
                index.to_str().unwrap()
            );
            std::fs::write(path, config).unwrap();
            let files = stract::eval::index::manifest(&index).unwrap();
            let mut bytes = serde_json::to_vec_pretty(
                &json!({"schema_version":1,"index":index,"pre_open_files":files,"documents":2}),
            )
            .unwrap();
            bytes.push(b'\n');
            indexes.push(json!({"shard":i,"documents":2,"content_sha256":if i==0{"a".repeat(64)}else{"b".repeat(64)},
                "manifest_sha256":stract::eval::input::sha256(&bytes),"executable_sha256":"a".repeat(64)}));
        }
        Self {
            management: format!("http://{socket}"),
            search_configs,
            indexes: json!(indexes),
            members,
            tasks,
        }
    }
}

/// Captured gate request used to assert exact runner protocol and zero requests on refusal.
pub struct GateRequest {
    /// Exact HTTP method and path.
    pub line: String,
    /// Request headers for encoding and connection assertions.
    pub headers: String,
    /// Parsed runner request body.
    pub body: serde_json::Value,
}

/// Bounded synthetic HTTP server; the owner explicitly stops and joins it after the gate.
pub async fn gate_http(
    responses: Vec<serde_json::Value>,
) -> (
    stract::eval::endpoint::Endpoint,
    std::sync::Arc<std::sync::Mutex<Vec<GateRequest>>>,
    tokio::task::JoinHandle<()>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = stract::eval::endpoint::Endpoint::parse(&format!(
        "http://{}",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = requests.clone();
    let task = tokio::spawn(async move {
        for response in responses {
            let (mut socket, _) =
                tokio::time::timeout(std::time::Duration::from_secs(30), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
            let mut bytes = Vec::new();
            let (end, headers, length) = loop {
                let mut chunk = [0; 1024];
                let n = socket.read(&mut chunk).await.unwrap();
                assert!(n > 0 && bytes.len() + n <= 128 * 1024);
                bytes.extend_from_slice(&chunk[..n]);
                if let Some(end) = bytes.windows(4).position(|p| p == b"\r\n\r\n") {
                    let end = end + 4;
                    let headers = String::from_utf8(bytes[..end].to_vec()).unwrap();
                    let length: usize = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap())
                        })
                        .unwrap();
                    break (end, headers, length);
                }
            };
            assert!(length <= 64 * 1024);
            while bytes.len() - end < length {
                let mut chunk = [0; 1024];
                let n = socket.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
            }
            recorded.lock().unwrap().push(GateRequest {
                line: headers.lines().next().unwrap().into(),
                headers,
                body: serde_json::from_slice(&bytes[end..end + length]).unwrap(),
            });
            let body = serde_json::to_vec(&response).unwrap();
            let head=format!("HTTP/1.1 200 Fixture\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",body.len());
            socket.write_all(head.as_bytes()).await.unwrap();
            socket.write_all(&body).await.unwrap();
            socket.shutdown().await.unwrap();
        }
    });
    (endpoint, requests, task)
}

/// A private synthetic feature fixture; its directory must outlive every reader.
pub struct Fixture {
    /// Owner of all graphs, stores, indexes, model files and output paths in this fixture.
    pub directory: file_store::temp::TempDir,
    /// CLI-equivalent inputs, with the optional checker omitted until explicitly trained.
    pub args: Arguments,
}

/// Build two duplicate-aware shards and a graph containing a duplicate and a self-edge.
/// Panics on fixture setup failure; never substitutes an empty index for a failed build.
pub fn fixture() -> Fixture {
    fixture_graph(false)
}

/// Add non-HTTP, over-bound, empty and exactly-8192-byte endpoints through the graph writer.
/// All other synthetic indexes and stores match fixture(); setup failures panic.
pub fn fixture_with_rejected_endpoints() -> Fixture {
    fixture_graph(true)
}

fn fixture_graph(rejected_endpoints: bool) -> Fixture {
    let directory = stract::gen_temp_dir().unwrap();
    let args = fixture_arguments(directory.as_ref(), rejected_endpoints);
    Fixture { args, directory }
}

/// Build the standard fixture inside a caller-owned, empty directory at any absolute path.
/// The caller retains and removes the directory; fixture setup errors panic.
pub fn fixture_at(root: &Path) -> Arguments {
    fixture_arguments(root, false)
}

fn fixture_arguments(root: &Path, rejected_endpoints: bool) -> Arguments {
    let graph = root.join("graph");
    let mut writer = stract::webgraph::Webgraph::open(&graph, 0.into()).unwrap();
    for (from, to) in [
        ("https://a.test/one", "https://b.test/two"),
        ("https://b.test/two", "https://b.test/two"),
        ("https://b.test/two", "https://c.test/three"),
    ] {
        writer
            .insert(Edge {
                from: Node::from(url::Url::parse(from).unwrap()),
                to: Node::from(url::Url::parse(to).unwrap()),
                ..Edge::empty()
            })
            .unwrap();
    }
    writer.commit().unwrap();
    // Separate commits preserve one duplicate through the real graph writer's batch dedup.
    writer
        .insert(Edge {
            from: Node::from(url::Url::parse("https://a.test/one").unwrap()),
            to: Node::from(url::Url::parse("https://b.test/two").unwrap()),
            ..Edge::empty()
        })
        .unwrap();
    writer.commit().unwrap();
    if rejected_endpoints {
        let long = Node::from(
            url::Url::parse(&format!("https://long.test/{}", "a".repeat(9000))).unwrap(),
        );
        // From<String> is crate-test-only; this public writer input preserves the same bytes.
        let empty = Node::from_str_not_validated("");
        assert!(long.as_str().len() > 8192);
        assert!(empty.as_str().is_empty());
        let bound = Node::from(
            url::Url::parse(&format!(
                "https://bound.test/{}",
                "a".repeat(8192 - "bound.test/".len())
            ))
            .unwrap(),
        );
        assert_eq!(bound.as_str().len(), 8192);
        for to in [
            Node::from(url::Url::parse("javascript:void(0)").unwrap()),
            long,
            empty,
            bound,
        ] {
            writer
                .insert(Edge {
                    from: Node::from(url::Url::parse("https://a.test/one").unwrap()),
                    to,
                    ..Edge::empty()
                })
                .unwrap();
            writer.commit().unwrap();
        }
    }
    writer.optimize_read().unwrap();
    drop(writer);
    let centrality = root.join("centrality");
    stores(&centrality);
    let paths = vec![root.join("index-0"), root.join("index-1")];
    build_index(
        &paths[0],
        0,
        &[
            ("https://a.test/one", "alpha", "the quick brown fox"),
            ("https://b.test/two", "beta", "privacy policy"),
        ],
    );
    build_index(
        &paths[1],
        1,
        &[
            ("https://a.test/four", "alpha", "the quick brown fox"),
            ("https://c.test/three", "gamma", "contact information"),
        ],
    );
    Arguments {
        graph,
        centrality,
        index: paths,
        spell_model: None,
        out: root.join("reports/features.json"),
    }
}

/// Write actual harmonic stores: a.test positive with rank zero, b.test explicit zero/sentinel.
/// Other hosts remain absent; the parent must be a new fixture directory.
pub fn stores(parent: &Path) {
    let mut values = speedy_kv::Db::<NodeID, f64>::open_or_create(parent.join("harmonic")).unwrap();
    let mut ranks =
        speedy_kv::Db::<NodeID, u64>::open_or_create(parent.join("harmonic_rank")).unwrap();
    for (name, value, rank) in [
        ("https://a.test/", 1.5, 0),
        ("https://b.test/", 0.0, u64::MAX),
    ] {
        let node = Node::from(url::Url::parse(name).unwrap()).into_host().id();
        values.insert(node, value).unwrap();
        ranks.insert(node, rank).unwrap();
    }
    values.commit().unwrap();
    ranks.commit().unwrap();
}

/// Build real stored webpages with fixed timestamps and no centrality-dependent content.
/// Each tuple is (exact URL, title, body); duplicated tuples remain duplicated documents.
pub fn build_index(path: &Path, shard: u64, documents: &[(&str, &str, &str)]) {
    build_index_with_keywords(path, shard, documents, &[], 0.0, u64::MAX);
}

/// Build real stored pages with explicit keywords and independent host centrality values.
/// Keyword order and membership are preserved at insertion; all timestamps remain fixed.
pub fn build_index_with_keywords(
    path: &Path,
    shard: u64,
    documents: &[(&str, &str, &str)],
    keywords: &[&str],
    host_centrality: f64,
    host_rank: u64,
) {
    let mut index = Index::open(path).unwrap();
    index.set_shard_id(stract::inverted_index::ShardId::Backbone(shard));
    index.inverted_index.prepare_writer().unwrap();
    for (url, title, body) in documents {
        let html = format!("<html><head><title>{title}</title></head><body><main><p>{body}</p><p>Synthetic stable document material for local feature indexing contracts.</p></main></body></html>");
        let mut page = Webpage::from(Html::parse(&html, url).unwrap());
        page.fetch_time_ms = 500;
        page.inserted_at = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        page.keywords = keywords.iter().map(|word| (*word).to_owned()).collect();
        page.host_centrality = host_centrality;
        page.host_centrality_rank = host_rank;
        index.insert(&page).unwrap();
    }
    index.commit().unwrap();
}

/// Read exact stored keyword strings from a stopped synthetic index, ordered by URL.
pub fn stored_keywords(path: &Path) -> Vec<(String, String)> {
    use tantivy::schema::Value as _;
    let index = tantivy::Index::open_in_dir(path.join("inverted_index")).unwrap();
    let schema = index.schema();
    let url = schema.get_field("url").unwrap();
    let keywords = schema.get_field("keywords").unwrap();
    let reader = index.reader().unwrap();
    let searcher = reader.searcher();
    let mut rows = Vec::new();
    for (ordinal, segment) in searcher.segment_readers().iter().enumerate() {
        for id in segment.doc_ids() {
            let doc: tantivy::TantivyDocument = searcher
                .doc(tantivy::DocAddress::new(ordinal as u32, id))
                .unwrap();
            rows.push((
                doc.get_first(url).unwrap().as_str().unwrap().to_owned(),
                doc.get_first(keywords)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned(),
            ));
        }
    }
    rows.sort();
    rows
}

/// Train English with 512 correct, 16 typo and 32 alternate-context typo occurrences.
/// Returns the checker directory, not its parent; malformed fixture/trainer state panics.
pub fn train_model(root: &Path) -> PathBuf {
    let first = root.join("training");
    let mut trainer = web_spell::FirstTrainer::new(&first).unwrap();
    for _ in 0..512 {
        trainer.add("the quick brown fox");
    }
    for _ in 0..16 {
        trainer.add("the quik brown fox");
    }
    // The inherited backoff conditional gives identical scores for the two isolated phrases.
    // Alternate synthetic left context makes the specified typo's correction observable.
    for _ in 0..32 {
        trainer.add("a quik brown fox");
    }
    let first = trainer.next_training_step().unwrap();
    let checker = root.join("web-spell/checker");
    web_spell::SecondTrainer::new(vec![first], checker.join("eng"))
        .unwrap()
        .train()
        .unwrap();
    checker
}

/// Resolve only exact `sample` values and `sample/` prefixes in a parsed TOML value tree.
/// Does not expand environment variables, tilde or arbitrary substrings.
pub fn resolve(value: &mut toml::Value, sample: &Path) {
    match value {
        toml::Value::String(text) if text == "sample" => {
            *text = sample.to_str().unwrap().to_owned()
        }
        toml::Value::String(text) if text.starts_with("sample/") => {
            *text = sample.join(&text[7..]).to_str().unwrap().to_owned()
        }
        toml::Value::Table(table) => {
            for (_, value) in table.iter_mut() {
                resolve(value, sample);
            }
        }
        toml::Value::Array(array) => {
            for value in array {
                resolve(value, sample);
            }
        }
        _ => {}
    }
}

/// Deterministic local spelling observer spending 25 ms per invocation.
#[derive(Clone)]
pub struct SpellObserver {
    /// Ordered parsed model text and selected language codes.
    pub calls: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
    /// Whether the observer offers replacement of quik with quick.
    pub offer: bool,
}

impl stract::searcher::api::SpellModel for SpellObserver {
    fn correct(&self, text: &str, language: &whatlang::Lang) -> Option<web_spell::Correction> {
        self.calls
            .lock()
            .unwrap()
            .push((text.to_owned(), language.code().to_owned()));
        std::thread::sleep(std::time::Duration::from_millis(25));
        if !self.offer {
            return None;
        }
        let mut correction = web_spell::Correction::empty(text.to_owned());
        for word in text.split_whitespace() {
            correction.push(if word == "quik" {
                web_spell::CorrectionTerm::Corrected {
                    orig: word.to_owned(),
                    correction: "quick".to_owned(),
                }
            } else {
                web_spell::CorrectionTerm::NotCorrected(word.to_owned())
            });
        }
        Some(correction)
    }
}
