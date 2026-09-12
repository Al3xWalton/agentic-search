//! Owns loopback HTTP servers and request/connection evidence for crawler conformance.
//! Every socket is bound by this fixture; responses are predetermined local data, never public input.
//! Explicit shutdown joins owned tasks; Drop aborts only this fixture's tasks after a test failure.

use std::{
    collections::{BTreeMap, VecDeque},
    net::{Ipv4Addr, TcpListener},
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use stract::{
    config::ingestion::IngestionPolicy,
    crawler::{
        network::LoopbackEndpoint,
        politeness::{Clock, SystemClock},
        robot_client::RobotClient,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::watch,
    task::{JoinHandle, JoinSet},
};
use url::Url;

/// Predetermined response; all bodies and header values are hand-authored fixture data.
#[derive(Clone)]
pub struct Reply {
    /// Actual response status sent on the wire.
    pub status: u16,
    /// Physical response headers, including repeated directives.
    pub headers: Vec<(String, String)>,
    /// Physical invalid-byte headers for transport parsing witnesses; never external input.
    pub raw_headers: Vec<(String, Vec<u8>)>,
    /// Entity bytes supplied by this fixture alone.
    pub body: Vec<u8>,
    /// Optional false Content-Length to exercise truncated streams and header lies.
    pub declared_length: Option<usize>,
    /// Delay after headers while the connection/body remains live.
    pub body_delay: Duration,
    /// Uses chunked framing with no Content-Length, including large streamed bodies.
    pub chunked: bool,
}
impl Reply {
    /// Constructs a simple text response without inventing a Content-Type.
    pub fn new(status: u16, body: impl AsRef<[u8]>) -> Self {
        Self {
            status,
            headers: vec![],
            raw_headers: vec![],
            body: body.as_ref().to_vec(),
            declared_length: None,
            body_delay: Duration::ZERO,
            chunked: false,
        }
    }
    /// Constructs a nonempty titled HTML fixture with the matching MIME header.
    pub fn html(body: &str) -> Self {
        Self::new(200, body).header("Content-Type", "text/html; charset=utf-8")
    }
    /// Appends one physical header occurrence, preserving repeated field semantics.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
    /// Appends raw fixture bytes without UTF-8 conversion, preserving invalid header octets.
    pub fn raw_header(mut self, name: &str, value: &[u8]) -> Self {
        self.raw_headers.push((name.into(), value.into()));
        self
    }
}
/// Actual received HTTP request, including wire arrival and independently captured user-agent.
#[derive(Clone, Debug)]
pub struct Request {
    /// Request target as received by the fixture, including any fixture query.
    pub target: String,
    /// Host header as received, including its explicit fixture port.
    pub host: String,
    /// User-Agent header captured independently of the client builder.
    pub user_agent: String,
    /// Monotonic arrival used by real-clock throttle assertions.
    pub arrived: Instant,
    /// Physical request fields needed by conditional-fetch witnesses.
    pub headers: BTreeMap<String, String>,
}
struct LiveConnection(Arc<AtomicUsize>);
impl Drop for LiveConnection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
/// Owned server/client pair; no caller-supplied remote address can be connected.
pub struct Fixture {
    /// Real library client using the owned endpoint and production admission code.
    pub client: RobotClient,
    /// Owned endpoint used to create virtual host URLs.
    pub endpoint: LoopbackEndpoint,
    /// Independently recorded requests, ordered by receipt.
    pub requests: Arc<Mutex<Vec<Request>>>,
    /// Maximum simultaneous live fixture connections, including unfinished bodies.
    pub max_connections: Arc<AtomicUsize>,
    /// Owner-private store root for independent persistence inspection.
    pub root: PathBuf,
    replies: Arc<Mutex<BTreeMap<String, VecDeque<Reply>>>>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}
impl Fixture {
    /// Creates the default 500ms/one-connection fixture using real monotonic time.
    pub fn new() -> Self {
        let mut policy = IngestionPolicy::default();
        policy.politeness.gap_ms = 500;
        Self::with_policy(policy, Arc::new(SystemClock::default()), 2)
    }
    /// Creates an owned loopback client with a validated policy and explicit clock seam.
    pub fn with_policy(
        policy: IngestionPolicy,
        clock: Arc<dyn Clock>,
        timeout_seconds: u64,
    ) -> Self {
        Self::with_resolver(policy, clock, timeout_seconds, None)
    }
    /// Adds a fake candidate resolver; the physical peer remains the owned listener.
    pub fn with_resolver(
        policy: IngestionPolicy,
        clock: Arc<dyn Clock>,
        timeout_seconds: u64,
        resolver: Option<Arc<dyn stract::crawler::network::AddressResolver>>,
    ) -> Self {
        Self::with_settings(policy, clock, timeout_seconds, resolver, None, &[])
    }
    /// Adds explicit owned-endpoint aliases and offline country answers for geography witnesses.
    pub fn with_settings(
        policy: IngestionPolicy,
        clock: Arc<dyn Clock>,
        timeout_seconds: u64,
        resolver: Option<Arc<dyn stract::crawler::network::AddressResolver>>,
        country: Option<Arc<dyn stract::crawler::exclusions::HostingCountryProvider>>,
        aliases: &[&str],
    ) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = LoopbackEndpoint::new(listener)
            .unwrap()
            .with_aliases(aliases)
            .unwrap();
        let endpoint = if let Some(country) = country {
            endpoint.with_country_provider(country)
        } else {
            endpoint
        };
        let endpoint = if let Some(resolver) = resolver {
            endpoint.with_resolver(resolver)
        } else {
            endpoint
        };
        let server = tokio::net::TcpListener::from_std(endpoint.listener().unwrap()).unwrap();
        let root = PathBuf::from(std::env::var_os("STORY584_SCRATCH").expect("external scratch"))
            .join(format!("fixture-{}", uuid::Uuid::new_v4()));
        let client =
            RobotClient::loopback(&root, &policy, endpoint.clone(), clock, timeout_seconds)
                .unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let replies = Arc::new(Mutex::new(BTreeMap::<String, VecDeque<Reply>>::new()));
        let active = Arc::new(AtomicUsize::new(0));
        let max_connections = Arc::new(AtomicUsize::new(0));
        let (stop, mut stopped) = watch::channel(false);
        let task = tokio::spawn({
            let requests = requests.clone();
            let replies = replies.clone();
            let active = active.clone();
            let max = max_connections.clone();
            async move {
                let mut connections = JoinSet::new();
                loop {
                    tokio::select! {
                        _=stopped.changed()=>break,
                        result=server.accept()=>{
                            let (mut stream,_)=result.unwrap();let current=active.fetch_add(1,Ordering::SeqCst)+1;max.fetch_max(current,Ordering::SeqCst);
                            let requests=requests.clone();let replies=replies.clone();let active=active.clone();
                            connections.spawn(async move {
                                let _connection=LiveConnection(active);let mut bytes=Vec::new();
                                while !bytes.windows(4).any(|w|w==b"\r\n\r\n") {
                                    let mut chunk=[0;4096];let Ok(n)=stream.read(&mut chunk).await else{return;};if n==0{return;}bytes.extend_from_slice(&chunk[..n]);
                                    if bytes.first()==Some(&0x16) {let _=stream.write_all(b"not a TLS server").await;let _=stream.shutdown().await;return;}
                                    if bytes.len()>65_536{return;}
                                }
                                let text=String::from_utf8(bytes).unwrap();let mut lines=text.split("\r\n");
                                let target=lines.next().unwrap().split_whitespace().nth(1).unwrap().to_owned();
                                let headers:BTreeMap<_,_>=lines.filter_map(|line|line.split_once(':')).map(|(k,v)|(k.to_ascii_lowercase(),v.trim().to_owned())).collect();
                                let host=headers.get("host").cloned().unwrap_or_default();
                                requests.lock().unwrap().push(Request {target:target.clone(),host:host.clone(),user_agent:headers.get("user-agent").cloned().unwrap_or_default(),arrived:Instant::now(),headers});
                                let reply={let mut replies=replies.lock().unwrap();replies.get_mut(&format!("{host}{target}")).and_then(VecDeque::pop_front).or_else(||replies.get_mut(&target).and_then(VecDeque::pop_front))};
                                let reply=reply.unwrap_or_else(||if target=="/robots.txt"{Reply::new(200,"User-agent: *\nAllow: /\n")}else{Reply::html("<html><title>Fixture</title><body>Owned fixture text.</body></html>")});
                                let mut header=format!("HTTP/1.1 {} Fixture\r\nConnection: close\r\n",reply.status);
                                if reply.chunked { header.push_str("Transfer-Encoding: chunked\r\n"); }
                                else { header.push_str(&format!("Content-Length: {}\r\n",reply.declared_length.unwrap_or(reply.body.len()))); }
                                for (name,value) in reply.headers {header.push_str(&format!("{name}: {value}\r\n"));}
                                let mut header=header.into_bytes();
                                for (name,value) in reply.raw_headers {header.extend_from_slice(format!("{name}: ").as_bytes());header.extend_from_slice(&value);header.extend_from_slice(b"\r\n");}
                                header.extend_from_slice(b"\r\n");
                                if stream.write_all(&header).await.is_err(){return;}
                                tokio::time::sleep(reply.body_delay).await;
                                if reply.chunked {
                                    for chunk in reply.body.chunks(65536) {
                                        if stream.write_all(format!("{:x}\r\n",chunk.len()).as_bytes()).await.is_err() { return; }
                                        if stream.write_all(chunk).await.is_err() { return; }
                                        if stream.write_all(b"\r\n").await.is_err() { return; }
                                    }
                                    let _=stream.write_all(b"0\r\n\r\n").await;
                                } else { let _=stream.write_all(&reply.body).await; }
                                let _=stream.shutdown().await;
                            });
                        }
                        Some(_)=connections.join_next()=>{}
                    }
                }
                connections.abort_all();
                while connections.join_next().await.is_some() {}
            }
        });
        Self {
            client,
            endpoint,
            requests,
            max_connections,
            root,
            replies,
            stop,
            task: Some(task),
        }
    }
    /// Enqueues a predetermined response for a request target or host+target key.
    pub fn reply(&self, key: &str, reply: Reply) {
        self.replies
            .lock()
            .unwrap()
            .entry(key.into())
            .or_default()
            .push_back(reply);
    }
    /// Creates a URL for a virtual fixture host; it always resolves to the owned listener.
    pub fn url(&self, host: &str, path: &str) -> Url {
        self.endpoint.url(host, path).unwrap()
    }
    /// Completes one full content fetch through robots, scope, address and body checks.
    pub async fn fetch(&self, path: &str) -> Result<String, stract::crawler::Error> {
        self.client
            .get(self.url("a.fixture.invalid", path))
            .await?
            .send()
            .await?
            .text()
            .await
    }
    /// Executes a real selected target through parsing, durable storage and the terminal ledger funnel.
    pub async fn crawl(
        &self,
        path: &str,
    ) -> Result<stract::crawler::ledger::LedgerRow, stract::crawler::Error> {
        self.crawl_raw(self.url("a.fixture.invalid", path).as_str())
            .await
            .map(|(row, _)| row)
    }
    /// Preserves malformed raw input in memory while exercising its real typed input rejection.
    pub async fn crawl_raw(
        &self,
        raw: &str,
    ) -> Result<(stract::crawler::ledger::LedgerRow, Vec<Url>), stract::crawler::Error> {
        use stract::crawler::{network::parse_fetch_url, Domain};
        let parsed = parse_fetch_url(raw).ok();
        let domain = parsed
            .as_ref()
            .map(Domain::from)
            .unwrap_or_else(|| Domain::from(String::new()));
        Ok(self
            .crawl_inputs(&[raw.to_owned()], domain)
            .await?
            .pop()
            .unwrap())
    }
    /// Journals all selected inputs before fetching so redirect edges reference pre-existing targets.
    pub async fn crawl_inputs(
        &self,
        inputs: &[String],
        domain: stract::crawler::Domain,
    ) -> Result<Vec<(stract::crawler::ledger::LedgerRow, Vec<Url>)>, stract::crawler::Error> {
        use stract::crawler::{ledger::TargetKind, JobExecutor, WorkerJob};
        let config: stract::config::CrawlerConfig =
            toml::from_str(include_str!("../../../../configs/crawler/crawler.toml")).unwrap();
        let job = WorkerJob {
            domain,
            urls: std::collections::VecDeque::new(),
            wandering_urls: 0,
        };
        let mut executor = JobExecutor::new(
            job,
            Arc::new(config),
            self.client.local_sink(),
            self.client.clone(),
        );
        let result = executor
            .process_raw_inputs(inputs, TargetKind::Seed)
            .await?;
        self.client.ledger().finish()?;
        Ok(result)
    }
    /// Reopens the same host/body/ledger store with a new run ID while preserving the owned HTTP server.
    pub async fn restart(&mut self) {
        let policy = self.client.policy().get().clone();
        let clock = self.client.clock();
        let placeholder = Fixture::new();
        drop(std::mem::replace(
            &mut self.client,
            placeholder.client.clone(),
        ));
        self.client =
            RobotClient::loopback(&self.root, &policy, self.endpoint.clone(), clock, 2).unwrap();
        placeholder.finish().await;
    }
    /// Cancels and joins this fixture's server tasks before ordinary field cleanup.
    pub async fn finish(mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            task.await.unwrap();
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
