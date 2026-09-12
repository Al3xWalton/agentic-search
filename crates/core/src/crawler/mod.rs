// Stract is an open source web search engine.
// Copyright (C) 2024 Stract ApS
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! # Crawler
//!
//! The crawler is responsible for fetching webpages and storing them in WARC files
//! for later processing.
//!
//! Before starting a crawl, a plan needs to be created. This plan is then used by
//! the crawler coordinator to assign sites to crawl to different workers.
//! A site is only assigned to one worker at a time for politeness.

use std::{collections::VecDeque, future::Future, net::SocketAddr, sync::Arc};

type HashMap<K, V> = std::collections::HashMap<K, V, ahash::RandomState>;

use anyhow::anyhow;
use robot_client::RobotClient;
use url::Url;

use crate::{config::CrawlerConfig, warc, webpage::url_ext::UrlExt};

use self::{local_sink::LocalSink, worker::WorkerThread};
pub use warc_writer::WarcWriter;
pub use worker::AuxiliaryResult;
pub use worker::JobExecutor;

pub mod coordinator;
pub mod directives;
pub mod exclusions;
pub mod host_state;
pub mod identity;
pub mod ledger;
pub mod local_sink;
pub mod network;
pub mod politeness;
pub mod record;
pub mod retention;
pub mod robots_txt;
pub mod router;
pub mod sample;
pub use router::Router;
mod file_queue;
pub mod planner;
pub mod robot_client;
mod wander_prioritiser;
mod warc_writer;
mod worker;

pub use coordinator::CrawlCoordinator;

pub const MAX_URL_LEN_BYTES: usize = 8192;

pub const MAX_OUTGOING_URLS_PER_PAGE: usize = 512;
pub const MAX_CONTENT_LENGTH: usize = 32 * 1024 * 1024; // 32 MB

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid content type: {0}")]
    InvalidContentType(String),

    #[error("fetch failed: {status_code}")]
    FetchFailed {
        status_code: u16,
        headers: network::ResponseHeaders,
    },

    #[error("invalid URL")]
    InvalidUrl,
    #[error("URL exceeds byte limit")]
    UrlTooLong,
    #[error("scheme refused")]
    SchemeRefused,
    #[error("port refused")]
    PortRefused,
    #[error("target outside authorized scope")]
    OffScope,
    #[error("private or special-use address refused")]
    RefusedPrivateAddress,
    #[error("connection failed")]
    ConnectError,
    #[error("TLS handshake failed")]
    TlsError,
    #[error("request timed out")]
    Timeout,
    #[error("host is blocked or awaiting its retry deadline")]
    HostBlocked,
    #[error("challenge detected")]
    Challenge,
    #[error("publisher delay exceeds policy skip threshold")]
    CrawlDelayExceedsCeiling,
    #[error("robots is unreachable")]
    RobotsUnreachable,
    #[error("host state could not be persisted")]
    HostStateWrite,
    #[error("store ownership or containment refused")]
    StoreRefused,
    #[error("store already has an owner")]
    StoreOwned,
    #[error("configured offline country provider is unavailable")]
    CountryProviderUnavailable,
    #[error("excluded by policy")]
    ExcludedByPolicy {
        reason: exclusions::ExclusionReason,
        phase: exclusions::ExclusionPhase,
    },
    #[error("invalid ingestion record")]
    RecordInvalid,
    #[error("durable body write failed")]
    SinkWrite,
    #[error("durable ledger write failed")]
    LedgerWrite,
    #[error("ledger has incomplete or inconsistent target coverage")]
    LedgerIncomplete,
    #[error("duplicate target admission or completion")]
    DuplicateTarget,
    #[error("crawl completed with a fatal target failure")]
    FatalRun,
    #[error("raw retention scan found failed or outstanding deletions")]
    RetentionBacklog,
    #[error("listing page-attempt budget exhausted")]
    ListingBudgetExhausted,
    #[error("crawl cancelled")]
    Cancelled,
    #[error("internal crawl invariant failed")]
    InternalInvariant,
    #[error("network disabled in library unit tests")]
    TestNetworkDisabled,
    #[error("target belongs to another job domain")]
    DomainMismatch,
    #[error("target already completed under this crawl policy")]
    AlreadyCrawled,
    #[error("selected target has an ignored extension")]
    IgnoredExtension,
    #[error("successful response contained no body")]
    EmptyBody,

    #[error("content too large")]
    ContentTooLarge,

    #[error("couldn't read response body")]
    ResponseBodyReadFailed,

    #[error("invalid redirect")]
    InvalidRedirect,

    #[error("request path is disallowed by robots.txt")]
    DisallowedPath,

    #[error("an error occurred: {0}")]
    Anyhow(#[from] anyhow::Error),
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
    bincode::Encode,
    bincode::Decode,
)]
struct Site(String);

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    bincode::Encode,
    bincode::Decode,
)]
pub struct Domain(String);

impl From<&Url> for Domain {
    fn from(url: &Url) -> Self {
        Self(url.icann_domain().unwrap_or_default().to_string())
    }
}

impl From<Url> for Domain {
    fn from(url: Url) -> Self {
        Self::from(&url)
    }
}

impl From<String> for Domain {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl Domain {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(serde::Serialize, serde::Deserialize, bincode::Encode, bincode::Decode, Debug, Clone)]
pub struct WeightedUrl {
    #[bincode(with_serde)]
    pub url: Url,
    pub weight: f64,
}

impl PartialEq for WeightedUrl {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url
    }
}

impl Eq for WeightedUrl {}

impl std::hash::Hash for WeightedUrl {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.url.hash(state);
    }
}

/// All urls in a job must be from the same domain and only one job per domain.
/// at a time. This ensures that we stay polite when crawling.
#[derive(serde::Serialize, serde::Deserialize, bincode::Encode, bincode::Decode, Debug, Clone)]
pub struct Job {
    pub domain: Domain,
    pub urls: VecDeque<WeightedUrl>,
    pub wandering_urls: u64,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
    bincode::Encode,
    bincode::Decode,
)]
pub struct UrlString(String);

impl From<&Url> for UrlString {
    fn from(url: &Url) -> Self {
        Self(url.as_str().to_string())
    }
}

impl From<Url> for UrlString {
    fn from(url: Url) -> Self {
        Self(url.as_str().to_string())
    }
}

impl TryFrom<&UrlString> for Url {
    type Error = anyhow::Error;
    fn try_from(url: &UrlString) -> Result<Self, Self::Error> {
        Ok(Url::parse(&url.0)?)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, bincode::Encode, bincode::Decode)]
pub struct UrlToInsert {
    pub url: UrlString,
    pub weight: f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, bincode::Encode, bincode::Decode)]
pub struct DiscoveredUrls {
    pub urls: HashMap<Domain, Vec<UrlToInsert>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, bincode::Encode, bincode::Decode)]
pub struct DomainCrawled {
    pub domain: Domain,
    pub budget_used: f64,
}

pub struct RetrieableUrl {
    weighted_url: WeightedUrl,
}

impl RetrieableUrl {
    pub fn url(&self) -> &Url {
        &self.weighted_url.url
    }
}

impl From<WeightedUrl> for RetrieableUrl {
    fn from(weighted_url: WeightedUrl) -> Self {
        Self { weighted_url }
    }
}

pub struct WorkerJob {
    pub domain: Domain,
    pub urls: VecDeque<RetrieableUrl>,
    pub wandering_urls: u64,
}

impl From<Job> for WorkerJob {
    fn from(value: Job) -> Self {
        Self {
            domain: value.domain,
            urls: value.urls.into_iter().map(RetrieableUrl::from).collect(),
            wandering_urls: value.wandering_urls,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CrawlDatum {
    /// Mandatory evidence for every new capture; only legacy WARC may lack an extension.
    pub record: record::DocumentRecord,
    pub url: Url,
    pub payload_type: warc::PayloadType,
    pub body: String,
    pub fetch_time_ms: u64,
    pub date: chrono::DateTime<chrono::Utc>,
}

pub struct Crawler {
    writer: Arc<LocalSink>,
    client: RobotClient,
    handles: Vec<tokio::task::JoinHandle<Result<()>>>,
}

impl Crawler {
    pub async fn new(config: CrawlerConfig) -> Result<Self> {
        config.ingestion.require_production_approval(
            chrono::Utc::now(),
            std::env::var("DPIA_ID").ok().as_deref(),
        )?;
        let mut handles = Vec::new();
        let mut router_hosts = Vec::new();
        let client = RobotClient::new(&config)?;
        let writer = client.local_sink();

        for host in &config.router_hosts {
            router_hosts.push(
                host.parse::<SocketAddr>()
                    .map_err(|e| Error::from(anyhow!(e)))?,
            );
        }

        for _ in 0..config.num_worker_threads {
            let worker = WorkerThread::new(
                Arc::clone(&writer),
                client.clone(),
                config.clone(),
                router_hosts.clone(),
            )?;

            handles.push(tokio::spawn(async move { worker.run().await }));
        }

        Ok(Self {
            writer,
            handles,
            client,
        })
    }

    pub async fn run(self) -> Result<()> {
        for handle in self.handles {
            handle.await.map_err(|_| Error::InternalInvariant)??;
        }

        self.writer.finish().await?;
        self.client.ledger().finish()
    }
}

pub trait DatumSink: Send + Sync {
    fn write(&self, crawl_datum: CrawlDatum) -> impl Future<Output = Result<()>> + Send;
    fn finish(&self) -> impl Future<Output = Result<()>> + Send;
}

/// Decodes an entity through the common bounded response path.
pub async fn encoded_body(res: network::BoundedResponse) -> Result<String> {
    res.text().await
}
