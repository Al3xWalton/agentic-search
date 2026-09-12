// Stract is an open source web search engine.
// Copyright (C) 2023 Stract ApS
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
//! Executes admitted jobs through the shared RobotClient and propagates fetch/sink failures.
//! Discovery retains the upstream domain and frontier bounds; policy decisions precede saving.
//! No protocol upgrade, floating-factor delay or automatic redirect can bypass host discipline.

use super::{
    network::{parse_fetch_url, BoundedResponse},
    robot_client::RobotClient,
    wander_prioritiser::WanderPrioritiser,
    CrawlDatum, DatumSink, Domain, Error, Result, RetrieableUrl, Site, WarcWriter, WeightedUrl,
    WorkerJob, MAX_OUTGOING_URLS_PER_PAGE, MAX_URL_LEN_BYTES,
};
use crate::{
    config::CrawlerConfig,
    dated_url::DatedUrl,
    distributed::{retry_strategy::ExponentialBackoff, sonic},
    entrypoint::crawler::router::{NewJob, RouterService},
    sitemap::{parse_sitemap, SitemapEntry},
    warc,
    webpage::{url_ext::UrlExt, Html},
};
use hashbrown::HashSet;
use itertools::Itertools;
use rand::seq::SliceRandom;
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use url::Url;

const IGNORED_EXTENSIONS: [&str; 27] = [
    ".pdf", ".jpg", ".zip", ".png", ".css", ".js", ".json", ".jsonp", ".woff2", ".woff", ".ttf",
    ".svg", ".gif", ".jpeg", ".ico", ".mp4", ".mp3", ".avi", ".mov", ".mpeg", ".webm", ".wav",
    ".flac", ".aac", ".ogg", ".m4a", ".m4v",
];
const INITIAL_WANDER_STEPS: u64 = 4;
struct ProcessedUrl {
    new_urls: Vec<Url>,
}

pub struct WorkerThread {
    writer: Arc<WarcWriter>,
    config: Arc<CrawlerConfig>,
    router_hosts: Vec<SocketAddr>,
    client: RobotClient,
}
impl WorkerThread {
    pub fn new(
        writer: Arc<WarcWriter>,
        client: RobotClient,
        config: CrawlerConfig,
        router_hosts: Vec<SocketAddr>,
    ) -> Result<Self> {
        Ok(Self {
            writer,
            client,
            config: Arc::new(config),
            router_hosts,
        })
    }
    async fn router_conn(&self) -> Result<sonic::service::Connection<RouterService>> {
        let retry = ExponentialBackoff::from_millis(1000).with_limit(Duration::from_secs(10));
        let router = *self
            .router_hosts
            .choose(&mut rand::thread_rng())
            .ok_or(Error::InternalInvariant)?;
        sonic::service::Connection::create_with_timeout_retry(
            router,
            Duration::from_secs(90),
            retry,
        )
        .await
        .map_err(|_| Error::ConnectError)
    }
    pub async fn run(self) -> Result<()> {
        loop {
            let mut conn = self.router_conn().await?;
            match conn
                .send_with_timeout(NewJob {}, Duration::from_secs(90))
                .await
            {
                Ok(Some(job)) => {
                    JobExecutor::new(
                        job.into(),
                        self.config.clone(),
                        self.writer.clone(),
                        self.client.clone(),
                    )
                    .run()
                    .await?
                }
                Ok(None) => return Ok(()),
                Err(_) => tokio::time::sleep(Duration::from_secs(60)).await,
            }
        }
    }
}

/// Receives one domain job and fetches selected targets through the shared admission path.
pub struct JobExecutor<S: DatumSink> {
    writer: Arc<S>,
    client: RobotClient,
    crawled_urls: HashSet<Url>,
    crawled_sitemaps: HashSet<Site>,
    sitemap_urls: HashSet<Url>,
    wander_prioritiser: WanderPrioritiser,
    wandered_urls: u64,
    job: WorkerJob,
}
impl<S: DatumSink> JobExecutor<S> {
    /// Retains existing job/sink structure; timing policy lives solely in the shared client.
    pub fn new(
        job: WorkerJob,
        _config: Arc<CrawlerConfig>,
        writer: Arc<S>,
        client: RobotClient,
    ) -> Self {
        Self {
            writer,
            client,
            crawled_urls: HashSet::new(),
            crawled_sitemaps: HashSet::new(),
            sitemap_urls: HashSet::new(),
            wander_prioritiser: WanderPrioritiser::new(),
            wandered_urls: 0,
            job,
        }
    }
    /// Processes selected targets and bounded discovery, propagating durable sink failures.
    pub async fn run(mut self) -> Result<()> {
        for target in &self.job.urls {
            let mut origin = target.url().clone();
            origin.set_path("/");
            origin.set_query(None);
            origin.set_fragment(None);
            self.wander_prioritiser.inc(origin, 1.0);
        }
        let mut wander_steps = 0;
        while self.wandered_urls < self.job.wandering_urls
            && self.wander_prioritiser.known_urls() > 0
            && wander_steps < INITIAL_WANDER_STEPS
        {
            self.wander().await?;
            wander_steps += 1;
        }
        let urls = self.job.urls.drain(..).collect();
        self.process_urls(urls).await?;
        if self.wandered_urls < self.job.wandering_urls {
            self.crawl_sitemaps().await?;
        }
        while self.wandered_urls < self.job.wandering_urls
            && self.wander_prioritiser.known_urls() > 0
        {
            self.wander().await?;
        }
        Ok(())
    }
    async fn wander(&mut self) -> Result<()> {
        let mut urls: Vec<_> = self
            .wander_prioritiser
            .top_and_clear(self.job.wandering_urls.saturating_sub(self.wandered_urls) as usize)
            .into_iter()
            .chain(self.sitemap_urls.drain().map(|url| (url, 0.0)))
            .filter(|(url, score)| {
                !self.crawled_urls.contains(url)
                    && self.job.domain == Domain::from(url)
                    && score.is_finite()
            })
            .unique_by(|(url, _)| url.clone())
            .collect();
        urls.sort_by(|(_, a), (_, b)| b.total_cmp(a));
        let urls: VecDeque<_> = urls
            .into_iter()
            .take(self.job.wandering_urls.saturating_sub(self.wandered_urls) as usize)
            .map(|(url, _)| RetrieableUrl::from(WeightedUrl { url, weight: 0.0 }))
            .collect();
        self.wandered_urls += urls.len() as u64;
        self.process_urls(urls).await
    }
    fn verify_url(&self, url: &Url) -> Result<()> {
        parse_fetch_url(url.as_str())?;
        if Domain::from(url) != self.job.domain {
            return Err(Error::DomainMismatch);
        }
        if self.crawled_urls.contains(url) {
            return Err(Error::AlreadyCrawled);
        }
        if IGNORED_EXTENSIONS
            .iter()
            .any(|ext| url.path().to_ascii_lowercase().ends_with(ext))
        {
            return Err(Error::IgnoredExtension);
        }
        self.client.scope().validate(url, false)
    }
    /// Processes each selected URL through typed admission and acknowledged storage.
    pub async fn process_urls(&mut self, mut urls: VecDeque<RetrieableUrl>) -> Result<()> {
        while let Some(target) = urls.pop_front() {
            self.verify_url(target.url())?;
            let processed = self.process_url(target.url().clone()).await?;
            for new_url in processed.new_urls {
                if new_url.host_str().is_some()
                    && new_url.root_domain() == target.url().root_domain()
                {
                    self.wander_prioritiser
                        .inc(new_url, target.weighted_url.weight);
                }
            }
        }
        Ok(())
    }
    fn new_urls(&self, html: &Html) -> Vec<Url> {
        html.anchor_links()
            .into_iter()
            .map(|link| link.destination)
            .filter(|url| {
                matches!(url.scheme(), "http" | "https") && url.as_str().len() <= MAX_URL_LEN_BYTES
            })
            .filter(|url| {
                IGNORED_EXTENSIONS
                    .iter()
                    .all(|ext| !url.path().to_ascii_lowercase().ends_with(ext))
            })
            .filter(|url| !self.crawled_urls.contains(url))
            .unique()
            .collect()
    }
    async fn process_url(&mut self, url: Url) -> Result<ProcessedUrl> {
        let start = Instant::now();
        let response = self.client.get(url.clone()).await?.send().await?;
        let status = response.status();
        if status != 200 {
            return Err(Error::FetchFailed {
                status_code: status,
                headers: response.headers().clone(),
            });
        }
        let payload_type = self.check_headers(&response);
        let body = response.text().await?;
        let payload_type = payload_type?;
        if body.is_empty() {
            return Err(Error::EmptyBody);
        }
        let new_urls = {
            let html = Html::parse(&body, url.as_str()).map_err(|_| Error::InvalidHtml)?;
            self.new_urls(&html)
                .into_iter()
                .filter(|new_url| new_url.root_domain() == url.root_domain())
                .take(MAX_OUTGOING_URLS_PER_PAGE)
                .collect()
        };
        self.writer
            .write(CrawlDatum {
                url: url.clone(),
                payload_type,
                body,
                fetch_time_ms: start
                    .elapsed()
                    .as_millis()
                    .try_into()
                    .map_err(|_| Error::InternalInvariant)?,
                date: chrono::Utc::now(),
            })
            .await?;
        self.crawled_urls.insert(url);
        Ok(ProcessedUrl { new_urls })
    }
    fn check_headers(&self, response: &BoundedResponse) -> Result<warc::PayloadType> {
        let values = response.headers().all("content-type");
        if values.is_empty() || values.iter().any(|value| value != &values[0]) {
            return Err(Error::InvalidContentType("missing-or-contradictory".into()));
        }
        let mime = values[0]
            .parse::<mime::Mime>()
            .map_err(|_| Error::InvalidContentType("invalid".into()))?;
        if mime.essence_str() == "text/html" || mime.essence_str() == "application/xhtml+xml" {
            Ok(warc::PayloadType::Html)
        } else {
            Err(Error::InvalidContentType("unsupported".into()))
        }
    }
    async fn crawl_sitemaps(&mut self) -> Result<()> {
        let urls: Vec<_> = self
            .job
            .urls
            .iter()
            .map(|target| target.url().clone())
            .collect();
        for url in urls {
            let site = Site(url.host_str().unwrap_or_default().into());
            if self.crawled_sitemaps.insert(site) {
                for sitemap in self.client.robots_txt_manager().sitemaps(&url).await {
                    let found = self.urls_from_sitemap(sitemap, 5).await?;
                    self.sitemap_urls.extend(found.into_iter().map(|u| u.url));
                }
            }
        }
        Ok(())
    }
    async fn urls_from_sitemap(&mut self, sitemap: Url, max_depth: usize) -> Result<Vec<DatedUrl>> {
        let mut stack = vec![(sitemap, 0)];
        let mut urls = Vec::new();
        while let Some((url, depth)) = stack.pop() {
            if depth >= max_depth {
                continue;
            }
            let response = self.client.get(url).await?.send().await?;
            if response.status() != 200 {
                return Err(Error::FetchFailed {
                    status_code: response.status(),
                    headers: response.headers().clone(),
                });
            }
            for entry in parse_sitemap(&response.text().await?) {
                match entry {
                    SitemapEntry::Url(url) => urls.push(url),
                    SitemapEntry::Sitemap(url) => stack.push((url, depth + 1)),
                }
            }
        }
        Ok(urls)
    }
}
