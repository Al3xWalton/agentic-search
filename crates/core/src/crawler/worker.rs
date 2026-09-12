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
    exclusions::ExclusionPhase,
    ledger::{
        AttemptTrace, FetchKind, HttpStatusReason, InternalCode, LedgerRow, Outcome,
        RedirectReason, Target, TargetKind,
    },
    local_sink::LocalSink,
    network::{parse_fetch_url, safe_url_for_record, sha256, url_key, HostKey, ResponseHeaders},
    record::{
        BodyRetentionReason, ContentHashSource, Observation, Tombstone, TombstoneScope, Validators,
    },
    robot_client::RobotClient,
    wander_prioritiser::WanderPrioritiser,
    CrawlDatum, DatumSink, Domain, Error, Result, RetrieableUrl, Site, WeightedUrl, WorkerJob,
    MAX_OUTGOING_URLS_PER_PAGE, MAX_URL_LEN_BYTES,
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
use std::{collections::VecDeque, net::SocketAddr, sync::Arc, time::Duration};
use url::Url;

const IGNORED_EXTENSIONS: [&str; 27] = [
    ".pdf", ".jpg", ".zip", ".png", ".css", ".js", ".json", ".jsonp", ".woff2", ".woff", ".ttf",
    ".svg", ".gif", ".jpeg", ".ico", ".mp4", ".mp3", ".avi", ".mov", ".mpeg", ".webm", ".wav",
    ".flac", ".aac", ".ogg", ".m4a", ".m4v",
];
const INITIAL_WANDER_STEPS: u64 = 4;

pub struct WorkerThread {
    writer: Arc<LocalSink>,
    config: Arc<CrawlerConfig>,
    router_hosts: Vec<SocketAddr>,
    client: RobotClient,
}
impl WorkerThread {
    pub fn new(
        writer: Arc<LocalSink>,
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

#[derive(Default)]
struct ProcessedTarget {
    links: Vec<Url>,
    body: Option<String>,
}
/// Bounded auxiliary result; body exists only in memory and never bypasses record/storage policy.
pub struct AuxiliaryResult {
    /// Actual terminal classification and subattempt evidence.
    pub row: LedgerRow,
    /// Decoded bounded entity, absent for failures, redirects and unchanged responses.
    pub body: Option<String>,
    /// Permitted frontier references; nofollow always yields an empty vector.
    pub links: Vec<Url>,
}

impl JobExecutor<LocalSink> {
    pub(crate) async fn auxiliary(
        client: RobotClient,
        url: Url,
        kind: FetchKind,
    ) -> Result<AuxiliaryResult> {
        if !matches!(
            kind,
            FetchKind::Feed | FetchKind::Sitemap | FetchKind::Frontpage | FetchKind::Robots
        ) {
            return Err(Error::InternalInvariant);
        }
        let job = WorkerJob {
            domain: Domain::from(&url),
            urls: VecDeque::new(),
            wandering_urls: 0,
        };
        let mut executor = Self::from_parts(job, client.local_sink(), client.clone());
        executor.fetch_kind = kind;
        let target = client
            .ledger()
            .admit_next(TargetKind::Auxiliary, None, Some(&url))?;
        let (row, processed) = executor.process_admitted(target, url.as_str()).await?;
        if row.fatal {
            return Err(Error::FatalRun);
        }
        Ok(AuxiliaryResult {
            row,
            body: processed.body,
            links: processed.links,
        })
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
    fetch_kind: FetchKind,
}
impl<S: DatumSink> JobExecutor<S> {
    /// Retains existing job/sink structure; timing policy lives solely in the shared client.
    pub fn new(
        job: WorkerJob,
        _config: Arc<CrawlerConfig>,
        writer: Arc<S>,
        client: RobotClient,
    ) -> Self {
        Self::from_parts(job, writer, client)
    }
    fn from_parts(job: WorkerJob, writer: Arc<S>, client: RobotClient) -> Self {
        Self {
            writer,
            client,
            crawled_urls: HashSet::new(),
            crawled_sitemaps: HashSet::new(),
            sitemap_urls: HashSet::new(),
            wander_prioritiser: WanderPrioritiser::new(),
            wandered_urls: 0,
            job,
            fetch_kind: FetchKind::Page,
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
        let urls = std::mem::take(&mut self.job.urls);
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
    /// Admits every selected input durably before fetching, then completes exactly one row per input.
    pub async fn process_urls(&mut self, urls: VecDeque<RetrieableUrl>) -> Result<()> {
        let ledger = self.client.ledger();
        let mut inputs = Vec::new();
        for input in urls {
            let raw = input.url().as_str().to_owned();
            let parsed = parse_fetch_url(&raw).ok();
            let target = ledger.admit_next(TargetKind::Frontier, None, parsed.as_ref())?;
            inputs.push((target, raw, input.weighted_url.weight));
        }
        let mut fatal = false;
        for (target, raw, weight) in inputs {
            let (row, links) = self.process_admitted(target, &raw).await?;
            fatal |= row.fatal;
            for new_url in links.links {
                self.wander_prioritiser.inc(new_url, weight);
            }
        }
        if fatal {
            return Err(Error::FatalRun);
        }
        Ok(())
    }
    /// Processes one already journalled input and uses the sole outer terminal-completion funnel.
    /// Raw input is used only in memory; cancellation is explicit and includes pending targets.
    async fn process_admitted(
        &mut self,
        target: Target,
        raw: &str,
    ) -> Result<(LedgerRow, ProcessedTarget)> {
        let trace = AttemptTrace::default();
        let mut row =
            LedgerRow::from_target(&target, Outcome::Cancelled, self.client.clock().utc());
        let result = tokio::select! {
            biased;
            _ = self.client.cancelled() => Err(Error::Cancelled),
            result = self.run_target(&target, raw, &mut row, &trace) => result,
        };
        let links = match result {
            Ok(links) => links,
            Err(error) => {
                row.outcome = classify_target_error(&error, &trace)?;
                row.record.retained_body_bytes = 0;
                row.body_object = None;
                ProcessedTarget::default()
            }
        };
        self.finish_observations(raw, &trace, &mut row)?;
        row.finished_at_utc = self.client.clock().utc();
        row.fatal = matches!(
            row.outcome,
            Outcome::InternalError { .. } | Outcome::SinkWriteFailed
        );
        self.client.ledger().complete(row.clone())?;
        if let Ok(url) = parse_fetch_url(raw) {
            self.crawled_urls.insert(url);
        }
        if row.fatal {
            self.client.cancel();
        }
        Ok((row, links))
    }
    /// Durably admits a complete raw input list before processing any target, including invalid URLs.
    /// Returns actual terminal rows and permitted discovered links in original input order.
    pub async fn process_raw_inputs(
        &mut self,
        inputs: &[String],
        kind: TargetKind,
    ) -> Result<Vec<(LedgerRow, Vec<Url>)>> {
        let ledger = self.client.ledger();
        let mut admitted = Vec::new();
        for raw in inputs {
            let parsed = parse_fetch_url(raw).ok();
            admitted.push(ledger.admit_next(kind, None, parsed.as_ref())?);
        }
        let mut rows = Vec::new();
        for (target, raw) in admitted.into_iter().zip(inputs) {
            let (row, processed) = self.process_admitted(target, raw).await?;
            rows.push((row, processed.links));
        }
        Ok(rows)
    }
    pub(crate) async fn process_targets(&mut self, inputs: Vec<(Target, String)>) -> Result<()> {
        for (target, raw) in inputs {
            self.process_admitted(target, &raw).await?;
        }
        Ok(())
    }
    fn finish_observations(
        &self,
        raw: &str,
        trace: &AttemptTrace,
        row: &mut LedgerRow,
    ) -> Result<()> {
        row.fetch_attempts = trace.attempts()?;
        if let Some(country) = trace.hosting_country()? {
            row.record.hosting_country = country;
        }
        if let Some(snapshot) = trace.last_robots()? {
            row.record.effective_gap_ms = self
                .client
                .policy()
                .get()
                .politeness
                .gap_ms
                .max(snapshot.crawl_delay_ms.unwrap_or(0));
            row.record.robots = Observation::Present(snapshot);
        }
        if let Some(attempt) = row.fetch_attempts.iter().rev().find(|attempt| {
            self.fetch_kind == FetchKind::Robots || attempt.kind != FetchKind::Robots
        }) {
            row.record.retrieved_at_utc = Observation::Present(attempt.started_at_utc);
            row.record.http_status = attempt.status.clone();
            row.record.queue_time_ms = Observation::Present(attempt.queue_time_ms);
            row.record.fetch_time_ms = Observation::Present(attempt.fetch_time_ms);
            row.record.body_bytes = Observation::Present(attempt.body_bytes);
            if attempt.status.value().is_some() {
                row.record.final_url = Observation::Present(attempt.requested_url.clone());
            }
        }
        if let Ok(url) = parse_fetch_url(raw) {
            match self.client.host_registry().state(&HostKey::from_url(&url)?) {
                Ok(state) => {
                    row.record.retry_at_utc = state.retry_at_utc;
                    row.record.blocked_until_utc = state.blocked_until_utc;
                    row.record.block_reason = state.block_reason;
                    row.record.consecutive_rate_responses = state.consecutive_rate_responses;
                    row.record.retry_after_invalid = state.retry_after_invalid;
                }
                Err(Error::HostStateWrite) => {
                    row.outcome = Outcome::InternalError {
                        code: InternalCode::HostStatePersistence,
                    };
                }
                Err(error) => return Err(error),
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
    async fn run_target(
        &self,
        target: &Target,
        raw: &str,
        row: &mut LedgerRow,
        trace: &AttemptTrace,
    ) -> Result<ProcessedTarget> {
        let url = parse_fetch_url(raw)?;
        self.verify_url(&url)?;
        if target.kind != TargetKind::Auxiliary {
            self.client.ledger().claim(&url)?;
        }
        let host = HostKey::from_url(&url)?;
        let classes = self.client.exclusions().class_matches(&host);
        row.record.content_classes = classes.classes;
        row.record.content_policies = classes.policies;
        row.record.exclusion_matches = classes.matches;
        if self.fetch_kind == FetchKind::Robots {
            return self.run_robots(raw, url, row, trace).await;
        }
        let previous = self.client.ledger().previous_success(&url)?;
        let mut request = self
            .client
            .get_traced(url.clone(), self.fetch_kind, Some(trace.clone()))
            .await?;
        if self.fetch_kind != FetchKind::Feed && self.fetch_kind != FetchKind::Sitemap {
            if let Some(limit) = self.client.exclusions().listing_limit(&host) {
                self.client.host_registry().admit_listing(&host, limit)?;
            }
        }
        if let Some(previous) = &previous {
            request = request.apply_validators(&previous.validators);
        }
        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let header_policy = super::directives::parse_headers(&headers, &url);
        row.record.directives = header_policy.effective;
        row.record.directives_seen = header_policy.seen;
        row.record.rights = header_policy.rights;
        row.record.index_only =
            row.record.rights.index_only() || row.record.directives.limit_exceeded;
        if header_policy.no_store {
            row.record.body_retention = BodyRetentionReason::NoStore;
        } else if row.record.rights.index_only() {
            row.record.body_retention = BodyRetentionReason::RightsReserved;
        }
        self.client.local_sink().enforce_record(&row.record)?;
        row.record.hosting_country = response.hosting_country.clone();
        row.record.final_url = Observation::Present(safe_url_for_record(&url));
        row.record.canonical_url = row.record.final_url.clone();
        row.record.canonical_key = Observation::Present(url_key(&url));
        let body = response.bytes().await;
        self.finish_observations(raw, trace, row)?;
        if let Ok(bytes) = &body {
            row.record.content_sha256 = Observation::Present(sha256(bytes));
            row.record.content_hash_source = ContentHashSource::CurrentResponse;
        }
        let now = self.client.clock().utc();
        if matches!(status, 404 | 410) {
            row.record.body_retention = BodyRetentionReason::Gone;
            row.record.tombstone = Some(Tombstone {
                scope: TombstoneScope::Url,
                observed_at_utc: now,
                delete_due_at_utc: now + chrono::TimeDelta::hours(24),
            });
            self.client.local_sink().enforce_record(&row.record)?;
            row.outcome = Outcome::Gone;
            return Ok(ProcessedTarget::default());
        }
        if status == 304 && previous.is_some() {
            return self.apply_not_modified(
                previous.ok_or(Error::InternalInvariant)?,
                headers,
                url,
                host,
                row,
                now,
            );
        }
        let bytes = body?;
        if super::host_state::detect_challenge(&headers, &bytes).is_some() {
            row.outcome = Outcome::HttpStatus {
                code: status,
                reason: HttpStatusReason::Challenge,
            };
            return Ok(ProcessedTarget::default());
        }
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            return self.redirect_response(target, url, headers, status, row, trace);
        }
        if status != 200 {
            row.outcome = if (300..400).contains(&status) && status != 304 {
                Outcome::RedirectInvalid {
                    reason: RedirectReason::UnsupportedStatus,
                }
            } else {
                Outcome::HttpStatus {
                    code: status,
                    reason: if status == 304 {
                        HttpStatusReason::UnexpectedNotModified
                    } else {
                        HttpStatusReason::Status
                    },
                }
            };
            return Ok(ProcessedTarget::default());
        }
        self.save_response(target, url, headers, bytes, row, now)
            .await
    }
    async fn run_robots(
        &self,
        raw: &str,
        url: Url,
        row: &mut LedgerRow,
        trace: &AttemptTrace,
    ) -> Result<ProcessedTarget> {
        let snapshot = self
            .client
            .robots_txt_manager()
            .snapshot_traced(&url, Some(trace))
            .await?;
        trace.robots(snapshot.clone())?;
        self.finish_observations(raw, trace, row)?;
        if snapshot.decision == super::robots_txt::RobotsDecision::DisallowUnreachable {
            return Err(Error::RobotsUnreachable);
        }
        let links = self
            .client
            .robots_txt_manager()
            .cached_sitemaps(&url)
            .await?
            .unwrap_or_default();
        if row.fetch_attempts.is_empty() {
            row.outcome = Outcome::AlreadyCrawled;
        } else {
            row.record.content_sha256 = snapshot.body_sha256.clone();
            row.record.content_hash_source = ContentHashSource::CurrentResponse;
            row.record.parsed_at_utc = Observation::Present(self.client.clock().utc());
            row.record.canonical_url = row.record.final_url.clone();
            row.record.canonical_key = row
                .record
                .final_url
                .value()
                .map(|value| {
                    parse_fetch_url(value.as_str()).map(|u| Observation::Present(url_key(&u)))
                })
                .transpose()?
                .unwrap_or_else(|| Observation::absent(super::record::AbsenceReason::NotAttempted));
            row.record.body_retention = BodyRetentionReason::Policy;
            row.record.index_only = true;
            row.record.index_eligible = false;
            row.outcome = Outcome::ParsedNotRetained;
        }
        Ok(ProcessedTarget { links, body: None })
    }
    fn apply_not_modified(
        &self,
        mut saved: super::record::DocumentRecord,
        headers: ResponseHeaders,
        url: Url,
        host: HostKey,
        row: &mut LedgerRow,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ProcessedTarget> {
        let observed = row.record.clone();
        let original_expiry = saved.raw_expires_at_utc;
        let original_parsed = saved.parsed_at_utc.clone();
        let original_retained = saved.retained_body_bytes;
        let mut parsed = super::directives::parse_headers(&headers, &url);
        parsed.no_store |= saved.body_retention == BodyRetentionReason::NoStore;
        parsed.effective.restrictive_merge(&saved.directives);
        parsed.rights.restrictive_merge(&saved.rights);
        saved.apply_policy(parsed, self.client.policy(), now)?;
        saved.raw_expires_at_utc = if saved.body_retention == BodyRetentionReason::Retained {
            original_expiry
        } else {
            None
        };
        saved.parsed_at_utc = original_parsed;
        saved.retained_body_bytes = if saved.body_retention == BodyRetentionReason::Retained {
            original_retained
        } else {
            0
        };
        if saved.raw_expires_at_utc.is_some_and(|expiry| expiry <= now) {
            saved.body_retention = BodyRetentionReason::Expired;
            saved.raw_expires_at_utc = None;
            saved.retained_body_bytes = 0;
        }
        saved.target_id = observed.target_id;
        saved.run_id = observed.run_id;
        saved.crawl_policy_version = observed.crawl_policy_version;
        saved.exclusion_version = observed.exclusion_version;
        saved.retention_policy_version = observed.retention_policy_version;
        saved.policy_config_sha256 = observed.policy_config_sha256;
        saved.exclusion_matches = observed.exclusion_matches;
        saved.content_classes = observed.content_classes;
        saved.content_policies = observed.content_policies;
        saved.requested_url = observed.requested_url;
        saved.final_url = observed.final_url;
        saved.http_status = observed.http_status;
        saved.retrieved_at_utc = observed.retrieved_at_utc;
        saved.fetch_time_ms = observed.fetch_time_ms;
        saved.queue_time_ms = observed.queue_time_ms;
        saved.body_bytes = observed.body_bytes;
        saved.robots = observed.robots;
        saved.hosting_country = observed.hosting_country;
        saved.content_hash_source = ContentHashSource::PreviousSuccess;
        self.client.host_registry().valid_not_modified(&host)?;
        self.client.local_sink().enforce_record(&saved)?;
        row.record = saved;
        row.outcome = Outcome::NotModified;
        Ok(ProcessedTarget::default())
    }
    fn redirect_response(
        &self,
        target: &Target,
        url: Url,
        headers: ResponseHeaders,
        status: u16,
        row: &mut LedgerRow,
        trace: &AttemptTrace,
    ) -> Result<ProcessedTarget> {
        let locations = headers.all("location");
        if headers.invalid("location") {
            row.outcome = Outcome::RedirectInvalid {
                reason: RedirectReason::InvalidLocation,
            };
            return Ok(ProcessedTarget::default());
        }
        if locations.len() != 1 {
            row.outcome = Outcome::RedirectInvalid {
                reason: RedirectReason::MissingOrConflictingLocation,
            };
            return Ok(ProcessedTarget::default());
        }
        let raw = &locations[0];
        if raw.is_empty() || raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
            row.outcome = Outcome::RedirectInvalid {
                reason: RedirectReason::InvalidLocation,
            };
            return Ok(ProcessedTarget::default());
        }
        let next = match url.join(raw) {
            Ok(url) => url,
            Err(_) => {
                row.outcome = Outcome::RedirectInvalid {
                    reason: RedirectReason::InvalidLocation,
                };
                return Ok(ProcessedTarget::default());
            }
        };
        if let Err(error) = parse_fetch_url(next.as_str()) {
            row.outcome = if matches!(error, Error::RefusedPrivateAddress) {
                Outcome::RefusedPrivateAddress
            } else {
                Outcome::RedirectInvalid {
                    reason: RedirectReason::InvalidLocation,
                }
            };
            return Ok(ProcessedTarget::default());
        }
        if reject_https_downgrade(&url, &next) {
            row.outcome = Outcome::RedirectInvalid {
                reason: RedirectReason::HttpsDowngrade,
            };
            return Ok(ProcessedTarget::default());
        }
        row.redirect_destination = Observation::Present(safe_url_for_record(&next));
        trace.redirect(&next)?;
        if !self.client.scope().contains_exact(&next) {
            row.outcome = Outcome::RedirectedOffSeed { status };
            return Ok(ProcessedTarget::default());
        }
        let (outcome, destination) = self.client.ledger().redirect(target, &next, status)?;
        row.outcome = outcome;
        row.destination_target_id = destination;
        Ok(ProcessedTarget::default())
    }
    fn parse_html(
        &self,
        body: &str,
        headers: &ResponseHeaders,
        url: &Url,
        row: &mut LedgerRow,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<Url>> {
        let links = {
            let html = Html::parse_without_text(body, url.as_str())
                .map_err(|_| Error::InternalInvariant)?;
            html.capture_ingestion_metadata(&mut row.record, headers, url);
            let parsed = html.ingestion_policy_observations(headers, url);
            row.record.parsed_at_utc = Observation::Present(now);
            row.record.validators = Validators::from_headers(headers);
            row.record.apply_policy(parsed, self.client.policy(), now)?;
            if let Err(error) = self
                .client
                .exclusions()
                .language(&row.record.declared_languages, ExclusionPhase::PostParse)
            {
                row.record.index_eligible = false;
                row.record.index_only = true;
                row.record.body_retention = BodyRetentionReason::Policy;
                row.record.raw_expires_at_utc = None;
                self.client.local_sink().enforce_record(&row.record)?;
                return Err(error);
            }
            if row.record.directives.nofollow {
                Vec::new()
            } else {
                self.new_urls(&html)
                    .into_iter()
                    .filter(|new_url| new_url.root_domain() == url.root_domain())
                    .take(MAX_OUTGOING_URLS_PER_PAGE)
                    .collect()
            }
        };

        Ok(links)
    }
    async fn save_response(
        &self,
        target: &Target,
        url: Url,
        headers: ResponseHeaders,
        bytes: Vec<u8>,
        row: &mut LedgerRow,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ProcessedTarget> {
        let mime = if matches!(self.fetch_kind, FetchKind::Feed | FetchKind::Sitemap) {
            auxiliary_mime(&headers)?
        } else {
            page_mime(&headers)?
        };
        row.record.media_type = Observation::Present(mime.essence_str().into());
        if bytes.is_empty() {
            return Err(Error::EmptyBody);
        }
        let declared_encoding = mime.get_param("charset").map(|value| value.as_str());
        let known_encoding =
            declared_encoding.and_then(|value| encoding_rs::Encoding::for_label(value.as_bytes()));
        let encoding = known_encoding.unwrap_or(encoding_rs::UTF_8);
        row.record.charset = Observation::Present(encoding.name().to_ascii_lowercase());
        row.record.charset_fallback = declared_encoding.is_some() && known_encoding.is_none();
        let body = encoding.decode(&bytes).0.into_owned();
        if matches!(self.fetch_kind, FetchKind::Feed | FetchKind::Sitemap) {
            row.record.parsed_at_utc = Observation::Present(now);
            row.record.validators = Validators::from_headers(&headers);
            row.record.apply_policy(
                super::directives::parse_headers(&headers, &url),
                self.client.policy(),
                now,
            )?;
            row.record.index_eligible = false;
            row.record.index_only = true;
            if row.record.body_retention == BodyRetentionReason::Retained {
                row.record.body_retention = BodyRetentionReason::Policy;
            }
            row.record.raw_expires_at_utc = None;
            self.client.local_sink().enforce_record(&row.record)?;
            row.outcome = Outcome::ParsedNotRetained;
            return Ok(ProcessedTarget {
                links: Vec::new(),
                body: Some(body),
            });
        }
        let links = self.parse_html(&body, &headers, &url, row, now)?;
        self.client.local_sink().enforce_record(&row.record)?;
        if row.record.body_retention != BodyRetentionReason::Retained || row.record.index_only {
            row.outcome = Outcome::ParsedNotRetained;
            return Ok(ProcessedTarget {
                links,
                body: (target.kind == TargetKind::Auxiliary).then_some(body),
            });
        }
        row.record.retained_body_bytes = body.len() as u64;
        row.record.validate()?;
        let auxiliary_body = (target.kind == TargetKind::Auxiliary).then(|| body.clone());
        self.writer
            .write(CrawlDatum {
                url: url.clone(),
                payload_type: warc::PayloadType::Html,
                body,
                fetch_time_ms: row
                    .record
                    .fetch_time_ms
                    .value()
                    .copied()
                    .ok_or(Error::RecordInvalid)?,
                date: now,
                record: row.record.clone(),
            })
            .await?;
        row.body_object = Some(super::retention::object_name(&row.target_id)?);
        row.outcome = if row.record.index_eligible {
            Outcome::Saved
        } else {
            Outcome::SavedNoindex
        };
        Ok(ProcessedTarget {
            links,
            body: auxiliary_body,
        })
    }
    async fn crawl_sitemaps(&mut self) -> Result<()> {
        let urls: Vec<_> = self.crawled_urls.iter().cloned().collect();
        for url in urls {
            let site = Site(url.host_str().unwrap_or_default().into());
            if self.crawled_sitemaps.insert(site) {
                for sitemap in self.client.discover_sitemaps(url).await? {
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
            let response = self.client.fetch_auxiliary(url, FetchKind::Sitemap).await?;
            if response.row.record.directives.nofollow {
                continue;
            }
            let Some(body) = response.body else {
                continue;
            };
            for entry in parse_sitemap(&body) {
                match entry {
                    SitemapEntry::Url(url) => urls.push(url),
                    SitemapEntry::Sitemap(url) => stack.push((url, depth + 1)),
                }
            }
        }
        Ok(urls)
    }
}

fn reject_https_downgrade(source: &Url, destination: &Url) -> bool {
    source.scheme() == "https" && destination.scheme() == "http"
}
fn auxiliary_mime(headers: &ResponseHeaders) -> Result<mime::Mime> {
    if headers.invalid("content-type") {
        return Err(Error::InvalidContentType("invalid-header-bytes".into()));
    }
    let values = headers.all("content-type");
    if values.is_empty() || values.iter().any(|value| value != &values[0]) {
        return Err(Error::InvalidContentType("missing-or-contradictory".into()));
    }
    let mime = values[0]
        .parse::<mime::Mime>()
        .map_err(|_| Error::InvalidContentType("invalid".into()))?;
    if matches!(
        mime.essence_str(),
        "application/rss+xml" | "application/atom+xml" | "application/xml" | "text/xml"
    ) {
        Ok(mime)
    } else {
        Err(Error::InvalidContentType("unsupported".into()))
    }
}
fn page_mime(headers: &ResponseHeaders) -> Result<mime::Mime> {
    if headers.invalid("content-type") {
        return Err(Error::InvalidContentType("invalid-header-bytes".into()));
    }
    let values = headers.all("content-type");
    if values.is_empty() || values.iter().any(|value| value != &values[0]) {
        return Err(Error::InvalidContentType("missing-or-contradictory".into()));
    }
    let mime = values[0]
        .parse::<mime::Mime>()
        .map_err(|_| Error::InvalidContentType("invalid".into()))?;
    if mime.essence_str() == "text/html" || mime.essence_str() == "application/xhtml+xml" {
        Ok(mime)
    } else {
        Err(Error::InvalidContentType("unsupported".into()))
    }
}
fn classify_target_error(error: &Error, trace: &AttemptTrace) -> Result<Outcome> {
    if matches!(error, Error::RobotsUnreachable) {
        if let Some(snapshot) = trace.last_robots()? {
            return Ok(match snapshot.failure_code.as_deref() {
                Some("timeout") => Outcome::Timeout,
                Some("tls") => Outcome::TlsError,
                Some("connect") => Outcome::ConnectError,
                Some("private-address") => Outcome::RefusedPrivateAddress,
                Some("host-blocked") => Outcome::HostBlocked,
                _ => Outcome::RobotsUnreachable,
            });
        }
    }
    Ok(Outcome::from_error(error))
}

#[cfg(test)]
mod tests {
    #[test]
    fn redirect_cross_scheme() {
        let http = url::Url::parse("http://fixture.invalid/page").unwrap();
        let https = url::Url::parse("https://fixture.invalid/page").unwrap();
        assert!(super::reject_https_downgrade(&https, &http));
        assert!(!super::reject_https_downgrade(&http, &https));
        assert!(!super::reject_https_downgrade(&https, &https));
    }
}
