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

//! Applies scope, host blocks, robots and shared host scheduling to every content request.
//! Only approved production, the frozen sample and owned loopback capabilities construct clients.
//! Raw HTTP clients/builders never escape identity.rs; unit-test sends remain disabled.

use super::{
    exclusions::Exclusions,
    host_state::HostRegistry,
    identity::build_http_client,
    ledger::{AttemptTrace, FetchKind, Ledger},
    local_sink::LocalSink,
    network::{BoundedResponse, CrawlScope, HostKey, LoopbackEndpoint, Transport, VettedResolver},
    politeness::{acquire_host, Clock, SystemClock},
    robots_txt::{RobotsDecision, RobotsSnapshot, RobotsTxtManager},
    Error, Result, MAX_CONTENT_LENGTH,
};
use crate::config::{
    ingestion::{IngestionPolicy, ValidatedPolicy},
    CrawlerConfig,
};
use std::{path::Path, sync::Arc, time::Duration};
use url::Url;

struct Inner {
    transport: Arc<Transport>,
    registry: Arc<HostRegistry>,
    policy: ValidatedPolicy,
    clock: Arc<dyn Clock>,
    robots: RobotsTxtManager,
    ledger: Arc<Ledger>,
    sink: Arc<LocalSink>,
    cancelled: std::sync::atomic::AtomicBool,
    cancellation: tokio::sync::Notify,
}
/// Shared validated crawler client; clones retain one transport, robots cache and host registry.
#[derive(Clone)]
pub struct RobotClient {
    inner: Arc<Inner>,
}

fn environment_dpia() -> Result<Option<String>> {
    match std::env::var("DPIA_ID") {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(Error::InternalInvariant),
    }
}
impl RobotClient {
    /// Fetches a bounded feed, sitemap or frontpage through the same durable completion funnel.
    /// Failed fetches return a typed terminal row; ledger failure is a fatal error.
    pub async fn fetch_auxiliary(
        &self,
        url: Url,
        kind: FetchKind,
    ) -> Result<super::AuxiliaryResult> {
        super::JobExecutor::auxiliary(self.clone(), url, kind).await
    }
    /// Reads fresh cached sitemap declarations or journals an owned robots refresh before discovery.
    pub async fn discover_sitemaps(&self, url: Url) -> Result<Vec<Url>> {
        if let Some(links) = self.inner.robots.cached_sitemaps(&url).await? {
            return Ok(links);
        }
        Ok(self.fetch_auxiliary(url, FetchKind::Robots).await?.links)
    }
    /// Validates production approval before creating storage or transport.
    /// Missing approval, unsafe config and an already-owned store are fatal startup errors.
    pub fn new(config: &CrawlerConfig) -> Result<Self> {
        let environment = environment_dpia()?;
        let permit = config
            .ingestion
            .require_production_approval(chrono::Utc::now(), environment.as_deref())?;
        let policy = permit.policy().clone();
        Self::construct(
            &config.local_store_path,
            policy,
            CrawlScope::production(permit),
            Arc::new(SystemClock::default()),
            config.timeout_seconds,
        )
    }
    /// Constructs a client that can connect only to the supplied owned loopback listener.
    /// The fixture clock cannot reach a production constructor or authorize other addresses.
    pub fn loopback(
        store: &Path,
        policy: &IngestionPolicy,
        endpoint: LoopbackEndpoint,
        clock: Arc<dyn Clock>,
        timeout_seconds: u64,
    ) -> Result<Self> {
        Self::construct(
            store,
            policy.validate()?,
            CrawlScope::loopback(endpoint),
            clock,
            timeout_seconds,
        )
    }
    pub(crate) fn sample(
        store: &Path,
        policy: ValidatedPolicy,
        urls: &[Url],
        timeout_seconds: u64,
    ) -> Result<Self> {
        Self::construct(
            store,
            policy,
            CrawlScope::sample(urls),
            Arc::new(SystemClock::default()),
            timeout_seconds,
        )
    }
    fn construct(
        store: &Path,
        policy: ValidatedPolicy,
        scope: CrawlScope,
        clock: Arc<dyn Clock>,
        timeout_seconds: u64,
    ) -> Result<Self> {
        let timeout = Duration::from_secs(timeout_seconds);
        if timeout.is_zero() || std::time::Instant::now().checked_add(timeout).is_none() {
            return Err(Error::Timeout);
        }
        let exclusions = Arc::new(Exclusions::new(
            &policy.get().exclusions,
            scope.country_provider(),
        )?);
        let registry = HostRegistry::open(store, policy.clone(), clock.clone())?;
        let sink = LocalSink::open(registry.clone(), policy.clone(), clock.clone())?;
        let ledger = Ledger::open(registry.clone(), policy.clone(), clock.clone())?;
        let resolver = Arc::new(VettedResolver::new(scope.candidate_resolver()));
        let client = build_http_client(&policy.get().identity, timeout, resolver.clone())?;
        let transport = Arc::new(Transport {
            client,
            resolver,
            scope,
            exclusions,
            clock: clock.clone(),
        });
        let robots = RobotsTxtManager::new(
            transport.clone(),
            registry.clone(),
            policy.clone(),
            clock.clone(),
        );
        Ok(Self {
            inner: Arc::new(Inner {
                transport,
                registry,
                policy,
                clock,
                robots,
                ledger,
                sink,
                cancelled: std::sync::atomic::AtomicBool::new(false),
                cancellation: tokio::sync::Notify::new(),
            }),
        })
    }
    /// Returns the shared robots manager for sitemap discovery and cache observations.
    pub fn robots_txt_manager(&self) -> &RobotsTxtManager {
        &self.inner.robots
    }
    /// Returns the authoritative durable target journal and terminal projection for this client run.
    pub fn ledger(&self) -> Arc<Ledger> {
        self.inner.ledger.clone()
    }
    /// Requests explicit owned-run cancellation; pending inputs are still completed by the executor.
    pub fn cancel(&self) {
        self.inner
            .cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.inner.cancellation.notify_waiters();
    }
    /// Waits for cancellation without appending a row from Drop or changing unrelated processes.
    pub async fn cancelled(&self) {
        loop {
            let notified = self.inner.cancellation.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self
                .inner
                .cancelled
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return;
            }
            notified.await;
        }
    }
    /// Returns the owned local sink; acknowledgement precedes any Saved outcome.
    pub fn local_sink(&self) -> Arc<LocalSink> {
        self.inner.sink.clone()
    }
    /// Returns immutable host/geographic/language policy shared by every physical fetch role.
    pub fn exclusions(&self) -> &Exclusions {
        &self.inner.transport.exclusions
    }
    /// Returns the exclusively owned host registry shared with local sink and outcome ledger.
    pub fn host_registry(&self) -> Arc<HostRegistry> {
        self.inner.registry.clone()
    }
    /// Returns immutable validated policy used by this client.
    pub fn policy(&self) -> &ValidatedPolicy {
        &self.inner.policy
    }
    /// Returns the clock for record timestamps; production clients always use the system clock.
    pub fn clock(&self) -> Arc<dyn Clock> {
        self.inner.clock.clone()
    }
    /// Returns sealed scope membership without granting new targets.
    pub fn scope(&self) -> &CrawlScope {
        &self.inner.transport.scope
    }
    /// Validates URL/scope and current blocks before returning a request with no network side effects.
    pub async fn get(&self, url: Url) -> Result<RequestBuilder> {
        if !self.scope().is_loopback() {
            return Err(Error::InternalInvariant);
        }
        self.get_traced(url, FetchKind::Page, None).await
    }
    pub(crate) async fn get_traced(
        &self,
        url: Url,
        kind: FetchKind,
        trace: Option<AttemptTrace>,
    ) -> Result<RequestBuilder> {
        let url = super::network::parse_fetch_url(url.as_str())?;
        self.inner.transport.scope.validate(&url, false)?;
        let previous = self.inner.ledger.previous_success(&url)?;
        self.exclusions().frontier(
            &url,
            previous
                .as_ref()
                .map(|record| record.declared_languages.as_slice()),
        )?;
        let state = self.inner.registry.state(&HostKey::from_url(&url)?)?;
        if state
            .blocked_until_utc
            .max(state.retry_at_utc)
            .is_some_and(|deadline| deadline > self.inner.clock.utc())
        {
            return Err(Error::HostBlocked);
        }
        Ok(RequestBuilder {
            client: self.clone(),
            url,
            validators: Vec::new(),
            kind,
            trace,
        })
    }
    async fn ensure_robots(
        &self,
        target: &Url,
        trace: Option<&AttemptTrace>,
    ) -> Result<RobotsSnapshot> {
        let snapshot = self.inner.robots.snapshot_traced(target, trace).await?;
        if let Some(trace) = trace {
            trace.robots(snapshot.clone())?;
        }
        match snapshot.decision {
            RobotsDecision::AllowRule | RobotsDecision::AllowAllUnavailable => Ok(snapshot),
            RobotsDecision::DisallowRule => Err(Error::DisallowedPath),
            RobotsDecision::DisallowUnreachable | RobotsDecision::Bootstrap => {
                Err(Error::RobotsUnreachable)
            }
        }
    }
}

/// Admitted content request with no raw-client constructor or redirect/auth/cookie escape hatch.
pub struct RequestBuilder {
    client: RobotClient,
    url: Url,
    validators: Vec<(String, String)>,
    kind: FetchKind,
    trace: Option<AttemptTrace>,
}
impl RequestBuilder {
    /// Applies both safe validators from a lookup for this exact URL/origin; no cross-origin reuse.
    pub(crate) fn apply_validators(mut self, validators: &super::record::Validators) -> Self {
        self.validators = validators.request_headers();
        if !self.validators.is_empty() {
            self.kind = FetchKind::Conditional;
        }
        self
    }
    /// Sends only after usable robots and host admission; holds the permit through bounded body read.
    /// Unit-test library builds always refuse sending at the identity boundary.
    pub async fn send(self) -> Result<BoundedResponse> {
        let target = self.url;
        for _ in 0..=self.client.policy().get().politeness.retry_budget {
            let snapshot = self
                .client
                .ensure_robots(&target, self.trace.as_ref())
                .await?;
            let prepared = self
                .client
                .inner
                .transport
                .prepare(&target, self.trace.as_ref())
                .await?;
            let permit = acquire_host(
                self.client.inner.registry.clone(),
                HostKey::from_url(&target)?,
                self.client.policy(),
                self.client.inner.clock.clone(),
                snapshot.crawl_delay_ms,
            )
            .await?;
            if !self
                .client
                .inner
                .robots
                .revalidate_snapshot_before_send(&target, &snapshot)
                .await?
            {
                drop(permit);
                continue;
            }
            let mut response = self
                .client
                .inner
                .transport
                .send(
                    prepared,
                    &self.validators,
                    permit,
                    MAX_CONTENT_LENGTH,
                    self.kind,
                    self.trace.as_ref(),
                )
                .await?;
            response.attach_robots(snapshot)?;
            return Ok(response);
        }
        Err(Error::RobotsUnreachable)
    }
}
