//! Owns the compile-time host limits and checked timing policy shared by every fetch.
//! Configuration may slow requests but cannot raise concurrency or lower the hard gap.
//! Cross-process coordination is a production deployment prerequisite, not implied here.

#![deny(missing_docs)]

/// Minimum time between request starts to one host, in milliseconds.
pub const HARD_MIN_HOST_GAP_MS: u64 = 500;
/// Maximum simultaneously live connections/bodies to one host.
pub const HARD_MAX_HOST_CONCURRENCY: usize = 2;
/// Minimum access-denial block, in seconds from observation.
pub const MIN_BLOCK_SECS: u64 = 24 * 60 * 60;
/// Maximum lifetime of a usable robots snapshot, in seconds.
pub const MAX_ROBOTS_CACHE_SECS: u64 = 24 * 60 * 60;
/// Default time between host request starts, in milliseconds.
pub const DEFAULT_HOST_GAP_MS: u64 = 10_000;
/// Default simultaneously live connections/bodies to one host.
pub const DEFAULT_HOST_CONCURRENCY: usize = 1;
/// Publisher delays above this many seconds cause a policy skip, never clamping.
pub const MAX_ACCEPTED_CRAWL_DELAY_SECS: u64 = 60;
/// Earliest retry of unreachable robots, in seconds; rate deadlines can enlarge it.
pub const ROBOTS_FAILURE_RETRY_SECS: u64 = 300;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ingestion::IngestionPolicy;
    use proptest::prelude::*;

    #[test]
    fn ceiling_constants() {
        const GAP: u64 = HARD_MIN_HOST_GAP_MS;
        const CONNECTIONS: usize = HARD_MAX_HOST_CONCURRENCY;
        assert_eq!(GAP, 500);
        assert_eq!(CONNECTIONS, 2);
    }

    #[test]
    fn backoff_third() {
        assert_eq!(super::super::host_state::backoff_seconds(1), 900);
        assert_eq!(super::super::host_state::backoff_seconds(2), 1800);
        assert_eq!(super::super::host_state::backoff_seconds(3), 3600);
        assert_eq!(super::super::host_state::backoff_seconds(u32::MAX), 86_400);
    }

    #[test]
    fn rate_deadlines() {
        use super::super::host_state::{parse_retry_after, HostRegistry};
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-11T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            parse_retry_after("Thu, 10 Sep 2026 12:00:00 GMT", now),
            Some(now)
        );
        assert!(parse_retry_after("18446744073709551615", now).is_none());
        let root = std::path::PathBuf::from(std::env::var_os("STORY584_SCRATCH").unwrap())
            .join(format!("rates-{}", uuid::Uuid::new_v4()));
        let clock = Arc::new(ManualClock::new(now));
        let registry =
            HostRegistry::open(&root, IngestionPolicy::default().validate().unwrap(), clock)
                .unwrap();
        let host =
            HostKey::from_url(&url::Url::parse("https://rates.fixture.invalid/").unwrap()).unwrap();
        let mut headers = ResponseHeaders::default();
        headers.observe("retry-after", Some("172800"));
        registry.observe(&host, 429, &headers, None).unwrap();
        let state = registry.state(&host).unwrap();
        assert_eq!(
            state.retry_at_utc,
            Some(now + chrono::TimeDelta::seconds(172800))
        );
        assert_eq!(state.blocked_until_utc, state.retry_at_utc);
        drop(registry);
        std::fs::remove_dir_all(root).unwrap();
    }

    proptest! {
        #[test]
        fn politeness_config_prop(gap in any::<u64>(), concurrency in any::<usize>()) {
            let mut policy = IngestionPolicy::default();
            policy.politeness.gap_ms = gap;
            policy.politeness.max_concurrent_per_host = concurrency;
            prop_assert_eq!(policy.validate().is_ok(), (500..=86_400_000).contains(&gap) && (1..=2).contains(&concurrency));
            for boundary in [0, 499, 500, 10_000, 86_400_000, 86_400_001, u64::MAX] {
                for count in [0, 1, 2, 3, usize::MAX] {
                    policy.politeness.gap_ms = boundary;
                    policy.politeness.max_concurrent_per_host = count;
                    prop_assert_eq!(policy.validate().is_ok(), (500..=86_400_000).contains(&boundary) && (1..=2).contains(&count));
                }
            }
        }
    }
}

use super::{
    host_state::{ChallengeKind, HostRegistry, HostState},
    network::{HostKey, ResponseHeaders},
    Error, Result,
};
use crate::config::ingestion::ValidatedPolicy;
use chrono::{DateTime, Utc};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

/// Asynchronous wait completion in the crawler's monotonic time domain.
pub type WaitFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
/// Time seam used by the scheduler and robots cache; production uses SystemClock exclusively.
pub trait Clock: Send + Sync {
    /// Returns the current UTC observation time for persisted deadlines and records.
    fn utc(&self) -> DateTime<Utc>;
    /// Returns monotonically increasing elapsed milliseconds in this clock's lifetime.
    fn ticks(&self) -> u64;
    /// Waits until the given monotonic millisecond deadline without changing system time.
    fn wait_until(&self, deadline: u64) -> WaitFuture<'_>;
}
/// Production clock anchored to a process-local monotonic instant.
pub struct SystemClock {
    start: Instant,
}
impl Default for SystemClock {
    fn default() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}
impl Clock for SystemClock {
    fn utc(&self) -> DateTime<Utc> {
        Utc::now()
    }
    fn ticks(&self) -> u64 {
        self.start
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }
    fn wait_until(&self, deadline: u64) -> WaitFuture<'_> {
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(deadline.saturating_sub(self.ticks()))).await
        })
    }
}
/// Explicit fixture clock; only an owned loopback client can accept it for transport.
pub struct ManualClock {
    time: Mutex<(DateTime<Utc>, u64)>,
    changed: Notify,
}
impl ManualClock {
    /// Creates a zero-tick fixture time domain at the supplied UTC instant.
    pub fn new(utc: DateTime<Utc>) -> Self {
        Self {
            time: Mutex::new((utc, 0)),
            changed: Notify::new(),
        }
    }
    /// Advances monotonic and wall time by checked milliseconds and wakes scheduler waits.
    pub fn advance(&self, milliseconds: u64) -> Result<()> {
        let mut time = self.time.lock().map_err(|_| Error::InternalInvariant)?;
        let delta = chrono::TimeDelta::try_milliseconds(
            milliseconds
                .try_into()
                .map_err(|_| Error::InternalInvariant)?,
        )
        .ok_or(Error::InternalInvariant)?;
        time.0 = time
            .0
            .checked_add_signed(delta)
            .ok_or(Error::InternalInvariant)?;
        time.1 = time
            .1
            .checked_add(milliseconds)
            .ok_or(Error::InternalInvariant)?;
        drop(time);
        self.changed.notify_waiters();
        Ok(())
    }
    /// Changes only wall time to witness that active monotonic waits cannot be shortened.
    pub fn set_utc(&self, utc: DateTime<Utc>) -> Result<()> {
        self.time.lock().map_err(|_| Error::InternalInvariant)?.0 = utc;
        self.changed.notify_waiters();
        Ok(())
    }
}
impl Clock for ManualClock {
    fn utc(&self) -> DateTime<Utc> {
        self.time.lock().expect("fixture clock lock").0
    }
    fn ticks(&self) -> u64 {
        self.time.lock().expect("fixture clock lock").1
    }
    fn wait_until(&self, deadline: u64) -> WaitFuture<'_> {
        Box::pin(async move {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self.ticks() >= deadline {
                    return;
                }
                changed.await;
            }
        })
    }
}

#[derive(Default)]
struct GateTiming {
    next_start: u64,
    last_headers: Option<u64>,
    blocked_until: u64,
    initialized: bool,
}
/// Shared host semaphore/start mutex; there is one gate per host in the owned registry.
pub(super) struct HostGate {
    permits: Arc<Semaphore>,
    start: Arc<tokio::sync::Mutex<()>>,
    timing: Mutex<GateTiming>,
}
impl HostGate {
    pub(super) fn new(permits: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(permits)),
            start: Arc::new(tokio::sync::Mutex::new(())),
            timing: Mutex::new(GateTiming::default()),
        }
    }
    fn sync_deadlines(&self, state: &HostState, clock: &dyn Clock, gap: u64) -> Result<()> {
        let mut timing = self.timing.lock().map_err(|_| Error::InternalInvariant)?;
        let remaining = |deadline: DateTime<Utc>| {
            u64::try_from(
                deadline
                    .signed_duration_since(clock.utc())
                    .num_milliseconds(),
            )
            .unwrap_or(0)
        };
        if let Some(deadline) = state.blocked_until_utc.max(state.retry_at_utc) {
            timing.blocked_until = timing
                .blocked_until
                .max(clock.ticks().saturating_add(remaining(deadline)));
        }
        if !timing.initialized {
            if let Some(last) = state.last_request_start {
                let deadline = last
                    .checked_add_signed(chrono::TimeDelta::milliseconds(gap as i64))
                    .ok_or(Error::InternalInvariant)?;
                timing.next_start = clock.ticks().saturating_add(remaining(deadline));
            }
            timing.initialized = true;
        }
        if let Some(last) = timing.last_headers {
            timing.next_start = timing
                .next_start
                .max(last.saturating_add(gap).saturating_add(1));
        }
        Ok(())
    }
}

/// Host admission permit held through connect, response headers and full bounded body consumption.
/// Dropping on success, error or cancellation releases the live-connection allowance.
pub struct HostPermit {
    _permit: OwnedSemaphorePermit,
    start_guard: Option<tokio::sync::OwnedMutexGuard<()>>,
    registry: Arc<HostRegistry>,
    host: HostKey,
    gate: Arc<HostGate>,
    clock: Arc<dyn Clock>,
    gap_ms: u64,
    /// UTC time of the actual admitted request start, excluding queue wait.
    pub started_at_utc: DateTime<Utc>,
    /// Scheduler wait in milliseconds before the actual start.
    pub queue_time_ms: u64,
}
impl HostPermit {
    /// Returns acknowledged host deadlines for the completed attempt record.
    pub(super) fn state(&self) -> Result<HostState> {
        self.registry.state(&self.host)
    }
    /// Ends connection/header admission; body reads retain the connection allowance.
    pub(super) fn headers_received(&mut self) {
        if self.start_guard.is_some() {
            // Measuring from received headers also covers connect and persistence latency.
            // One extra millisecond covers the clock's integer rounding.
            if let Ok(mut timing) = self.gate.timing.lock() {
                timing.last_headers = Some(self.clock.ticks());
                timing.next_start = timing.next_start.max(
                    self.clock
                        .ticks()
                        .saturating_add(self.gap_ms)
                        .saturating_add(1),
                );
            }
            self.start_guard.take();
        }
    }
    /// Records access/rate headers before MIME/body interpretation, then updates monotonic deadlines.
    pub(super) fn observe(
        &self,
        status: u16,
        headers: &ResponseHeaders,
        challenge: Option<ChallengeKind>,
    ) -> Result<()> {
        self.registry
            .observe(&self.host, status, headers, challenge)?;
        self.gate.sync_deadlines(
            &self.registry.state(&self.host)?,
            self.clock.as_ref(),
            self.gap_ms,
        )
    }
    /// Adds body-only challenge evidence without counting the HTTP status a second time.
    pub(super) fn observe_body_challenge(
        &self,
        headers: &ResponseHeaders,
        challenge: ChallengeKind,
    ) -> Result<()> {
        self.observe(0, headers, Some(challenge))
    }
}
impl Drop for HostPermit {
    fn drop(&mut self) {
        self.headers_received();
    }
}

/// Acquires the shared host permit and reserves the actual request start under the host mutex.
/// Existing block/rate deadlines reject this admission; ordinary gap waits remain asynchronous.
/// A publisher delay above 60 seconds is skipped, never clamped to allow a faster request.
pub async fn acquire_host(
    registry: Arc<HostRegistry>,
    host: HostKey,
    policy: &ValidatedPolicy,
    clock: Arc<dyn Clock>,
    robots_delay: Option<u64>,
) -> Result<HostPermit> {
    if robots_delay.is_some_and(|delay| delay > MAX_ACCEPTED_CRAWL_DELAY_SECS * 1000) {
        return Err(Error::CrawlDelayExceedsCeiling);
    }
    let gap = policy.get().politeness.gap_ms.max(HARD_MIN_HOST_GAP_MS);
    let gap = gap.max(robots_delay.unwrap_or(0));
    let gate = registry.gate(&host)?;
    let queued = clock.ticks();
    let permit = gate
        .permits
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| Error::Cancelled)?;
    let start_guard = gate.start.clone().lock_owned().await;
    {
        gate.sync_deadlines(&registry.state(&host)?, clock.as_ref(), gap)?;
        let next_start = {
            let timing = gate.timing.lock().map_err(|_| Error::InternalInvariant)?;
            if timing.blocked_until > clock.ticks() {
                return Err(Error::HostBlocked);
            }
            timing.next_start
        };
        clock.wait_until(next_start).await;
        gate.sync_deadlines(&registry.state(&host)?, clock.as_ref(), gap)?;
        {
            let mut timing = gate.timing.lock().map_err(|_| Error::InternalInvariant)?;
            if timing.blocked_until > clock.ticks() {
                return Err(Error::HostBlocked);
            }
            timing.next_start = clock
                .ticks()
                .checked_add(gap)
                .ok_or(Error::InternalInvariant)?;
        }
        registry.started(&host, clock.utc())?;
    }
    Ok(HostPermit {
        _permit: permit,
        start_guard: Some(start_guard),
        registry,
        host,
        gate,
        started_at_utc: clock.utc(),
        queue_time_ms: clock.ticks().saturating_sub(queued),
        clock,
        gap_ms: gap,
    })
}
