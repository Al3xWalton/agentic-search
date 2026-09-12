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

//! Resolves robots by exact origin with single-flight refresh and fail-closed failure caching.
//! Each content request receives the immutable decision actually used at admission.
//! HTTPS failures never trigger downgrade; parser/matcher/delay panics deny access.
//! The adapter is conservative for tested path representations, not a general RFC proof.

use super::{
    host_state::HostRegistry,
    network::{safe_url_for_record, sha256, HostKey, OriginKey, SafeUrl, Transport},
    politeness::{acquire_host, Clock, ROBOTS_FAILURE_RETRY_SECS},
    Error, Result,
};
use crate::config::ingestion::ValidatedPolicy;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{Arc, Mutex},
};
use url::Url;

/// Maximum received robots entity bytes; larger bodies are refused before buffer growth.
pub const ROBOTS_BODY_LIMIT: usize = 512_000;
/// Access decision from a specific robots response or bootstrap request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RobotsDecision {
    /// Matching rules permit the exact and conservative forms.
    AllowRule,
    /// At least one checked representation is denied.
    DisallowRule,
    /// A completed 4xx establishes known policy absence; independent host blocks still win.
    AllowAllUnavailable,
    /// Transport, status, redirect or parser failure prevents permission.
    DisallowUnreachable,
    /// Robots request needed to establish the first decision, never page permission.
    Bootstrap,
}
/// Explicit entity presence so an absent body never receives a fabricated empty hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RobotsBodyState {
    /// Completed entity bytes, including a genuine zero-byte response.
    Received,
    /// No complete entity was received.
    NotReceived,
}
/// Immutable metadata of the robots response used to decide one content request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RobotsSnapshot {
    /// Exact origin whose policy was evaluated, without query/userinfo/fragment.
    pub origin: SafeUrl,
    /// UTC time the policy response or failure was observed.
    pub fetched_at_utc: DateTime<Utc>,
    /// UTC freshness/retry deadline; queue validation also checks monotonic age.
    pub expires_at_utc: DateTime<Utc>,
    /// Actual last policy HTTP status, absent when no response arrived.
    pub http_status: Option<u16>,
    /// SHA-256 of a completed robots entity; absent for incomplete transport.
    pub body_sha256: Option<String>,
    /// Explicit presence state for body/hash observations.
    pub body_state: RobotsBodyState,
    /// Result for the exact content target, including unavailable and unreachable states.
    pub decision: RobotsDecision,
    /// Matched rule action or "default"/"unavailable"/"unreachable".
    pub matched_rule_kind: String,
    /// Hash of the selected rule pattern, absent when no pattern matched.
    pub matched_rule_sha256: Option<String>,
    /// Publisher delay rounded up to milliseconds; never clamped down.
    pub crawl_delay_ms: Option<u64>,
    /// Typed fixed diagnostic code; no parser/response text or URL is copied here.
    pub failure_code: Option<String>,
}

struct Cached {
    parsed: Option<robotstxt::Robots>,
    selected: String,
    snapshot: RobotsSnapshot,
    ticks: u64,
    ttl_ms: u64,
}
impl Cached {
    fn expired(&self, now: u64) -> bool {
        let age = now.saturating_sub(self.ticks);
        let cache_ttl = self.ttl_ms;
        age >= cache_ttl
    }
}
struct OriginEntry {
    cache: tokio::sync::Mutex<Option<Cached>>,
}
struct Inner {
    entries: Mutex<BTreeMap<OriginKey, Arc<OriginEntry>>>,
    transport: Arc<Transport>,
    registry: Arc<HostRegistry>,
    policy: ValidatedPolicy,
    clock: Arc<dyn Clock>,
}
/// Cloneable origin-keyed robots manager sharing the transport and every host gate.
#[derive(Clone)]
pub struct RobotsTxtManager {
    inner: Arc<Inner>,
}
impl RobotsTxtManager {
    pub(super) fn new(
        transport: Arc<Transport>,
        registry: Arc<HostRegistry>,
        policy: ValidatedPolicy,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                entries: Mutex::new(BTreeMap::new()),
                transport,
                registry,
                policy,
                clock,
            }),
        }
    }
    fn entry(&self, url: &Url) -> Result<Arc<OriginEntry>> {
        let cache_key = OriginKey::from_url(url)?;
        Ok(self
            .inner
            .entries
            .lock()
            .map_err(|_| Error::InternalInvariant)?
            .entry(cache_key)
            .or_insert_with(|| {
                Arc::new(OriginEntry {
                    cache: tokio::sync::Mutex::new(None),
                })
            })
            .clone())
    }
    /// Resolves one immutable robots decision; concurrent misses perform only one refresh.
    pub async fn snapshot(&self, url: &Url) -> Result<RobotsSnapshot> {
        let entry = self.entry(url)?;
        let singleflight = &entry.cache;
        let mut cache = singleflight.lock().await;
        if cache
            .as_ref()
            .is_none_or(|entry| entry.expired(self.inner.clock.ticks()))
        {
            *cache = Some(self.refresh(url).await?);
        }
        let entry = cache.as_ref().ok_or(Error::InternalInvariant)?;
        let mut snapshot = entry.snapshot.clone();
        let conservative = conservative_url(url)?;
        if let Some(robots) = &entry.parsed {
            let decision = catch_unwind(AssertUnwindSafe(|| {
                let allow_exact = robots.is_allowed_strict(url);
                let allow_conservative = robots.is_allowed_strict(&conservative);
                let allowed = allow_exact && allow_conservative;
                let matched = matching_rule(
                    &entry.selected,
                    if allow_exact { &conservative } else { url },
                );
                Ok::<_, Error>((allowed, matched))
            }));
            match decision {
                Ok(Ok((allowed, matched))) => {
                    snapshot.decision = if allowed {
                        RobotsDecision::AllowRule
                    } else {
                        RobotsDecision::DisallowRule
                    };
                    if let Some((kind, hash)) = matched {
                        snapshot.matched_rule_kind = kind;
                        snapshot.matched_rule_sha256 = Some(hash);
                    }
                }
                _ => {
                    snapshot.decision = RobotsDecision::DisallowUnreachable;
                    snapshot.failure_code = Some("parser-failure".into());
                }
            }
        }
        Ok(snapshot)
    }
    /// Returns false on unavailable permission, including transport/parser failure.
    pub async fn is_allowed(&self, url: &Url) -> bool {
        self.snapshot(url).await.is_ok_and(|s| {
            matches!(
                s.decision,
                RobotsDecision::AllowRule | RobotsDecision::AllowAllUnavailable
            )
        })
    }
    /// Returns the publisher delay without clamping it to the policy threshold.
    pub async fn crawl_delay(&self, url: &Url) -> Option<std::time::Duration> {
        self.snapshot(url)
            .await
            .ok()
            .and_then(|s| s.crawl_delay_ms.map(std::time::Duration::from_millis))
    }
    /// Returns declared sitemap URLs only after robots resolution; never fetches them here.
    pub async fn sitemaps(&self, url: &Url) -> Vec<Url> {
        if self.snapshot(url).await.is_err() {
            return vec![];
        }
        let Ok(entry) = self.entry(url) else {
            return vec![];
        };
        let cache = entry.cache.lock().await;
        cache
            .as_ref()
            .and_then(|e| e.parsed.as_ref())
            .and_then(|robots| {
                catch_unwind(AssertUnwindSafe(|| {
                    robots
                        .sitemaps()
                        .iter()
                        .filter_map(|s| Url::parse(s).ok())
                        .collect()
                }))
                .ok()
            })
            .unwrap_or_default()
    }
    /// Revalidates freshness after waiting for a permit; expiry requires another refresh before send.
    pub(super) async fn revalidate_snapshot_before_send(
        &self,
        url: &Url,
        snapshot: &RobotsSnapshot,
    ) -> Result<bool> {
        let entry = self.entry(url)?;
        let cache = entry.cache.lock().await;
        Ok(cache.as_ref().is_some_and(|e| {
            !e.expired(self.inner.clock.ticks())
                && e.snapshot.fetched_at_utc == snapshot.fetched_at_utc
        }))
    }
    async fn refresh(&self, url: &Url) -> Result<Cached> {
        let mut origin = url.clone();
        origin.set_path("/");
        origin.set_query(None);
        origin.set_fragment(None);
        let mut target = origin.join("robots.txt").map_err(|_| Error::InvalidUrl)?;
        let fetched_at_utc = self.inner.clock.utc();
        let mut snapshot = RobotsSnapshot {
            origin: safe_url_for_record(&origin),
            fetched_at_utc,
            expires_at_utc: fetched_at_utc,
            http_status: None,
            body_sha256: None,
            body_state: RobotsBodyState::NotReceived,
            decision: RobotsDecision::DisallowUnreachable,
            matched_rule_kind: "unreachable".into(),
            matched_rule_sha256: None,
            crawl_delay_ms: None,
            failure_code: None,
        };
        let mut parsed = None;
        let mut selected = String::new();
        let mut visited = std::collections::BTreeSet::new();
        for hop in 0..=10 {
            if hop == 10 || !visited.insert(target.as_str().to_owned()) {
                snapshot.failure_code = Some("redirect-loop-or-limit".into());
                break;
            }
            if hop == 0 {
                self.inner.transport.scope.validate(&target, true)?;
            }
            let attempt = async {
                self.inner.transport.prepare(&target).await?;
                let permit = acquire_host(
                    self.inner.registry.clone(),
                    HostKey::from_url(&target)?,
                    &self.inner.policy,
                    self.inner.clock.clone(),
                    None,
                )
                .await?;
                self.inner
                    .transport
                    .send(target.clone(), &[], permit, ROBOTS_BODY_LIMIT)
                    .await
            }
            .await;
            let response = match attempt {
                Ok(response) => response,
                Err(error @ (Error::HostStateWrite | Error::InternalInvariant)) => {
                    return Err(error)
                }
                Err(error) => {
                    snapshot.failure_code = Some(failure_code(&error).into());
                    break;
                }
            };
            let status = response.status();
            snapshot.http_status = Some(status);
            let headers = response.headers().clone();
            let bytes = match response.bytes().await {
                Ok(bytes) => bytes,
                Err(error @ (Error::HostStateWrite | Error::InternalInvariant)) => {
                    return Err(error)
                }
                Err(error) => {
                    snapshot.failure_code = Some(failure_code(&error).into());
                    break;
                }
            };
            snapshot.body_sha256 = Some(sha256(&bytes));
            snapshot.body_state = RobotsBodyState::Received;
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                let destinations = headers.all("location");
                let next = if !headers.invalid("location") && destinations.len() == 1 {
                    target.join(&destinations[0]).ok()
                } else {
                    None
                };
                let Some(next) = next else {
                    snapshot.failure_code = Some("redirect-invalid".into());
                    break;
                };
                if super::network::parse_fetch_url(next.as_str()).is_err()
                    || (target.scheme() == "https" && next.scheme() == "http")
                {
                    snapshot.failure_code = Some("redirect-invalid".into());
                    break;
                }
                if self
                    .inner
                    .transport
                    .scope
                    .validate_robots_redirect(&next)
                    .is_err()
                {
                    snapshot.failure_code = Some("redirect-off-scope".into());
                    break;
                }
                target = next;
                continue;
            }
            if (400..500).contains(&status) {
                snapshot.decision = RobotsDecision::AllowAllUnavailable;
                snapshot.matched_rule_kind = "unavailable".into();
                break;
            }
            if status != 200 {
                snapshot.failure_code = Some("http-unreachable".into());
                break;
            }
            let result = catch_unwind(AssertUnwindSafe(|| {
                let body = std::str::from_utf8(&bytes).map_err(|_| Error::RobotsUnreachable)?;
                let selected = select_exact_groups(body);
                let declared_delay = validate_declared_delays(&selected)?;
                let robots = robotstxt::Robots::parse("AVASearchBot", &selected)
                    .map_err(|_| Error::RobotsUnreachable)?;
                let delay = robots
                    .crawl_delay()
                    .map(|duration| {
                        u64::try_from(duration.as_nanos().div_ceil(1_000_000))
                            .map_err(|_| Error::RobotsUnreachable)
                    })
                    .transpose()?;
                Ok::<_, Error>((robots, selected, delay.max(declared_delay)))
            }));
            match result {
                Ok(Ok((robots, text, delay))) => {
                    parsed = Some(robots);
                    selected = text;
                    snapshot.crawl_delay_ms = delay;
                    snapshot.decision = RobotsDecision::AllowRule;
                    snapshot.matched_rule_kind = "default".into();
                }
                _ => snapshot.failure_code = Some("parser-failure".into()),
            }
            break;
        }
        let ttl_ms = if snapshot.decision == RobotsDecision::DisallowUnreachable {
            ROBOTS_FAILURE_RETRY_SECS * 1000
        } else {
            self.inner.policy.get().robots.cache_secs * 1000
        };
        snapshot.fetched_at_utc = self.inner.clock.utc();
        snapshot.expires_at_utc = snapshot
            .fetched_at_utc
            .checked_add_signed(chrono::TimeDelta::milliseconds(ttl_ms as i64))
            .ok_or(Error::InternalInvariant)?;
        Ok(Cached {
            parsed,
            selected,
            snapshot,
            ticks: self.inner.clock.ticks(),
            ttl_ms,
        })
    }
}
fn validate_declared_delays(selected: &str) -> Result<Option<u64>> {
    let mut delay = None;
    for line in selected.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("crawl-delay") {
            continue;
        }
        let seconds = value
            .trim()
            .parse::<f64>()
            .map_err(|_| Error::RobotsUnreachable)?;
        let milliseconds = (seconds * 1000.0).ceil();
        if !seconds.is_finite() || seconds < 0.0 || milliseconds >= u64::MAX as f64 {
            return Err(Error::RobotsUnreachable);
        }
        delay = delay.max(Some(milliseconds as u64));
    }
    Ok(delay)
}
fn failure_code(error: &Error) -> &'static str {
    match error {
        Error::Timeout => "timeout",
        Error::TlsError => "tls",
        Error::ContentTooLarge => "body-too-large",
        Error::HostBlocked => "host-blocked",
        Error::RefusedPrivateAddress => "private-address",
        _ => "transport-failed",
    }
}
/// Compares the decoded, slash-collapsed path after RFC 3986 dot-segment removal.
/// Trailing dot segments resolve too; climbing above root is ambiguous and returns InvalidUrl.
/// The caller denies when either this form or the exact transmitted path is disallowed.
fn conservative_url(url: &Url) -> Result<Url> {
    let path = percent_encoding::percent_decode_str(url.path())
        .decode_utf8()
        .map_err(|_| Error::InvalidUrl)?;
    let mut collapsed = String::new();
    let mut slash = false;
    for c in path.chars() {
        if c != '/' || !slash {
            collapsed.push(c);
        }
        slash = c == '/';
    }
    let mut result = url.clone();
    result.set_path(&remove_dot_segments(&collapsed)?);
    Ok(result)
}
fn remove_dot_segments(path: &str) -> Result<String> {
    let mut segments = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop().ok_or(Error::InvalidUrl)?;
            }
            segment => segments.push(segment),
        }
    }
    let mut resolved = format!("/{}", segments.join("/"));
    if resolved != "/" && (path.ends_with('/') || path.ends_with("/.") || path.ends_with("/..")) {
        resolved.push('/');
    }
    Ok(resolved)
}
fn select_exact_groups(body: &str) -> String {
    let mut groups: Vec<(Vec<String>, Vec<String>)> = Vec::new();
    let mut current = (Vec::new(), Vec::new());
    let mut has_rule = false;
    let mut sitemaps = Vec::new();
    for raw in body.lines() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        if name == "user-agent" {
            if has_rule {
                groups.push(current);
                current = (vec![], vec![]);
                has_rule = false;
            }
            current.0.extend(
                value
                    .split([',', ' ', '\t'])
                    .filter(|s| !s.is_empty())
                    .map(str::to_ascii_lowercase),
            );
        } else if name == "sitemap" {
            sitemaps.push(line.to_owned());
        } else if matches!(name.as_str(), "allow" | "disallow" | "crawl-delay") {
            current.1.push(line.to_owned());
            has_rule = true;
        }
    }
    groups.push(current);
    let has_specific = groups
        .iter()
        .any(|(agents, _)| agents.iter().any(|a| a == "avasearchbot"));
    let token = if has_specific { "avasearchbot" } else { "*" };
    let mut selected = String::from("User-agent: AVASearchBot\n");
    for (agents, lines) in groups {
        if agents.is_empty() || agents.iter().any(|a| a == token) {
            for line in lines {
                selected.push_str(&line);
                selected.push('\n');
            }
        }
    }
    for sitemap in sitemaps {
        selected.push_str(&sitemap);
        selected.push('\n');
    }
    selected
}
fn matching_rule(selected: &str, url: &Url) -> Option<(String, String)> {
    let mut matches = Vec::new();
    for line in selected.lines() {
        let (name, pattern) = line.split_once(':')?;
        let name = name.trim().to_ascii_lowercase();
        let pattern = pattern.trim();
        if !matches!(name.as_str(), "allow" | "disallow") || pattern.is_empty() {
            continue;
        }
        let single = robotstxt::Robots::parse(
            "AVASearchBot",
            &format!("User-agent: AVASearchBot\nDisallow: {pattern}"),
        )
        .ok()?;
        if !single.is_allowed_strict(url) {
            matches.push((pattern.len(), name, pattern));
        }
    }
    matches.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    matches
        .first()
        .map(|(_, kind, pattern)| (kind.clone(), sha256(pattern.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    type RobotsTxt = robotstxt::Robots;

    #[test]
    fn simple() {
        let ua_token = "StractBot";
        let robots_txt = RobotsTxt::parse(
            ua_token,
            r#"User-agent: StractBot
            Disallow: /test"#,
        )
        .unwrap();

        assert!(!robots_txt.is_allowed(&Url::parse("http://example.com/test").unwrap()));
        assert!(robots_txt.is_allowed(&Url::parse("http://example.com/example").unwrap()));
    }

    #[test]
    fn lowercase() {
        let ua_token = "StractBot";
        let robots_txt = RobotsTxt::parse(
            ua_token,
            r#"User-agent: stractbot
            Disallow: /test"#,
        )
        .unwrap();

        assert!(!robots_txt.is_allowed(&Url::parse("http://example.com/test").unwrap()));
        assert!(robots_txt.is_allowed(&Url::parse("http://example.com/example").unwrap()));
    }

    #[test]
    fn test_extra_newline() {
        let ua_token = "StractBot";
        let robots_txt = RobotsTxt::parse(
            ua_token,
            r#"User-agent: StractBot


            Disallow: /test"#,
        )
        .unwrap();

        assert!(!robots_txt.is_allowed(&Url::parse("http://example.com/test").unwrap()));
        assert!(robots_txt.is_allowed(&Url::parse("http://example.com/example").unwrap()));
    }

    #[test]
    fn test_multiple_agents() {
        let ua_token = "StractBot";

        let robots_txt = RobotsTxt::parse(
            ua_token,
            r#"User-Agent: GoogleBot
User-Agent: StractBot
Disallow: /

User-Agent: *
Allow: /"#,
        )
        .unwrap();

        assert!(!robots_txt.is_allowed(&Url::parse("http://example.com/test").unwrap()));

        let ua_token = "StractBot";

        let robots_txt = RobotsTxt::parse(
            ua_token,
            r#"User-Agent: GoogleBot, StractBot
Disallow: /

User-Agent: *
Allow: /"#,
        )
        .unwrap();

        assert!(!robots_txt.is_allowed(&Url::parse("http://example.com/test").unwrap()));
    }

    #[test]
    fn test_sitemap() {
        let ua_token = "StractBot";
        let robots_txt = RobotsTxt::parse(
            ua_token,
            r#"User-agent: *
Disallow: /test

Sitemap: http://example.com/sitemap.xml"#,
        )
        .unwrap();

        assert_eq!(robots_txt.sitemaps(), &["http://example.com/sitemap.xml"]);

        let robots_txt = RobotsTxt::parse(
            ua_token,
            r#"User-agent: *
Disallow: /test

SiTeMaP: http://example.com/sitemap.xml"#,
        )
        .unwrap();

        assert_eq!(robots_txt.sitemaps(), &["http://example.com/sitemap.xml"]);
    }

    #[test]
    fn wildcard() {
        let ua_token = "StractBot";

        let robots_txt = RobotsTxt::parse(
            ua_token,
            r#"User-agent: StractBot
Disallow: /test/*
"#,
        )
        .unwrap();

        assert!(!robots_txt.is_allowed(&Url::parse("http://example.com/test/").unwrap()));
        assert!(!robots_txt.is_allowed(&Url::parse("http://example.com/test/foo").unwrap()));
        assert!(!robots_txt.is_allowed(&Url::parse("http://example.com/test/foo/bar").unwrap()));
        assert!(robots_txt.is_allowed(&Url::parse("http://example.com/test").unwrap()));
        assert!(robots_txt.is_allowed(&Url::parse("http://example.com/testfoo").unwrap()));

        let robots_txt = RobotsTxt::parse(
            ua_token,
            r#"User-agent: StractBot
    Disallow: /test/*/bar
    "#,
        )
        .unwrap();

        assert!(robots_txt.is_allowed(&Url::parse("http://example.com/test/").unwrap()));
        assert!(robots_txt.is_allowed(&Url::parse("http://example.com/test/foo").unwrap()));
        assert!(!robots_txt.is_allowed(&Url::parse("http://example.com/test/foo/bar").unwrap()));
        assert!(!robots_txt.is_allowed(&Url::parse("http://example.com/test/foo/baz/bar").unwrap()));
        assert!(robots_txt.is_allowed(&Url::parse("http://example.com/test").unwrap()));
        assert!(robots_txt.is_allowed(&Url::parse("http://example.com/testfoo").unwrap()));
    }
}
