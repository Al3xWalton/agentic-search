//! Admits exact crawl targets and pins each connection to vetted DNS answers.
//! Host identity preserves www; origin identity additionally includes scheme and port.
//! Loopback capabilities own their listeners and cannot be converted into production scope.
//! This module neither follows redirects nor stores response bodies or arbitrary headers.

#![deny(missing_docs)]

use super::{
    exclusions::{Exclusions, HostingCountry, HostingCountryProvider},
    identity::{HttpClient, HttpResponse},
    ledger::{AttemptTrace, FetchKind, WireError, WireGuard},
    politeness::{Clock, HostPermit},
    record::Observation,
    Error, Result, MAX_URL_LEN_BYTES,
};
use crate::config::ingestion::ProductionPermit;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    net::{IpAddr, SocketAddr, TcpListener},
    pin::Pin,
    sync::{Arc, RwLock},
};
use url::Url;

/// Canonical lowercase ASCII host, preserving www and spanning schemes and ports.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HostKey(String);
impl HostKey {
    /// Extracts a host without normalizing away www; hostless URLs are refused.
    pub fn from_url(url: &Url) -> Result<Self> {
        let host = url.host_str().ok_or(Error::InvalidUrl)?;
        Ok(Self(
            host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase(),
        ))
    }
    /// Returns the non-secret ASCII host for policy lookup and host-only diagnostics.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact origin key for robots and validators; ports are effective, not textual.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OriginKey(String);
impl OriginKey {
    /// Includes scheme, canonical host and effective HTTP(S) port.
    pub fn from_url(url: &Url) -> Result<Self> {
        Ok(Self(format!(
            "{}://{}:{}",
            url.scheme(),
            HostKey::from_url(url)?.as_str(),
            url.port_or_known_default().ok_or(Error::SchemeRefused)?
        )))
    }
    /// Returns the canonical origin without a path, query or credentials.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Record-only exact URL with userinfo and fragment removed; queries are retained.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SafeUrl(String);
impl std::fmt::Debug for SafeUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SafeUrl([operational record])")
    }
}
impl SafeUrl {
    /// Returns the operational URL for private records and audit joins; never use in tracing.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Removes userinfo and fragment for record serialization while preserving the exact query.
/// Fetch admission separately rejects credential-bearing input before this transformation.
pub fn safe_url_for_record(url: &Url) -> SafeUrl {
    let mut safe_url = url.clone();
    let _ = safe_url.set_username("");
    let _ = safe_url.set_password(None);
    safe_url.set_fragment(None);
    SafeUrl(safe_url.into())
}

/// SHA-256 join key of exact record-normalized URL bytes; no private HMAC key is needed.
pub fn url_key(url: &Url) -> String {
    sha256(safe_url_for_record(url).as_str().as_bytes())
}
/// Computes the lower-case SHA-256 of received entity bytes, before text decoding.
pub fn sha256(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn reject_userinfo_before_normalize(raw: &str, url: &Url) -> Result<()> {
    if !url.username().is_empty()
        || url.password().is_some()
        || raw.split('/').nth(2).is_some_and(|s| s.contains('@'))
    {
        return Err(Error::InvalidUrl);
    }
    Ok(())
}

/// Parses input without erasing credential evidence, rejecting controls and malformed escapes.
/// Length is bounded to 8,192 bytes before parsing. Fragment removal never strips the query.
pub fn parse_fetch_url(raw: &str) -> Result<Url> {
    if raw.len() > MAX_URL_LEN_BYTES {
        return Err(Error::UrlTooLong);
    }
    if raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(Error::InvalidUrl);
    }
    let mut url = Url::parse(raw).map_err(|_| Error::InvalidUrl)?;
    reject_userinfo_before_normalize(raw, &url)?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Error::SchemeRefused);
    }
    HostKey::from_url(&url)?;
    if url
        .host_str()
        .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
        .is_some_and(|address| !is_public_address(&address))
    {
        return Err(Error::RefusedPrivateAddress);
    }
    for (i, byte) in raw.as_bytes().iter().enumerate() {
        if *byte == b'%'
            && !(raw.as_bytes().get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                && raw.as_bytes().get(i + 2).is_some_and(u8::is_ascii_hexdigit))
        {
            return Err(Error::InvalidUrl);
        }
    }
    url.set_fragment(None);
    Ok(url)
}

/// Applies the conservative global-unicast policy, including mapped/tunnel and special-use ranges.
/// This is a crawl-admission policy; it is not a general Internet routability classifier.
pub fn is_public_address(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192
                    && (b == 168 || (b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            (s[0] & 0xe000) == 0x2000
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

/// Bounded asynchronous DNS lookup result used at the connection-admission seam.
pub type LookupFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<IpAddr>>> + Send + 'a>>;
/// Resolves candidate addresses before connection; implementations cannot themselves authorize them.
pub trait AddressResolver: Send + Sync {
    /// Returns all observed A/AAAA answers or a typed connect error, without logging the name.
    fn lookup<'a>(&'a self, host: &'a str) -> LookupFuture<'a>;
}
struct SystemResolver;
impl AddressResolver for SystemResolver {
    fn lookup<'a>(&'a self, host: &'a str) -> LookupFuture<'a> {
        Box::pin(async move {
            tokio::net::lookup_host((host, 0))
                .await
                .map(|addresses| addresses.map(|a| a.ip()).collect())
                .map_err(|_| Error::ConnectError)
        })
    }
}

/// Resolves and validates every returned address; mixed public/private sets fail closed.
/// No connection is opened here; callers must pin only the returned socket addresses.
pub async fn resolve_public(
    host: &str,
    port: u16,
    resolver: &dyn AddressResolver,
) -> Result<Vec<SocketAddr>> {
    let addresses = match host.trim_matches(['[', ']']).parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => resolver.lookup(host).await?,
    };
    if addresses.is_empty() {
        return Err(Error::ConnectError);
    }
    if !addresses.iter().all(is_public_address) {
        return Err(Error::RefusedPrivateAddress);
    }
    Ok(addresses
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
}

/// Resolver backing the shared HTTP client; an unadmitted host has no DNS fallback.
pub struct VettedResolver {
    addresses: RwLock<BTreeMap<String, Vec<SocketAddr>>>,
    candidate: Arc<dyn AddressResolver>,
}
impl VettedResolver {
    pub(super) fn new(candidate: Arc<dyn AddressResolver>) -> Self {
        Self {
            addresses: RwLock::new(BTreeMap::new()),
            candidate,
        }
    }
    pub(super) fn pin_vetted_addresses(
        &self,
        host: &str,
        addresses: Vec<SocketAddr>,
    ) -> Result<()> {
        self.addresses
            .write()
            .map_err(|_| Error::InternalInvariant)?
            .insert(host.into(), addresses);
        Ok(())
    }
    pub(super) fn admitted(&self, host: &str) -> Result<Vec<SocketAddr>> {
        self.addresses
            .read()
            .map_err(|_| Error::InternalInvariant)?
            .get(host.strip_suffix('.').unwrap_or(host))
            .cloned()
            .ok_or(Error::RefusedPrivateAddress)
    }
}
impl AddressResolver for VettedResolver {
    fn lookup<'a>(&'a self, host: &'a str) -> LookupFuture<'a> {
        self.candidate.lookup(host)
    }
}

struct FixtureResolver;
impl AddressResolver for FixtureResolver {
    fn lookup<'a>(&'a self, _host: &'a str) -> LookupFuture<'a> {
        Box::pin(async { Ok(vec![IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 215, 14))]) })
    }
}

/// Owned listener capability for HTTP fixtures; the only private-address admission path.
/// The retained descriptor keeps the endpoint owned until every fixture client is dropped.
#[derive(Clone)]
pub struct LoopbackEndpoint {
    listener: Arc<TcpListener>,
    address: SocketAddr,
    resolver: Arc<dyn AddressResolver>,
    country_provider: Option<Arc<dyn HostingCountryProvider>>,
    aliases: BTreeSet<String>,
}
impl LoopbackEndpoint {
    /// Adds explicit DNS-shaped fixture aliases; they still connect only to this owned descriptor.
    pub fn with_aliases(mut self, hosts: &[&str]) -> Result<Self> {
        for host in hosts {
            let url = parse_fetch_url(&format!("http://{host}/"))?;
            let key = HostKey::from_url(&url)?;
            if key.as_str().parse::<IpAddr>().is_ok() {
                return Err(Error::RefusedPrivateAddress);
            }
            self.aliases.insert(key.as_str().into());
        }
        Ok(self)
    }
    fn admits_host(&self, host: &HostKey) -> bool {
        host.as_str().ends_with(".fixture.invalid") || self.aliases.contains(host.as_str())
    }
    /// Supplies deterministic offline country answers only for this already owned fixture endpoint.
    pub fn with_country_provider(mut self, provider: Arc<dyn HostingCountryProvider>) -> Self {
        self.country_provider = Some(provider);
        self
    }
    /// Accepts only an already-bound loopback listener owned by the caller.
    pub fn new(listener: TcpListener) -> Result<Self> {
        let address = listener.local_addr().map_err(|_| Error::ConnectError)?;
        if !address.ip().is_loopback() {
            return Err(Error::RefusedPrivateAddress);
        }
        Ok(Self {
            listener: Arc::new(listener),
            address,
            resolver: Arc::new(FixtureResolver),
            country_provider: None,
            aliases: BTreeSet::new(),
        })
    }
    /// Clones the owned descriptor for the fixture server; never binds a new endpoint.
    pub fn listener(&self) -> Result<TcpListener> {
        self.listener.try_clone().map_err(|_| Error::ConnectError)
    }
    /// Returns the owned socket's actual address for request/peer assertions.
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    /// Supplies fake candidate DNS answers while preserving this capability's only possible peer.
    /// Every candidate is checked by the public-address guard before the owned socket is pinned.
    pub fn with_resolver(mut self, resolver: Arc<dyn AddressResolver>) -> Self {
        self.resolver = resolver;
        self
    }
    /// Builds a virtual host URL whose non-default port is admitted only by this capability.
    pub fn url(&self, host: &str, path: &str) -> Result<Url> {
        parse_fetch_url(&format!("http://{host}:{}{path}", self.address.port()))
    }
}

#[derive(Clone)]
enum ScopeKind {
    Production,
    Sample(BTreeSet<String>),
    Loopback(LoopbackEndpoint),
}
/// Sealed request scope; fixtures and sample scope cannot issue production permits.
#[derive(Clone)]
pub struct CrawlScope {
    kind: ScopeKind,
}
impl CrawlScope {
    /// Reports whether this is an owned-loopback capability; it never grants production authority.
    pub fn is_loopback(&self) -> bool {
        matches!(self.kind, ScopeKind::Loopback(_))
    }
    pub(super) fn country_provider(&self) -> Option<Arc<dyn HostingCountryProvider>> {
        match &self.kind {
            ScopeKind::Loopback(endpoint) => endpoint.country_provider.clone(),
            _ => None,
        }
    }
    pub(super) fn candidate_resolver(&self) -> Arc<dyn AddressResolver> {
        match &self.kind {
            ScopeKind::Loopback(endpoint) => endpoint.resolver.clone(),
            _ => Arc::new(SystemResolver),
        }
    }
    pub(super) fn production(_permit: ProductionPermit) -> Self {
        Self {
            kind: ScopeKind::Production,
        }
    }
    pub(crate) fn sample(urls: &[Url]) -> Self {
        Self {
            kind: ScopeKind::Sample(urls.iter().map(|u| safe_url_for_record(u).0).collect()),
        }
    }
    pub(super) fn loopback(endpoint: LoopbackEndpoint) -> Self {
        Self {
            kind: ScopeKind::Loopback(endpoint),
        }
    }
    /// Tests exact target membership; same-domain URLs receive no implicit sample permission.
    pub fn contains_exact(&self, url: &Url) -> bool {
        match &self.kind {
            ScopeKind::Production => true,
            ScopeKind::Sample(urls) => urls.contains(safe_url_for_record(url).as_str()),
            ScopeKind::Loopback(endpoint) => {
                url.port_or_known_default() == Some(endpoint.address.port())
                    && HostKey::from_url(url).is_ok_and(|h| endpoint.admits_host(&h))
            }
        }
    }
    /// Validates scheme, port and exact scope before DNS; robots is limited to admitted origins.
    pub fn validate(&self, url: &Url, robots: bool) -> Result<()> {
        if !matches!(url.scheme(), "http" | "https") {
            return Err(Error::SchemeRefused);
        }
        let fixture_port = match &self.kind {
            ScopeKind::Loopback(e) => Some(e.address.port()),
            _ => None,
        };
        let expected = if url.scheme() == "https" { 443 } else { 80 };
        if url.port_or_known_default() != Some(fixture_port.unwrap_or(expected)) {
            return Err(Error::PortRefused);
        }
        if self.contains_exact(url) {
            return Ok(());
        }
        if robots && url.path() == "/robots.txt" && url.query().is_none() {
            if let ScopeKind::Sample(urls) = &self.kind {
                let origin = OriginKey::from_url(url)?;
                if urls.iter().any(|value| {
                    Url::parse(value)
                        .ok()
                        .and_then(|u| OriginKey::from_url(&u).ok())
                        .is_some_and(|key| key == origin)
                }) {
                    return Ok(());
                }
            }
        }
        Err(Error::OffScope)
    }
    /// Applies exact sample scope to a robots redirect; no alternate-robots-path exception exists.
    pub fn validate_robots_redirect(&self, url: &Url) -> Result<()> {
        self.validate(url, false)
    }
    pub(super) async fn resolve(
        &self,
        url: &Url,
        resolver: &dyn AddressResolver,
    ) -> Result<Vec<SocketAddr>> {
        let host = HostKey::from_url(url)?;
        match &self.kind {
            ScopeKind::Loopback(endpoint) => {
                // IP literals are never fixture aliases; only the owned descriptor supplies the peer.
                if !endpoint.admits_host(&host) {
                    return Err(Error::RefusedPrivateAddress);
                }
                resolve_public(host.as_str(), endpoint.address.port(), resolver).await?;
                Ok(vec![endpoint.address])
            }
            _ => {
                resolve_public(
                    host.as_str(),
                    url.port_or_known_default().ok_or(Error::PortRefused)?,
                    resolver,
                )
                .await
            }
        }
    }
}

/// Shared process transport; every connection is re-vetted and idle pooling is disabled.
pub(super) struct Transport {
    pub(super) client: HttpClient,
    pub(super) resolver: Arc<VettedResolver>,
    pub(super) scope: CrawlScope,
    pub(super) exclusions: Arc<Exclusions>,
    pub(super) clock: Arc<dyn Clock>,
}
pub(super) struct PreparedTarget {
    url: Url,
    addresses: Vec<SocketAddr>,
    country: HostingCountry,
}
impl Transport {
    pub(super) async fn prepare(
        &self,
        url: &Url,
        trace: Option<&AttemptTrace>,
    ) -> Result<PreparedTarget> {
        self.exclusions.frontier(url, None)?;
        let addresses = self.scope.resolve(url, self.resolver.as_ref()).await?;
        let country = self.exclusions.country(&addresses);
        if let Some(trace) = trace {
            trace.country(country.clone())?;
        }
        self.exclusions.admit_country(&country)?;
        Ok(PreparedTarget {
            url: url.clone(),
            addresses,
            country,
        })
    }
    pub(super) async fn send(
        &self,
        target: PreparedTarget,
        validators: &[(String, String)],
        mut permit: HostPermit,
        limit: usize,
        kind: FetchKind,
        trace: Option<&AttemptTrace>,
    ) -> Result<BoundedResponse> {
        let url = target.url;
        // The shared host start mutex remains held until headers: another same-host request cannot
        // replace this request's DNS pin between admission and connection resolution.
        self.resolver
            .pin_vetted_addresses(HostKey::from_url(&url)?.as_str(), target.addresses)?;
        let mut wire = trace
            .map(|trace| {
                trace.start(
                    &url,
                    kind,
                    self.clock.clone(),
                    permit.started_at_utc,
                    permit.queue_time_ms,
                )
            })
            .transpose()?;
        let response = match self.client.send(url.clone(), validators).await {
            Ok(response) => response,
            Err(error) => {
                if let Some(wire) = &mut wire {
                    wire.finish(Some(wire_error(&error)))?;
                }
                return Err(error);
            }
        };
        if let Some(wire) = &wire {
            wire.update(|attempt| attempt.status = Observation::Present(response.status()))?;
        }
        if let Err(error) = permit.observe(
            response.status(),
            response.headers(),
            super::host_state::detect_challenge(response.headers(), &[]),
        ) {
            if let Some(wire) = &mut wire {
                wire.finish(Some(wire_error(&error)))?;
            }
            return Err(error);
        }
        permit.headers_received();
        Ok(BoundedResponse {
            response,
            host_permit: permit,
            limit,
            url,
            robots: None,
            wire,
            hosting_country: target.country,
        })
    }
}

/// Response wrapper retaining the host permit until complete body consumption or cancellation.
/// Raw HTTP types never leave identity.rs, and every caller receives the same byte bound.
pub struct BoundedResponse {
    response: HttpResponse,
    host_permit: HostPermit,
    limit: usize,
    url: Url,
    /// Immutable robots decision actually used after the host queue; None only for bootstrap.
    pub robots: Option<super::robots_txt::RobotsSnapshot>,
    /// Country observation from the actual vetted connection addresses, never inferred from a suffix.
    pub hosting_country: HostingCountry,
    wire: Option<WireGuard>,
}
impl BoundedResponse {
    /// Attaches the immutable content decision to both response and nested attempt evidence.
    pub(super) fn attach_robots(
        &mut self,
        snapshot: super::robots_txt::RobotsSnapshot,
    ) -> Result<()> {
        if let Some(wire) = &self.wire {
            wire.update(|attempt| attempt.robots = Observation::Present(snapshot.clone()))?;
        }
        self.robots = Some(snapshot);
        Ok(())
    }
    /// Returns the actual response status, before MIME or directive processing.
    pub fn status(&self) -> u16 {
        self.response.status()
    }
    /// Returns the last actually fetched URL, never an unfetched Location.
    pub fn url(&self) -> &Url {
        &self.url
    }
    /// Returns bounded policy/protocol header values; cookies and authorization are never exposed.
    pub fn headers(&self) -> &ResponseHeaders {
        self.response.headers()
    }
    /// Reads bounded entity bytes, checking each chunk before extending the accumulated buffer.
    pub async fn bytes(mut self) -> Result<Vec<u8>> {
        let mut result = self.read_bytes().await;
        if let Some(wire) = &mut self.wire {
            match self.host_permit.state() {
                Ok(state) => wire.update(|attempt| {
                    attempt.retry_at_utc = state.retry_at_utc;
                    attempt.blocked_until_utc = state.blocked_until_utc;
                })?,
                Err(error) => result = Err(error),
            }
            wire.finish(result.as_ref().err().map(wire_error))?;
        }
        result
    }
    async fn read_bytes(&mut self) -> Result<Vec<u8>> {
        if self
            .headers()
            .get("content-length")
            .and_then(|s| s.parse::<u64>().ok())
            .is_some_and(|n| n > self.limit as u64)
        {
            return Err(Error::ContentTooLarge);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = self.response.chunk().await? {
            if let Some(wire) = &self.wire {
                wire.update(|attempt| {
                    attempt.body_bytes = attempt.body_bytes.saturating_add(chunk.len() as u64)
                })?;
            }
            if chunk.len() > self.limit.saturating_sub(bytes.len()) {
                return Err(Error::ContentTooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        if let Some(challenge) = super::host_state::detect_challenge(self.headers(), &bytes) {
            self.host_permit
                .observe_body_challenge(self.headers(), challenge)?;
        }
        Ok(bytes)
    }
    /// Decodes a bounded body once, preserving the upstream UTF-8 fallback for unknown encodings.
    pub async fn text(self) -> Result<String> {
        let headers = self.headers().clone();
        let encoding = self
            .headers()
            .get("content-type")
            .and_then(|s| s.parse::<mime::Mime>().ok())
            .and_then(|m| m.get_param("charset").map(|c| c.as_str().to_owned()));
        let encoding = encoding
            .as_deref()
            .and_then(|e| encoding_rs::Encoding::for_label(e.as_bytes()))
            .unwrap_or(encoding_rs::UTF_8);
        let bytes = self.bytes().await?;
        if super::host_state::detect_challenge(&headers, &bytes).is_some() {
            return Err(Error::Challenge);
        }
        Ok(encoding.decode(&bytes).0.into_owned())
    }
}

fn wire_error(error: &Error) -> WireError {
    match error {
        Error::Timeout => WireError::Timeout,
        Error::ConnectError => WireError::Connect,
        Error::TlsError => WireError::Tls,
        Error::ResponseBodyReadFailed => WireError::BodyRead,
        Error::ContentTooLarge => WireError::TooLarge,
        Error::Cancelled => WireError::Cancelled,
        Error::HostStateWrite => WireError::HostState,
        _ => WireError::Internal,
    }
}

/// In-memory allowlist of response policy headers, never a raw header map or persistent record.
/// Each name retains visible ASCII values and an invalid flag if any occurrence fails decoding.
/// Invalid bytes are discarded, never substituted with text. Consumers fail closed: robots tags
/// prohibit indexing/following, cache control prohibits storage, TDM signals reserve rights,
/// MIME/redirects are rejected, validators/language are absent, rate deadlines stay conservative,
/// and cf-mitigated implies a challenge. Invalid Content-Length is absent; streamed bounds remain.
#[derive(Clone, Default)]
pub struct ResponseHeaders(BTreeMap<String, HeaderValues>);
#[derive(Clone, Default)]
struct HeaderValues {
    values: Vec<String>,
    invalid: bool,
}
impl std::fmt::Debug for ResponseHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseHeaders")
            .field("field_count", &self.0.len())
            .finish()
    }
}
impl ResponseHeaders {
    pub(super) fn observe(&mut self, name: &str, value: Option<&str>) {
        let entry = self.0.entry(name.to_ascii_lowercase()).or_default();
        if let Some(value) = value.filter(|value| value.bytes().all(|b| (b' '..=b'~').contains(&b)))
        {
            entry.values.push(value.to_owned());
        } else {
            entry.invalid = true;
        }
    }
    /// Reports whether any occurrence of this case-insensitive name contained invalid bytes.
    pub fn invalid(&self, name: &str) -> bool {
        self.0
            .get(&name.to_ascii_lowercase())
            .is_some_and(|entry| entry.invalid)
    }
    /// Returns the first value only if every occurrence is valid; invalid names are absent.
    /// Use all() with invalid() for merge-sensitive fields and restrictive decisions.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .get(&name.to_ascii_lowercase())
            .filter(|entry| !entry.invalid)
            .and_then(|entry| entry.values.first())
            .map(String::as_str)
    }
    /// Returns valid physical occurrences only; invalid() must also be checked by policy consumers.
    pub fn all(&self, name: &str) -> &[String] {
        self.0
            .get(&name.to_ascii_lowercase())
            .map(|entry| entry.values.as_slice())
            .unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn response_headers_invalid() {
        let mut headers = ResponseHeaders::default();
        headers.observe("Content-Length", Some("999999999"));
        headers.observe("content-length", None);
        assert!(headers.invalid("CONTENT-LENGTH"));
        assert_eq!(headers.all("content-length"), &["999999999"]);
        assert!(headers.get("content-length").is_none());
        headers.observe("etag", Some("valid"));
        headers.observe("etag", Some("invalid\tvalue"));
        assert!(headers.invalid("etag"));
        assert!(headers.get("etag").is_none());
        assert_eq!(headers.all("etag"), &["valid"]);
        assert!(!headers.invalid("absent"));
    }
    #[test]
    fn url_reference_redaction() {
        let url = Url::parse(
            "https://user:secret@example.org/path?query=keep&utm_source=also-keep#fragment",
        )
        .unwrap();
        assert_eq!(
            safe_url_for_record(&url).as_str(),
            "https://example.org/path?query=keep&utm_source=also-keep"
        );
        assert!(parse_fetch_url(url.as_str()).is_err());
        assert!(parse_fetch_url("https://@example.org/").is_err());
    }
    #[test]
    fn public_address_matrix() {
        for address in [
            "0.0.0.0",
            "10.1.2.3",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.1.1",
            "172.31.255.255",
            "192.168.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fc00::1",
            "fe80::1",
            "ff00::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "2002:0808:0808::1",
        ] {
            assert!(
                !is_public_address(&address.parse().unwrap()),
                "accepted special-use address"
            );
        }
        for address in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.215.14",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
        ] {
            assert!(is_public_address(&address.parse().unwrap()));
        }
    }
    #[test]
    fn scope_capabilities() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let endpoint = LoopbackEndpoint::new(listener).unwrap();
        let scope = CrawlScope::loopback(endpoint.clone());
        assert!(scope
            .validate(&endpoint.url("a.fixture.invalid", "/page").unwrap(), false)
            .is_ok());
        assert!(scope
            .validate(&Url::parse("https://example.org/").unwrap(), false)
            .is_err());
        let sample = CrawlScope::sample(&[Url::parse("https://example.org/a?x=1").unwrap()]);
        assert!(!sample.contains_exact(&Url::parse("https://example.org/a?x=2").unwrap()));
    }
}
