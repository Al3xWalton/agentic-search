//! Performs a single credential-safe exchange with independent monotonic and phase deadlines.
//! Parsed header limits apply after Hyper's finite parser, not to socket-buffer allocation.

#![deny(missing_docs)]

use super::*;
use reqwest::{header::HeaderMap, Client, RequestBuilder};
use tracing::instrument::WithSubscriber;

/// Private phase budgets; tests inject durations into this same production timeout path.
#[derive(Clone, Copy)]
pub(super) struct Budgets {
    /// Maximum connect duration, including TLS.
    pub(super) connect: Duration,
    /// Maximum response-header wait.
    pub(super) header: Duration,
    /// Maximum interval between body chunks.
    pub(super) idle: Duration,
    /// Whole exchange duration without resetting the deadline.
    pub(super) total: Duration,
}

impl Default for Budgets {
    // One source of defaults prevents tests and connectors from acquiring different policies.
    fn default() -> Self {
        Self {
            connect: PROVIDER_CONNECT_TIMEOUT,
            header: PROVIDER_HEADER_TIMEOUT,
            idle: PROVIDER_IDLE_TIMEOUT,
            total: PROVIDER_TOTAL_TIMEOUT,
        }
    }
}

/// Private collected response; never implements Debug or forwards remote headers.
pub(super) struct Collected {
    /// Upstream status for the adapter's closed mapping.
    pub(super) status: u16,
    /// Cumulatively bounded bytes, regardless of status or Content-Length.
    pub(super) body: Vec<u8>,
}

/// Constructs an idle client with no proxy, redirect, decoding, referer or idle connection pool.
pub(super) fn client(budgets: Budgets) -> Result<Client, PaperProviderError> {
    let builder = Client::builder()
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .danger_accept_invalid_certs(false)
        // Locked default-tls keeps hostname verification enabled; its override feature is absent.
        .http1_only()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .connection_verbose(false)
        .pool_max_idle_per_host(0)
        .referer(false)
        .connect_timeout(budgets.connect)
        .timeout(budgets.total + Duration::from_secs(1));
    #[cfg(test)]
    let builder = super::tests::configure_client(builder);
    builder
        .build()
        .map_err(|_| PaperProviderError::Configuration)
}

/// Validates a complete, canonical, explicitly configured service URL without resolving it.
pub(super) fn endpoint(raw: &str) -> Result<url::Url, PaperProviderError> {
    let value = url::Url::parse(raw).map_err(|_| PaperProviderError::Configuration)?;
    let loopback = match value.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip == std::net::Ipv6Addr::LOCALHOST,
        _ => false,
    };
    if value.as_str() != raw
        || raw.contains('\\')
        || raw.chars().any(|c| c.is_whitespace() || c.is_control())
        || !(value.scheme() == "https" || (value.scheme() == "http" && loopback))
        || value.host().is_none()
        || value.port_or_known_default().is_none()
        || value.port() == Some(0)
        || value.path() != "/v1/search"
        || !value.username().is_empty()
        || value.password().is_some()
        || value.query().is_some()
        || value.fragment().is_some()
    {
        return Err(PaperProviderError::Configuration);
    }
    Ok(value)
}

/// Isolates the future that constructs, sends, drains and maps the actual provider operation.
/// Dropping this future cancels its exchange; no retry or detached provider task exists.
pub(super) async fn isolated<T>(future: impl std::future::Future<Output = T>) -> T {
    future
        .with_subscriber(tracing::subscriber::NoSubscriber::default())
        .await
}

/// Sends exactly once and enforces the same body bound for successes and failures.
pub(super) async fn exchange(
    builder: RequestBuilder,
    budgets: Budgets,
    generic: bool,
) -> Result<Collected, PaperProviderError> {
    let end = tokio::time::Instant::now() + budgets.total;
    let operation = async {
        let builder = builder
            .header("Accept", "application/json")
            .header("Accept-Encoding", "identity")
            .header("Connection", "close");
        let send = builder.send();
        let response = tokio::time::timeout(budgets.header, send)
            .await
            .map_err(|_| PaperProviderError::Deadline)?;
        #[cfg(test)]
        let response = super::tests::send_fault(response);
        let mut response = response.map_err(send_error)?;
        check_headers(response.headers())?;
        let status = response.status().as_u16();
        if status == 200 || (generic && error_name(status).is_some()) {
            check_media(response.headers())?;
        }
        let overflow = if status != 200 && !(generic && error_name(status).is_some()) {
            PaperProviderError::Unavailable
        } else {
            PaperProviderError::InvalidResponse
        };
        let body = collect(&mut response, budgets.idle, overflow).await?;
        Ok(Collected { status, body })
    };
    tokio::time::timeout_at(end, operation)
        .await
        .map_err(|_| PaperProviderError::Deadline)?
}

// Never carry reqwest's URL-bearing error across the transport boundary.
fn send_error(error: reqwest::Error) -> PaperProviderError {
    if error.is_timeout() {
        PaperProviderError::Deadline
    } else {
        PaperProviderError::Unavailable
    }
}

// Actual frames, rather than declared Content-Length, own the allocation budget.
async fn collect(
    response: &mut reqwest::Response,
    idle: Duration,
    overflow: PaperProviderError,
) -> Result<Vec<u8>, PaperProviderError> {
    let mut bytes = Vec::new();
    loop {
        let chunk = tokio::time::timeout(idle, response.chunk())
            .await
            .map_err(|_| PaperProviderError::Deadline)?
            .map_err(send_error)?;
        let Some(chunk) = chunk else {
            break;
        };
        if chunk.len() > MAX_PROVIDER_BODY_BYTES.saturating_sub(bytes.len()) {
            return Err(overflow);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

// Parsed headers may already occupy Hyper's larger finite parser buffer; this caps accepted data.
fn check_headers(headers: &HeaderMap) -> Result<(), PaperProviderError> {
    if headers.iter().count() > MAX_PROVIDER_HEADERS
        || headers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.as_bytes().len())
            .sum::<usize>()
            > MAX_PROVIDER_HEADER_BYTES
    {
        return Err(PaperProviderError::InvalidResponse);
    }
    Ok(())
}

// Repeated media fields are ambiguous even when their individual values look valid.
fn check_media(headers: &HeaderMap) -> Result<(), PaperProviderError> {
    let mut types = headers.get_all("content-type").iter();
    let media = types
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(PaperProviderError::InvalidResponse)?;
    let mut parts = media.split(';').map(str::trim);
    if !parts
        .next()
        .is_some_and(|p| p.eq_ignore_ascii_case("application/json"))
        || parts
            .next()
            .is_some_and(|p| !p.eq_ignore_ascii_case("charset=utf-8"))
        || parts.next().is_some()
        || types.next().is_some()
    {
        return Err(PaperProviderError::InvalidResponse);
    }
    let mut encodings = headers.get_all("content-encoding").iter();
    if encodings
        .next()
        .is_some_and(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"))
        || encodings.next().is_some()
    {
        return Err(PaperProviderError::InvalidResponse);
    }
    Ok(())
}

/// Decodes the actual bounded body and drops parser diagnostics at the single mapping site.
pub(super) fn parse(bytes: &[u8]) -> Result<serde_json::Value, PaperProviderError> {
    let parsed = super::decode(bytes);
    #[cfg(test)]
    let parsed = super::tests::parse_fault(parsed);
    parsed.map_err(|_| PaperProviderError::InvalidResponse)
}

/// Lists only standardized protocol literals, independently of any private implementation.
pub(super) fn error_name(status: u16) -> Option<&'static str> {
    match status {
        400 => Some("invalid-request"),
        401 => Some("unauthenticated"),
        413 => Some("body-too-large"),
        429 => Some("busy"),
        503 => Some("unavailable"),
        504 => Some("deadline"),
        500 => Some("internal"),
        404 => Some("not-found"),
        405 => Some("method-not-allowed"),
        _ => None,
    }
}
