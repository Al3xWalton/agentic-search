//! Supplies opt-in, metadata-only paper pages through an operator-selected provider.
//! Providers preserve order, use closed failures and cooperate with future cancellation.
//! The route owns four nonqueued permits and a 15-second deadline through final serialization.
//! See `docs/paper-providers.md` for the HTTP protocol, field limits and embedding log policy.

#![deny(missing_docs)]

mod http;
mod openalex;
#[cfg(test)]
pub(super) mod tests;
mod transport;

use super::{dto::AttributedResult, error::V1Error};
use futures::future::BoxFuture;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::{fmt, sync::Arc, time::Duration};

/// Inclusive plain-text query size in UTF-8 bytes, shared with web input validation.
pub(super) const MAX_PAPER_QUERY_BYTES: usize = crate::query::planner::bounds::MAX_QUERY_BYTES;
/// Inclusive number of maximal Unicode alphanumeric runs; at least one is required.
pub(super) const MAX_PAPER_QUERY_TERMS: usize = 64;
/// Inclusive requested and returned record count per paper page.
pub(super) const MAX_PAPER_RESULTS: usize = 20;
/// Inclusive complete serialized HTTP request size, in bytes.
const MAX_PROVIDER_REQUEST_BYTES: usize = 32_768;
/// Inclusive cumulative response body size, in bytes, for every HTTP status.
const MAX_PROVIDER_BODY_BYTES: usize = 4_194_304;
/// Inclusive serialized attributed-hit size, in bytes.
pub(super) const MAX_PAPER_HIT_BYTES: usize = 131_072;
/// Inclusive complete serialized v1 paper response size, in bytes.
pub(super) const MAX_PAPER_RESPONSE_BYTES: usize = 4_194_304;
/// Inclusive parsed header-value count, including duplicates.
const MAX_PROVIDER_HEADERS: usize = 32;
/// Inclusive sum of parsed header name/value lengths, in bytes.
const MAX_PROVIDER_HEADER_BYTES: usize = 16_384;
/// Inclusive nesting depth, counting containers only.
const MAX_PROVIDER_JSON_DEPTH: usize = 32;
/// Inclusive JSON token count; keys, scalars and both container delimiters count.
const MAX_PROVIDER_JSON_TOKENS: usize = 262_144;
/// Inclusive ordered author count per attributed paper.
pub(super) const MAX_PAPER_AUTHORS: usize = 100;
/// Inclusive paper title length, in Unicode scalars.
pub(super) const MAX_PAPER_TITLE_SCALARS: usize = 500;
/// Inclusive paper title length, in UTF-8 bytes.
pub(super) const MAX_PAPER_TITLE_BYTES: usize = 2_000;
/// Inclusive author or venue length, in Unicode scalars.
pub(super) const MAX_PAPER_NAME_SCALARS: usize = 256;
/// Inclusive author or venue length, in UTF-8 bytes.
pub(super) const MAX_PAPER_NAME_BYTES: usize = 1_024;
/// Inclusive DOI or OA URL length, in UTF-8 bytes.
pub(super) const MAX_PAPER_URL_BYTES: usize = 2_048;
/// Inclusive canonical OpenAlex work URL length, in ASCII bytes.
pub(super) const MAX_OPENALEX_ID_BYTES: usize = 64;
/// Inclusive publication year; minimum is one.
pub(super) const MAX_PAPER_YEAR: u16 = 9_999;
/// Exact non-null calendar-date length, in ASCII bytes.
pub(super) const SNAPSHOT_DATE_BYTES: usize = 10;
/// Maximum DNS/TCP/TLS connection establishment duration.
const PROVIDER_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Maximum wait between response body chunks, after headers arrive.
const PROVIDER_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum wait for response headers, permitting a service's ten-second deadline response.
const PROVIDER_HEADER_TIMEOUT: Duration = Duration::from_secs(12);
/// Maximum complete operation duration, without resetting between phases.
pub(super) const PROVIDER_TOTAL_TIMEOUT: Duration = Duration::from_secs(15);
/// Maximum nonqueued operations shared by every state from one resource bundle.
pub(super) const MAX_PROVIDER_IN_FLIGHT: usize = 4;

/// Closed failures without payload, source chains or deserialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaperProviderError {
    /// Display: `Paper provider configuration is invalid`.
    Configuration,
    /// Display: `Paper request is invalid`.
    InvalidRequest,
    /// Display: `Paper provider is unavailable`.
    Unavailable,
    /// Display: `Paper response is invalid`.
    InvalidResponse,
    /// Display: `Paper provider deadline expired`.
    Deadline,
}

impl fmt::Display for PaperProviderError {
    // Fixed strings are the entire diagnostic surface, even for transport and parser errors.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Configuration => "Paper provider configuration is invalid",
            Self::InvalidRequest => "Paper request is invalid",
            Self::Unavailable => "Paper provider is unavailable",
            Self::InvalidResponse => "Paper response is invalid",
            Self::Deadline => "Paper provider deadline expired",
        })
    }
}
impl std::error::Error for PaperProviderError {}

/// Validated immutable original text, zero-based page and result count; Debug is opaque.
#[derive(Clone)]
pub struct PaperQuery {
    query: String,
    page: u16,
    num_results: u8,
}

impl fmt::Debug for PaperQuery {
    // Queries may contain private user information.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PaperQuery { .. }")
    }
}

impl PaperQuery {
    /// Validates <=4096 bytes, 1..=64 alphanumeric runs, page 0..=99 and count 1..=20.
    /// Non-whitespace controls fail with InvalidRequest; text is never normalized or logged.
    pub fn try_new(query: String, page: u16, num_results: u8) -> Result<Self, PaperProviderError> {
        let terms = query
            .split(|c: char| !c.is_alphanumeric())
            .filter(|s| !s.is_empty())
            .count();
        if query.len() > MAX_PAPER_QUERY_BYTES
            || terms == 0
            || terms > MAX_PAPER_QUERY_TERMS
            || query.chars().any(|c| c.is_control() && !c.is_whitespace())
            || u64::from(page) > super::search::MAX_PAGE
            || num_results == 0
            || usize::from(num_results) > MAX_PAPER_RESULTS
        {
            return Err(PaperProviderError::InvalidRequest);
        }
        Ok(Self {
            query,
            page,
            num_results,
        })
    }
    /// Returns the unchanged original plain-text query.
    pub fn query(&self) -> &str {
        &self.query
    }
    /// Returns the validated zero-based page in 0..=99.
    pub fn page(&self) -> u16 {
        self.page
    }
    /// Returns the validated requested count in 1..=20.
    pub fn num_results(&self) -> u8 {
        self.num_results
    }
}

/// Immutable metadata-only page with at most twenty hits and an explicit nullable page hint.
pub struct PaperPage {
    results: Vec<AttributedResult>,
    next_page: Option<u16>,
}

impl fmt::Debug for PaperPage {
    // Provider bodies and attribution never become diagnostic text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PaperPage { .. }")
    }
}

impl PaperPage {
    /// Validates metadata attribution, empty snippets, <=20 hits and a nullable hint <=99.
    /// Each serialized hit is at most 131072 bytes; violations return InvalidResponse.
    pub fn try_new(
        results: Vec<AttributedResult>,
        next_page: Option<u16>,
    ) -> Result<Self, PaperProviderError> {
        if results.len() > MAX_PAPER_RESULTS
            || next_page.is_some_and(|page| u64::from(page) > super::search::MAX_PAGE)
        {
            return Err(PaperProviderError::InvalidResponse);
        }
        for result in &results {
            if result.scholarly().is_none() || !result.snippet().is_empty() {
                return Err(PaperProviderError::InvalidResponse);
            }
            validate_hit_size(result, MAX_PAPER_HIT_BYTES)?;
        }
        Ok(Self { results, next_page })
    }
    /// Rechecks the caller's count and exact next-page relation at every serving boundary.
    pub(crate) fn validate_for(&self, query: &PaperQuery) -> Result<(), PaperProviderError> {
        if self.results.len() > usize::from(query.num_results)
            || self.results.iter().any(|hit| hit.scholarly().is_none())
            || self
                .next_page
                .is_some_and(|page| u64::from(page) > super::search::MAX_PAGE)
            || self
                .next_page
                .is_some_and(|next| query.page.checked_add(1) != Some(next))
        {
            return Err(PaperProviderError::InvalidResponse);
        }
        Ok(())
    }
    /// Transfers bounded results without cloning provider content.
    pub(crate) fn into_parts(self) -> (Vec<AttributedResult>, Option<u16>) {
        (self.results, self.next_page)
    }
}

// A private budget parameter makes the real writer boundary testable below stronger field bounds.
fn validate_hit_size(result: &AttributedResult, cap: usize) -> Result<(), PaperProviderError> {
    super::error::capped_bytes(result, cap).map_err(|_| PaperProviderError::InvalidResponse)?;
    Ok(())
}

/// Trusted Rust extension returning one ordered, bounded page without web fallback.
/// Implementations must cooperate with cancellation and avoid logging input or credentials.
pub trait PaperProvider: Send + Sync {
    /// Searches once; return a closed error, preserve order and release work when dropped.
    fn search(&self, request: PaperQuery) -> BoxFuture<'_, Result<PaperPage, PaperProviderError>>;
}

/// One startup owner shared across states, never reconstructed by listener attachment.
pub(super) struct Resources {
    /// Operator-selected provider; None never reads secrets or constructs a client.
    pub(super) provider: Option<Arc<dyn PaperProvider>>,
    /// Shared nonqueued operations, retained through local response serialization.
    pub(super) admission: Arc<tokio::sync::Semaphore>,
}

impl Resources {
    /// Uses exactly one config builder for every production resource constructor.
    pub(super) fn load(config: &crate::config::ApiConfig) -> Result<Arc<Self>, PaperProviderError> {
        let provider = config
            .v1
            .paper_provider
            .as_ref()
            .map(|p| p.build())
            .transpose()?;
        Ok(Self::with_provider(provider))
    }
    /// Creates the same finite admission owner for configured and trusted embedded providers.
    pub(super) fn with_provider(provider: Option<Arc<dyn PaperProvider>>) -> Arc<Self> {
        Arc::new(Self {
            provider,
            admission: Arc::new(tokio::sync::Semaphore::new(MAX_PROVIDER_IN_FLIGHT)),
        })
    }
}

/// Rejects all transport dependency targets regardless of user-selected log levels.
/// Embedders must apply this to every sink, including log-to-tracing bridges, before construction.
pub fn transport_log_allowed(metadata: &tracing::Metadata<'_>) -> bool {
    let target = metadata.target();
    !["reqwest", "hyper", "h2", "native_tls", "tokio_native_tls"]
        .iter()
        .any(|root| {
            target == *root
                || target
                    .strip_prefix(root)
                    .is_some_and(|s| s.starts_with("::"))
        })
}

/// Constructs the fixed-origin adapter without doing network I/O.
pub(crate) fn build_openalex(
    secret: crate::config::papers::Secret,
) -> Result<Arc<dyn PaperProvider>, PaperProviderError> {
    Ok(Arc::new(openalex::OpenAlex::new(secret)?))
}

/// Constructs the explicit compatible-service adapter without doing network I/O.
pub(crate) fn build_http(
    endpoint: &str,
    secret: crate::config::papers::Secret,
) -> Result<Arc<dyn PaperProvider>, PaperProviderError> {
    Ok(Arc::new(http::HttpProvider::new(endpoint, secret)?))
}

/// Validates canonical paper links before any shared web canonicalizer can strip a fragment.
pub(super) fn validate_link(value: &str) -> Result<(), V1Error> {
    if value.len() > MAX_PAPER_URL_BYTES {
        return Err(V1Error::invalid_result());
    }
    let parsed = url::Url::parse(value).map_err(|_| V1Error::invalid_result())?;
    if value.chars().any(|c| c.is_control() || c.is_whitespace())
        || value.contains('\\')
        || !matches!(parsed.scheme(), "http" | "https")
        || !matches!(parsed.host(), Some(url::Host::Domain(_)))
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || parsed.as_str() != value
    {
        return Err(V1Error::invalid_result());
    }
    Ok(())
}

/// Validates the canonical HTTPS DOI resolver and a four-to-nine-digit registrant.
pub(super) fn validate_doi(value: &str) -> Result<(), V1Error> {
    validate_link(value)?;
    let path = value
        .strip_prefix("https://doi.org/10.")
        .ok_or_else(V1Error::invalid_result)?;
    let (registrant, suffix) = path.split_once('/').ok_or_else(V1Error::invalid_result)?;
    if !(4..=9).contains(&registrant.len())
        || !registrant.bytes().all(|b| b.is_ascii_digit())
        || suffix.is_empty()
        || value.contains('?')
    {
        return Err(V1Error::invalid_result());
    }
    Ok(())
}

/// Validates the canonical bounded OpenAlex work identity, without network resolution.
pub(super) fn validate_id(value: &str) -> Result<(), V1Error> {
    let digits = value
        .strip_prefix("https://openalex.org/W")
        .ok_or_else(V1Error::invalid_result)?;
    if value.len() > MAX_OPENALEX_ID_BYTES
        || digits.is_empty()
        || !digits.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(V1Error::invalid_result());
    }
    Ok(())
}

// Bound ignored fields too: serde's generic Value decoder alone permits unbounded nested arrays.
fn decode(bytes: &[u8]) -> Result<serde_json::Value, serde_json::Error> {
    let mut tokens = 0;
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = JsonSeed {
        tokens: &mut tokens,
        depth: 0,
        key: "",
        role: JsonRole::Root,
        retain: true,
    }
    .deserialize(&mut decoder)?;
    decoder.end()?;
    Ok(value)
}

struct JsonSeed<'a> {
    tokens: &'a mut usize,
    depth: usize,
    key: &'a str,
    role: JsonRole,
    retain: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JsonRole {
    Root,
    Results,
    Work,
    Attribution,
    Authors,
    Authorships,
    Other,
}

impl JsonRole {
    // Reserved words inside ignored metadata must not acquire domain-specific array limits.
    fn field(self, key: &str) -> Self {
        match (self, key) {
            (Self::Root, "results") => Self::Results,
            (Self::Work, "authorships") => Self::Authorships,
            (Self::Work | Self::Attribution, "authors") => Self::Authors,
            (Self::Work, "scholarly") => Self::Attribution,
            _ => Self::Other,
        }
    }
}

impl JsonSeed<'_> {
    // Count before accepting another scalar or delimiter so limit+1 is never retained.
    fn token<E: serde::de::Error>(&mut self) -> Result<(), E> {
        *self.tokens += 1;
        if *self.tokens > MAX_PROVIDER_JSON_TOKENS {
            return Err(E::custom("paper JSON bounds"));
        }
        Ok(())
    }
    // Only containers increase depth; their closing delimiter counts as a second token.
    fn container<E: serde::de::Error>(&mut self) -> Result<(), E> {
        self.depth += 1;
        if self.depth > MAX_PROVIDER_JSON_DEPTH {
            return Err(E::custom("paper JSON depth"));
        }
        self.token()
    }
}

impl<'de> DeserializeSeed<'de> for JsonSeed<'_> {
    type Value = serde_json::Value;
    // All recursive reads reuse this budget, including values that will be discarded.
    fn deserialize<D: serde::Deserializer<'de>>(mut self, d: D) -> Result<Self::Value, D::Error> {
        self.token()?;
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for JsonSeed<'_> {
    type Value = serde_json::Value;
    // Error descriptions are fixed because they may reach serde's internal diagnostics.
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded JSON")
    }
    // Preserve scalar types so adapter validation cannot coerce malformed records.
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
        Ok(v.into())
    }
    // JSON integers retain exact signedness for domain validation.
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
        Ok(v.into())
    }
    // Counts must retain the full u64 range.
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
        Ok(v.into())
    }
    // Unrelated OpenAlex fields include finite fractional usage counters.
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
        serde_json::Number::from_f64(v)
            .map(serde_json::Value::Number)
            .ok_or_else(|| E::custom("paper JSON number"))
    }
    // Absent and null fields remain distinguishable in the retained object.
    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }
    // Discarded array tails still undergo parsing but need not retain string allocations.
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(if self.retain {
            v.into()
        } else {
            serde_json::Value::Null
        })
    }
    // Results stop before decoding entry 21; excessive authorships mark a dropped record.
    fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<Self::Value, A::Error> {
        self.container()?;
        let cap = match self.key {
            "results" if self.role == JsonRole::Results => MAX_PAPER_RESULTS,
            "authors" if self.role == JsonRole::Authors => MAX_PAPER_AUTHORS,
            _ => usize::MAX,
        };
        let mut values = Vec::new();
        let mut count = 0;
        loop {
            if count == cap {
                if seq.next_element_seed(RejectElement)?.is_some() {
                    return Err(serde::de::Error::custom("paper array bounds"));
                }
                break;
            }
            let retain =
                self.retain && (self.role != JsonRole::Authorships || count <= MAX_PAPER_AUTHORS);
            let child = JsonSeed {
                tokens: self.tokens,
                depth: self.depth,
                key: "",
                role: if self.role == JsonRole::Results {
                    JsonRole::Work
                } else {
                    JsonRole::Other
                },
                retain,
            };
            let Some(value) = seq.next_element_seed(child)? else {
                break;
            };
            if retain {
                values.push(value);
            }
            count += 1;
        }
        Ok(values.into())
    }
    // Reject duplicates before insertion, avoiding last-value-wins ambiguity at either adapter.
    fn visit_map<A: MapAccess<'de>>(mut self, mut map: A) -> Result<Self::Value, A::Error> {
        self.container()?;
        let mut values = serde_json::Map::new();
        let mut seen = std::collections::BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            self.token()?;
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom("duplicate key"));
            }
            let child = JsonSeed {
                tokens: self.tokens,
                depth: self.depth,
                key: &key,
                role: self.role.field(&key),
                retain: self.retain,
            };
            let value = map.next_value_seed(child)?;
            if self.retain {
                values.insert(key, value);
            }
        }
        Ok(values.into())
    }
}

struct RejectElement;
impl<'de> DeserializeSeed<'de> for RejectElement {
    type Value = ();
    // The sequence reports presence without allocating or decoding the forbidden next element.
    fn deserialize<D: serde::Deserializer<'de>>(self, _d: D) -> Result<(), D::Error> {
        Err(serde::de::Error::custom("paper array bounds"))
    }
}
