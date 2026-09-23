//! Defines strict ingest input, finite byte/metadata bounds and immutable acknowledgement DTOs.
//! An acknowledgement proves WAL receipt and durable local metadata, not searchable visibility.

#![deny(missing_docs)]

use super::{
    dto::{AttributedResult, V1Version},
    error::{V1Error, V1Failure},
    suppression::DocumentId,
};
use crate::query::planner::bounds::InputError;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Closed admission explanations; publisher/listed details never enter an error response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum V1AdmissionReason {
    /// The URL cannot retain its identity and derived attribution through indexing.
    InvalidUrl,
    /// The indexer's policy or an already expired meta deadline forbids admission.
    Noindex,
    /// The derived HTML title is missing or blank.
    EmptyTitle,
    /// Applicable HTTP publisher directives cannot be carried safely by this ingest path.
    HeaderDirective,
    /// Current rules or unsupported meta display restrictions forbid admission.
    Excluded,
}

/// Index into the one authoritative numeric bound table; lengths measure UTF-8 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum IngestBound {
    /// Requested and canonical URL bytes.
    Url,
    /// Decoded HTML bytes, additionally constrained by the complete wire-body cap.
    Body,
    /// Observed fetch duration in milliseconds.
    FetchTime,
    /// UTC seconds through year 9999.
    Timestamp,
    /// Operational source-label bytes.
    Source,
    /// Number of physical X-Robots-Tag header occurrences.
    HeaderCount,
    /// Bytes in one physical header occurrence.
    HeaderValue,
}

/// Inclusive numeric bounds in IngestBound order, independent of HTTP body collection.
pub const INGEST_BOUNDS: [(i128, i128); 7] = [
    (1, 2_048),
    (1, 8_388_608),
    (0, 86_400_000),
    (0, 253_402_300_799),
    (1, 64),
    (0, 32),
    (1, 1_024),
];

/// Validates a numeric value or byte length; returns the fixed invalid_request failure.
pub fn validate_bound(bound: IngestBound, value: i128) -> Result<(), V1Error> {
    let (minimum, maximum) = INGEST_BOUNDS[bound as usize];
    if (minimum..=maximum).contains(&value) {
        Ok(())
    } else {
        Err(InputError::InvalidRequest.into())
    }
}

/// Checks a bounded operational label, never a path, URL or authenticated identity.
pub fn validate_source(source: &str) -> Result<(), V1Error> {
    validate_bound(IngestBound::Source, source.len() as i128)?;
    let first = source.bytes().next().unwrap_or_default();
    if !(first.is_ascii_lowercase() || first.is_ascii_digit())
        || !source.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.-".contains(&byte)
        })
    {
        return Err(InputError::InvalidRequest.into());
    }
    Ok(())
}

/// One fetched HTML document. Every field is required; unknown and duplicate fields are rejected.
/// Authentication attests the caller's fetch authority; the API performs no network fetch.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct V1IngestRequest {
    /// HTTP(S) source URL: 1..=2048 UTF-8 bytes before and after canonicalization.
    pub url: String,
    /// Fetched HTML: 1..=8388608 UTF-8 bytes; the entire JSON must fit the listener's wire cap.
    pub body: String,
    /// Measured fetch duration, in milliseconds; zero is a measured zero.
    #[schema(minimum = 0, maximum = 86400000)]
    pub fetch_time_ms: u64,
    /// Retrieval time in UTC seconds, no later than the API's captured receipt time.
    #[schema(minimum = 0, maximum = 253402300799_i64)]
    pub retrieved_at: i64,
    /// Operational source claim: 1..=64 ASCII bytes, not an identity or credential.
    #[schema(
        min_length = 1,
        max_length = 64,
        pattern = "^[a-z0-9][a-z0-9_.-]{0,63}$"
    )]
    pub source: String,
    /// 0..=32 physical header occurrences, each 1..=1024 UTF-8 bytes; order is preserved.
    #[schema(max_items = 32)]
    pub x_robots_tag: Vec<String>,
}

impl V1IngestRequest {
    /// Validates byte bounds, integer bounds and source grammar before any policy or store work.
    /// Timestamp ordering and URL identity require the route's clock and canonicalizer afterward.
    pub fn validate(&self) -> Result<(), V1Error> {
        validate_bound(IngestBound::Url, self.url.len() as i128)?;
        validate_bound(IngestBound::Body, self.body.len() as i128)?;
        validate_bound(IngestBound::FetchTime, self.fetch_time_ms.into())?;
        validate_bound(IngestBound::Timestamp, self.retrieved_at.into())?;
        validate_source(&self.source)?;
        validate_bound(IngestBound::HeaderCount, self.x_robots_tag.len() as i128)?;
        for value in &self.x_robots_tag {
            validate_bound(IngestBound::HeaderValue, value.len() as i128)?;
        }
        Ok(())
    }
}

/// Derived attribution and the durable version receipt; no existence or suppression flag.
#[derive(Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct V1IngestDocument {
    id: DocumentId,
    #[schema(minimum = 1)]
    version: u64,
    canonical_url: String,
    domain: String,
    title: String,
    #[schema(minimum = 0, maximum = 253402300799_i64)]
    accepted_at: i64,
}

/// Acknowledges admitted metadata and live-index WAL receipt, with a durable local delivery marker.
/// Visibility waits for the ten-minute autocommit schedule, indexing and search-client refresh.
/// Replacements can leave physical duplicates; the first allowed served candidate may be older.
/// Acknowledged identical HTML replays without writes or RPC; a recorded retry re-dispatches once.
#[derive(Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct V1IngestResponse {
    version: V1Version,
    document: V1IngestDocument,
}

impl V1IngestResponse {
    /// Constructs only from validated attribution and a positive persisted version receipt.
    pub(super) fn new(
        attribution: &AttributedResult,
        version: u64,
        accepted_at: i64,
    ) -> Result<Self, V1Error> {
        if version == 0 || validate_bound(IngestBound::Timestamp, accepted_at.into()).is_err() {
            return Err(V1Error::failure(V1Failure::InternalError));
        }
        Ok(Self {
            version: V1Version::V1,
            document: V1IngestDocument {
                id: attribution.id().clone(),
                version,
                canonical_url: attribution.url().into(),
                domain: attribution.domain().into(),
                title: attribution.title().into(),
                accepted_at,
            },
        })
    }
}
