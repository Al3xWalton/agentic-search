//! Owns private report history and independently available, reversible serving protection.
//! The journal is authoritative for tickets; personal content lives in purgeable committed files.
//! Local file ownership and trusted UTC are operational requirements, not distributed guarantees.

#![deny(missing_docs)]

/// Fixed-width startup bearer authentication and bounded operator aliases.
pub mod auth;
/// Shared byte, cardinality and capacity limits used before writes and during replay.
pub mod bounds;
/// Blocking private-filesystem commands using the same validated domain owners and readers.
pub mod cli;
/// Checked statutory UTC arithmetic, using the existing injected clock.
pub mod clock;
/// Shared Unix file hardening and finite storage-stage instrumentation.
pub mod disk;
/// Private create-new HTML exports of every immutable envelope version.
pub mod export;
/// Canonical append-only chain, durable checkpoint and bounded uncommitted-tail recovery.
pub mod journal;
/// Hash-only URL and normalized-host protection without membership disclosure.
pub mod listed;
/// Exact supplied measures vocabulary and alternative-measure validation.
pub mod measures;
/// Checked integer aggregates and retention eligibility from verified ticket metadata.
pub mod metrics;
/// Domain identifiers, validated assets and entropy generation.
pub mod model;
/// Immutable salted personal revisions, with reference-authorized deletion.
pub mod payload;
/// Independently verified ordered record index and checkpoint recovery.
pub mod record_index;
/// Strict typed assessments, records and immutable references.
pub mod record_types;
/// Independent record owner, immutable publication and read-only snapshots.
pub mod records;
/// Startup reconciliation of journal projections and unfinished durable work.
pub mod recovery;
/// Pure significant-change validation against approved immutable assessment updates.
pub mod release;
/// Pure review deadlines and idempotent work records under the independent record owner.
pub mod reviews;
/// Indexed, reversible serving rules and monotone deadline observation.
pub mod rules;
/// Deterministic public policy text from validated configuration and immutable record selections.
pub mod statement;
/// Serialized admission, administration, queue discovery and tracked durable tasks.
pub mod tickets;
/// Closed lifecycle reducer and pure deadline and retention eligibility.
pub mod transitions;

/// Closed domain failures; neither personal text nor filesystem details are carried here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A decoded value violates its shape, bounds or route-specific requirements.
    InvalidInput,
    /// The requested event is outside the closed lifecycle.
    InvalidTransition,
    /// No ticket with the validated capability exists.
    NotFound,
    /// The private journal or its required payloads cannot safely be used.
    Unavailable,
    /// A complete transaction would exceed a healthy store's finite capacity.
    Capacity,
    /// A serving-rule commit or load cannot establish durable protection.
    RulesUnavailable,
    /// A closed ticket has not reached its configured calendar retention period.
    RetentionNotDue,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "invalid compliance input",
            Self::InvalidTransition => "invalid compliance transition",
            Self::NotFound => "ticket not found",
            Self::Unavailable => "compliance unavailable",
            Self::Capacity => "compliance capacity exhausted",
            Self::RulesUnavailable => "serving rules unavailable",
            Self::RetentionNotDue => "payload retention not due",
        })
    }
}
impl std::error::Error for Error {}

/// Domain result with a closed, non-personal failure vocabulary.
pub type Result<T> = std::result::Result<T, Error>;
