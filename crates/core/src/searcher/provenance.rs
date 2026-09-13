// SPDX-License-Identifier: AGPL-3.0-only
//! Describe completed request-local stages and the first producer of every displayed hit.
//! Only typed terms, safe compilation text, counts and coarse durations are public.
//! This module does not execute queries or expose shard identities, timings or explanations.

/// Finite producer identifiers, shared with the deterministic planner.
pub use crate::query::planner::StageId as PlanStageId;
use crate::{
    collector::approx_count::Count,
    query::{
        parser::{SimpleOrPhrase, Term},
        planner::StagePlan,
    },
};

/// Why a request uses one or several eligible stages.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    bincode::Encode,
    bincode::Decode,
    utoipa::ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PlanMode {
    /// Page-zero planning is enabled; execution may still stop after strict.
    Staged,
    /// Server configuration disables relaxation.
    StrictOnly,
    /// Pages after zero use the original strict query only.
    PaginationStrict,
}

/// Scope of the existing top-level numHits count.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    bincode::Encode,
    bincode::Decode,
    utoipa::ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum NumHitsScope {
    /// Existing count from the single completed stage.
    SingleStage,
    /// Approximate largest-stage estimate, not a sum or an exact union.
    LargestStageEstimate,
}

/// Closed source-level term kinds, excluding schema field identifiers.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    bincode::Encode,
    bincode::Decode,
    utoipa::ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum TermKind {
    /// Ordinary unquoted text.
    Literal,
    /// Explicit or preferred phrase.
    Phrase,
    /// English capitalization preference token.
    Entity,
    /// Site constraint.
    Site,
    /// Link target constraint.
    Linkto,
    /// Title constraint.
    Title,
    /// Body constraint.
    Body,
    /// URL text constraint.
    Url,
    /// Exact URL constraint.
    Exacturl,
    /// Unknown bang retained as a literal constraint.
    Bang,
}

/// An atom's role in the selected candidate or preference query.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    bincode::Encode,
    bincode::Decode,
    utoipa::ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TermOccur {
    /// Mandatory atom or constraint.
    Must,
    /// One complete content atom in a threshold vote.
    Should,
    /// Immutable excluded atom.
    MustNot,
    /// Optional entity phrase ranking predicate.
    Preference,
}

/// A source-level term; literals remain query data and are serialized with JSON escaping.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    bincode::Encode,
    bincode::Decode,
    utoipa::ToSchema,
)]
pub struct PlanTerm {
    /// Canonical literal or operand text, retaining its case and punctuation.
    pub text: String,
    /// Closed parser meaning, never an arbitrary schema field supplied by a client.
    pub kind: TermKind,
    /// Mandatory, excluded, threshold or optional preference occurrence.
    pub occur: TermOccur,
    /// Declared weight, exactly one or two; unrelated to learned ranking coefficients.
    pub weight: u8,
}

/// One completed stage, measured around fan-out, ranking and retrieval at the API.
#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    bincode::Encode,
    bincode::Decode,
    utoipa::ToSchema,
)]
#[serde(rename_all = "camelCase")]
pub struct StageProvenance {
    /// Actual executed stage.
    pub id: PlanStageId,
    /// Selected source-ordered atoms, with optional phrases after their first constituent.
    pub terms: Vec<PlanTerm>,
    /// Readable source query, never reparsed for execution.
    pub rewritten_query: String,
    /// Complete actual lexical compilation plus named digests for applied request filters.
    pub rendered_query: String,
    /// Distinct content-atom vote threshold, null outside relaxed/core.
    pub minimum_should_match: Option<usize>,
    /// Sum of successful shard match counts before trimming/deduplication.
    pub hit_count: Count,
    /// Retrieved stage page size before cross-stage deduplication, at most requested count.
    pub returned_count: usize,
    /// Slots actually added to the accumulated output.
    pub added_count: usize,
    /// Complete stage elapsed wall time, rounded down to whole milliseconds.
    pub elapsed_ms: u128,
    /// Exactly returnedCount > 0; duplicate-only stages may add no slots.
    pub produced_results: bool,
}

/// Request-local explanation of the completed website search stages.
#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    bincode::Encode,
    bincode::Decode,
    utoipa::ToSchema,
)]
#[serde(rename_all = "camelCase")]
pub struct QueryPlanProvenance {
    /// Provenance schema version, currently one.
    pub version: u16,
    /// Server configuration and pagination policy for this request.
    pub mode: PlanMode,
    /// Whether numHits describes one stage or an approximate multistage estimate.
    pub num_hits_scope: NumHitsScope,
    /// Only completed stages actually sent, in execution order; never skipped placeholders.
    pub stages: Vec<StageProvenance>,
}

fn plain(text: &SimpleOrPhrase) -> String {
    match text {
        SimpleOrPhrase::Simple(s) => s.as_str().to_owned(),
        SimpleOrPhrase::Phrase(p) => p.join(" "),
    }
}
fn describe(term: &Term) -> (String, TermKind) {
    match term {
        Term::SimpleOrPhrase(s) => (
            plain(s),
            if matches!(s, SimpleOrPhrase::Phrase(_)) {
                TermKind::Phrase
            } else {
                TermKind::Literal
            },
        ),
        Term::Site(s) => (s.clone(), TermKind::Site),
        Term::LinkTo(s) => (s.clone(), TermKind::Linkto),
        Term::Title(s) => (plain(s), TermKind::Title),
        Term::Body(s) => (plain(s), TermKind::Body),
        Term::Url(s) => (plain(s), TermKind::Url),
        Term::ExactUrl(s) => (s.clone(), TermKind::Exacturl),
        Term::PossibleBang { prefix, bang } => {
            (format!("{prefix}{}", bang.as_str()), TermKind::Bang)
        }
        Term::Not(inner) => describe(inner),
    }
}

impl StageProvenance {
    /// Build a completed-stage record from actual counts and the actual safe rendering.
    pub fn completed(
        stage: &StagePlan,
        rendered_query: String,
        hit_count: Count,
        returned_count: usize,
        added_count: usize,
        elapsed_ms: u128,
    ) -> Self {
        let mut terms = Vec::new();
        for atom in &stage.atoms {
            let (text, mut kind) = describe(&atom.source.term);
            if atom.entity {
                kind = TermKind::Entity;
            }
            let negative = matches!(atom.source.term, Term::Not(_));
            let weight = if !negative && (atom.entity || kind == TermKind::Phrase) {
                2
            } else {
                1
            };
            terms.push(PlanTerm {
                text,
                kind,
                weight,
                occur: if negative {
                    TermOccur::MustNot
                } else if !atom.constraint && stage.minimum.is_some() {
                    TermOccur::Should
                } else {
                    TermOccur::Must
                },
            });
            for preference in stage.preferences.iter().filter(|p| {
                p.source.start == atom.source.source.start && p.source.end > atom.source.source.end
            }) {
                terms.push(PlanTerm {
                    text: describe(&preference.term).0,
                    kind: TermKind::Phrase,
                    occur: TermOccur::Preference,
                    weight: 2,
                });
            }
        }
        Self {
            id: stage.id,
            terms,
            rewritten_query: stage.rewritten_query(),
            rendered_query,
            minimum_should_match: stage.minimum,
            hit_count,
            returned_count,
            added_count,
            elapsed_ms,
            produced_results: returned_count > 0,
        }
    }
}

/// The separate 404 code for a completed bare-bang search without a target.
#[derive(Debug, Clone, Copy, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BangErrorCode {
    /// The one permitted bare-bang search produced no page.
    NoBangTarget,
}

/// Closed union of safe client-input, service and bare-bang error codes.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
#[serde(untagged)]
pub enum SearchErrorCode {
    /// Validation failure before RPC.
    Input(crate::query::planner::bounds::InputError),
    /// Bounded search-service execution failure.
    Service(super::wire::QueryServiceError),
    /// Completed bare-bang request without a redirect target.
    Bang(BangErrorCode),
}

/// Fixed error detail without query text or infrastructure data.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct SearchErrorDetail {
    /// Finite snake_case error code.
    pub code: SearchErrorCode,
    /// Fixed safe message associated with the code.
    pub message: String,
}

/// Search-route JSON error envelope used for HTTP 400, 404, 413 and 503.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct SearchErrorResponse {
    /// The typed failure; no successful result fields accompany it.
    pub error: SearchErrorDetail,
}
