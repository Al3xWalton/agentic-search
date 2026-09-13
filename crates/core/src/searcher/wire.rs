// SPDX-License-Identifier: AGPL-3.0-only
//! Preserve legacy service bytes while selecting deterministic, validated V2 stages.
//! Only a version and stage tag cross the new wire; atoms and preferences are recomputed.
//! This module does not redesign sonic framing or choose a fallback stage.

use super::{InitialWebsiteResult, SearchQuery};
use crate::{
    api::search::ReturnBody,
    inverted_index::{RetrievedWebpage, WebpagePointer},
    query::planner::{bounds, AgentPlan, StageId, PLANNER_VERSION},
    ranking::SignalCoefficients,
    webpage::region::Region,
};
use optics::{HostRankings, Optic};

/// The exact twelve-field pre-Story codec, in its original field order.
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct LegacySearchQuery {
    /// Original UTF-8 query; validated after legacy decode.
    pub query: String,
    /// Zero-based page; checked with the result count before execution.
    pub page: usize,
    /// Internal page size, validated in 1..=300.
    pub num_results: usize,
    /// Existing geographic preference.
    pub selected_region: Option<Region>,
    /// Existing explicitly parsed optic.
    pub optic: Option<Optic>,
    /// Existing host preferences and restrictions.
    pub host_rankings: Option<HostRankings>,
    /// Existing signal-output request.
    pub return_ranking_signals: bool,
    /// Existing mandatory safety filter.
    pub safe_search: bool,
    /// Existing exact stage-count request.
    pub count_results_exact: bool,
    /// Existing body-output request.
    pub return_body: Option<ReturnBody>,
    /// Existing structured-data output request.
    pub return_structured_data: bool,
    /// Existing ranking coefficient overrides.
    pub signal_coefficients: SignalCoefficients,
}

impl From<&SearchQuery> for LegacySearchQuery {
    fn from(q: &SearchQuery) -> Self {
        Self {
            query: q.query.clone(),
            page: q.page,
            num_results: q.num_results,
            selected_region: q.selected_region,
            optic: q.optic.clone(),
            host_rankings: q.host_rankings.clone(),
            return_ranking_signals: q.return_ranking_signals,
            safe_search: q.safe_search,
            count_results_exact: q.count_results_exact,
            return_body: q.return_body,
            return_structured_data: q.return_structured_data,
            signal_coefficients: q.signal_coefficients.clone(),
        }
    }
}

impl From<LegacySearchQuery> for SearchQuery {
    fn from(q: LegacySearchQuery) -> Self {
        Self {
            query: q.query,
            page: q.page,
            num_results: q.num_results,
            selected_region: q.selected_region,
            optic: q.optic,
            host_rankings: q.host_rankings,
            return_ranking_signals: q.return_ranking_signals,
            safe_search: q.safe_search,
            count_results_exact: q.count_results_exact,
            return_body: q.return_body,
            return_structured_data: q.return_structured_data,
            signal_coefficients: q.signal_coefficients,
            stage_plan: None,
        }
    }
}

/// Sanitized failures; none carry request strings, addresses or dependency errors.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    thiserror::Error,
    serde::Serialize,
    serde::Deserialize,
    bincode::Encode,
    bincode::Decode,
    utoipa::ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum QueryServiceError {
    /// No logical search shard is available.
    #[error("No search shards are available")]
    NoShards,
    /// Membership exceeds eight logical shards.
    #[error("Search membership exceeds its limit")]
    TooManyShards,
    /// A request exhausted its stage or RPC allowance.
    #[error("The search request exhausted its execution budget")]
    BudgetExhausted,
    /// A peer cannot complete the required V2 exchange.
    #[error("The search protocol is unavailable")]
    ProtocolUnavailable,
    /// The selector, original query or selected rule is invalid.
    #[error("The search plan is invalid")]
    InvalidPlan,
    /// Actual compiled rendering differs between coordinator and shard.
    #[error("Search schemas do not agree")]
    SchemaMismatch,
    /// A shard could not execute the selected query.
    #[error("A search shard failed")]
    ShardFailed,
    /// Retrieval failed or returned a different pointer cardinality.
    #[error("Search result retrieval failed")]
    RetrievalFailed,
    /// A blocking search worker failed to join.
    #[error("A search worker failed")]
    WorkerFailed,
}

/// Minimal V2 selector, versioned independently of the inherited twelve-field payload.
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct StageSelector {
    /// Wire version, currently exactly one.
    pub version: u16,
    /// Deterministic planner rule version, currently exactly one.
    pub planner_version: u16,
    /// Stage tag: 0 strict, 1 content, 2 relaxed, 3 core; other tags fail validation.
    pub stage: u8,
    /// Original request, preserving the legacy field order and codecs.
    pub query: LegacySearchQuery,
}

impl StageSelector {
    /// Encode a chosen stage, refusing forged internal plans rather than trusting their atoms.
    pub fn from_query(query: &SearchQuery) -> Result<Self, QueryServiceError> {
        let stage = query.stage_plan.as_ref().map_or(StageId::Strict, |p| p.id);
        let selector = Self {
            version: 1,
            planner_version: PLANNER_VERSION,
            stage: match stage {
                StageId::Strict => 0,
                StageId::Content => 1,
                StageId::Relaxed => 2,
                StageId::Core => 3,
            },
            query: query.into(),
        };
        let resolved = selector.resolve()?;
        if query
            .stage_plan
            .as_ref()
            .is_some_and(|p| Some(p) != resolved.stage_plan.as_ref())
        {
            return Err(QueryServiceError::InvalidPlan);
        }
        Ok(selector)
    }

    /// Validate version, original bounds and stage eligibility, then recompute the entire plan.
    /// Returns InvalidPlan before compilation for an unknown or ineligible selector.
    pub fn resolve(&self) -> Result<SearchQuery, QueryServiceError> {
        if self.version != 1 || self.planner_version != PLANNER_VERSION {
            return Err(QueryServiceError::InvalidPlan);
        }
        let stage = match self.stage {
            0 => StageId::Strict,
            1 => StageId::Content,
            2 => StageId::Relaxed,
            3 => StageId::Core,
            _ => return Err(QueryServiceError::InvalidPlan),
        };
        bounds::validate_numbers(self.query.page, self.query.num_results, false)
            .map_err(|_| QueryServiceError::InvalidPlan)?;
        let plan = AgentPlan::new(&self.query.query).map_err(|_| QueryServiceError::InvalidPlan)?;
        let selected = plan
            .stages
            .into_iter()
            .find(|p| p.id == stage)
            .ok_or(QueryServiceError::InvalidPlan)?;
        if self.query.page > 0 && stage != StageId::Strict {
            return Err(QueryServiceError::InvalidPlan);
        }
        let mut query: SearchQuery = self.query.clone().into();
        query.stage_plan = Some(selected);
        Ok(query)
    }
}

/// Initial V2 response; the unchanged legacy result is accompanied by actual rendering.
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct SearchV2Result {
    /// Legacy candidate pointers, scores and stage count.
    pub result: InitialWebsiteResult,
    /// Rendering emitted by the actual selected-query compilation.
    pub rendered_query: String,
}

/// Retrieval V2 response preserving request pointer order.
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct RetrieveV2Result {
    /// One page per requested pointer, in precisely the same order.
    pub webpages: Vec<RetrievedWebpage>,
}

/// Pointer list whose declared length is checked before allocating during V2 decoding.
#[derive(Debug, Clone, bincode::Encode)]
pub struct BoundedPointers(pub Vec<WebpagePointer>);

impl bincode::Decode for BoundedPointers {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let len = usize::decode(decoder)?;
        if len > bounds::MAX_CANDIDATES {
            return Err(bincode::error::DecodeError::Other(
                "too many retrieval pointers",
            ));
        }
        let mut pointers = Vec::with_capacity(len);
        for _ in 0..len {
            pointers.push(WebpagePointer::decode(decoder)?);
        }
        Ok(Self(pointers))
    }
}

impl<'de> bincode::BorrowDecode<'de> for BoundedPointers {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        bincode::Decode::decode(decoder)
    }
}

impl bincode::Encode for SearchQuery {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        LegacySearchQuery::from(self).encode(encoder)
    }
}
impl bincode::Decode for SearchQuery {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        LegacySearchQuery::decode(decoder).map(Into::into)
    }
}
impl<'de> bincode::BorrowDecode<'de> for SearchQuery {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        bincode::Decode::decode(decoder)
    }
}
#[cfg(test)]
impl From<String> for LegacySearchQuery {
    fn from(query: String) -> Self {
        Self::from(&SearchQuery {
            query,
            ..Default::default()
        })
    }
}
