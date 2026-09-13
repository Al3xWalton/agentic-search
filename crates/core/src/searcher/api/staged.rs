// SPDX-License-Identifier: AGPL-3.0-only
//! Accumulate completed stages without reranking earlier slots or normalizing their URLs.
//! The shared SearchSession owns RPC limits; this state owns only one request's output.
//! Skipped stages and failed RPCs never become successful provenance records.

use super::super::{
    provenance::{NumHitsScope, PlanMode, QueryPlanProvenance, StageProvenance},
    WebsitesResult,
};
use crate::{
    collector::approx_count::Count, query::planner::StagePlan, search_prettifier::DisplayedWebpage,
};
use std::collections::HashSet;

/// A bare-bang strict search completed without a redirect target.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("No bang target was found")]
pub struct NoBangTarget;

/// Bounded append-only response state, allocated afresh for each API website request.
pub struct StageAccumulator {
    limit: usize,
    mode: PlanMode,
    webpages: Vec<DisplayedWebpage>,
    seen: HashSet<String>,
    stages: Vec<StageProvenance>,
    largest: u64,
    first_count: Count,
    more: bool,
}

impl StageAccumulator {
    /// Construct a page accumulator after public 1..=100 result-count validation.
    pub fn new(limit: usize, mode: PlanMode) -> Self {
        Self {
            limit,
            mode,
            webpages: Vec::new(),
            seen: HashSet::new(),
            stages: Vec::new(),
            largest: 0,
            first_count: Count::Exact(0),
            more: false,
        }
    }

    /// Whether a short accumulated page may attempt an eligible untried stage.
    pub fn needs_more(&self) -> bool {
        self.webpages.len() < self.limit
    }

    /// Append one successful ranked page, preserving all first-stage slots and first ownership.
    pub fn complete(
        &mut self,
        plan: &StagePlan,
        rendered: String,
        result: WebsitesResult,
        elapsed_ms: u128,
    ) {
        let first = self.stages.is_empty();
        if first {
            self.first_count = result.num_hits;
        }
        self.largest = self.largest.max(result.num_hits.as_u64());
        self.more |= result.has_more_results;
        let returned = result.webpages.len();
        let before = self.webpages.len();
        for mut webpage in result.webpages {
            if !first && self.seen.contains(&webpage.url) {
                continue;
            }
            if self.webpages.len() == self.limit {
                self.more = true;
                continue;
            }
            self.seen.insert(webpage.url.clone());
            webpage.plan_stage = Some(plan.id);
            self.webpages.push(webpage);
        }
        self.stages.push(StageProvenance::completed(
            plan,
            rendered,
            result.num_hits,
            returned,
            self.webpages.len() - before,
            elapsed_ms,
        ));
    }

    /// Finish with whole-request timing and honest multistage count/continuation semantics.
    pub fn finish(self, elapsed_ms: u128, eligible_untried: bool) -> WebsitesResult {
        let multiple = self.stages.len() > 1;
        let num_hits = if multiple {
            Count::Approximate(self.largest.max(self.webpages.len() as u64))
        } else {
            self.first_count
        };
        WebsitesResult {
            webpages: self.webpages,
            num_hits,
            search_duration_ms: elapsed_ms,
            has_more_results: self.more || (multiple && eligible_untried),
            query_plan: Some(QueryPlanProvenance {
                version: 1,
                mode: self.mode,
                num_hits_scope: if multiple {
                    NumHitsScope::LargestStageEstimate
                } else {
                    NumHitsScope::SingleStage
                },
                stages: self.stages,
            }),
        }
    }
}
