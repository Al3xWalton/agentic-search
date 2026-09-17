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

//! Modifiers are used to modify the ranking of pages.
//!
//! Each page is ranked by a linear combination of the signals like
//! `score = boost * (signal_1 * weight_1 + signal_2 * weight_2 + ...)`
//!
//! Modifiers can either modify the multiplicative boost factor for
//! each page or override the ranking entirely (if we want to rank
//! for something other than the score).
//! The default sort shares the collector's numeric-before-NaN score priority and
//! ascending stored URL-hash/address tie key, without changing scores or boosts.

mod inbound_similarity;

use super::{RankableWebpage, Top};
use crate::collector::{score_cmp, Doc};
pub use inbound_similarity::InboundSimilarity;

/// A modifier that gives full control over the ranking.
pub trait FullModifier: Send + Sync {
    type Webpage: RankableWebpage;
    /// Modify the boost factor for each page.
    fn update_boosts(&self, webpages: &mut [Self::Webpage]);

    /// Ranks by descending score priority, then ascending stored URL hash and address.
    /// NaNs have the lowest score priority; modifiers may override this ordering.
    fn rank(&self, webpages: &mut [Self::Webpage]) {
        webpages.sort_by(|a, b| {
            score_cmp(RankableWebpage::score(b), RankableWebpage::score(a))
                .then_with(|| a.tie_key().cmp(&b.tie_key()))
        });
    }

    /// The number of pages to return from this part of the pipeline.
    fn top(&self) -> Top {
        Top::Unlimited
    }
}

/// A modifier that modifies the multiplicative boost factor for each page.
///
/// This is the most common type of modifier.
pub trait Modifier: Send + Sync {
    type Webpage: RankableWebpage;
    /// Modify the boost factor for a page.
    ///
    /// The new boost factor will be multiplied with the page's current boost factor.
    fn boost(&self, webpage: &Self::Webpage) -> f64;

    /// The number of pages to return from this part of the pipeline.
    fn top(&self) -> Top {
        Top::Unlimited
    }
}

impl<T> FullModifier for T
where
    T: Modifier,
{
    type Webpage = <T as Modifier>::Webpage;

    fn update_boosts(&self, webpages: &mut [Self::Webpage]) {
        for webpage in webpages {
            let cur_boost = webpage.boost();
            webpage.set_boost(cur_boost * self.boost(webpage));
        }
    }

    fn top(&self) -> Top {
        Modifier::top(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        collector::{Doc, Hashes},
        enum_map::EnumMap,
        inverted_index::{DocAddress, ShardId, WebpagePointer},
        ranking::{
            initial::Score,
            pipeline::{FullRankingStage, LocalRecallRankingWebpage, RankingPipeline},
            signals::HostCentrality,
            SignalCalculation, SignalCoefficients, SignalEnum,
        },
        searcher::SearchQuery,
    };
    use itertools::Itertools;

    struct UnchangedBoosts;
    impl FullModifier for UnchangedBoosts {
        type Webpage = LocalRecallRankingWebpage;
        fn update_boosts(&self, _: &mut [Self::Webpage]) {}
    }
    struct UnchangedSignals;
    impl FullRankingStage for UnchangedSignals {
        type Webpage = LocalRecallRankingWebpage;
        fn compute(&self, _: &mut [Self::Webpage]) {}
    }

    #[test]
    fn rank_uses_total_order_and_nan_last() {
        let scores = [
            1.0,
            1.0,
            f64::NEG_INFINITY,
            f64::from_bits(0x7ff8_0000_0000_0001),
            f64::from_bits(0xfff8_0000_0000_0002),
        ];
        let keys = [20, 10, 1, 30, 30];
        let pages = scores
            .into_iter()
            .enumerate()
            .map(|(id, score)| {
                let mut signals = EnumMap::new();
                signals.insert(
                    HostCentrality.into(),
                    SignalCalculation {
                        value: score,
                        score,
                    },
                );
                LocalRecallRankingWebpage::new_testing(
                    WebpagePointer {
                        score: Score { total: score },
                        address: DocAddress::new(0, id as u32, ShardId::Backbone(0)),
                        hashes: Hashes {
                            url: keys[id].into(),
                            site: (id as u128 + 100).into(),
                            title: (id as u128 + 200).into(),
                            url_without_tld: (id as u128 + 300).into(),
                            simhash: 0,
                        },
                    },
                    signals,
                    score,
                )
            })
            .collect::<Vec<_>>();
        let expected = [1, 0, 2, 3, 4].map(|id| {
            (
                DocAddress::new(0, id as u32, ShardId::Backbone(0)),
                scores[id].to_bits(),
            )
        });
        let observe = |pages: &[LocalRecallRankingWebpage]| {
            pages
                .iter()
                .map(|p| (p.address(), p.unboosted_score().to_bits()))
                .collect::<Vec<_>>()
        };
        let pipeline = RankingPipeline::new()
            .add_stage(UnchangedSignals)
            .add_modifier(UnchangedBoosts);
        let query = SearchQuery {
            num_results: 5,
            signal_coefficients: SignalCoefficients::new(SignalEnum::all().map(|signal| {
                (
                    signal,
                    if signal == HostCentrality.into() {
                        1.0
                    } else {
                        0.0
                    },
                )
            })),
            ..Default::default()
        };
        for permutation in pages.into_iter().permutations(5) {
            let mut direct = permutation.clone();
            UnchangedBoosts.rank(&mut direct);
            assert_eq!(observe(&direct), expected);
            assert_eq!(observe(&pipeline.apply(permutation, &query)), expected);
        }
    }
}
