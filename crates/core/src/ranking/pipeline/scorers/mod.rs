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

//! Scorers are used to compute the ranking signals in the ranking pipeline.
//!
//! Each scorer computes a single signal which is then used to rank the pages.
//! Default ranking shares the collector's numeric-before-NaN score priority and
//! ascending stored URL-hash/address tie key; scoring arithmetic remains independent.

pub mod embedding;
pub mod inbound_similarity;
pub mod lambdamart;
pub mod reranker;
pub mod term_distance;

pub use reranker::ReRanker;

use crate::collector::{score_cmp, Doc};
use crate::ranking::{SignalCalculation, SignalCoefficients, SignalEnum};

use super::{RankableWebpage, Top};

/// A ranking stage that computes some signals for each page.
///
/// This trait is implemented for all scorers.
/// Most of the time you will want to implement the [`RankingStage`] trait instead,
/// but this trait gives you more control over the ranking pipeline.
pub trait FullRankingStage: Send + Sync {
    type Webpage: RankableWebpage;

    /// Compute the signal for each page.
    fn compute(&self, webpages: &mut [Self::Webpage]);

    /// The number of pages to return from this part of the pipeline.
    fn top(&self) -> Top {
        Top::Unlimited
    }

    /// Update the score for each page.
    fn update_scores(&self, webpages: &mut [Self::Webpage], coefficients: &SignalCoefficients) {
        for webpage in webpages.iter_mut() {
            webpage.set_raw_score(webpage.signals().iter().fold(0.0, |acc, (signal, calc)| {
                acc + calc.score * coefficients.get(&signal)
            }));
        }
    }

    /// Ranks by descending score priority, then ascending stored URL hash and address.
    /// NaNs have the lowest score priority and retain their original numeric bits.
    fn rank(&self, webpages: &mut [Self::Webpage]) {
        webpages.sort_by(|a, b| {
            score_cmp(RankableWebpage::score(b), RankableWebpage::score(a))
                .then_with(|| a.tie_key().cmp(&b.tie_key()))
        });
    }
}

/// A ranking stage that computes a single signal for each page.
pub trait RankingStage: Send + Sync {
    type Webpage: RankableWebpage;

    /// Compute the signal for a single page.
    fn compute(&self, webpage: &Self::Webpage) -> (SignalEnum, SignalCalculation);

    /// The number of pages to return from this part of the pipeline.
    fn top(&self) -> Top {
        Top::Unlimited
    }
}

impl<T> FullRankingStage for T
where
    T: RankingStage,
{
    type Webpage = <T as RankingStage>::Webpage;

    fn compute(&self, webpages: &mut [Self::Webpage]) {
        for webpage in webpages.iter_mut() {
            let (signal, signal_calculation) = self.compute(webpage);
            webpage.signals_mut().insert(signal, signal_calculation);
        }
    }

    fn top(&self) -> Top {
        self.top()
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
            pipeline::{LocalRecallRankingWebpage, RankingPipeline},
            signals::HostCentrality,
        },
        searcher::SearchQuery,
    };
    use itertools::Itertools;

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
        let pipeline = RankingPipeline::new().add_stage(UnchangedSignals);
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
            UnchangedSignals.rank(&mut direct);
            assert_eq!(observe(&direct), expected);
            assert_eq!(observe(&pipeline.apply(permutation, &query)), expected);
        }
    }
}
