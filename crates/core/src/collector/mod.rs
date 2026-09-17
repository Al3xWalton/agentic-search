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

//! Shared selection contract for per-segment, cross-segment and cross-shard collectors.
//! Numeric scores have priority over NaNs; ties use the stored URL hash and full address.
//! Carrying identity through ranking keeps selection independent of insertion order,
//! without fetching URL text or changing scores, penalties or candidate limits.

use crate::{
    inverted_index::DocAddress, prehashed::Prehashed, ranking::initial::InitialScoreTweaker,
    simhash,
};

pub mod approx_count;
mod top_docs;

pub use top_docs::{BucketCollector, TopDocs};
pub type MainCollector = top_docs::TweakedScoreTopCollector<InitialScoreTweaker>;

#[derive(Clone, Debug)]
pub struct MaxDocsConsidered {
    pub total_docs: usize,
    pub segments: usize,
}

#[derive(
    Clone,
    Copy,
    Debug,
    serde::Serialize,
    serde::Deserialize,
    bincode::Encode,
    bincode::Decode,
    PartialEq,
)]
pub struct Hashes {
    pub site: Prehashed,
    pub title: Prehashed,
    pub url: Prehashed,
    pub url_without_tld: Prehashed,
    pub simhash: simhash::HashType,
}

/// A scored candidate carrying its stored hashes and physical index address.
pub trait Doc: Clone {
    /// Returns the candidate's current score, without normalizing its numeric bits.
    fn score(&self) -> f64;
    /// Returns the stored hashes used for tie-breaking and similarity penalties.
    fn hashes(&self) -> Hashes;
    /// Returns the complete address in the unchanged index, including its shard.
    fn address(&self) -> DocAddress;

    /// Returns the ascending tie key; the address disambiguates duplicate URL hashes.
    fn tie_key(&self) -> (u128, DocAddress) {
        (self.hashes().url.0, self.address())
    }
}

/// Compares score priority, treating all NaNs as one class below every numeric value.
/// Numeric values use IEEE total order, including infinities and distinct signed zeros.
/// This changes comparison only; callers retain the original score bits.
pub(crate) fn score_cmp(left: f64, right: f64) -> std::cmp::Ordering {
    match (left.is_nan(), right.is_nan()) {
        (true, true) => std::cmp::Ordering::Equal,
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        (false, false) => left.total_cmp(&right),
    }
}
