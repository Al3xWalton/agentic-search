// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded minimum-should-match adapter over complete atom scorers.
//! Each child supplies one vote per document; advance and seek preserve increasing doc IDs.
//! Field expansion belongs to the existing planner, and this adapter performs no stored reads.

use crate::query::planner::bounds::{InputError, MAX_ATOMS};
use tantivy::{
    query::{EnableScoring, Explanation, Query, Scorer, Weight},
    DocId, DocSet, Score, SegmentReader, TERMINATED,
};

/// A conjunction threshold over at most 32 complete atom queries.
#[derive(Debug)]
pub struct MinimumMatch {
    children: Vec<Box<dyn Query>>,
    minimum: usize,
}

impl MinimumMatch {
    /// Construct a bounded threshold; zero, impossible minima and more than 32 children fail.
    pub fn new(minimum: usize, children: Vec<Box<dyn Query>>) -> Result<Self, InputError> {
        if minimum == 0 || minimum > children.len() || children.len() > MAX_ATOMS {
            return Err(InputError::PlanTooComplex);
        }
        Ok(Self { children, minimum })
    }
}

impl Clone for MinimumMatch {
    fn clone(&self) -> Self {
        Self {
            minimum: self.minimum,
            children: self.children.iter().map(|q| q.box_clone()).collect(),
        }
    }
}

impl Query for MinimumMatch {
    fn weight(&self, scoring: EnableScoring<'_>) -> tantivy::Result<Box<dyn Weight>> {
        Ok(Box::new(MinimumWeight {
            minimum: self.minimum,
            children: self
                .children
                .iter()
                .map(|q| q.weight(scoring))
                .collect::<tantivy::Result<_>>()?,
        }))
    }
    fn query_terms<'a>(&'a self, visitor: &mut dyn FnMut(&'a tantivy::Term, bool)) {
        for child in &self.children {
            child.query_terms(visitor);
        }
    }
}

struct MinimumWeight {
    minimum: usize,
    children: Vec<Box<dyn Weight>>,
}
impl Weight for MinimumWeight {
    fn scorer(&self, reader: &SegmentReader, boost: Score) -> tantivy::Result<Box<dyn Scorer>> {
        let children = self
            .children
            .iter()
            .map(|w| w.scorer(reader, boost))
            .collect::<tantivy::Result<_>>()?;
        Ok(Box::new(MinimumScorer::new(self.minimum, children)))
    }
    fn explain(&self, reader: &SegmentReader, doc: DocId) -> tantivy::Result<Explanation> {
        let mut scorer = self.scorer(reader, 1.0)?;
        if doc == TERMINATED || scorer.seek(doc) != doc {
            return Err(tantivy::TantivyError::InvalidArgument(
                "Document does not match the minimum".into(),
            ));
        }
        let mut explanation = Explanation::new("Minimum matching atom count", scorer.score());
        for child in &self.children {
            if let Ok(detail) = child.explain(reader, doc) {
                explanation.add_detail(detail);
            }
        }
        Ok(explanation)
    }
}

struct MinimumScorer {
    minimum: usize,
    children: Vec<Box<dyn Scorer>>,
    current: DocId,
}
impl MinimumScorer {
    fn new(minimum: usize, children: Vec<Box<dyn Scorer>>) -> Self {
        let mut scorer = Self {
            minimum,
            children,
            current: TERMINATED,
        };
        scorer.align();
        scorer
    }
    fn align(&mut self) -> DocId {
        loop {
            let next = self
                .children
                .iter()
                .map(|child| child.doc())
                .min()
                .unwrap_or(TERMINATED);
            if next == TERMINATED {
                self.current = TERMINATED;
                return TERMINATED;
            }
            let votes = self
                .children
                .iter()
                .filter(|child| child.doc() == next)
                .count();
            if votes >= self.minimum {
                self.current = next;
                return next;
            }
            for child in &mut self.children {
                if child.doc() == next {
                    child.advance();
                }
            }
        }
    }
}
impl DocSet for MinimumScorer {
    fn doc(&self) -> DocId {
        self.current
    }
    fn advance(&mut self) -> DocId {
        if self.current == TERMINATED {
            return TERMINATED;
        }
        for child in &mut self.children {
            if child.doc() == self.current {
                child.advance();
            }
        }
        self.align()
    }
    fn seek(&mut self, target: DocId) -> DocId {
        if self.current >= target {
            return self.current;
        }
        for child in &mut self.children {
            if child.doc() < target {
                child.seek(target);
            }
        }
        self.align()
    }
    fn size_hint(&self) -> u32 {
        self.children
            .iter()
            .map(|c| c.size_hint())
            .fold(0, u32::saturating_add)
    }
}
impl Scorer for MinimumScorer {
    fn score(&mut self) -> Score {
        if self.current == TERMINATED {
            return 0.0;
        }
        self.children
            .iter_mut()
            .filter(|c| c.doc() == self.current)
            .map(|c| c.score())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tantivy::{
        collector::Count,
        doc,
        schema::{IndexRecordOption, Schema, TEXT},
        Index,
    };
    fn fixture(minimum: usize, k: usize) -> (tantivy::IndexReader, MinimumMatch) {
        let mut schema = Schema::builder();
        let field = schema.add_text_field("text", TEXT);
        let index = Index::create_in_ram(schema.build());
        let mut writer: tantivy::IndexWriter<tantivy::TantivyDocument> =
            index.writer_with_num_threads(1, 20_000_000).unwrap();
        for mask in 0..32 {
            let text = (0..5)
                .filter(|i| mask & (1 << i) != 0)
                .map(|i| format!("atom{i}"))
                .collect::<Vec<_>>()
                .join(" ");
            writer.add_document(doc!(field=>text)).unwrap();
        }
        writer.commit().unwrap();
        let children = (0..k)
            .map(|i| {
                Box::new(tantivy::query::TermQuery::new(
                    tantivy::Term::from_field_text(field, &format!("atom{i}")),
                    IndexRecordOption::Basic,
                )) as Box<dyn Query>
            })
            .collect();
        (
            index.reader().unwrap(),
            MinimumMatch::new(minimum, children).unwrap(),
        )
    }
    #[test]
    fn minimum_match_doc_set() {
        for k in 1..=5 {
            for minimum in 1..=k {
                let (reader, query) = fixture(minimum, k);
                let searcher = reader.searcher();
                let expected = (0u32..32)
                    .filter(|mask| (mask & ((1 << k) - 1)).count_ones() as usize >= minimum)
                    .count();
                assert_eq!(searcher.search(&query, &Count).unwrap(), expected);
            }
        }
    }
    #[test]
    fn minimum_match_advance() {
        let (reader, query) = fixture(2, 3);
        let searcher = reader.searcher();
        let weight = query
            .weight(EnableScoring::disabled_from_searcher(&searcher))
            .unwrap();
        let mut scorer = weight.scorer(searcher.segment_reader(0), 1.0).unwrap();
        let mut found = Vec::new();
        while scorer.doc() != TERMINATED {
            found.push(scorer.doc());
            scorer.advance();
        }
        assert_eq!(
            found,
            (0u32..32)
                .filter(|mask| (mask & 7).count_ones() >= 2)
                .collect::<Vec<_>>()
        );
    }
    #[test]
    fn minimum_match_seek() {
        let (reader, query) = fixture(2, 3);
        let searcher = reader.searcher();
        let weight = query
            .weight(EnableScoring::disabled_from_searcher(&searcher))
            .unwrap();
        let mut scorer = weight.scorer(searcher.segment_reader(0), 1.0).unwrap();
        for target in [4, 6, 8, 12, 25, 31] {
            let expected = (target..32)
                .find(|mask| (mask & 7u32).count_ones() >= 2)
                .unwrap_or(TERMINATED);
            assert_eq!(scorer.seek(target), expected);
        }
    }
    #[test]
    fn minimum_match_exhaustion() {
        let mut empty = MinimumScorer::new(1, vec![]);
        assert_eq!(empty.doc(), TERMINATED);
        assert_eq!(empty.advance(), TERMINATED);
        assert_eq!(empty.seek(TERMINATED), TERMINATED);
        let (reader, query) = fixture(3, 3);
        let searcher = reader.searcher();
        let mut scorer = query
            .weight(EnableScoring::disabled_from_searcher(&searcher))
            .unwrap()
            .scorer(searcher.segment_reader(0), 1.0)
            .unwrap();
        assert_eq!(scorer.seek(TERMINATED), TERMINATED);
        assert_eq!(scorer.advance(), TERMINATED);
        assert_eq!(scorer.score(), 0.0);
    }
    #[test]
    fn minimum_match_no_score_count() {
        let (reader, query) = fixture(3, 5);
        let searcher = reader.searcher();
        let weight = query
            .weight(EnableScoring::disabled_from_searcher(&searcher))
            .unwrap();
        assert_eq!(weight.count(searcher.segment_reader(0)).unwrap(), 16);
        let mut found = Vec::new();
        weight
            .for_each_no_score(searcher.segment_reader(0), &mut |docs| {
                found.extend_from_slice(docs)
            })
            .unwrap();
        assert_eq!(found.len(), 16);
    }
    #[test]
    fn minimum_match_constructor_bounds() {
        let child = || Box::new(tantivy::query::EmptyQuery) as Box<dyn Query>;
        assert!(MinimumMatch::new(0, vec![child()]).is_err());
        assert!(MinimumMatch::new(2, vec![child()]).is_err());
        assert!(MinimumMatch::new(1, (0..33).map(|_| child()).collect()).is_err());
        assert!(MinimumMatch::new(32, (0..32).map(|_| child()).collect()).is_ok());
    }
}
