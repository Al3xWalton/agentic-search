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
// along with this program.  If not, see <https://www.gnu.org/licenses/

use itertools::Itertools;
mod minimum_match;
mod node;
pub mod render;

pub use node::Node;

use crate::schema::{self, text_field::TextField, TextFieldEnum};

use super::{
    parser::{SimpleOrPhrase, SimpleTerm},
    MAX_TERMS_FOR_NGRAM_LOOKUPS,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Term {
    text: SimpleOrPhrase,
    field: schema::TextFieldEnum,
}

impl Term {
    pub fn new(text: SimpleOrPhrase, field: TextFieldEnum) -> Self {
        Term { text, field }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Occur {
    Must,
    Should,
    MustNot,
}

impl Occur {
    pub fn compose(left: Occur, right: Occur) -> Occur {
        match (left, right) {
            (Occur::Should, _) => right,
            (Occur::Must, Occur::MustNot) => Occur::MustNot,
            (Occur::Must, _) => Occur::Must,
            (Occur::MustNot, Occur::MustNot) => Occur::Must,
            (Occur::MustNot, _) => Occur::MustNot,
        }
    }
}

impl From<Occur> for tantivy::query::Occur {
    fn from(value: Occur) -> Self {
        match value {
            Occur::Must => tantivy::query::Occur::Must,
            Occur::Should => tantivy::query::Occur::Should,
            Occur::MustNot => tantivy::query::Occur::MustNot,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Query {
    Term(Term),
    Boolean {
        clauses: Vec<(Occur, Query)>,
    },
    /// Threshold over complete atom queries, bounded by the compiler to 32 children.
    AtLeast {
        /// Required complete-atom votes, validated by the bounded adapter.
        minimum: usize,
        /// Complete atom queries; optimizers must not flatten these into field votes.
        children: Vec<Query>,
    },
}

impl Query {
    #[cfg(test)]
    pub fn len(&self) -> usize {
        match self {
            Query::Term(_) => 1,
            Query::AtLeast { children, .. } => children.iter().map(Query::len).sum(),
            Query::Boolean { clauses } => clauses.iter().map(|(_, q)| q.len()).sum(),
        }
    }

    fn compact(self) -> Query {
        match self {
            query @ Query::AtLeast { .. } => query,
            Query::Boolean { clauses } => {
                let mut new_clauses = vec![];
                for (occur, query) in clauses {
                    let query = query.compact();
                    // if the query is a boolean query, and it has the same occur as the current
                    // query, we can merge the clauses into the current query
                    // otherwise, we add the clause as is
                    match query {
                        Query::Boolean {
                            clauses: inner_clauses,
                        } if inner_clauses
                            .iter()
                            .all(|(inner_occur, _)| occur == *inner_occur) =>
                        {
                            new_clauses.extend(inner_clauses);
                        }

                        Query::Boolean {
                            clauses: inner_clauses,
                        } if inner_clauses.len() == 1 => {
                            let (inner_occur, q) = inner_clauses.into_iter().next().unwrap();

                            new_clauses.push((Occur::compose(occur, inner_occur), q));
                        }

                        _ => new_clauses.push((occur, query)),
                    }
                }
                Query::Boolean {
                    clauses: new_clauses,
                }
            }
            Query::Term(term) => Query::Term(term),
        }
    }

    fn deduplicate(self) -> Query {
        match self {
            query @ Query::AtLeast { .. } => query,
            Query::Boolean { clauses } => Query::Boolean {
                clauses: clauses
                    .into_iter()
                    .map(|(occur, query)| (occur, query.deduplicate()))
                    .unique()
                    .collect(),
            },
            Query::Term(term) => Query::Term(term),
        }
    }
}

fn sliding_window(window_size: usize, i: usize) -> impl Iterator<Item = (usize, usize)> {
    (0..=window_size)
        .map(move |offset| {
            let start = (i + offset).saturating_sub(window_size);
            let end = i + offset;

            (start, end)
        })
        .filter(|(start, end)| start < end)
        .filter(|(start, end)| end != start)
}

pub fn initial(terms: Vec<super::Term>) -> Option<Node> {
    let mut nodes = Vec::new();
    let terms_for_adjacent = terms.clone();

    let augment_with_adjacent = terms.len() <= MAX_TERMS_FOR_NGRAM_LOOKUPS;

    for (i, term) in terms.into_iter().enumerate() {
        let mut adjacent = Vec::new();

        if augment_with_adjacent {
            if let super::Term::SimpleOrPhrase(SimpleOrPhrase::Simple(_)) = &term {
                for window_size in 2..=3 {
                    for (start, end) in sliding_window(window_size, i) {
                        let mut compounds = Vec::new();

                        for k in start..=end {
                            if let Some(super::Term::SimpleOrPhrase(
                                super::SimpleOrPhrase::Simple(s),
                            )) = terms_for_adjacent.get(k)
                            {
                                compounds.push(s.clone());
                            }
                        }

                        if !compounds.is_empty() {
                            adjacent.push(super::TermCompound { terms: compounds });
                        }
                    }
                }
            }
        }

        let node = Node::from_term(term);

        if !adjacent.is_empty() {
            match adjacent
                .into_iter()
                .flat_map(|compound| {
                    TextFieldEnum::all()
                        .filter(|f| f.is_searchable())
                        .filter(|f| f.is_compound_searchable())
                        .map(move |field| {
                            let compound_text: String = compound
                                .terms
                                .iter()
                                .map(|s| s.as_str().to_string())
                                .collect();

                            Node::Term(Term {
                                text: SimpleOrPhrase::Simple(SimpleTerm::from(compound_text)),
                                field,
                            })
                        })
                })
                .reduce(|left, right| left.or(right))
            {
                Some(adj) => nodes.push(node.or(adj)),
                None => nodes.push(node),
            }
        } else {
            nodes.push(node);
        }
    }

    nodes.into_iter().reduce(|left, right| left.and(right))
}

#[cfg(test)]
mod tests {
    use crate::schema::text_field;

    use super::*;

    fn parse(query: &str, fields: &[TextFieldEnum]) -> Node {
        let terms = query
            .split_whitespace()
            .map(|s| SimpleTerm::from(s.to_string()))
            .collect::<Vec<_>>();

        let mut queries = vec![];

        for term in terms {
            let nodes: Vec<_> = fields
                .iter()
                .copied()
                .map(|f| {
                    Node::Term(Term {
                        text: SimpleOrPhrase::Simple(term.clone()),
                        field: f,
                    })
                })
                .collect();

            let term_q = if nodes.len() == 1 {
                nodes[0].clone()
            } else {
                nodes
                    .into_iter()
                    .reduce(|left, right| left.or(right))
                    .unwrap()
            };

            queries.push(term_q);
        }

        if queries.len() == 1 {
            queries[0].clone()
        } else {
            queries
                .into_iter()
                .reduce(|left, right| left.and(right))
                .unwrap()
        }
    }

    #[test]
    fn test_compact() {
        let query = Query::Boolean { clauses: vec![] };

        assert_eq!(query.clone().compact(), query);

        let query = parse(
            "foo bar",
            &[text_field::Title.into(), text_field::AllBody.into()],
        );

        let expected = Query::Boolean {
            clauses: vec![
                (
                    Occur::Must,
                    Query::Boolean {
                        clauses: vec![
                            (
                                Occur::Should,
                                Query::Term(Term {
                                    text: SimpleOrPhrase::Simple(SimpleTerm::from(
                                        "foo".to_string(),
                                    )),
                                    field: text_field::Title.into(),
                                }),
                            ),
                            (
                                Occur::Should,
                                Query::Term(Term {
                                    text: SimpleOrPhrase::Simple(SimpleTerm::from(
                                        "foo".to_string(),
                                    )),
                                    field: text_field::AllBody.into(),
                                }),
                            ),
                        ],
                    },
                ),
                (
                    Occur::Must,
                    Query::Boolean {
                        clauses: vec![
                            (
                                Occur::Should,
                                Query::Term(Term {
                                    text: SimpleOrPhrase::Simple(SimpleTerm::from(
                                        "bar".to_string(),
                                    )),
                                    field: text_field::Title.into(),
                                }),
                            ),
                            (
                                Occur::Should,
                                Query::Term(Term {
                                    text: SimpleOrPhrase::Simple(SimpleTerm::from(
                                        "bar".to_string(),
                                    )),
                                    field: text_field::AllBody.into(),
                                }),
                            ),
                        ],
                    },
                ),
            ],
        };

        assert_eq!(query.into_query().compact(), expected);
    }

    #[test]
    fn test_sliding_window() {
        let window_size = 3;
        let i = 3;

        let expected = vec![(0, 3), (1, 4), (2, 5), (3, 6)];

        assert_eq!(sliding_window(window_size, i).collect::<Vec<_>>(), expected);

        let window_size = 2;
        let i = 3;

        let expected = vec![(1, 3), (2, 4), (3, 5)];

        assert_eq!(sliding_window(window_size, i).collect::<Vec<_>>(), expected);

        let window_size = 2;
        let i = 0;

        let expected = vec![(0, 1), (0, 2)];

        assert_eq!(sliding_window(window_size, i).collect::<Vec<_>>(), expected);
    }
}
