// Stract is an open source web search engine.
// Copyright (C) 2023 Stract ApS
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

use crate::{
    inverted_index::InvertedIndex,
    query::parser::TermCompound,
    ranking::SignalCoefficients,
    schema::text_field,
    search_ctx::Ctx,
    searcher::SearchQuery,
    webpage::{region::Region, safety_classifier},
    Result,
};

use optics::{HostRankings, Optic};

use tantivy::query::{BooleanQuery, Occur, QueryClone};

mod const_query;
pub mod intersection;
pub mod optic;
pub mod parser;
mod pattern_query;
mod plan;
pub mod planner;
pub mod union;

use self::{optic::AsMultipleTantivyQuery, parser::SimpleOrPhrase};
use parser::Term;

pub const MAX_TERMS_FOR_NGRAM_LOOKUPS: usize = 16;

#[derive(Debug)]
pub struct Query {
    simple_terms_text: Vec<String>,
    tantivy_query: Box<dyn tantivy::query::Query>,
    host_rankings: HostRankings,
    offset: usize,
    region: Option<Region>,
    optics: Vec<Optic>,
    top_n: usize,
    count_results_exact: bool,
    signal_coefficients: SignalCoefficients,
    lang: Option<whatlang::Lang>,
    rendered_query: String,
    preference_queries: Vec<std::sync::Arc<dyn tantivy::query::Query>>,
}

struct CompiledStage {
    query: Box<dyn tantivy::query::Query>,
    rendered: String,
    preferences: Vec<std::sync::Arc<dyn tantivy::query::Query>>,
    lang: Option<whatlang::Lang>,
    simple_terms: Vec<String>,
}

impl Query {
    fn compile_stage(
        query: &SearchQuery,
        schema: &tantivy::schema::Schema,
    ) -> Result<CompiledStage, planner::bounds::InputError> {
        use planner::{bounds::InputError, AgentPlan};
        planner::bounds::validate_numbers(query.page, query.num_results, false)?;
        let strict;
        let stage = match &query.stage_plan {
            Some(stage) if stage.original == query.query => stage,
            Some(_) => return Err(InputError::InvalidQuerySyntax),
            None => {
                strict = AgentPlan::new(&query.query)?.stages.remove(0);
                &strict
            }
        };
        let lang = stage.lang()?;
        let mut budget = plan::render::Budget::default();
        // Validate whole atoms before compound alternatives can conceal a tokenless mandatory atom.
        for atom in &stage.atoms {
            plan::render::compile(
                &plan::Node::from_term(atom.source.term.clone()).into_query(),
                lang.as_ref(),
                schema,
                &mut budget,
            )?;
        }
        let mut node = stage.node()?;
        if query.safe_search {
            node = node.and(plan::Node::Not(Box::new(plan::Node::Term(
                plan::Term::new(
                    parser::SimpleTerm::from(safety_classifier::Label::NSFW.to_string()).into(),
                    text_field::SafetyClassification.into(),
                ),
            ))));
        }
        let compiled =
            plan::render::compile(&node.into_query(), lang.as_ref(), schema, &mut budget)?;
        let mut rendered = compiled.rendered;
        let mut preferences = Vec::new();
        for preference in &stage.preferences {
            let preferred = plan::render::compile(
                &plan::Node::from_term(preference.term.clone()).into_query(),
                lang.as_ref(),
                schema,
                &mut budget,
            )?;
            budget.push(&mut rendered, ";PREFERENCE(weight=2,")?;
            rendered.push_str(&preferred.rendered);
            budget.push(&mut rendered, ")")?;
            preferences.push(std::sync::Arc::from(preferred.query));
        }
        for (name, value) in [
            ("optic", query.optic.as_ref().map(serde_json::to_vec)),
            (
                "host_rankings",
                query.host_rankings.as_ref().map(serde_json::to_vec),
            ),
        ] {
            if let Some(value) = value {
                budget.nodes(1)?;
                let bytes = value.map_err(|_| InputError::InvalidRequest)?;
                let digest: String = ring::digest::digest(&ring::digest::SHA256, &bytes)
                    .as_ref()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                budget.push(&mut rendered, &format!(";FILTER({name},sha256={digest})"))?;
            }
        }
        Ok(CompiledStage {
            query: compiled.query,
            rendered,
            preferences,
            lang,
            simple_terms: stage.simple_terms(),
        })
    }

    /// Compile the coordinator schema's complete safe query description, with typed input limits.
    pub fn render_query(query: &SearchQuery) -> Result<String, planner::bounds::InputError> {
        Self::compile_stage(query, &crate::schema::create_schema())
            .map(|compiled| compiled.rendered)
    }

    /// Actual bounded rendering produced while constructing this executable query.
    pub fn rendered_query(&self) -> &str {
        &self.rendered_query
    }

    /// Optional compiled predicates; each contributes at most one ranking preference vote.
    pub fn preference_queries(&self) -> &[std::sync::Arc<dyn tantivy::query::Query>] {
        &self.preference_queries
    }
}

impl Clone for Query {
    fn clone(&self) -> Self {
        Self {
            simple_terms_text: self.simple_terms_text.clone(),
            tantivy_query: self.tantivy_query.box_clone(),
            host_rankings: self.host_rankings.clone(),
            offset: self.offset,
            region: self.region,
            optics: self.optics.clone(),
            top_n: self.top_n,
            count_results_exact: self.count_results_exact,
            signal_coefficients: self.signal_coefficients.clone(),
            lang: self.lang,
            rendered_query: self.rendered_query.clone(),
            preference_queries: self.preference_queries.clone(),
        }
    }
}

impl Query {
    pub fn parse(ctx: &Ctx, query: &SearchQuery, index: &InvertedIndex) -> Result<Query> {
        if query.stage_plan.is_none() && query.query.is_empty() {
            return Err(crate::Error::EmptyQuery.into());
        }
        let compiled = Self::compile_stage(query, &index.schema())?;
        let lang = compiled.lang;
        let simple_terms_text = compiled.simple_terms;
        let mut tantivy_query = compiled.query;
        let schema = index.schema();
        let mut optics = Vec::new();
        if let Some(site_rankigns_optic) = query.host_rankings.clone().map(|sr| sr.into_optic()) {
            optics.push(site_rankigns_optic);
        }

        if let Some(optic) = &query.optic {
            optics.push(optic.clone());
        }

        for optic in &optics {
            let mut subqueries = vec![(Occur::Must, tantivy_query.box_clone())];
            subqueries.append(&mut optic.as_multiple_tantivy(&schema, &ctx.columnfield_reader));
            tantivy_query = Box::new(BooleanQuery::new(subqueries));
        }

        Ok(Query {
            host_rankings: optics.iter().fold(HostRankings::default(), |mut acc, el| {
                acc.merge_into(el.host_rankings.clone());
                acc
            }),
            simple_terms_text,
            tantivy_query,
            optics,
            offset: planner::bounds::validate_numbers(query.page, query.num_results, false)?,
            region: query.selected_region,
            top_n: query.num_results,
            count_results_exact: query.count_results_exact
                || query
                    .stage_plan
                    .as_ref()
                    .is_some_and(|p| p.id != planner::StageId::Strict),
            signal_coefficients: query.signal_coefficients(),
            lang,
            rendered_query: compiled.rendered,
            preference_queries: compiled.preferences,
        })
    }

    pub fn count_results_exact(&self) -> bool {
        self.count_results_exact
    }

    pub fn simple_terms(&self) -> &[String] {
        &self.simple_terms_text
    }

    pub fn optics(&self) -> &[Optic] {
        &self.optics
    }

    pub fn num_results(&self) -> usize {
        self.top_n
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn region(&self) -> Option<&Region> {
        self.region.as_ref()
    }

    pub fn host_rankings(&self) -> &HostRankings {
        &self.host_rankings
    }

    pub fn signal_coefficients(&self) -> SignalCoefficients {
        self.signal_coefficients.clone()
    }

    pub fn lang(&self) -> Option<whatlang::Lang> {
        self.lang
    }
}

impl tantivy::query::Query for Query {
    fn weight(
        &self,
        enable_scoring: tantivy::query::EnableScoring,
    ) -> tantivy::Result<Box<dyn tantivy::query::Weight>> {
        self.tantivy_query.weight(enable_scoring)
    }

    fn query_terms<'a>(&'a self, visitor: &mut dyn FnMut(&'a tantivy::Term, bool)) {
        self.tantivy_query.query_terms(visitor)
    }
}

#[cfg(test)]
mod tests {
    use crate::Error;
    use std::sync::Arc;

    use crate::{index::Index, rand_words, searcher::LocalSearcher, webpage::Webpage};
    use proptest::prelude::*;
    use tokio::sync::RwLock;

    use super::*;

    fn empty_index() -> (InvertedIndex, file_store::temp::TempDir) {
        InvertedIndex::temporary().unwrap()
    }

    #[test]
    fn simple_parse() {
        let (index, _dir) = empty_index();
        let ctx = index.local_search_ctx();

        let query = Query::parse(
            &ctx,
            &SearchQuery {
                query: "this is a simple query".to_string(),
                ..Default::default()
            },
            &index,
        )
        .expect("Failed to parse query");

        assert_eq!(
            query.simple_terms(),
            vec![
                "this".to_string(),
                "is".to_string(),
                "a".to_string(),
                "simple".to_string(),
                "query".to_string(),
            ]
        );
    }

    #[test]
    fn parse_trailing_leading_whitespace() {
        let (index, _dir) = empty_index();
        let ctx = index.local_search_ctx();

        let query = Query::parse(
            &ctx,
            &SearchQuery {
                query: "   this is a simple query   ".to_string(),
                ..Default::default()
            },
            &index,
        )
        .expect("Failed to parse query");

        assert_eq!(
            query.simple_terms(),
            vec![
                "this".to_string(),
                "is".to_string(),
                "a".to_string(),
                "simple".to_string(),
                "query".to_string(),
            ]
        );
    }

    #[test]
    fn parse_weird_characters() {
        let (index, _dir) = empty_index();
        let ctx = index.local_search_ctx();

        let terms = Query::parse(
            &ctx,
            &SearchQuery {
                query: "123".to_string(),
                ..Default::default()
            },
            &index,
        )
        .expect("Failed to parse query")
        .simple_terms()
        .to_vec();
        assert_eq!(terms, vec!["123".to_string()]);

        let terms = Query::parse(
            &ctx,
            &SearchQuery {
                query: "123 33".to_string(),
                ..Default::default()
            },
            &index,
        )
        .expect("Failed to parse query")
        .simple_terms()
        .to_vec();
        assert_eq!(terms, vec!["123".to_string(), "33".to_string()]);

        let terms = Query::parse(
            &ctx,
            &SearchQuery {
                query: "term! term# $".to_string(),
                ..Default::default()
            },
            &index,
        )
        .expect("Failed to parse query")
        .simple_terms()
        .to_vec();
        assert_eq!(
            terms,
            vec!["term!".to_string(), "term#".to_string(), "$".to_string()]
        );
    }

    #[test]
    fn simple_terms_phrase() {
        let (index, _dir) = empty_index();
        let ctx = index.local_search_ctx();

        let terms = Query::parse(
            &ctx,
            &SearchQuery {
                query: "\"test term\"".to_string(),
                ..Default::default()
            },
            &index,
        )
        .expect("Failed to parse query")
        .simple_terms()
        .to_vec();

        assert_eq!(terms, vec!["test".to_string(), "term".to_string()]);
    }

    #[test]
    fn not_query() {
        let (mut index, _dir) = Index::temporary().expect("Unable to open index");
        let query = SearchQuery {
            query: "test -website".to_string(),
            ..Default::default()
        };

        index
            .insert(
                &Webpage::test_parse(
                    r#"
                        <html>
                            <head>
                                <title>Test website</title>
                            </head>
                            <body>
                                This is a test website
                            </body>
                        </html>
                    "#,
                    "https://www.first.com",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index
            .insert(
                &Webpage::test_parse(
                    r#"
                        <html>
                            <head>
                                <title>Test test</title>
                            </head>
                            <body>
                                This test page does not contain the forbidden word
                            </body>
                        </html>
                    "#,
                    "https://www.second.com",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index.commit().expect("failed to commit index");
        let searcher = LocalSearcher::builder(Arc::new(RwLock::new(index))).build();

        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 1);
        assert_eq!(result.webpages[0].url, "https://www.second.com/");
    }

    #[test]
    fn site_query() {
        let (mut index, _dir) = Index::temporary().expect("Unable to open index");

        index
            .insert(
                &Webpage::test_parse(
                    r#"
                        <html>
                            <head>
                                <title>Test website</title>
                            </head>
                            <body>
                                This is a test website
                            </body>
                        </html>
                    "#,
                    "https://www.first.com",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index
            .insert(
                &Webpage::test_parse(
                    r#"
                        <html>
                            <head>
                                <title>Test test</title>
                            </head>
                            <body>
                                This test page does not contain the forbidden word
                            </body>
                        </html>
                    "#,
                    "https://www.second.com",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index
            .insert(
                &Webpage::test_parse(
                    r#"
                        <html>
                            <head>
                                <title>Test test</title>
                            </head>
                            <body>
                                This test page does not contain the forbidden word
                            </body>
                        </html>
                    "#,
                    "https://www.second.com/first",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index.commit().expect("failed to commit index");
        let searcher = LocalSearcher::builder(Arc::new(RwLock::new(index))).build();

        let query = SearchQuery {
            query: "test site:first.com".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 1);
        assert_eq!(result.webpages[0].url, "https://www.first.com/");

        let query = SearchQuery {
            query: "test site:www.first.com".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 1);
        assert_eq!(result.webpages[0].url, "https://www.first.com/");

        let query = SearchQuery {
            query: "test -site:first.com".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 2);

        assert!(result
            .webpages
            .iter()
            .all(|w| w.url != "https://www.first.com/"));
    }

    #[test]
    fn links_to_query() {
        let (mut index, _dir) = Index::temporary().expect("Unable to open index");

        index
            .insert(
                &Webpage::test_parse(
                    r#"
                        <html>
                            <head>
                                <title>Test website</title>
                            </head>
                            <body>
                                This is a test website
                                <a href="https://www.second.com/example/abc">Second</a>
                            </body>
                        </html>
                    "#,
                    "https://www.first.com",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index
            .insert(
                &Webpage::test_parse(
                    r#"
                        <html>
                            <head>
                                <title>Test test</title>
                            </head>
                            <body>
                                This test page does not contain the forbidden word
                                <a href="https://www.first.com">First</a>
                            </body>
                        </html>
                    "#,
                    "https://www.second.com/example/abc",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index.commit().expect("failed to commit index");
        let searcher = LocalSearcher::builder(Arc::new(RwLock::new(index))).build();

        let query = SearchQuery {
            query: "test linksto:first.com".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 1);
        assert_eq!(result.webpages[0].url, "https://www.second.com/example/abc");

        let query = SearchQuery {
            query: "test linkto:www.first.com".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 1);
        assert_eq!(result.webpages[0].url, "https://www.second.com/example/abc");

        let query = SearchQuery {
            query: "test -linkto:first.com".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 1);
        assert_eq!(result.webpages[0].url, "https://www.first.com/");

        let query = SearchQuery {
            query: "test linkto:second.com".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 1);
        assert_eq!(result.webpages[0].url, "https://www.first.com/");

        let query = SearchQuery {
            query: "test linkto:www.second.com".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 1);
        assert_eq!(result.webpages[0].url, "https://www.first.com/");

        let query = SearchQuery {
            query: "test linkto:second.com/example".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 1);
        assert_eq!(result.webpages[0].url, "https://www.first.com/");

        let query = SearchQuery {
            query: "test linksto:second.com/example/abc".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 1);
        assert_eq!(result.webpages[0].url, "https://www.first.com/");
    }

    #[test]
    fn links_to_uppercase() {
        let (mut index, _dir) = Index::temporary().expect("Unable to open index");

        index
            .insert(
                &Webpage::test_parse(
                    r#"
                        <html>
                            <head>
                                <title>Test website</title>
                            </head>
                            <body>
                                This is a test website
                                <a href="https://www.SeCoNd.CoM/eXaMpLe/AbC">Second</a>
                            </body>
                        </html>
                    "#,
                    "https://www.first.com",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index
            .insert(
                &Webpage::test_parse(
                    r#"
                        <html>
                            <head>
                                <title>Test test</title>
                            </head>
                            <body>
                                This test page does not contain the forbidden word
                                <a href="https://www.first.com">First</a>
                            </body>
                        </html>
                    "#,
                    "https://www.second.com/example/AbC",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index.commit().expect("failed to commit index");
        let searcher = LocalSearcher::builder(Arc::new(RwLock::new(index))).build();

        let query = SearchQuery {
            query: "test linkto:second.com".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 1);
        assert_eq!(result.webpages[0].url, "https://www.first.com/");
    }

    #[test]
    fn title_query() {
        let (mut index, _dir) = Index::temporary().expect("Unable to open index");

        index
            .insert(
                &Webpage::test_parse(
                    r#"
                        <html>
                            <head>
                                <title>Test website</title>
                            </head>
                            <body>
                                This is a test website
                            </body>
                        </html>
                    "#,
                    "https://www.first.com",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index
            .insert(
                &Webpage::test_parse(
                    r#"
                        <html>
                            <head>
                                <title>Test test</title>
                            </head>
                            <body>
                                This is a test website
                            </body>
                        </html>
                    "#,
                    "https://www.second.com",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index.commit().expect("failed to commit index");
        let searcher = LocalSearcher::builder(Arc::new(RwLock::new(index))).build();

        let query = SearchQuery {
            query: "intitle:website".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 1);
        assert_eq!(result.webpages[0].url, "https://www.first.com/");
    }

    #[test]
    fn url_query() {
        let (mut index, _dir) = Index::temporary().expect("Unable to open index");

        index
            .insert(
                &Webpage::test_parse(
                    r#"
                        <html>
                            <head>
                                <title>Test website</title>
                            </head>
                            <body>
                                This is a test website
                            </body>
                        </html>
                    "#,
                    "https://www.first.com/forum",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index
            .insert(
                &Webpage::test_parse(
                    r#"
                        <html>
                            <head>
                                <title>Test test</title>
                            </head>
                            <body>
                                This is a test website
                            </body>
                        </html>
                    "#,
                    "https://www.second.com",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index.commit().expect("failed to commit index");
        let searcher = LocalSearcher::builder(Arc::new(RwLock::new(index))).build();

        let query = SearchQuery {
            query: "test inurl:forum".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 1);
        assert_eq!(result.webpages[0].url, "https://www.first.com/forum");
    }

    #[test]
    fn empty_query() {
        let (index, _dir) = empty_index();
        let ctx = index.local_search_ctx();

        let query = Query::parse(
            &ctx,
            &SearchQuery {
                query: "".to_string(),
                ..Default::default()
            },
            &index,
        );

        assert!(query.is_err());
        assert_eq!(
            query.err().unwrap().to_string(),
            anyhow::Error::from(Error::EmptyQuery).to_string()
        );
    }

    #[test]
    fn query_term_only_special_char() {
        let (index, _dir) = empty_index();
        let ctx = index.local_search_ctx();

        let _query = Query::parse(
            &ctx,
            &SearchQuery {
                query: "&".to_string(),
                ..Default::default()
            },
            &index,
        )
        .expect("Failed to parse query");
    }

    #[test]
    fn site_query_split_domain() {
        let (mut index, _dir) = Index::temporary().expect("Unable to open index");

        index
            .insert(
                &Webpage::test_parse(
                    &format!(
                        r#"
                        <html>
                            <head>
                                <title>Test website</title>
                            </head>
                            <body>
                                This is a test website {}
                            </body>
                        </html>
                    "#,
                        rand_words(1000)
                    ),
                    "https://www.the-first.com",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index
            .insert(
                &Webpage::test_parse(
                    &format!(
                        r#"
                        <html>
                            <head>
                                <title>Test test</title>
                            </head>
                            <body>
                                This test page does not contain the forbidden word {}
                            </body>
                        </html>
                    "#,
                        rand_words(1000)
                    ),
                    "https://www.second.com",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index.commit().expect("failed to commit index");
        let searcher = LocalSearcher::builder(Arc::new(RwLock::new(index))).build();

        let query = SearchQuery {
            query: "test site:first.com".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 0);

        let query = SearchQuery {
            query: "test site:the-first.com".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 1);
        assert_eq!(result.webpages[0].url, "https://www.the-first.com/");

        let query = SearchQuery {
            query: "test site:www.the-first.com".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 1);
        assert_eq!(result.webpages[0].url, "https://www.the-first.com/");
    }

    #[test]
    fn phrase_query() {
        let (mut index, _dir) = Index::temporary().expect("Unable to open index");

        index
            .insert(
                &Webpage::test_parse(
                    &format!(
                        r#"
                        <html>
                            <head>
                                <title>Test website</title>
                            </head>
                            <body>
                                This is a test website {}
                            </body>
                        </html>
                    "#,
                        rand_words(1000)
                    ),
                    "https://www.first.com",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index
            .insert(
                &Webpage::test_parse(
                    &format!(
                        r#"
                        <html>
                            <head>
                                <title>Test test</title>
                            </head>
                            <body>
                                This is a bad test website {}
                            </body>
                        </html>
                    "#,
                        rand_words(1000)
                    ),
                    "https://www.second.com",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index.commit().expect("failed to commit index");
        let searcher = LocalSearcher::builder(Arc::new(RwLock::new(index))).build();

        let query = SearchQuery {
            query: "\"Test website\"".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 1);
        assert_eq!(result.webpages[0].url, "https://www.first.com/");

        let query = SearchQuery {
            query: "\"Test website\" site:www.second.com".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 0);
    }

    #[test]
    fn match_compound_words() {
        let (mut index, _dir) = Index::temporary().expect("Unable to open index");

        index
            .insert(
                &Webpage::test_parse(
                    &format!(
                        r#"
                        <html>
                            <head>
                                <title>Test website</title>
                            </head>
                            <body>
                                This is a test website {}
                            </body>
                        </html>
                    "#,
                        rand_words(1000)
                    ),
                    "https://www.first.com",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");

        index
            .insert(
                &Webpage::test_parse(
                    &format!(
                        r#"
                        <html>
                            <head>
                                <title>Testwebsite</title>
                            </head>
                            <body>
                                This is a testwebsite {}
                            </body>
                        </html>
                    "#,
                        rand_words(1000)
                    ),
                    "https://www.second.com",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");

        index.commit().expect("failed to commit index");
        let searcher = LocalSearcher::builder(Arc::new(RwLock::new(index))).build();

        let query = SearchQuery {
            query: "testwebsite".to_string(),
            ..Default::default()
        };

        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 2);

        let query = SearchQuery {
            query: "test website".to_string(),
            ..Default::default()
        };

        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 2);
    }

    #[test]
    fn deduplicate_terms() {
        let a = parser::parse("the the the the the").unwrap();
        let a = plan::initial(a).unwrap();
        let a = a.into_query();

        let b = parser::parse("the the the the the the the the the the the the").unwrap();
        let b = plan::initial(b).unwrap();
        let b = b.into_query();

        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn safe_search() {
        let (mut index, _dir) = Index::temporary().expect("Unable to open index");
        let mut webpage = Webpage::test_parse(
            &format!(
                r#"
                <html>
                    <head>
                        <title>Test website</title>
                    </head>
                    <body>
                        This is a test website {}
                    </body>
                </html>
            "#,
                rand_words(1000)
            ),
            "https://www.sfw.com",
        )
        .unwrap();

        webpage.safety_classification = Some(safety_classifier::Label::SFW);
        webpage.html.set_clean_text("sfw".to_string());

        index.insert(&webpage).expect("failed to insert webpage");

        let mut webpage = Webpage::test_parse(
            &format!(
                r#"
                <html>
                    <head>
                        <title>Test website</title>
                    </head>
                    <body>
                        This is a test website {}
                    </body>
                </html>
            "#,
                rand_words(1000)
            ),
            "https://www.nsfw.com",
        )
        .unwrap();

        webpage.safety_classification = Some(safety_classifier::Label::NSFW);
        webpage.html.set_clean_text("nsfw".to_string());

        index.insert(&webpage).expect("failed to insert webpage");

        index.commit().expect("failed to commit index");
        let searcher = LocalSearcher::builder(Arc::new(RwLock::new(index))).build();

        let query = SearchQuery {
            query: "test".to_string(),
            safe_search: false,
            ..Default::default()
        };

        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 2);

        let query = SearchQuery {
            query: "test".to_string(),
            safe_search: true,
            ..Default::default()
        };

        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 1);

        assert_eq!(result.webpages[0].url, "https://www.sfw.com/");
    }

    #[test]
    fn suffix_domain_prefix_path_site_operator() {
        let (mut index, _dir) = Index::temporary().expect("Unable to open index");

        index
            .insert(
                &Webpage::test_parse(
                    &format!(
                        r#"
                        <html>
                            <head>
                                <title>Test website</title>
                            </head>
                            <body>
                                This is a test website {}
                            </body>
                        </html>
                    "#,
                        rand_words(1000)
                    ),
                    "https://www.first.com/example",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index
            .insert(
                &Webpage::test_parse(
                    &format!(
                        r#"
                        <html>
                            <head>
                                <title>Test test</title>
                            </head>
                            <body>
                                This is a test website {}
                            </body>
                        </html>
                    "#,
                        rand_words(1000)
                    ),
                    "https://www.second.com",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index
            .insert(
                &Webpage::test_parse(
                    &format!(
                        r#"
                        <html>
                            <head>
                                <title>Test test</title>
                            </head>
                            <body>
                                This is a test website {}
                            </body>
                        </html>
                    "#,
                        rand_words(1000)
                    ),
                    "https://www.third.io",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index.commit().expect("failed to commit index");
        let searcher = LocalSearcher::builder(Arc::new(RwLock::new(index))).build();

        let query = SearchQuery {
            query: "test site:.com".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 2);

        let query = SearchQuery {
            query: "test site:.com/example".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 1);

        let query = SearchQuery {
            query: "test site:first.com/example".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 1);

        let query = SearchQuery {
            query: "test site:first.com".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 1);

        let query = SearchQuery {
            query: "test site:www.first.com".to_string(),
            ..Default::default()
        };

        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 1);
    }

    #[test]
    fn exact_url_operator() {
        let (mut index, _dir) = Index::temporary().expect("Unable to open index");

        index
            .insert(
                &Webpage::test_parse(
                    &format!(
                        r#"
                        <html>
                            <head>
                                <title>Test website</title>
                            </head>
                            <body>
                                This is a test website {}
                            </body>
                        </html>
                    "#,
                        rand_words(1000)
                    ),
                    "https://www.first.com/example",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index
            .insert(
                &Webpage::test_parse(
                    &format!(
                        r#"
                        <html>
                            <head>
                                <title>Test test</title>
                            </head>
                            <body>
                                This is a test website {}
                            </body>
                        </html>
                    "#,
                        rand_words(1000)
                    ),
                    "https://www.second.com",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index
            .insert(
                &Webpage::test_parse(
                    &format!(
                        r#"
                        <html>
                            <head>
                                <title>Test test</title>
                            </head>
                            <body>
                                This is a test website {}
                            </body>
                        </html>
                    "#,
                        rand_words(1000)
                    ),
                    "https://www.third.io",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index.commit().expect("failed to commit index");
        let searcher = LocalSearcher::builder(Arc::new(RwLock::new(index))).build();

        let query = SearchQuery {
            query: "test exacturl:https://www.first.com/example".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 1);

        let query = SearchQuery {
            query: "test exacturl:https://www.first.com".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 0);
    }

    #[test]
    fn mix_phrase_term_query() {
        let (mut index, _dir) = Index::temporary().expect("Unable to open index");

        index
            .insert(
                &Webpage::test_parse(
                    &format!(
                        r#"
                        <html>
                            <head>
                                <title>Test website</title>
                            </head>
                            <body>
                                This is a test website {}
                            </body>
                        </html>
                    "#,
                        rand_words(1000)
                    ),
                    "https://www.first.com/example",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index
            .insert(
                &Webpage::test_parse(
                    &format!(
                        r#"
                        <html>
                            <head>
                                <title>Test test</title>
                            </head>
                            <body>
                                This is a test website {}
                            </body>
                        </html>
                    "#,
                        rand_words(1000)
                    ),
                    "https://www.second.com",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index
            .insert(
                &Webpage::test_parse(
                    &format!(
                        r#"
                        <html>
                            <head>
                                <title>Test test</title>
                            </head>
                            <body>
                                This is a test website {}
                            </body>
                        </html>
                    "#,
                        rand_words(1000)
                    ),
                    "https://www.third.io",
                )
                .unwrap(),
            )
            .expect("failed to insert webpage");
        index.commit().expect("failed to commit index");
        let searcher = LocalSearcher::builder(Arc::new(RwLock::new(index))).build();

        let query = SearchQuery {
            query: "\"test test\" website".to_string(),
            ..Default::default()
        };
        let result = searcher.search_sync(&query).expect("Search failed");
        assert_eq!(result.webpages.len(), 2);
    }

    fn fixture(query: &str) -> Result<(), TestCaseError> {
        if query.trim().is_empty() {
            return Ok(());
        }

        let parsed_terms = parser::truncate(
            parser::parse(query).map_err(|_| TestCaseError::fail("parse failed"))?,
        );
        let plan =
            plan::initial(parsed_terms).ok_or(TestCaseError::fail("plan should not be empty"))?;
        let _ = plan.into_query();

        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]
        #[test]
        fn test_query_parse_non_panic(query in ".*") {
            fixture(&query)?;
        }
    }
}
