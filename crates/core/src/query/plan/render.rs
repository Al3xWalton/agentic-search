// SPDX-License-Identifier: AGPL-3.0-only
//! Compile and describe the same analyzed lexical tree in one bounded traversal.
//! Rendering exposes schema names and escaped literals, never internal query Debug output.
//! Ranking preferences and mandatory request envelopes are composed by Query::parse.

use tantivy::{query::Query as TantivyQuery, tokenizer::Tokenizer as _};

use super::{minimum_match::MinimumMatch, Occur, Query, Term};
use crate::{
    query::{
        parser::SimpleOrPhrase,
        planner::bounds::{InputError, MAX_COMPILED_NODES, MAX_RENDER_BYTES},
    },
    schema::text_field::TextField as _,
};

/// Compiled lexical query and its exact safe description from the same traversal.
pub struct Compiled {
    /// Executable query; source strings are never interpreted as optics or regexes.
    pub query: Box<dyn TantivyQuery>,
    /// Complete lexical rendering, at most 256 KiB under the production budget.
    pub rendered: String,
}

/// Shared stage budget, including analyzed leaves, preferences and envelope markers.
#[derive(Debug)]
pub struct Budget {
    nodes: usize,
    bytes: usize,
    max_nodes: usize,
    max_bytes: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Self::new(MAX_COMPILED_NODES, MAX_RENDER_BYTES)
    }
}

impl Budget {
    /// Construct explicit limits in nodes and UTF-8 bytes, also used by boundary tests.
    pub fn new(max_nodes: usize, max_bytes: usize) -> Self {
        Self {
            nodes: 0,
            bytes: 0,
            max_nodes,
            max_bytes,
        }
    }

    /// Charge nodes before allocating them; overflow or exceeding the cap is PlanTooComplex.
    pub fn nodes(&mut self, count: usize) -> Result<(), InputError> {
        self.nodes = self
            .nodes
            .checked_add(count)
            .ok_or(InputError::PlanTooComplex)?;
        if self.nodes > self.max_nodes {
            return Err(InputError::PlanTooComplex);
        }
        Ok(())
    }

    /// Append text only if its complete byte length fits the remaining stage budget.
    pub fn push(&mut self, output: &mut String, text: &str) -> Result<(), InputError> {
        self.bytes = self
            .bytes
            .checked_add(text.len())
            .ok_or(InputError::PlanTooComplex)?;
        if self.bytes > self.max_bytes {
            return Err(InputError::PlanTooComplex);
        }
        output.push_str(text);
        Ok(())
    }
}

/// Compile with explicit shared bounds; tokenless mandatory predicates fail closed.
/// Returns NoSearchableTerms for an entirely tokenless tree, or PlanTooComplex at a cap.
pub fn compile(
    query: &Query,
    lang: Option<&whatlang::Lang>,
    schema: &tantivy::schema::Schema,
    budget: &mut Budget,
) -> Result<Compiled, InputError> {
    compile_optional(query, lang, schema, budget)?.ok_or(InputError::NoSearchableTerms)
}

fn compile_optional(
    query: &Query,
    lang: Option<&whatlang::Lang>,
    schema: &tantivy::schema::Schema,
    budget: &mut Budget,
) -> Result<Option<Compiled>, InputError> {
    budget.nodes(1)?;
    let mut rendered = String::new();
    let compiled: Box<dyn TantivyQuery> = match query {
        Query::Term(Term { text, field }) => {
            let Some(tv_field) = field.tantivy_field(schema) else {
                return Ok(None);
            };
            let source = match text {
                SimpleOrPhrase::Simple(s) => s.as_str().to_owned(),
                SimpleOrPhrase::Phrase(words) => words.join(" "),
            };
            let mut tokenizer = field.query_tokenizer(lang);
            let mut stream = tokenizer.token_stream(&source);
            let mut terms = Vec::new();
            while stream.advance() {
                budget.nodes(1)?;
                terms.push(tantivy::Term::from_field_text(
                    tv_field,
                    &stream.token().text,
                ));
            }
            if terms.is_empty() {
                return Ok(None);
            }
            let option = field.record_option();
            if matches!(text, SimpleOrPhrase::Phrase(_))
                && terms.len() > 1
                && !option.has_positions()
            {
                return Ok(None);
            }
            budget.push(&mut rendered, field.name())?;
            let phrase = terms.len() > 1 && option.has_positions();
            budget.push(
                &mut rendered,
                if phrase {
                    ":PHRASE("
                } else if terms.len() == 1 {
                    ":TERM("
                } else {
                    ":AND("
                },
            )?;
            for (position, term) in terms.iter().enumerate() {
                if position > 0 {
                    budget.push(&mut rendered, ",")?;
                }
                if phrase {
                    budget.push(&mut rendered, &format!("{position}:"))?;
                }
                let literal = serde_json::to_string(
                    term.value()
                        .as_str()
                        .ok_or(InputError::InvalidQuerySyntax)?,
                )
                .map_err(|_| InputError::InvalidQuerySyntax)?;
                budget.push(&mut rendered, &literal)?;
            }
            budget.push(&mut rendered, ")")?;
            if terms.len() == 1 {
                Box::new(tantivy::query::TermQuery::new(terms.remove(0), option))
            } else if phrase {
                Box::new(tantivy::query::PhraseQuery::new(terms))
            } else {
                Box::new(tantivy::query::BooleanQuery::new(
                    terms
                        .into_iter()
                        .map(|term| {
                            (
                                tantivy::query::Occur::Must,
                                Box::new(tantivy::query::TermQuery::new(term, option))
                                    as Box<dyn TantivyQuery>,
                            )
                        })
                        .collect(),
                ))
            }
        }
        Query::Boolean { clauses } => {
            let mut children = Vec::new();
            budget.push(&mut rendered, "BOOL(")?;
            for (occur, child) in clauses {
                if let Some(child) = compile_optional(child, lang, schema, budget)? {
                    if !children.is_empty() {
                        budget.push(&mut rendered, ",")?;
                    }
                    budget.push(
                        &mut rendered,
                        match occur {
                            Occur::Must => "must:",
                            Occur::Should => "should:",
                            Occur::MustNot => "must_not:",
                        },
                    )?;
                    // Child bytes have already been charged during its compilation.
                    rendered.push_str(&child.rendered);
                    children.push(((*occur).into(), child.query));
                } else if *occur != Occur::Should {
                    return Err(InputError::NoSearchableTerms);
                }
            }
            if children.is_empty() {
                return Ok(None);
            }
            budget.push(&mut rendered, ")")?;
            Box::new(tantivy::query::BooleanQuery::new(children))
        }
        Query::AtLeast { minimum, children } => {
            if children.len() > 32 || *minimum == 0 || *minimum > children.len() {
                return Err(InputError::InvalidQuerySyntax);
            }
            budget.push(&mut rendered, &format!("AT_LEAST({minimum};"))?;
            let mut compiled = Vec::new();
            for child in children {
                let child = compile(child, lang, schema, budget)?;
                if !compiled.is_empty() {
                    budget.push(&mut rendered, ",")?;
                }
                rendered.push_str(&child.rendered);
                compiled.push(child.query);
            }
            budget.push(&mut rendered, ")")?;
            Box::new(
                MinimumMatch::new(*minimum, compiled)
                    .map_err(|_| InputError::InvalidQuerySyntax)?,
            )
        }
    };
    Ok(Some(Compiled {
        query: compiled,
        rendered,
    }))
}

#[cfg(test)]
mod tests {
    use super::InputError;
    #[test]
    fn rendered_query_is_compiled_query() {
        use crate::query::{parser, plan};
        let logical =
            plan::initial(parser::parse("title:\"C++ compiler\" -body:obsolete").unwrap())
                .unwrap()
                .into_query();
        let schema = crate::schema::create_schema();
        let compiled =
            plan::render::compile(&logical, None, &schema, &mut Default::default()).unwrap();
        assert!(compiled.rendered.contains("title:PHRASE("));
        assert!(compiled.rendered.contains("must_not:"));
        assert!(!compiled.rendered.contains("Segment"));
        let mut terms = Vec::new();
        compiled
            .query
            .query_terms(&mut |term, _| terms.push(term.value().as_str().unwrap().to_owned()));
        for term in terms {
            assert!(compiled
                .rendered
                .contains(&serde_json::to_string(&term).unwrap()));
        }
    }

    #[test]
    fn compiler_budget_fail_closed() {
        use crate::query::{parser, plan};
        let logical = plan::initial(parser::parse("compiler").unwrap())
            .unwrap()
            .into_query();
        let schema = crate::schema::create_schema();
        assert!(matches!(
            plan::render::compile(
                &logical,
                None,
                &schema,
                &mut plan::render::Budget::new(1, usize::MAX)
            ),
            Err(InputError::PlanTooComplex)
        ));
        assert!(matches!(
            plan::render::compile(
                &logical,
                None,
                &schema,
                &mut plan::render::Budget::new(usize::MAX, 1)
            ),
            Err(InputError::PlanTooComplex)
        ));
    }

    #[test]
    fn missing_schema_is_typed() {
        use crate::query::{parser, plan};
        let logical = plan::initial(parser::parse("title:compiler").unwrap())
            .unwrap()
            .into_query();
        let schema = tantivy::schema::Schema::builder().build();
        assert!(matches!(
            plan::render::compile(&logical, None, &schema, &mut Default::default()),
            Err(InputError::NoSearchableTerms)
        ));
    }
}
