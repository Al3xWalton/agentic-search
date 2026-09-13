// SPDX-License-Identifier: AGPL-3.0-only
//! Deterministic, query-local stage construction for bounded agent requests.
//! Explicit constraints retain their original meaning; no corpus, label or clock is consulted.
//! Execution, ranking and public provenance belong to the existing searcher layers.

pub mod bounds;
pub mod stopwords;

use crate::query::{
    parser::{SimpleOrPhrase, Term},
    plan::{self, Node},
};
use bounds::{InputError, SourceAtom};

/// Version of the complete deterministic planner rules, including static English data.
pub const PLANNER_VERSION: u16 = 1;

/// Ordered, finite stage identifiers; public rendering uses lowercase strings.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    bincode::Encode,
    bincode::Decode,
    utoipa::ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum StageId {
    /// Unmodified, compound-aware legacy conjunction.
    Strict,
    /// Conjunction of retained content atoms and immutable constraints.
    Content,
    /// At least ceil(k/2) distinct content atoms with every constraint.
    Relaxed,
    /// At least one of up to three query-local core atoms with every constraint.
    Core,
}

impl StageId {
    /// Return the stable lowercase identifier used by provenance and diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Content => "content",
            Self::Relaxed => "relaxed",
            Self::Core => "core",
        }
    }
}

/// One selected parser atom, with query-local ranking and occurrence metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Atom {
    /// Original parser atom and exact byte range; cleaned literals retain original source.
    pub source: SourceAtom,
    /// True for every quote, field selector, negation and unknown bang.
    pub constraint: bool,
    /// Whether the declared English capitalization heuristic prefers this content atom.
    pub entity: bool,
    /// Number of original equivalent content occurrences before deduplication, at most eight.
    pub occurrences: usize,
    /// Original top-level position used for deterministic ordering and adjacency.
    pub position: usize,
}

/// An optional predicate supplying one bounded ranking preference, never an MSM vote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preference {
    /// Typed literal or phrase predicate compiled through the ordinary field analyzers.
    pub term: Term,
    /// Original source interval covering its constituents.
    pub source: std::ops::Range<usize>,
}

/// Reason for an internal rewrite; these records cannot become executable query syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewriteReason {
    /// One longest leading scaffolding phrase.
    Scaffold,
    /// A declared English stopword.
    Stopword,
    /// A normalized or empty punctuation atom.
    Punctuation,
    /// Repeated content whose first occurrence owns the predicate.
    Duplicate,
}

/// One original atom affected by a lexical rewrite, retained only for internal diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rewrite {
    /// Exact source bytes affected by this rewrite.
    pub source: std::ops::Range<usize>,
    /// Declared reason for dropping or normalizing those bytes.
    pub reason: RewriteReason,
}

/// Complete selected stage, derived solely from validated original bytes and planner version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagePlan {
    /// Selected stage; shards never choose an alternative.
    pub id: StageId,
    /// Unmodified original request text, bounded by 4096 UTF-8 bytes.
    pub original: String,
    /// Stable ISO language code detected once from the original query.
    pub language: Option<String>,
    /// Source-ordered selected atoms, at most 32 including immutable constraints.
    pub atoms: Vec<Atom>,
    /// Distinct optional preference predicates with declared weight two.
    pub preferences: Vec<Preference>,
    /// Minimum number of distinct content votes; absent outside relaxed/core.
    pub minimum: Option<usize>,
    /// Internal explanations for lexical changes; excluded from structural equivalence.
    pub rewrites: Vec<Rewrite>,
}

impl StagePlan {
    /// Return the original-query language without redetecting rewritten terms.
    pub fn lang(&self) -> Result<Option<whatlang::Lang>, InputError> {
        self.language
            .as_deref()
            .map(|code| whatlang::Lang::from_code(code).ok_or(InputError::InvalidQuerySyntax))
            .transpose()
    }

    /// Render readable source syntax for diagnostics only; S1 preserves original query bytes.
    pub fn rewritten_query(&self) -> String {
        if self.id == StageId::Strict {
            return self.original.clone();
        }
        self.atoms
            .iter()
            .map(|a| a.source.term.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Return effective plain and phrase terms for the existing ranking and snippet seams.
    pub fn simple_terms(&self) -> Vec<String> {
        self.atoms
            .iter()
            .filter_map(|a| a.source.term.as_simple_text())
            .flat_map(|s| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
            .collect()
    }

    /// Build the existing lexical plan with immutable constraints outside the MSM vote.
    /// Returns `NoSearchableTerms` for an ineligible empty stage, never a match-all node.
    pub(crate) fn node(&self) -> Result<Node, InputError> {
        if self.id == StageId::Strict {
            return plan::initial(self.atoms.iter().map(|a| a.source.term.clone()).collect())
                .ok_or(InputError::NoSearchableTerms);
        }
        let mut mandatory = Vec::new();
        let mut content = Vec::new();
        for atom in &self.atoms {
            let node = Node::from_term(atom.source.term.clone());
            if atom.constraint {
                mandatory.push(node);
            } else {
                content.push(node);
            }
        }
        if let Some(minimum) = self.minimum {
            if !content.is_empty() {
                mandatory.push(Node::AtLeast {
                    minimum,
                    children: content,
                });
            }
        } else {
            mandatory.extend(content);
        }
        mandatory
            .into_iter()
            .reduce(Node::and)
            .ok_or(InputError::NoSearchableTerms)
    }

    fn equivalent(&self, other: &Self) -> Result<bool, InputError> {
        Ok(self.node()?.into_query() == other.node()?.into_query()
            && self
                .preferences
                .iter()
                .map(|p| &p.term)
                .eq(other.preferences.iter().map(|p| &p.term)))
    }
}

/// Eligible, structurally distinct stages in execution order, with strict always first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentPlan {
    /// At most four complete stages; execution may stop before exhausting this list.
    pub stages: Vec<StagePlan>,
}

fn literal(term: &Term) -> Option<&str> {
    match term {
        Term::SimpleOrPhrase(SimpleOrPhrase::Simple(s)) => Some(s.as_str()),
        _ => None,
    }
}

fn punctuation(text: &str) -> String {
    if !text.is_ascii() {
        return text.to_owned();
    }
    let trimmed = text.trim_matches([',', ';', ':', '?', '!', '(', ')', '[', ']', '{', '}']);
    if trimmed.ends_with('.')
        && trimmed.bytes().filter(|b| *b == b'.').count() == 1
        && !trimmed.bytes().any(|b| b.is_ascii_digit())
    {
        trimmed[..trimmed.len() - 1].to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn acronym(text: &str) -> bool {
    text.is_ascii()
        && text.bytes().filter(u8::is_ascii_alphabetic).count() >= 2
        && !text.bytes().any(|b| b.is_ascii_lowercase())
}

fn title_case(text: &str) -> bool {
    text.is_ascii()
        && text.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
        && text.bytes().skip(1).all(|b| !b.is_ascii_uppercase())
        && text.bytes().any(|b| b.is_ascii_lowercase())
        && !stopwords::is_vocabulary(text)
}

fn mixed_case(text: &str) -> bool {
    text.is_ascii()
        && text.bytes().any(|b| b.is_ascii_lowercase())
        && text.bytes().skip(1).any(|b| b.is_ascii_uppercase())
}

fn preferred(atoms: &mut [Atom]) -> Vec<Preference> {
    let mut preferences = Vec::new();
    for atom in atoms.iter_mut() {
        if let Some(text) = literal(&atom.source.term) {
            atom.entity =
                acronym(text) || mixed_case(text) || (atom.position > 0 && title_case(text));
        }
    }
    let mut i = 0;
    while i < atoms.len() {
        let mut end = i;
        while end < atoms.len()
            && !atoms[end].constraint
            && literal(&atoms[end].source.term).is_some_and(title_case)
            && atoms[end].source.original == literal(&atoms[end].source.term).unwrap_or_default()
            && (end == i || atoms[end - 1].position + 1 == atoms[end].position)
        {
            end += 1;
        }
        if end - i >= 2 {
            for atom in &mut atoms[i..end] {
                atom.entity = true;
            }
            preferences.push(Preference {
                term: Term::SimpleOrPhrase(SimpleOrPhrase::Phrase(
                    atoms[i..end]
                        .iter()
                        .filter_map(|a| literal(&a.source.term).map(str::to_owned))
                        .collect(),
                )),
                source: atoms[i].source.source.start..atoms[end - 1].source.source.end,
            });
        }
        i = if end > i { end } else { i + 1 };
    }
    for atom in atoms.iter() {
        if atom.entity
            || matches!(
                atom.source.term,
                Term::SimpleOrPhrase(SimpleOrPhrase::Phrase(_))
            )
        {
            preferences.push(Preference {
                term: atom.source.term.clone(),
                source: atom.source.source.clone(),
            });
        }
    }
    preferences.sort_by_key(|p| p.source.start);
    let mut distinct = Vec::new();
    for preference in preferences {
        if !distinct
            .iter()
            .any(|p: &Preference| p.term == preference.term)
        {
            distinct.push(preference);
        }
    }
    distinct
}

impl AgentPlan {
    /// Plan admissible query bytes without index, labels, remote statistics or time access.
    /// Returns the bounds scanner's typed errors and never expands beyond four stages.
    pub fn new(query: &str) -> Result<Self, InputError> {
        let sources = bounds::validate_query(query)?;
        let language = whatlang::detect_lang(query).map(|lang| lang.code().to_owned());
        let original: Vec<_> = sources
            .into_iter()
            .enumerate()
            .map(|(position, source)| Atom {
                constraint: literal(&source.term).is_none(),
                source,
                entity: false,
                occurrences: 1,
                position,
            })
            .collect();
        let strict = StagePlan {
            id: StageId::Strict,
            original: query.to_owned(),
            language: language.clone(),
            atoms: original.clone(),
            preferences: vec![],
            minimum: None,
            rewrites: vec![],
        };
        let mut prefix = 0;
        for scaffold in stopwords::SCAFFOLDS {
            let words: Vec<_> = scaffold.split(' ').collect();
            if words.len() > prefix
                && words.len() <= original.len()
                && words.iter().zip(&original).all(|(word, atom)| {
                    literal(&atom.source.term)
                        .is_some_and(|s| s.is_ascii() && s.eq_ignore_ascii_case(word))
                })
            {
                prefix = words.len();
            }
        }
        let mut rewrites = Vec::new();
        let mut retained: Vec<Atom> = Vec::new();
        for mut atom in original {
            if atom.position < prefix {
                rewrites.push(Rewrite {
                    source: atom.source.source.clone(),
                    reason: RewriteReason::Scaffold,
                });
                continue;
            }
            if let Some(text) = literal(&atom.source.term) {
                let text = punctuation(text);
                if text != literal(&atom.source.term).unwrap_or_default() {
                    rewrites.push(Rewrite {
                        source: atom.source.source.clone(),
                        reason: RewriteReason::Punctuation,
                    });
                }
                if text.is_empty() {
                    continue;
                }
                if stopwords::is_stopword(&text) {
                    rewrites.push(Rewrite {
                        source: atom.source.source.clone(),
                        reason: RewriteReason::Stopword,
                    });
                    continue;
                }
                atom.source.term =
                    Term::SimpleOrPhrase(SimpleOrPhrase::Simple(text.clone().into()));
                let key = bounds::comparison_key(&text);
                if let Some(first) = retained.iter_mut().find(|a| {
                    !a.constraint
                        && literal(&a.source.term).is_some_and(|s| bounds::comparison_key(s) == key)
                }) {
                    first.occurrences += 1;
                    rewrites.push(Rewrite {
                        source: atom.source.source.clone(),
                        reason: RewriteReason::Duplicate,
                    });
                    continue;
                }
            }
            retained.push(atom);
        }
        let mut plan = Self {
            stages: vec![strict],
        };
        if !retained.iter().any(|a| bounds::positive(&a.source.term)) {
            return Ok(plan);
        }
        let preferences = preferred(&mut retained);
        let content = StagePlan {
            id: StageId::Content,
            original: query.to_owned(),
            language,
            atoms: retained,
            preferences,
            minimum: None,
            rewrites,
        };
        let count = content.atoms.iter().filter(|a| !a.constraint).count();
        plan.push(content.clone())?;
        if count > 1 {
            plan.push(StagePlan {
                id: StageId::Relaxed,
                minimum: Some(count.div_ceil(2)),
                ..content.clone()
            })?;
        }
        if count > 0 {
            let mut selected: Vec<_> = content
                .atoms
                .iter()
                .filter(|a| !a.constraint)
                .cloned()
                .collect();
            let specific = |a: &Atom| {
                literal(&a.source.term).is_some_and(|s| {
                    acronym(s)
                        || s.chars()
                            .any(|c| c.is_ascii_digit() || "_.-/+#".contains(c))
                })
            };
            selected.sort_by(|a, b| {
                specific(b)
                    .cmp(&specific(a))
                    .then(a.occurrences.cmp(&b.occurrences))
                    .then_with(|| {
                        literal(&b.source.term)
                            .unwrap_or_default()
                            .chars()
                            .count()
                            .cmp(&literal(&a.source.term).unwrap_or_default().chars().count())
                    })
                    .then(a.source.source.start.cmp(&b.source.source.start))
                    .then_with(|| literal(&a.source.term).cmp(&literal(&b.source.term)))
            });
            selected.truncate(3);
            let atoms: Vec<_> = content
                .atoms
                .iter()
                .filter(|a| a.constraint || selected.iter().any(|s| s.position == a.position))
                .cloned()
                .collect();
            let preferences = content
                .preferences
                .iter()
                .filter(|p| {
                    content
                        .atoms
                        .iter()
                        .filter(|a| {
                            a.source.source.start >= p.source.start
                                && a.source.source.end <= p.source.end
                        })
                        .all(|a| atoms.iter().any(|r| r.position == a.position))
                })
                .cloned()
                .collect();
            if count > 1 {
                plan.push(StagePlan {
                    id: StageId::Core,
                    atoms,
                    preferences,
                    minimum: Some(1),
                    ..content
                })?;
            }
        }
        Ok(plan)
    }

    fn push(&mut self, stage: StagePlan) -> Result<(), InputError> {
        for existing in &self.stages {
            if stage.equivalent(existing)? {
                return Ok(());
            }
        }
        self.stages.push(stage);
        Ok(())
    }
}
