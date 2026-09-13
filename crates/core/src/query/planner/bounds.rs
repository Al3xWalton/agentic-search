// SPDX-License-Identifier: AGPL-3.0-only
//! Validate original query bytes before parsing, allocation, or search fan-out.
//! Atoms retain UTF-8 source boundaries; no truncation or text repair is permitted.
//! Searchability after field analysis and known-bang lookup belong to the callers.

use std::ops::Range;

use crate::query::parser::{self, SimpleOrPhrase, Term};

/// Maximum decoded search HTTP body, in bytes.
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// Maximum original query length, in UTF-8 bytes.
pub const MAX_QUERY_BYTES: usize = 4096;
/// Maximum top-level atoms; each phrase or field operand counts once.
pub const MAX_ATOMS: usize = parser::MAX_TERMS_PER_QUERY;
/// Maximum simple or operator operand length, in Unicode scalars.
pub const MAX_ATOM_SCALARS: usize = 1024;
/// Maximum whitespace-separated words in an explicit phrase.
pub const MAX_PHRASE_WORDS: usize = 32;
/// Maximum combined field, negation and bang prefixes.
pub const MAX_OPERATORS: usize = 8;
/// Maximum repetitions of one parsed atom before relaxation deduplicates it.
pub const MAX_REPETITIONS: usize = 8;
/// Maximum public page size, in results.
pub const MAX_PUBLIC_RESULTS: usize = 100;
/// Existing internal ranking candidate limit, in documents.
pub const MAX_CANDIDATES: usize = 300;
/// Maximum attempted stages per request, including strict bang reentry.
pub const MAX_STAGES: usize = 4;
/// Maximum logical search shards in one immutable membership snapshot.
pub const MAX_SHARDS: usize = 8;
/// Maximum search RPCs and, separately, retrieval RPCs per request.
pub const MAX_RPCS: usize = MAX_STAGES * MAX_SHARDS;
/// Maximum constructed plan and compiler nodes per stage.
pub const MAX_COMPILED_NODES: usize = 16_384;
/// Maximum safe rendering size per stage, in UTF-8 bytes.
pub const MAX_RENDER_BYTES: usize = 256 * 1024;
/// Maximum parsed optic rules accepted before query compilation.
pub const MAX_OPTIC_RULES: usize = 1024;
/// Maximum combined liked, disliked and blocked hosts across request preferences.
pub const MAX_HOST_RANKING_ENTRIES: usize = 1024;
/// Maximum length of each host preference, in UTF-8 bytes.
pub const MAX_HOST_BYTES: usize = 8192;

/// Finite input failures with fixed messages that never include request text.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    thiserror::Error,
    serde::Serialize,
    serde::Deserialize,
    utoipa::ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InputError {
    /// Malformed JSON, unsupported JSON shape or invalid explicit optic.
    #[error("The search request is invalid")]
    InvalidRequest,
    /// Decoded HTTP body exceeds 64 KiB.
    #[error("The search request is too large")]
    RequestTooLarge,
    /// Query is empty or contains only permitted whitespace.
    #[error("The query is empty")]
    EmptyQuery,
    /// Original query exceeds 4096 UTF-8 bytes.
    #[error("The query is too long")]
    QueryTooLong,
    /// Query contains more than 32 top-level atoms.
    #[error("The query has too many terms")]
    TooManyTerms,
    /// A simple or operator operand exceeds 1024 Unicode scalars.
    #[error("A query term is too long")]
    TermTooLong,
    /// Explicit phrase exceeds 32 words.
    #[error("A query phrase is too long")]
    PhraseTooLong,
    /// Explicit phrase contains no words.
    #[error("A query phrase is empty")]
    EmptyPhrase,
    /// Quote pairs are unbalanced, nested, crossed or not fully consumed.
    #[error("The query has invalid quotes")]
    InvalidQuotes,
    /// Recognized operator has an invalid or absent operand.
    #[error("The query has an invalid operator")]
    InvalidOperator,
    /// A non-whitespace input byte cannot be associated with a parsed atom.
    #[error("The query syntax is invalid")]
    InvalidQuerySyntax,
    /// Query exceeds eight field, bang and negation prefixes combined.
    #[error("The query has too many operators")]
    TooManyOperators,
    /// No positive anchor or mandatory atom survives field analysis.
    #[error("The query has no searchable terms")]
    NoSearchableTerms,
    /// Query contains a forbidden control, invisible or bidi formatting scalar.
    #[error("The query contains a forbidden character")]
    ForbiddenCharacter,
    /// A parsed atom repeats more than eight times.
    #[error("The query repeats a term too often")]
    ExcessiveRepetition,
    /// Public page size is outside 1..=100, or internal size exceeds 300.
    #[error("The result count is invalid")]
    InvalidResultCount,
    /// Page multiplication or end-offset addition overflows usize.
    #[error("The page is invalid")]
    InvalidPage,
    /// Constructed nodes or rendered bytes exceed their finite budgets.
    #[error("The query plan is too complex")]
    PlanTooComplex,
    /// Parsed optic rules or host preferences exceed their finite size limits.
    #[error("The search preferences are too large")]
    PreferencesTooLarge,
}

/// A parsed atom paired by the scanner with its exact original byte interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceAtom {
    /// Original parser meaning; no field identifier is accepted from callers.
    pub term: Term,
    /// Half-open byte range into the original string, always on UTF-8 boundaries.
    pub source: Range<usize>,
    /// Unmodified source text including original operator spelling and delimiters.
    pub original: String,
}

/// Validate page size and checked offsets, returning the starting document offset.
/// `public` selects the 100-result HTTP bound; internal requests permit 300 candidates.
/// Returns `InvalidResultCount` or `InvalidPage` without allocating or sending RPCs.
pub fn validate_numbers(page: usize, count: usize, public: bool) -> Result<usize, InputError> {
    let limit = if public {
        MAX_PUBLIC_RESULTS
    } else {
        MAX_CANDIDATES
    };
    if count == 0 || count > limit {
        return Err(InputError::InvalidResultCount);
    }
    let offset = page.checked_mul(count).ok_or(InputError::InvalidPage)?;
    offset.checked_add(count).ok_or(InputError::InvalidPage)?;
    Ok(offset)
}

/// Bound parsed preferences before planning or index traversal, without cloning their contents.
/// At most 1024 optic rules and 1024 combined host entries of 8192 bytes are allowed.
/// Optic-embedded host lists share the entry budget; failure is PreferencesTooLarge.
pub fn validate_preferences(
    optic: Option<&optics::Optic>,
    host_rankings: Option<&optics::HostRankings>,
) -> Result<(), InputError> {
    if optic.is_some_and(|optic| optic.rules.len() > MAX_OPTIC_RULES) {
        return Err(InputError::PreferencesTooLarge);
    }
    let mut entries = 0usize;
    for hosts in host_rankings
        .into_iter()
        .chain(optic.map(|o| &o.host_rankings))
    {
        for list in [&hosts.liked, &hosts.disliked, &hosts.blocked] {
            entries = entries
                .checked_add(list.len())
                .ok_or(InputError::PreferencesTooLarge)?;
            if entries > MAX_HOST_RANKING_ENTRIES
                || list.iter().any(|host| host.len() > MAX_HOST_BYTES)
            {
                return Err(InputError::PreferencesTooLarge);
            }
        }
    }
    Ok(())
}

/// Return the ASCII comparison identity, leaving any non-ASCII string byte-exact.
pub fn comparison_key(text: &str) -> String {
    if text.is_ascii() {
        text.to_ascii_lowercase()
    } else {
        text.to_owned()
    }
}

/// Reject the explicitly forbidden scalar set while preserving natural RTL scripts.
pub fn forbidden(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{00ad}' | '\u{034f}' | '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}')
}

fn quote(c: char) -> bool {
    matches!(c, '"' | '“' | '”' | '«' | '»' | '„' | '「' | '」')
}

fn inner_query(query: &str) -> Result<(usize, &str), InputError> {
    let input = query.trim();
    let offset = query.len() - query.trim_start().len();
    for (left, right) in [('«', '»'), ('„', '“'), ('»', '«'), ('「', '」')] {
        if let Some(inner) = input.strip_prefix(left) {
            let inner = inner.strip_suffix(right).ok_or(InputError::InvalidQuotes)?;
            if inner.chars().any(quote) {
                return Err(InputError::InvalidQuotes);
            }
            return Ok((offset + left.len_utf8(), inner));
        }
    }
    Ok((offset, input))
}

fn operand_bound(term: &Term) -> Result<(), InputError> {
    match term {
        Term::Not(inner) => operand_bound(inner),
        Term::SimpleOrPhrase(value) | Term::Title(value) | Term::Body(value) | Term::Url(value) => {
            match value {
                SimpleOrPhrase::Simple(s) => scalar_bound(s.as_str()),
                SimpleOrPhrase::Phrase(words) => {
                    if words.is_empty() {
                        return Err(InputError::EmptyPhrase);
                    }
                    if words.len() > MAX_PHRASE_WORDS {
                        return Err(InputError::PhraseTooLong);
                    }
                    for word in words {
                        scalar_bound(word)?;
                    }
                    Ok(())
                }
            }
        }
        Term::Site(value) | Term::LinkTo(value) | Term::ExactUrl(value) => scalar_bound(value),
        Term::PossibleBang { bang, .. } => scalar_bound(bang),
    }
}

fn scalar_bound(value: &str) -> Result<(), InputError> {
    if value.chars().count() > MAX_ATOM_SCALARS {
        Err(InputError::TermTooLong)
    } else {
        Ok(())
    }
}

/// Test whether an atom provides a syntactic positive anchor; compilation verifies tokens.
pub fn positive(term: &Term) -> bool {
    !matches!(term, Term::Not(_) | Term::PossibleBang { .. })
}

fn operand_length(operand: &str, bang: bool, field: Option<&str>) -> Result<usize, InputError> {
    let first = operand
        .chars()
        .next()
        .ok_or(InputError::InvalidQuerySyntax)?;
    if matches!(first, '"' | '“') {
        if bang || matches!(field, Some("site:" | "linkto:" | "linksto:" | "exacturl:")) {
            return Err(InputError::InvalidOperator);
        }
        let mut end = None;
        for (i, c) in operand.char_indices().skip(1) {
            if quote(c) {
                if (first == '"' && c == '"') || (first == '“' && matches!(c, '“' | '”')) {
                    end = Some(i + c.len_utf8());
                    break;
                }
                return Err(InputError::InvalidQuotes);
            }
        }
        end.ok_or(InputError::InvalidQuotes)
    } else {
        let length = operand.find(char::is_whitespace).unwrap_or(operand.len());
        if operand[..length].chars().any(quote) {
            return Err(InputError::InvalidQuotes);
        }
        // Validate before exacturl normalization can add scheme and root slash.
        scalar_bound(&operand[..length])?;
        Ok(length)
    }
}

/// Scan bounded original bytes and reuse the legacy parser for each fully consumed atom.
/// Bang-only syntax is admitted here solely so the API can recognize configured redirects.
/// Returns finite input errors for all bounds, quote, operator and repetition failures.
pub fn scan_query(query: &str) -> Result<Vec<SourceAtom>, InputError> {
    if query.len() > MAX_QUERY_BYTES {
        return Err(InputError::QueryTooLong);
    }
    if query.chars().any(forbidden) {
        return Err(InputError::ForbiddenCharacter);
    }
    if query.trim().is_empty() {
        return Err(InputError::EmptyQuery);
    }
    let (base, input) = inner_query(query)?;
    let mut cursor = 0;
    let mut atoms: Vec<SourceAtom> = Vec::new();
    let mut operators = 0;
    while cursor < input.len() {
        let remaining = &input[cursor..];
        cursor += remaining.len() - remaining.trim_start().len();
        if cursor == input.len() {
            break;
        }
        if atoms.len() == MAX_ATOMS {
            return Err(InputError::TooManyTerms);
        }
        let start = cursor;
        let mut operand = &input[cursor..];
        if let Some(rest) = operand.strip_prefix('-') {
            operators += 1;
            if rest.is_empty() || rest.starts_with('-') || rest.starts_with(char::is_whitespace) {
                return Err(InputError::InvalidOperator);
            }
            cursor += 1;
            operand = rest;
        }
        let mut field = None;
        for prefix in [
            "site:",
            "linkto:",
            "linksto:",
            "intitle:",
            "inbody:",
            "inurl:",
            "exacturl:",
        ] {
            if let Some(rest) = operand.strip_prefix(prefix) {
                operators += 1;
                cursor += prefix.len();
                operand = rest;
                field = Some(prefix);
                break;
            }
        }
        let bang = operand.starts_with(['!', '！']) && field.is_none();
        if bang {
            operators += 1;
        }
        if operators > MAX_OPERATORS {
            return Err(InputError::TooManyOperators);
        }
        if operand.is_empty() || operand.starts_with(char::is_whitespace) {
            return Err(InputError::InvalidOperator);
        }
        cursor += operand_length(operand, bang, field)?;
        if cursor < input.len() && !input[cursor..].starts_with(char::is_whitespace) {
            return Err(InputError::InvalidQuotes);
        }
        let original = &input[start..cursor];
        let mut parsed = parser::parse(original).map_err(|_| InputError::InvalidQuerySyntax)?;
        if parsed.len() != 1 {
            return Err(InputError::InvalidQuerySyntax);
        }
        let term = parsed.pop().ok_or(InputError::InvalidQuerySyntax)?;
        let unnegated = if let Term::Not(inner) = &term {
            inner.as_ref()
        } else {
            &term
        };
        if field.is_some() && matches!(unnegated, Term::SimpleOrPhrase(_)) {
            return Err(InputError::InvalidOperator);
        }
        if !matches!(unnegated, Term::ExactUrl(_)) {
            operand_bound(&term)?;
        }
        let identity = comparison_key(&term.to_string());
        if atoms
            .iter()
            .filter(|a| comparison_key(&a.term.to_string()) == identity)
            .count()
            >= MAX_REPETITIONS
        {
            return Err(InputError::ExcessiveRepetition);
        }
        atoms.push(SourceAtom {
            term,
            source: base + start..base + cursor,
            original: original.to_owned(),
        });
    }
    if atoms.is_empty() {
        return Err(InputError::EmptyQuery);
    }
    Ok(atoms)
}

/// Validate a searchable query, including the positive-anchor requirement.
/// Configured redirect lookup must use `scan_query` first; unknown bangs cannot anchor search.
/// All source intervals refer to `query`; errors never contain its bytes.
pub fn validate_query(query: &str) -> Result<Vec<SourceAtom>, InputError> {
    let atoms = scan_query(query)?;
    if !atoms.iter().any(|a| positive(&a.term)) {
        return Err(InputError::NoSearchableTerms);
    }
    Ok(atoms)
}
