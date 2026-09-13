// SPDX-License-Identifier: AGPL-3.0-only
//! Conservative English data fixed by the query-planning contract, not corpus tuning.
//! Comparisons use ASCII case only; these lists do not translate or stem text.

/// Sorted conservative English stopwords, applied only to positive plain atoms in S2–S4.
pub const STOPWORDS: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "been", "being", "by", "can", "could", "did", "do",
    "does", "for", "from", "had", "has", "have", "how", "i", "in", "into", "is", "it", "me", "my",
    "of", "on", "or", "our", "please", "that", "the", "their", "them", "there", "these", "they",
    "this", "those", "to", "was", "we", "were", "what", "when", "where", "which", "who", "why",
    "will", "with", "would", "you", "your",
];

/// Sorted leading phrases; remove at most one longest match, then use lexical tie order.
pub const SCAFFOLDS: &[&str] = &[
    "can you find",
    "can you show me",
    "could you find",
    "could you show me",
    "find me",
    "give me",
    "help me find",
    "how can i",
    "how do i",
    "i want to find",
    "please find",
    "please show me",
    "show me",
    "tell me",
    "what are",
    "what is",
    "where can i find",
];

/// Return whether a word exactly matches the declared ASCII stopword vocabulary.
pub fn is_stopword(word: &str) -> bool {
    word.is_ascii()
        && STOPWORDS
            .iter()
            .any(|candidate| word.eq_ignore_ascii_case(candidate))
}

/// Return whether capitalization must not promote a scaffolding or stopword token.
pub fn is_vocabulary(word: &str) -> bool {
    is_stopword(word)
        || SCAFFOLDS
            .iter()
            .flat_map(|s| s.split(' '))
            .any(|s| word.eq_ignore_ascii_case(s))
}
