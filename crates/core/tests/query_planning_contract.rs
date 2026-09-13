// SPDX-License-Identifier: AGPL-3.0-only
//! Synthetic public query contracts independent of the retained evaluation labels.
//! Inputs exercise original byte ranges and fail-closed bounds; no network or corpus is used.

use stract::query::planner::bounds::{validate_numbers, validate_query, InputError};
use stract::query::planner::{AgentPlan, StageId};

fn terms(query: &str, stage: StageId) -> Vec<String> {
    AgentPlan::new(query)
        .unwrap()
        .stages
        .into_iter()
        .find(|s| s.id == stage)
        .unwrap()
        .atoms
        .into_iter()
        .map(|a| a.source.term.to_string())
        .collect()
}

#[test]
fn s2_removes_only_declared_stopwords() {
    assert_eq!(
        terms("please find the alpha package for quux", StageId::Content),
        ["alpha", "package", "quux"]
    );
}

#[test]
fn s2_longest_scaffold_once() {
    assert_eq!(
        terms("can you show me alpha beta", StageId::Content),
        ["alpha", "beta"]
    );
    assert_eq!(
        terms("please find please find alpha", StageId::Content),
        ["find", "alpha"]
    );
}

#[test]
fn s2_punctuation_preserves_identifiers() {
    assert_eq!(
        terms(
            "please find C++ read_to_string 1.98.1 S203U-C15 example.org (alpha); beta.",
            StageId::Content
        ),
        [
            "C++",
            "read_to_string",
            "1.98.1",
            "S203U-C15",
            "example.org",
            "alpha",
            "beta"
        ]
    );
}

#[test]
fn non_latin_preserved() {
    assert_eq!(
        terms("please find العربية עברית 中文 Русский", StageId::Content),
        ["العربية", "עברית", "中文", "Русский"]
    );
}

#[test]
fn entities_are_preferences() {
    let plan = AgentPlan::new("please find API OpenAI New York alpha").unwrap();
    let content = plan
        .stages
        .iter()
        .find(|s| s.id == StageId::Content)
        .unwrap();
    let preferences: Vec<_> = content
        .preferences
        .iter()
        .map(|p| p.term.to_string())
        .collect();
    for required in ["API", "OpenAI", "\"New York\"", "New", "York"] {
        assert!(preferences.iter().any(|p| p == required));
    }
    assert_eq!(content.atoms.iter().filter(|a| !a.constraint).count(), 5);
    assert!(content.atoms.iter().all(|a| !a.constraint));
}

#[test]
fn s3_requires_ceil_half() {
    let plan = AgentPlan::new("please find alpha beta gamma delta epsilon").unwrap();
    assert_eq!(
        plan.stages
            .iter()
            .find(|s| s.id == StageId::Relaxed)
            .unwrap()
            .minimum,
        Some(3)
    );
    let one = AgentPlan::new("please find alpha").unwrap();
    assert!(one.stages.iter().all(|s| s.id != StageId::Relaxed));
}

#[test]
fn s4_core_priority_and_three_limit() {
    assert_eq!(
        terms(
            "please find apple apple beta gamma enormousidentifier Z9 tiny",
            StageId::Core
        ),
        ["gamma", "enormousidentifier", "Z9"]
    );
}

#[test]
fn content_duplicates_count_once() {
    let plan = AgentPlan::new("please find alpha ALPHA beta gamma").unwrap();
    let content = plan
        .stages
        .iter()
        .find(|s| s.id == StageId::Content)
        .unwrap();
    assert_eq!(content.atoms.len(), 3);
    assert_eq!(content.atoms[0].occurrences, 2);
    assert_eq!(content.atoms[0].source.original, "alpha");
}

#[test]
fn same_bytes_same_plan() {
    let query = "please find gamma alpha omega delta sigma";
    let first = AgentPlan::new(query).unwrap();
    for _ in 0..100 {
        assert_eq!(AgentPlan::new(query).unwrap(), first);
    }
    assert_eq!(terms(query, StageId::Core), ["gamma", "alpha", "omega"]);
}

#[test]
fn no_empty_relaxation_rescue() {
    assert_eq!(AgentPlan::new("the and of").unwrap().stages.len(), 1);
    assert!(AgentPlan::new("-alpha").is_err());
}

#[test]
fn language_fixed_from_original() {
    let plan =
        AgentPlan::new("please find the complete guide to configuring the alpha beta server")
            .unwrap();
    let language = plan.stages[0].language.clone();
    assert!(plan.stages.iter().all(|stage| stage.language == language));
}

#[test]
fn empty_query_rejected() {
    for input in ["", "   ", "\u{2002}"] {
        assert_eq!(validate_query(input).unwrap_err(), InputError::EmptyQuery);
    }
}

#[test]
fn query_utf8_byte_bound() {
    let boundary = vec!["é".repeat(512); 3].join(" ") + " " + "a".repeat(1021).as_str();
    assert_eq!(boundary.len(), 4096);
    assert!(validate_query(&boundary).is_ok());
    assert_eq!(
        validate_query(&(boundary + "a")).unwrap_err(),
        InputError::QueryTooLong
    );
}

#[test]
fn term_count_not_truncated() {
    let terms: Vec<_> = (0..33).map(|n| format!("word{n}")).collect();
    assert_eq!(validate_query(&terms[..32].join(" ")).unwrap().len(), 32);
    assert_eq!(
        validate_query(&terms.join(" ")).unwrap_err(),
        InputError::TooManyTerms
    );
}

#[test]
fn simple_atom_scalar_bound() {
    assert!(validate_query(&"a".repeat(1024)).is_ok());
    assert_eq!(
        validate_query(&"a".repeat(1025)).unwrap_err(),
        InputError::TermTooLong
    );
}

#[test]
fn operator_value_scalar_bound() {
    for operator in [
        "site:",
        "linkto:",
        "linksto:",
        "intitle:",
        "inbody:",
        "inurl:",
        "exacturl:",
    ] {
        assert!(validate_query(&format!("{operator}{}", "a".repeat(1024))).is_ok());
        assert_eq!(
            validate_query(&format!("{operator}{}", "a".repeat(1025))).unwrap_err(),
            InputError::TermTooLong
        );
    }
}

#[test]
fn phrase_word_bound() {
    assert!(validate_query(&format!("\"{}\"", vec!["word"; 32].join(" "))).is_ok());
    assert_eq!(
        validate_query(&format!("\"{}\"", vec!["word"; 33].join(" "))).unwrap_err(),
        InputError::PhraseTooLong
    );
}

#[test]
fn empty_phrase_rejected() {
    for input in ["\"\"", "\"  \"", "intitle:\"\""] {
        assert_eq!(validate_query(input).unwrap_err(), InputError::EmptyPhrase);
    }
}

#[test]
fn quote_pairs_depth_one() {
    for input in [
        "\"alpha beta\"",
        "“alpha beta”",
        "“alpha beta“",
        "that's literal",
    ] {
        assert!(validate_query(input).is_ok(), "{input}");
    }
    for input in [
        "\"alpha",
        "alpha\"",
        "“alpha\"beta”",
        "\"alpha “beta”\"",
        "“alpha”suffix",
    ] {
        assert!(validate_query(input).is_err(), "{input}");
    }
}

#[test]
fn wrapper_full_consumption() {
    for (left, right) in [('«', '»'), ('„', '“'), ('»', '«'), ('「', '」')] {
        let input = format!("{left}alpha beta{right}");
        assert_eq!(validate_query(&input).unwrap().len(), 2);
        assert!(validate_query(&format!("{input} suffix")).is_err());
        assert!(validate_query(&format!("prefix {input}")).is_err());
    }
}

#[test]
fn parser_consumes_all() {
    for input in [
        "\"alpha\"tail",
        "intitle:",
        "site:",
        "exacturl:http://[",
        "alpha --beta",
    ] {
        assert!(validate_query(input).is_err(), "{input}");
    }
    let input = "alpha\u{2002}beta";
    let atoms = validate_query(input).unwrap();
    assert_eq!(atoms.len(), 2);
    assert_eq!(&input[atoms[1].source.clone()], "beta");
}

#[test]
fn operator_count_bound() {
    let fields: Vec<_> = (0..9).map(|i| format!("intitle:word{i}")).collect();
    assert!(validate_query(&fields[..8].join(" ")).is_ok());
    assert_eq!(
        validate_query(&fields.join(" ")).unwrap_err(),
        InputError::TooManyOperators
    );
    assert_eq!(
        validate_query("anchor -site:a -site:b -site:c -site:d -site:e").unwrap_err(),
        InputError::TooManyOperators
    );
}

#[test]
fn operator_grammar_closed() {
    for input in ["--alpha", "-", "site:", "-intitle:", "exacturl:http://["] {
        assert!(validate_query(input).is_err(), "{input}");
    }
    assert!(validate_query("foo:bar").is_ok());
}

#[test]
fn positive_anchor_required() {
    for input in ["-alpha", "-site:example.test", "!unknown"] {
        assert_eq!(
            validate_query(input).unwrap_err(),
            InputError::NoSearchableTerms
        );
    }
    assert!(validate_query("site:example.test").is_ok());
    assert!(validate_query("anchor !unknown").is_ok());
}

#[test]
fn controls_rejected_before_trim() {
    for scalar in (0..=0x9f)
        .filter_map(char::from_u32)
        .filter(|c| c.is_control())
    {
        assert_eq!(
            validate_query(&format!("{scalar}anchor")).unwrap_err(),
            InputError::ForbiddenCharacter
        );
    }
}

#[test]
fn invisibles_and_bidi_controls_rejected() {
    for scalar in [0x00ad, 0x034f, 0x061c, 0xfeff]
        .into_iter()
        .chain(0x200b..=0x200f)
        .chain(0x202a..=0x202e)
        .chain(0x2060..=0x206f)
    {
        assert_eq!(
            validate_query(&format!("anchor{}", char::from_u32(scalar).unwrap())).unwrap_err(),
            InputError::ForbiddenCharacter
        );
    }
    for input in ["العربية", "עברית", "中文", "Русский"] {
        assert!(validate_query(input).is_ok());
    }
}

#[test]
fn repetition_bound_before_dedup() {
    assert!(validate_query(&vec!["alpha"; 8].join(" ")).is_ok());
    assert_eq!(
        validate_query(&vec!["alpha"; 9].join(" ")).unwrap_err(),
        InputError::ExcessiveRepetition
    );
    assert_eq!(
        validate_query("alpha ALPHA alpha ALPHA alpha ALPHA alpha ALPHA alpha").unwrap_err(),
        InputError::ExcessiveRepetition
    );
    assert!(validate_query("alpha intitle:alpha -alpha").is_ok());
}

#[test]
fn public_result_count_bound() {
    for n in [1, 100] {
        assert!(validate_numbers(0, n, true).is_ok());
    }
    for n in [0, 101, 300] {
        assert_eq!(
            validate_numbers(0, n, true).unwrap_err(),
            InputError::InvalidResultCount
        );
    }
    assert!(validate_numbers(0, 300, false).is_ok());
}

#[test]
fn page_overflow_typed() {
    assert_eq!(
        validate_numbers(usize::MAX, 2, true).unwrap_err(),
        InputError::InvalidPage
    );
    assert_eq!(
        validate_numbers(usize::MAX, 1, true).unwrap_err(),
        InputError::InvalidPage
    );
    assert_eq!(
        validate_numbers(usize::MAX - 1, 1, true).unwrap(),
        usize::MAX - 1
    );
}
