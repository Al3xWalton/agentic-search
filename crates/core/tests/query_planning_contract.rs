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

#[tokio::test]
async fn no_empty_relaxation_rescue() {
    let (searcher, _dir) = query_index::searcher(
        &[
            ("https://e.test/a", "alpha", "alpha"),
            ("https://e.test/b", "beta", "beta"),
        ],
        true,
    )
    .await;
    let found = websites(searcher.search(&query("the and of", 10)).await.unwrap());
    assert!(found.webpages.is_empty());
    assert_eq!(AgentPlan::new("the and of").unwrap().stages.len(), 1);
    assert!(AgentPlan::new("-alpha").is_err());
}

#[test]
fn language_fixed_from_original() {
    let mixed = "can you show me университет";
    assert_ne!(
        whatlang::detect_lang(mixed),
        whatlang::detect_lang("университет")
    );
    let mixed_plan = AgentPlan::new(mixed).unwrap();
    assert!(mixed_plan
        .stages
        .iter()
        .all(|stage| stage.language == mixed_plan.stages[0].language));
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
    assert!(validate_query(&format!("\"{}\"", ["word"; 32].join(" "))).is_ok());
    assert_eq!(
        validate_query(&format!("\"{}\"", ["word"; 33].join(" "))).unwrap_err(),
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
    for input in [
        "anchor --alpha",
        "--alpha",
        "-",
        "site:",
        "-intitle:",
        "exacturl:http://[",
    ] {
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
    assert!(validate_query(&["alpha"; 8].join(" ")).is_ok());
    assert_eq!(
        validate_query(&["alpha"; 9].join(" ")).unwrap_err(),
        InputError::ExcessiveRepetition
    );
    assert_eq!(
        validate_query("alpha ALPHA alpha ALPHA alpha ALPHA alpha ALPHA alpha").unwrap_err(),
        InputError::ExcessiveRepetition
    );
    assert!(validate_query("alpha intitle:alpha -alpha").is_ok());
}

#[test]
fn internal_result_count_bound() {
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

#[path = "support/query_index.rs"]
mod query_index;

fn websites(result: stract::searcher::SearchResult) -> stract::searcher::WebsitesResult {
    match result {
        stract::searcher::SearchResult::Websites(result) => result,
        _ => panic!("expected websites"),
    }
}

#[tokio::test]
async fn fallback_on_zero() {
    let (searcher, _dir) = query_index::searcher(
        &[(
            "https://compiler.test/a",
            "Compiler allocation",
            "compiler allocation diagnostics",
        )],
        true,
    )
    .await;
    let result = websites(
        searcher
            .search(&stract::searcher::SearchQuery {
                query: "please find compiler allocation".into(),
                num_results: 2,
                count_results_exact: true,
                ..Default::default()
            })
            .await
            .unwrap(),
    );
    assert_eq!(result.webpages.len(), 1);
    let plan = result.query_plan.unwrap();
    assert_eq!(plan.stages[0].id, stract::query::planner::StageId::Strict);
    assert_eq!(plan.stages[0].returned_count, 0);
    assert_eq!(plan.stages[1].id, stract::query::planner::StageId::Content);
    assert_eq!(
        result.webpages[0].plan_stage,
        Some(stract::query::planner::StageId::Content)
    );
}

#[tokio::test]
async fn planner_off_strict_provenance() {
    let (searcher, _dir) = query_index::searcher(
        &[(
            "https://compiler.test/a",
            "Compiler allocation",
            "compiler allocation diagnostics",
        )],
        false,
    )
    .await;
    let result = websites(
        searcher
            .search(&stract::searcher::SearchQuery {
                query: "please find compiler allocation".into(),
                num_results: 2,
                ..Default::default()
            })
            .await
            .unwrap(),
    );
    assert!(result.webpages.is_empty());
    let plan = result.query_plan.unwrap();
    assert_eq!(
        plan.mode,
        stract::searcher::provenance::PlanMode::StrictOnly
    );
    assert_eq!(plan.stages.len(), 1);
    assert_eq!(plan.stages[0].returned_count, 0);
}

#[tokio::test]
async fn constraints_survive_all_stages() {
    let docs = [
        (
            "https://allowed.test/a",
            "Compiler manual",
            "compiler runtime safe",
        ),
        (
            "https://blocked.test/a",
            "Compiler manual",
            "compiler runtime safe",
        ),
        (
            "https://allowed.test/b",
            "Compiler manual",
            "compiler runtime obsolete",
        ),
    ];
    let (searcher, _dir) = query_index::searcher(&docs, true).await;
    let result = websites(
        searcher
            .search(&stract::searcher::SearchQuery {
                query: "please find compiler runtime site:allowed.test -obsolete".into(),
                num_results: 5,
                ..Default::default()
            })
            .await
            .unwrap(),
    );
    assert_eq!(
        result
            .webpages
            .iter()
            .map(|p| p.url.as_str())
            .collect::<Vec<_>>(),
        ["https://allowed.test/a"]
    );
    assert!(result.query_plan.unwrap().stages.iter().all(|s| s
        .rendered_query
        .contains("must_not:")
        && s.terms
            .iter()
            .any(|t| t.kind == stract::searcher::provenance::TermKind::Site)));
}

#[tokio::test]
async fn relaxed_count_uses_atom_votes() {
    let docs = [
        ("https://alpha.test/a", "alpha", "alpha"),
        ("https://beta.test/a", "alpha", "beta"),
        ("https://gamma.test/a", "gamma", "gamma"),
    ];
    let (searcher, _dir) = query_index::searcher(&docs, true).await;
    let result = websites(
        searcher
            .search(&stract::searcher::SearchQuery {
                query: "alpha beta gamma".into(),
                num_results: 5,
                count_results_exact: true,
                ..Default::default()
            })
            .await
            .unwrap(),
    );
    let plan = result.query_plan.unwrap();
    let relaxed = plan
        .stages
        .iter()
        .find(|s| s.id == stract::query::planner::StageId::Relaxed)
        .unwrap();
    assert_eq!(relaxed.minimum_should_match, Some(2));
    assert_eq!(serde_json::to_value(relaxed.hit_count).unwrap()["value"], 1);
    assert_eq!(result.webpages[0].url, "https://beta.test/a");
    assert_eq!(
        result.webpages[0].plan_stage,
        Some(stract::query::planner::StageId::Relaxed)
    );
}

use serde_json::json;
use stract::searcher::{
    api::staged::StageAccumulator,
    provenance::{PlanMode, StageProvenance},
    WebsitesResult,
};
fn page(url: &str) -> serde_json::Value {
    json!({"title":"synthetic","url":url,"site":"fixture.test","domain":"fixture.test","prettyUrl":url,"snippet":{"date":null,"text":{"fragments":[]}},"richSnippet":null,"rankingSignals":null,"structuredData":null,"likelyHasAds":false,"likelyHasPaywall":false})
}
fn result(urls: &[&str], count: u64, more: bool) -> WebsitesResult {
    serde_json::from_value(json!({"webpages":urls.iter().map(|u|page(u)).collect::<Vec<_>>(),"numHits":{"_type":"exact","value":count},"searchDurationMs":1,"hasMoreResults":more})).unwrap()
}
fn plans() -> Vec<stract::query::planner::StagePlan> {
    AgentPlan::new("please find compiler allocation runtime errors")
        .unwrap()
        .stages
}
fn accumulation(limit: usize) -> WebsitesResult {
    let plans = plans();
    let mut acc = StageAccumulator::new(limit, PlanMode::Staged);
    acc.complete(
        &plans[0],
        "strict compiled".into(),
        result(&["https://e.test/a"], 7, false),
        3,
    );
    acc.complete(
        &plans[1],
        "content compiled".into(),
        result(&["https://e.test/a", "https://e.test/b"], 9, false),
        8,
    );
    acc.finish(15, true)
}
#[test]
fn api_provenance_default() {
    let value = serde_json::to_value(accumulation(3)).unwrap();
    assert!(value["queryPlan"].is_object());
    let tagged =
        serde_json::to_value(stract::searcher::SearchResult::Websites(accumulation(3))).unwrap();
    assert!(tagged.to_string().contains("queryPlan"));
}
#[test]
fn provenance_version() {
    assert_eq!(accumulation(3).query_plan.unwrap().version, 1);
}
#[test]
fn provenance_mode() {
    for mode in [
        PlanMode::Staged,
        PlanMode::StrictOnly,
        PlanMode::PaginationStrict,
    ] {
        let mut acc = StageAccumulator::new(1, mode);
        acc.complete(&plans()[0], "compiled".into(), result(&[], 0, false), 0);
        assert_eq!(acc.finish(0, false).query_plan.unwrap().mode, mode);
    }
}
#[test]
fn provenance_stage_order() {
    let value = accumulation(3);
    assert_eq!(
        value
            .query_plan
            .unwrap()
            .stages
            .iter()
            .map(|s| s.id)
            .collect::<Vec<_>>(),
        [StageId::Strict, StageId::Content]
    );
}
fn detailed() -> StageProvenance {
    let plan = AgentPlan::new(
        "please find Rust API compiler \"memory safety\" site:allowed.test -obsolete",
    )
    .unwrap();
    let selected = plan
        .stages
        .iter()
        .find(|s| s.id == StageId::Relaxed)
        .unwrap();
    StageProvenance::completed(
        selected,
        "compiled".into(),
        serde_json::from_value(json!({"_type":"exact","value":19})).unwrap(),
        3,
        1,
        8,
    )
}
#[test]
fn provenance_term_text() {
    let p = detailed();
    let texts: Vec<_> = p.terms.iter().map(|t| t.text.as_str()).collect();
    for expected in [
        "Rust",
        "API",
        "compiler",
        "memory safety",
        "allowed.test",
        "obsolete",
    ] {
        assert!(texts.contains(&expected), "missing {expected}: {texts:?}");
    }
    assert!(!texts.contains(&"please"));
}
#[test]
fn provenance_term_kind() {
    let p = detailed();
    let value = serde_json::to_value(p).unwrap();
    for (text, kind) in [
        ("API", "entity"),
        ("memory safety", "phrase"),
        ("allowed.test", "site"),
        ("obsolete", "literal"),
    ] {
        assert!(value["terms"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["text"] == text && t["kind"] == kind));
    }
}
#[test]
fn provenance_occurrence() {
    let value = serde_json::to_value(detailed()).unwrap();
    for (text, occur) in [
        ("compiler", "should"),
        ("memory safety", "must"),
        ("allowed.test", "must"),
        ("obsolete", "must_not"),
    ] {
        assert!(value["terms"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["text"] == text && t["occur"] == occur));
    }
}
#[test]
fn provenance_weights() {
    let value = serde_json::to_value(detailed()).unwrap();
    for (text, weight) in [
        ("compiler", 1),
        ("API", 2),
        ("memory safety", 2),
        ("obsolete", 1),
    ] {
        assert!(value["terms"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["text"] == text && t["weight"] == weight));
    }
}
#[test]
fn provenance_rewritten_query() {
    let stages = plans();
    let actual = stages
        .iter()
        .map(|stage| {
            let completed = StageProvenance::completed(
                stage,
                "compiled".into(),
                serde_json::from_value(json!({"_type":"exact","value":0})).unwrap(),
                0,
                0,
                0,
            );
            serde_json::to_value(completed).unwrap()["rewrittenQuery"].clone()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        [
            json!("please find compiler allocation runtime errors"),
            json!("compiler allocation runtime errors"),
            json!("compiler allocation runtime errors"),
            json!("compiler allocation runtime"),
        ]
    );
}

#[test]
fn provenance_minimum() {
    let stages = plans();
    let counts = stages
        .iter()
        .map(|s| {
            StageProvenance::completed(
                s,
                "compiled".into(),
                serde_json::from_value(json!({"_type":"exact","value":0})).unwrap(),
                0,
                0,
                0,
            )
            .minimum_should_match
        })
        .collect::<Vec<_>>();
    assert_eq!(counts, vec![None, None, Some(2), Some(1)]);
}
#[test]
fn provenance_hit_count() {
    let value = serde_json::to_value(accumulation(3)).unwrap();
    assert_eq!(
        value["queryPlan"]["stages"][0]["hitCount"],
        json!({"_type":"exact","value":7})
    );
    assert_eq!(value["queryPlan"]["stages"][1]["hitCount"]["value"], 9);
}
#[test]
fn provenance_returned_count() {
    assert_eq!(
        accumulation(3).query_plan.unwrap().stages[1].returned_count,
        2
    );
}
#[test]
fn provenance_added_count() {
    assert_eq!(accumulation(3).query_plan.unwrap().stages[1].added_count, 1);
}
#[test]
fn provenance_produced_results() {
    let mut acc = StageAccumulator::new(3, PlanMode::Staged);
    let stages = plans();
    for stage in &stages[..2] {
        acc.complete(
            stage,
            "compiled".into(),
            result(&["https://e.test/a"], 1, false),
            2,
        );
    }
    let p = acc.finish(5, false).query_plan.unwrap();
    assert!(p.stages[1].produced_results);
    assert_eq!(p.stages[1].added_count, 0);
}
#[test]
fn per_page_producer() {
    let r = accumulation(3);
    assert_eq!(
        r.webpages.iter().map(|p| p.plan_stage).collect::<Vec<_>>(),
        [Some(StageId::Strict), Some(StageId::Content)]
    );
}
#[test]
fn empty_success_has_provenance() {
    let mut acc = StageAccumulator::new(3, PlanMode::Staged);
    for stage in plans() {
        acc.complete(&stage, "compiled".into(), result(&[], 0, false), 0);
    }
    let r = acc.finish(1, false);
    assert!(r.webpages.is_empty());
    assert_eq!(r.query_plan.unwrap().stages.len(), 4);
}
#[test]
fn provenance_count_scope() {
    use stract::searcher::provenance::NumHitsScope;
    let mut acc = StageAccumulator::new(3, PlanMode::Staged);
    acc.complete(&plans()[0], "compiled".into(), result(&[], 0, false), 0);
    assert_eq!(
        acc.finish(0, false).query_plan.unwrap().num_hits_scope,
        NumHitsScope::SingleStage
    );
    assert_eq!(
        accumulation(3).query_plan.unwrap().num_hits_scope,
        NumHitsScope::LargestStageEstimate
    );
}
#[test]
fn multistage_count_is_estimate() {
    let r = serde_json::to_value(accumulation(3)).unwrap();
    assert_eq!(r["numHits"], json!({"_type":"approximate","value":9}));
}
#[test]
fn multistage_has_more() {
    let stages = plans();
    for (tried_more, untried, omitted, expected) in [
        (true, false, false, true),
        (false, true, false, true),
        (false, false, true, true),
        (false, false, false, false),
    ] {
        let mut acc = StageAccumulator::new(2, PlanMode::Staged);
        acc.complete(
            &stages[0],
            "compiled".into(),
            result(&["https://e.test/a"], 1, tried_more),
            0,
        );
        let urls = if omitted {
            vec!["https://e.test/b", "https://e.test/c"]
        } else {
            vec!["https://e.test/b"]
        };
        acc.complete(&stages[1], "compiled".into(), result(&urls, 2, false), 0);
        assert_eq!(acc.finish(0, untried).has_more_results, expected);
    }
}
#[test]
fn earliest_stage_prefix_preserved() {
    let mut acc = StageAccumulator::new(5, PlanMode::Staged);
    let stages = plans();
    acc.complete(
        &stages[0],
        "compiled".into(),
        result(
            &["https://e.test/B", "https://e.test/a", "https://e.test/a"],
            3,
            false,
        ),
        0,
    );
    acc.complete(
        &stages[1],
        "compiled".into(),
        result(
            &["https://e.test/a", "http://e.test/a/", "https://e.test/c"],
            3,
            false,
        ),
        0,
    );
    let r = acc.finish(0, false);
    assert_eq!(
        r.webpages
            .iter()
            .map(|p| p.url.as_str())
            .collect::<Vec<_>>(),
        [
            "https://e.test/B",
            "https://e.test/a",
            "https://e.test/a",
            "http://e.test/a/",
            "https://e.test/c"
        ]
    );
}
#[test]
fn provenance_allowlisted_schema_only() {
    let value = serde_json::to_value(accumulation(3)).unwrap();
    let plan = value["queryPlan"].as_object().unwrap();
    let serialized = serde_json::to_string(&plan).unwrap();
    for marker in ["127.0.0.1", "Backbone(", "shardAddress", "SegmentReader"] {
        assert!(!serialized.contains(marker));
    }
    assert_eq!(
        plan.keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        ["version", "mode", "numHitsScope", "stages"]
            .into_iter()
            .collect()
    );
    let stage = plan["stages"][0].as_object().unwrap();
    assert_eq!(
        stage
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        [
            "id",
            "terms",
            "rewrittenQuery",
            "renderedQuery",
            "minimumShouldMatch",
            "hitCount",
            "returnedCount",
            "addedCount",
            "elapsedMs",
            "producedResults"
        ]
        .into_iter()
        .collect()
    );
    for term in stage["terms"].as_array().unwrap() {
        assert_eq!(term.as_object().unwrap().len(), 4);
    }
}
#[test]
fn provenance_request_isolation() {
    let stages = plans();
    let mut a = StageAccumulator::new(2, PlanMode::Staged);
    let mut b = StageAccumulator::new(2, PlanMode::StrictOnly);
    a.complete(
        &stages[0],
        "request_a".into(),
        result(&["https://a.test/"], 1, false),
        2,
    );
    b.complete(
        &stages[0],
        "request_b".into(),
        result(&["https://b.test/"], 1, false),
        4,
    );
    a.complete(
        &stages[1],
        "request_a_second".into(),
        result(&[], 0, false),
        3,
    );
    let a = serde_json::to_string(&a.finish(8, false)).unwrap();
    let b = serde_json::to_string(&b.finish(5, false)).unwrap();
    assert!(!a.contains("request_b") && !b.contains("request_a"));
}

fn query(text: &str, count: usize) -> stract::searcher::SearchQuery {
    stract::searcher::SearchQuery {
        query: text.into(),
        num_results: count,
        count_results_exact: true,
        ..Default::default()
    }
}
#[tokio::test]
async fn fallback_on_short_nonzero() {
    let docs = [
        (
            "https://e.test/a",
            "please find compiler allocation",
            "please find compiler allocation",
        ),
        (
            "https://e.test/b",
            "compiler allocation",
            "compiler allocation",
        ),
    ];
    let (searcher, _dir) = query_index::searcher(&docs, true).await;
    let r = websites(
        searcher
            .search(&query("please find compiler allocation", 2))
            .await
            .unwrap(),
    );
    assert_eq!(r.webpages.len(), 2);
    assert_eq!(r.webpages[0].plan_stage, Some(StageId::Strict));
    assert_eq!(r.webpages[1].plan_stage, Some(StageId::Content));
}
#[tokio::test]
async fn fallback_after_duplicate_only_stage() {
    let docs = [
        (
            "https://e.test/a",
            "please find compiler allocation runtime",
            "please find compiler allocation runtime",
        ),
        (
            "https://e.test/b",
            "compiler allocation",
            "compiler allocation",
        ),
    ];
    let (searcher, _dir) = query_index::searcher(&docs, true).await;
    let r = websites(
        searcher
            .search(&query("please find compiler allocation runtime", 2))
            .await
            .unwrap(),
    );
    let p = r.query_plan.unwrap();
    assert_eq!(p.stages[1].returned_count, 1);
    assert_eq!(p.stages[1].added_count, 0);
    assert_eq!(p.stages[2].id, StageId::Relaxed);
    assert_eq!(r.webpages.len(), 2);
}
#[tokio::test]
async fn full_page_stops() {
    let docs = [(
        "https://e.test/a",
        "please find compiler allocation",
        "please find compiler allocation",
    )];
    let (searcher, _dir) = query_index::searcher(&docs, true).await;
    let r = websites(
        searcher
            .search(&query("please find compiler allocation", 1))
            .await
            .unwrap(),
    );
    assert_eq!(r.query_plan.unwrap().stages.len(), 1);
}
#[tokio::test]
async fn all_stages_empty_is_empty_success() {
    let (searcher, _dir) = query_index::searcher(
        &[("https://e.test/a", "unrelated content", "unrelated content")],
        true,
    )
    .await;
    let r = websites(
        searcher
            .search(&query("please find compiler allocation runtime errors", 5))
            .await
            .unwrap(),
    );
    assert!(r.webpages.is_empty());
    let p = r.query_plan.unwrap();
    assert_eq!(p.stages.len(), 4);
    assert!(p.stages.iter().all(|s| s.returned_count == 0));
    assert!(!r.has_more_results);
}
#[tokio::test]
async fn planner_off_strict_only() {
    let (searcher, _dir) = query_index::searcher(
        &[(
            "https://e.test/a",
            "compiler allocation",
            "compiler allocation",
        )],
        false,
    )
    .await;
    let r = websites(
        searcher
            .search(&query("please find compiler allocation", 2))
            .await
            .unwrap(),
    );
    assert!(r.webpages.is_empty());
    let p = r.query_plan.unwrap();
    assert_eq!(p.mode, PlanMode::StrictOnly);
    assert_eq!(p.stages.len(), 1);
}
#[tokio::test]
async fn pagination_strict_only() {
    let (searcher, _dir) = query_index::searcher(
        &[
            (
                "https://e.test/a",
                "compiler allocation",
                "compiler allocation",
            ),
            (
                "https://e.test/b",
                "compiler allocation",
                "compiler allocation",
            ),
        ],
        true,
    )
    .await;
    let mut q = query("compiler allocation", 1);
    q.page = 1;
    let r = websites(searcher.search(&q).await.unwrap());
    assert_eq!(r.webpages.len(), 1);
    let p = r.query_plan.unwrap();
    assert_eq!(p.mode, PlanMode::PaginationStrict);
    assert_eq!(p.stages.len(), 1);
    q.page = 400;
    let r = websites(searcher.search(&q).await.unwrap());
    assert!(r.webpages.is_empty());
    assert_eq!(r.query_plan.unwrap().stages.len(), 1);
}
#[test]
fn equivalent_stages_not_executed() {
    let p = AgentPlan::new("compiler").unwrap();
    assert_eq!(p.stages.len(), 1);
    assert_eq!(p.stages[0].id, StageId::Strict);
}
#[tokio::test]
async fn strict_preserves_legacy_candidates() {
    let docs = [
        (
            "https://e.test/a",
            "compiler allocation",
            "compiler allocation",
        ),
        ("https://e.test/b", "compiler", "compiler unrelated"),
        ("https://e.test/c", "allocation", "allocation unrelated"),
    ];
    let (searcher, _dir) = query_index::searcher(&docs, false).await;
    let r = websites(
        searcher
            .search(&query("compiler allocation", 5))
            .await
            .unwrap(),
    );
    assert_eq!(
        r.webpages
            .iter()
            .map(|p| p.url.as_str())
            .collect::<Vec<_>>(),
        ["https://e.test/a"]
    );
}
fn all_four_stages(text: &str) -> Vec<stract::query::planner::StagePlan> {
    let stages = AgentPlan::new(text).unwrap().stages;
    assert_eq!(
        stages.iter().map(|stage| stage.id).collect::<Vec<_>>(),
        [
            StageId::Strict,
            StageId::Content,
            StageId::Relaxed,
            StageId::Core
        ]
    );
    stages
}

#[tokio::test]
async fn quotes_remain_required_phrases() {
    let docs = [
        (
            "https://e.test/a",
            "memory safety compiler allocation runtime errors",
            "memory safety compiler allocation runtime errors",
        ),
        (
            "https://e.test/b",
            "memory separate safety compiler allocation runtime errors",
            "memory separate safety compiler allocation runtime errors",
        ),
    ];
    let (local, _dir) = query_index::local(&docs, |_, _| {});
    for stage in all_four_stages("please find compiler allocation runtime errors \"memory safety\"")
    {
        let mut q = query(&stage.original, 10);
        q.stage_plan = Some(stage);
        let r = local.search_initial_v2(&q).await.unwrap();
        assert_eq!(
            r.result.num_websites.as_u64(),
            if q.stage_plan.as_ref().unwrap().id == StageId::Strict {
                0
            } else {
                1
            }
        );
    }
}
#[tokio::test]
async fn negation_survives_all_stages() {
    let docs = [
        (
            "https://e.test/a",
            "compiler allocation runtime memory",
            "compiler allocation runtime memory current",
        ),
        (
            "https://e.test/b",
            "compiler allocation runtime memory obsolete",
            "compiler allocation runtime memory obsolete",
        ),
    ];
    let (local, _dir) = query_index::local(&docs, |_, _| {});
    for text in [
        "please find compiler allocation runtime memory -obsolete",
        "please find compiler allocation runtime memory -\"memory obsolete\"",
        "please find compiler allocation runtime memory -intitle:obsolete",
    ] {
        for stage in all_four_stages(text) {
            let mut q = query(text, 10);
            let strict = stage.id == StageId::Strict;
            q.stage_plan = Some(stage);
            let r = local.search_initial_v2(&q).await.unwrap();
            assert_eq!(
                r.result.num_websites.as_u64(),
                if strict { 0 } else { 1 },
                "query={text} stage={:?} rendering={}",
                q.stage_plan.as_ref().unwrap().id,
                r.rendered_query
            );
        }
    }
}
#[tokio::test]
async fn safe_search_every_stage() {
    use stract::webpage::safety_classifier::Label;
    let docs = [
        (
            "https://e.test/a",
            "compiler allocation runtime errors",
            "compiler allocation runtime errors",
        ),
        (
            "https://e.test/b",
            "compiler allocation runtime errors",
            "compiler allocation runtime errors",
        ),
    ];
    let (local, _dir) = query_index::local(&docs, |i, w| {
        w.safety_classification = Some(if i == 0 { Label::SFW } else { Label::NSFW });
    });
    for stage in all_four_stages("please find compiler allocation runtime errors") {
        let strict = stage.id == StageId::Strict;
        let mut q = query(&stage.original, 10);
        q.safe_search = true;
        q.stage_plan = Some(stage);
        assert_eq!(
            local
                .search_initial_v2(&q)
                .await
                .unwrap()
                .result
                .num_websites
                .as_u64(),
            if strict { 0 } else { 1 }
        );
    }
}
#[tokio::test]
async fn relaxed_count_uses_matching_node() {
    let (local, _dir) = query_index::local_with_collector(
        &[
            ("https://e.test/a", "alpha beta", "alpha beta"),
            ("https://e.test/b", "alpha gamma", "alpha gamma"),
            ("https://e.test/c", "beta gamma", "beta gamma"),
            ("https://e.test/d", "alpha", "alpha"),
        ],
        |_, _| {},
        stract::config::CollectorConfig {
            max_docs_considered: 1,
            ..Default::default()
        },
    );
    let stage = AgentPlan::new("alpha beta gamma")
        .unwrap()
        .stages
        .into_iter()
        .find(|s| s.id == StageId::Relaxed)
        .unwrap();
    let mut q = query(&stage.original, 10);
    q.count_results_exact = false;
    q.stage_plan = Some(stage);
    let found = local.search_initial_v2(&q).await.unwrap();
    assert_eq!(
        serde_json::to_value(found.result.num_websites).unwrap(),
        json!({"_type":"exact", "value":3})
    );
}

#[tokio::test]
async fn s3_one_atom_one_vote() {
    let (local, _dir) = query_index::local(
        &[
            ("https://alpha.test/alpha", "alpha", "alpha alpha alpha"),
            ("https://e.test/b", "alpha", "beta"),
        ],
        |_, _| {},
    );
    let stage = AgentPlan::new("alpha beta gamma")
        .unwrap()
        .stages
        .into_iter()
        .find(|s| s.id == StageId::Relaxed)
        .unwrap();
    let mut q = query(&stage.original, 10);
    q.stage_plan = Some(stage);
    assert_eq!(
        local
            .search_initial_v2(&q)
            .await
            .unwrap()
            .result
            .num_websites
            .as_u64(),
        1
    );
}
#[tokio::test]
async fn unknown_bang_keeps_legacy_meaning() {
    let (local, _dir) =
        query_index::local(&[("https://e.test/a", "compiler", "compiler")], |_, _| {});
    let bangs =
        stract::bangs::Bangs::from_json(r#"[{"t":"docs","u":"https://docs.test/?q={{{s}}}"}]"#);
    let searcher = query_index::api(local, true, bangs).await;
    assert!(matches!(
        searcher
            .search(&query("compiler !notregistered", 1))
            .await
            .unwrap(),
        stract::searcher::SearchResult::Websites(_)
    ));
    let p = AgentPlan::new("compiler !notregistered").unwrap();
    assert!(p.stages.iter().all(|s| s
        .atoms
        .iter()
        .any(|a| a.source.term.to_string() == "!notregistered" && a.constraint)));
}
#[tokio::test]
async fn bare_bang_uses_shared_strict_budget() {
    let probe = std::sync::Arc::new(std::sync::Mutex::new(query_client::Probe::default()));
    let (searcher, _dir) = observed(
        &[("https://e.test/a", "compiler", "compiler")],
        probe.clone(),
        stract::bangs::Bangs::empty(),
    )
    .await;
    let hit = searcher.search(&query("compiler !", 1)).await.unwrap();
    assert_eq!(probe.lock().unwrap().searches.len(), 1);
    assert!(matches!(hit, stract::searcher::SearchResult::Bang(_)));
    let error = searcher
        .search(&query("nomatchingword !", 1))
        .await
        .unwrap_err();
    assert!(error
        .downcast_ref::<stract::searcher::api::staged::NoBangTarget>()
        .is_some());
    assert_eq!(probe.lock().unwrap().searches.len(), 2);
}
#[tokio::test]
async fn bang_has_no_provenance() {
    let (local, _dir) =
        query_index::local(&[("https://e.test/a", "compiler", "compiler")], |_, _| {});
    let bangs =
        stract::bangs::Bangs::from_json(r#"[{"t":"docs","u":"https://docs.test/?q={{{s}}}"}]"#);
    let searcher = query_index::api(local, true, bangs).await;
    for text in ["compiler !docs", "compiler !"] {
        let hit = searcher.search(&query(text, 1)).await.unwrap();
        let value = serde_json::to_string(&hit).unwrap();
        assert!(matches!(hit, stract::searcher::SearchResult::Bang(_)));
        assert!(!value.contains("queryPlan") && !value.contains("planStage"));
    }
}
#[tokio::test]
async fn known_bang_redirect_preserved() {
    let (local, _dir) = query_index::local(&[], |_, _| {});
    let bangs =
        stract::bangs::Bangs::from_json(r#"[{"t":"docs","u":"https://docs.test/?q={{{s}}}"}]"#);
    let searcher = query_index::api(local, true, bangs).await;
    let hit = searcher.search(&query("!docs compiler", 1)).await.unwrap();
    match hit {
        stract::searcher::SearchResult::Bang(hit) => {
            assert!(hit.redirect_to.as_str().contains("compiler"))
        }
        _ => panic!("redirect expected"),
    };
}

async fn validated_route(body: axum::body::Body) -> (axum::http::StatusCode, serde_json::Value) {
    use tower::ServiceExt;
    let app = axum::Router::new().route(
        "/beta/api/search",
        axum::routing::post(|_: stract::api::search::ValidatedSearchRequest| async {
            axum::Json(json!({"valid":true}))
        }),
    );
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/beta/api/search")
                .header("content-type", "application/json")
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 10000)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}
#[tokio::test]
async fn body_limit_before_json() {
    use axum::{body::Body, http::StatusCode};
    let base = r#"{"query":"compiler"}"#;
    let exact = format!("{base}{}", " ".repeat(65536 - base.len()));
    assert_eq!(
        validated_route(Body::from(exact.clone())).await.0,
        StatusCode::OK
    );
    let (status, value) = validated_route(Body::from(exact + " ")).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(value["error"]["code"], "request_too_large");
    let chunks = futures::stream::iter(vec![
        Ok::<_, std::io::Error>(vec![b' '; 32768]),
        Ok(vec![b' '; 32769]),
    ]);
    assert_eq!(
        validated_route(Body::from_stream(chunks)).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}
#[tokio::test]
async fn invalid_json_typed() {
    for body in [
        "{",
        r#"{"query":42}"#,
        r#"{"query":"compiler","stagePlan":"core"}"#,
    ] {
        let (status, value) = validated_route(axum::body::Body::from(body)).await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(value["error"]["code"], "invalid_request");
    }
}
#[tokio::test]
async fn public_result_count_bound() {
    for (n, status) in [(0, 400), (1, 200), (100, 200), (101, 400), (300, 400)] {
        let (actual, value) = validated_route(axum::body::Body::from(
            json!({"query":"compiler","numResults":n}).to_string(),
        ))
        .await;
        assert_eq!(actual.as_u16(), status);
        if status == 400 {
            assert_eq!(value["error"]["code"], "invalid_result_count");
        }
    }
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config { cases: 64, failure_persistence: None, ..Default::default() })]
    #[test]
    fn full_allowed_compiler_property(chars in proptest::collection::vec(proptest::char::any(),0..128)) {
        let text:String=chars.into_iter().collect();
        if let Ok(plan)=AgentPlan::new(&text) {
            let (local,_dir)=query_index::local(&[("https://e.test/a","compiler","synthetic compiler manual")],|_,_|{});
            let runtime=tokio::runtime::Runtime::new().unwrap();
            for stage in plan.stages {
                let mut q=query(&text,10); q.stage_plan=Some(stage);
                let rendering=stract::query::Query::render_query(&q);
                let result=runtime.block_on(local.search_initial_v2(&q));
                if let Ok(rendering)=rendering { proptest::prop_assert!(rendering.len()<=262144); proptest::prop_assert_eq!(&rendering,&stract::query::Query::render_query(&q).unwrap()); if let Ok(result)=result {proptest::prop_assert_eq!(result.rendered_query,rendering);} }
                else {proptest::prop_assert!(result.is_err());}
            }
        }
    }
}

#[tokio::test]
async fn operators_survive_all_stages() {
    let docs = [
        (
            "https://allowed.test/special",
            "compiler allocation runtime errors manual",
            "compiler allocation runtime errors secret <a href='https://target.test/page'>reference</a>",
        ),
        (
            "https://other.test/plain",
            "compiler allocation runtime errors guide",
            "compiler allocation runtime errors ordinary <a href='https://unrelated.test/'>reference</a>",
        ),
    ];
    let (local, _dir) = query_index::local(&docs, |_, _| {});
    for constraint in [
        "site:allowed.test",
        "linkto:target.test",
        "linksto:target.test",
        "intitle:manual",
        "inbody:secret",
        "inurl:special",
        "exacturl:https://allowed.test/special",
    ] {
        let text = format!("please find compiler allocation runtime errors {constraint}");
        for stage in all_four_stages(&text) {
            let strict = stage.id == StageId::Strict;
            let mut q = query(&text, 10);
            q.stage_plan = Some(stage);
            let result = local.search_initial_v2(&q).await.unwrap();
            assert_eq!(
                result.result.num_websites.as_u64(),
                if strict { 0 } else { 1 },
                "constraint {constraint}, stage {:?}",
                q.stage_plan.as_ref().unwrap().id
            );
        }
    }
}
#[tokio::test]
async fn optic_every_stage() {
    let docs = [
        (
            "https://allowed.test/a",
            "compiler allocation runtime errors",
            "compiler allocation runtime errors",
        ),
        (
            "https://blocked.test/b",
            "compiler allocation runtime errors",
            "compiler allocation runtime errors",
        ),
    ];
    let (local, _dir) = query_index::local(&docs, |_, _| {});
    for optic in [
        r#"Rule { Matches { Site("blocked.test") } Action(Discard) }"#,
        r#"DiscardNonMatching; Rule { Matches { Site("allowed.test") } }"#,
    ] {
        for stage in all_four_stages("please find compiler allocation runtime errors") {
            let strict = stage.id == StageId::Strict;
            let mut q = query(&stage.original, 10);
            q.optic = Some(optics::Optic::parse(optic).unwrap());
            q.stage_plan = Some(stage);
            assert_eq!(
                local
                    .search_initial_v2(&q)
                    .await
                    .unwrap()
                    .result
                    .num_websites
                    .as_u64(),
                if strict { 0 } else { 1 }
            );
        }
    }
}
#[tokio::test]
async fn host_rankings_every_stage() {
    let docs = [
        (
            "https://allowed.test/a",
            "compiler allocation runtime errors",
            "compiler allocation runtime errors",
        ),
        (
            "https://blocked.test/b",
            "compiler allocation runtime errors",
            "compiler allocation runtime errors",
        ),
        (
            "https://opticblocked.test/c",
            "compiler allocation runtime errors",
            "compiler allocation runtime errors",
        ),
    ];
    let (local, _dir) = query_index::local(&docs, |_, _| {});
    for stage in all_four_stages("please find compiler allocation runtime errors") {
        let strict = stage.id == StageId::Strict;
        let mut q = query(&stage.original, 10);
        q.host_rankings = Some(optics::HostRankings {
            blocked: vec!["blocked.test".into()],
            liked: vec!["allowed.test".into()],
            disliked: vec!["opticblocked.test".into()],
        });
        let mut optic = optics::Optic::default();
        optic.host_rankings.blocked.push("opticblocked.test".into());
        q.optic = Some(optic);
        q.stage_plan = Some(stage);
        assert_eq!(
            local
                .search_initial_v2(&q)
                .await
                .unwrap()
                .result
                .num_websites
                .as_u64(),
            if strict { 0 } else { 1 }
        );
    }
}
#[test]
fn query_text_never_becomes_regex_or_optic() {
    for text in [
        "a{1000000}",
        "/a+/",
        "[abc]",
        "foo|bar",
        "SELECT data FROM table",
        "DiscardNonMatching; Rule Matches Site",
    ] {
        let q = query(text, 10);
        let rendered = stract::query::Query::render_query(&q).unwrap();
        assert!(!rendered.contains("RegexQuery") && !rendered.contains("optic(sha256="));
        assert!(rendered.contains("TERM(") || rendered.contains("PHRASE("));
    }
}

#[tokio::test]
async fn entity_preference_changes_tied_order() {
    use stract::ranking::{
        pipeline::RankableWebpage, signals::HostCentrality, SignalCoefficients, SignalEnum,
    };
    let docs = [
        (
            "https://separated.test/a",
            "cedar long harbor",
            "cedar long harbor",
        ),
        (
            "https://adjacent.test/a",
            "cedar harbor long",
            "cedar harbor long",
        ),
    ];
    let (local, _dir) = query_index::local(&docs, |_, w| w.host_centrality = 1.0);
    let stage = AgentPlan::new("please find Cedar Harbor")
        .unwrap()
        .stages
        .into_iter()
        .find(|s| s.id == StageId::Content)
        .unwrap();
    let mut q = query(&stage.original, 10);
    q.stage_plan = Some(stage);
    q.signal_coefficients = SignalCoefficients::new(SignalEnum::all().map(|s| {
        let coefficient = if s == SignalEnum::from(HostCentrality) {
            1.0
        } else {
            0.0
        };
        (s, coefficient)
    }));
    let r = local.search_initial_v2(&q).await.unwrap();
    assert_eq!(r.result.websites.len(), 2);
    assert_eq!(r.result.websites[0].pointer().address.doc_id, 1);
    let mut boosts = r
        .result
        .websites
        .iter()
        .map(|p| (p.pointer().address.doc_id, p.boost()))
        .collect::<Vec<_>>();
    boosts.sort_by_key(|p| p.0);
    assert!((boosts[0].1 - 5.0 / 3.0).abs() < 1e-9);
    assert!((boosts[1].1 - 2.0).abs() < 1e-9);
}
#[tokio::test]
async fn preference_applied_once_with_optics() {
    use stract::ranking::pipeline::RankableWebpage;
    let (local, _dir) = query_index::local(
        &[("https://e.test/a", "cedar harbor", "cedar harbor")],
        |_, _| {},
    );
    let stage = AgentPlan::new("please find Cedar Harbor")
        .unwrap()
        .stages
        .into_iter()
        .find(|s| s.id == StageId::Content)
        .unwrap();
    let mut q = query(&stage.original, 10);
    q.stage_plan = Some(stage);
    q.optic=Some(optics::Optic::parse(r#"Rule { Matches { Site("e.test") } Action(Boost(3)) }; Rule { Matches { Site("e.test") } Action(Downrank(1)) }"#).unwrap());
    let r = local.search_initial_v2(&q).await.unwrap();
    assert_eq!(r.result.websites.len(), 1);
    assert!((r.result.websites[0].boost() - 6.0).abs() < 1e-9);
}
#[tokio::test]
async fn ranking_uses_effective_stage_terms() {
    let (local, _dir) = query_index::local(
        &[(
            "https://e.test/a",
            "compiler allocation",
            "compiler allocation",
        )],
        |_, _| {},
    );
    let stage = AgentPlan::new("please find compiler allocation")
        .unwrap()
        .stages
        .into_iter()
        .find(|s| s.id == StageId::Content)
        .unwrap();
    let mut q = query(&stage.original, 10);
    q.stage_plan = Some(stage);
    let r = local.search_initial_v2(&q).await.unwrap();
    assert_eq!(r.result.websites[0].iter_title_positions().count(), 2);
    assert!(r.result.websites[0]
        .iter_title_positions()
        .all(|p| !p.is_empty()));
}
#[tokio::test]
async fn snippets_use_effective_stage() {
    let body = "These examples show compiler diagnostics. The manual explains memory allocation and runtime behavior with concrete examples for software developers. ".repeat(20);
    let (searcher, _dir) =
        query_index::searcher(&[("https://e.test/a", "compiler manual", &body)], true).await;
    let r = websites(
        searcher
            .search(&query("can you show me compiler", 1))
            .await
            .unwrap(),
    );
    assert_eq!(r.webpages[0].plan_stage, Some(StageId::Content));
    let value = serde_json::to_value(&r.webpages[0].snippet).unwrap();
    let highlighted = value["text"]["fragments"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["kind"] == "highlighted")
        .map(|f| f["text"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(
        highlighted
            .iter()
            .any(|s| s.to_ascii_lowercase().contains("compiler")),
        "snippet={value}"
    );
    assert!(!highlighted
        .iter()
        .any(|s| s.to_ascii_lowercase().contains("show")));
}

#[path = "support/query_client.rs"]
mod query_client;
async fn observed(
    docs: &[(&str, &str, &str)],
    probe: std::sync::Arc<std::sync::Mutex<query_client::Probe>>,
    bangs: stract::bangs::Bangs,
) -> (
    stract::searcher::api::ApiSearcher<query_client::Client, stract::webgraph::Webgraph>,
    file_store::temp::TempDir,
) {
    let (local, dir) = query_index::local(docs, |_, _| {});
    let mut config = stract::searcher::api::Config::default();
    config.widgets.calculator_fetch_currencies_exchange = false;
    config.widgets.thesaurus_paths.clear();
    let client = query_client::Client { local, probe };
    (
        stract::searcher::api::ApiSearcher::new(client, None, bangs, config).await,
        dir,
    )
}
#[tokio::test]
async fn shard_failure_is_not_fallback() {
    use stract::searcher::wire::QueryServiceError;
    let probe = std::sync::Arc::new(std::sync::Mutex::new(query_client::Probe {
        failure: Some(QueryServiceError::ShardFailed),
        ..Default::default()
    }));
    let (searcher, _dir) = observed(&[], probe.clone(), stract::bangs::Bangs::empty()).await;
    let error = searcher
        .search(&query("please find compiler allocation", 5))
        .await
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<QueryServiceError>(),
        Some(&QueryServiceError::ShardFailed)
    );
    assert_eq!(probe.lock().unwrap().searches, [StageId::Strict]);
}
#[tokio::test]
async fn retrieval_mismatch_is_error() {
    use stract::searcher::wire::QueryServiceError;
    let probe = std::sync::Arc::new(std::sync::Mutex::new(query_client::Probe {
        missing_page: true,
        ..Default::default()
    }));
    let (searcher, _dir) = observed(
        &[("https://e.test/a", "compiler", "compiler")],
        probe.clone(),
        stract::bangs::Bangs::empty(),
    )
    .await;
    let error = searcher.search(&query("compiler", 1)).await.unwrap_err();
    assert_eq!(
        error.downcast_ref::<QueryServiceError>(),
        Some(&QueryServiceError::RetrievalFailed)
    );
    assert_eq!(probe.lock().unwrap().searches, [StageId::Strict]);
}
#[tokio::test]
async fn provenance_elapsed_covers_stage() {
    let probe = std::sync::Arc::new(std::sync::Mutex::new(query_client::Probe {
        retrieval_delay_ms: 30,
        ..Default::default()
    }));
    let (searcher, _dir) = observed(
        &[("https://e.test/a", "compiler", "compiler")],
        probe,
        stract::bangs::Bangs::empty(),
    )
    .await;
    let r = websites(searcher.search(&query("compiler", 1)).await.unwrap());
    assert!(r.query_plan.unwrap().stages[0].elapsed_ms >= 30);
    assert!(r.search_duration_ms >= 30);
}
#[tokio::test]
async fn known_bang_does_not_search() {
    let probe = std::sync::Arc::new(std::sync::Mutex::new(query_client::Probe::default()));
    let bangs =
        stract::bangs::Bangs::from_json(r#"[{"t":"docs","u":"https://docs.test/?q={{{s}}}"}]"#);
    let (searcher, _dir) = observed(&[], probe.clone(), bangs).await;
    assert!(matches!(
        searcher.search(&query("!docs compiler", 1)).await.unwrap(),
        stract::searcher::SearchResult::Bang(_)
    ));
    let p = probe.lock().unwrap();
    assert_eq!(p.sessions, 0);
    assert!(p.searches.is_empty() && p.retrievals.is_empty());
}
#[tokio::test]
async fn api_request_session_is_shared() {
    let probe = std::sync::Arc::new(std::sync::Mutex::new(query_client::Probe::default()));
    let (searcher, _dir) = observed(&[], probe.clone(), stract::bangs::Bangs::empty()).await;
    let r = websites(
        searcher
            .search(&query("please find compiler allocation runtime errors", 5))
            .await
            .unwrap(),
    );
    assert_eq!(r.query_plan.unwrap().stages.len(), 4);
    let p = probe.lock().unwrap();
    assert_eq!(p.sessions, 1);
    assert_eq!(p.searches.len(), 4);
}

#[tokio::test]
async fn legacy_query_bounds_at_shard() {
    let (local, _dir) = query_index::local(&[], |_, _| {});
    for text in [
        "x".repeat(4097),
        "compiler\u{200b}".into(),
        "-compiler".into(),
        "a ".repeat(33),
    ] {
        let original = stract::searcher::SearchQuery {
            query: text,
            ..Default::default()
        };
        let legacy = stract::searcher::wire::LegacySearchQuery::from(&original);
        let query: stract::searcher::SearchQuery = legacy.into();
        assert_eq!(query.query, original.query);
        assert!(local.search_initial(&query, true).await.is_err());
    }
}

#[tokio::test]
async fn query_compiler_full_path_regressions() {
    let (local, _dir) =
        query_index::local(&[("https://e.test/a", "compiler", "compiler")], |_, _| {});
    for text in [
        "\"...\"",
        "intitle:\"!!!\"",
        "compiler \"...\"",
        "...",
        "compiler -inbody:\"...\"",
    ] {
        let q = query(text, 10);
        let compiled = stract::query::Query::render_query(&q);
        let result = local.search_initial_v2(&q).await;
        if compiled.is_err() {
            assert!(result.is_err());
        }
    }
}
