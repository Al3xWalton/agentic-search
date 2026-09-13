// SPDX-License-Identifier: AGPL-3.0-only
//! Synthetic compatibility and selector contracts for the search service wire.
//! Fixtures preserve base bytes; forged selectors must fail before query compilation.
//! No retained labels or remote services participate in codec assertions.

use stract::{
    distributed::sonic::service::{Service, Wrapper},
    entrypoint::search_server::{RetrieveWebsitesV2, SearchService, SearchV2},
    query::{
        planner::{AgentPlan, StageId},
        Query,
    },
    searcher::{
        wire::{BoundedPointers, LegacySearchQuery, QueryServiceError, StageSelector},
        SearchQuery,
    },
};

fn fixture(name: &str) -> Vec<u8> {
    let value: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/query_planning/legacy-wire.json")).unwrap();
    serde_json::from_value(
        value["fixtures"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == name)
            .unwrap()["bytes"]
            .clone(),
    )
    .unwrap()
}

fn selected() -> SearchQuery {
    let query = "please find compiler runtime allocation errors";
    let stage = AgentPlan::new(query)
        .unwrap()
        .stages
        .into_iter()
        .find(|p| p.id == StageId::Relaxed)
        .unwrap();
    SearchQuery {
        query: query.into(),
        stage_plan: Some(stage),
        ..Default::default()
    }
}

#[test]
fn legacy_search_bytes_unchanged() {
    let bytes = fixture("legacy_query");
    let (query, consumed): (LegacySearchQuery, _) =
        bincode::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(query.query, "alpha site:example.test");
    assert_eq!((query.page, query.num_results), (7, 11));
    assert!(query.safe_search && query.count_results_exact && query.return_ranking_signals);
    assert_eq!(
        bincode::encode_to_vec(query, bincode::config::standard()).unwrap(),
        bytes
    );
}

#[test]
fn legacy_service_discriminants() {
    for name in ["search_request", "retrieve_request", "size_request"] {
        let bytes = fixture(name);
        let (request, consumed): (<SearchService as Service>::Request, _) =
            bincode::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(
            bincode::encode_to_vec(request, bincode::config::standard()).unwrap(),
            bytes
        );
    }
    let selector = StageSelector::from_query(&selected()).unwrap();
    assert_eq!(
        bincode::encode_to_vec(
            SearchV2::wrap_request(SearchV2 {
                selector: selector.clone()
            }),
            bincode::config::standard()
        )
        .unwrap()[0],
        12
    );
    assert_eq!(
        bincode::encode_to_vec(
            RetrieveWebsitesV2::wrap_request(RetrieveWebsitesV2 {
                selector,
                websites: BoundedPointers(vec![])
            }),
            bincode::config::standard()
        )
        .unwrap()[0],
        13
    );
}

#[test]
fn legacy_response_bytes_unchanged() {
    for name in [
        "search_response",
        "retrieve_response",
        "size_retrieve_response",
    ] {
        let bytes = fixture(name);
        let (response, consumed): (<SearchService as Service>::Response, _) =
            bincode::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(
            bincode::encode_to_vec(response, bincode::config::standard()).unwrap(),
            bytes
        );
    }
}

#[test]
fn v2_selector_roundtrip() {
    let query = selected();
    let selector = StageSelector::from_query(&query).unwrap();
    let bytes = bincode::encode_to_vec(selector, bincode::config::standard()).unwrap();
    let (decoded, consumed): (StageSelector, _) =
        bincode::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(
        (decoded.version, decoded.planner_version, decoded.stage),
        (1, 1, 2)
    );
    let resolved = decoded.resolve().unwrap();
    assert_eq!(resolved.stage_plan, query.stage_plan);
    assert_eq!(
        Query::render_query(&resolved).unwrap(),
        Query::render_query(&query).unwrap()
    );
}

#[test]
fn v2_version_rejected() {
    let mut selector = StageSelector::from_query(&selected()).unwrap();
    selector.version = 2;
    assert!(matches!(
        selector.resolve(),
        Err(QueryServiceError::InvalidPlan)
    ));
}

#[test]
fn v2_revalidates_selector() {
    let baseline = StageSelector::from_query(&selected()).unwrap();
    for mutate in 0..5 {
        let mut selector = baseline.clone();
        match mutate {
            0 => selector.planner_version = 99,
            1 => selector.stage = 255,
            2 => selector.query.query = "a".repeat(4097),
            3 => selector.query.query = "compiler\u{200b}".into(),
            _ => selector.query.query = "compiler".into(),
        }
        assert!(matches!(
            selector.resolve(),
            Err(QueryServiceError::InvalidPlan)
        ));
    }
}

#[test]
fn v2_retrieval_roundtrip() {
    let query = selected();
    let request = RetrieveWebsitesV2 {
        selector: StageSelector::from_query(&query).unwrap(),
        websites: BoundedPointers(vec![]),
    };
    let bytes = bincode::encode_to_vec(request, bincode::config::standard()).unwrap();
    let (decoded, consumed): (RetrieveWebsitesV2, _) =
        bincode::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(
        decoded.selector.resolve().unwrap().stage_plan,
        query.stage_plan
    );
    assert!(decoded.websites.0.is_empty());
    let forged = bincode::encode_to_vec(301usize, bincode::config::standard()).unwrap();
    assert!(
        bincode::decode_from_slice::<BoundedPointers, _>(&forged, bincode::config::standard())
            .is_err()
    );
}

#[test]
fn request_budget_is_shared() {
    use stract::searcher::distributed::SearchSession;
    let mut session = SearchSession::for_shards(8).unwrap();
    for _ in 0..4 {
        session.begin_search().unwrap();
        session.begin_retrieval(8).unwrap();
    }
    assert_eq!(session.usage(), (4, 32, 32));
    assert_eq!(
        session.begin_search(),
        Err(QueryServiceError::BudgetExhausted)
    );
    assert_eq!(
        session.begin_retrieval(1),
        Err(QueryServiceError::BudgetExhausted)
    );
    assert!(matches!(
        SearchSession::for_shards(0),
        Err(QueryServiceError::NoShards)
    ));
    assert!(matches!(
        SearchSession::for_shards(9),
        Err(QueryServiceError::TooManyShards)
    ));
}
