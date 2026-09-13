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

#[test]
fn four_stage_budget() {
    use stract::searcher::distributed::SearchSession;
    let mut s = SearchSession::for_shards(1).unwrap();
    for _ in 0..4 {
        s.begin_search().unwrap();
    }
    assert_eq!(s.begin_search(), Err(QueryServiceError::BudgetExhausted));
    assert_eq!(s.usage(), (4, 4, 0));
}
#[test]
fn shard_membership_bound() {
    use stract::searcher::distributed::SearchSession;
    assert!(matches!(
        SearchSession::for_shards(0),
        Err(QueryServiceError::NoShards)
    ));
    assert!(SearchSession::for_shards(8).is_ok());
    assert!(matches!(
        SearchSession::for_shards(9),
        Err(QueryServiceError::TooManyShards)
    ));
}
#[test]
fn rpc_amplification_bound() {
    use stract::searcher::distributed::SearchSession;
    let mut s = SearchSession::for_shards(8).unwrap();
    for i in 1..=4 {
        s.begin_search().unwrap();
        s.begin_retrieval(8).unwrap();
        assert_eq!(s.usage(), (i, i * 8, i * 8));
    }
    assert_eq!(
        s.begin_retrieval(1),
        Err(QueryServiceError::BudgetExhausted)
    );
    assert_eq!(s.begin_search(), Err(QueryServiceError::BudgetExhausted));
}

#[test]
fn every_legacy_generic_pair_keeps_its_tag() {
    use stract::entrypoint::search_server::*;
    use stract::generic_query::*;
    macro_rules! pair {
        ($query:expr, $ty:ty, $retrieve:ident, $id:expr) => {{
            let query = $query;
            let request = <$ty>::wrap_request(query.clone());
            let bytes = bincode::encode_to_vec(request, bincode::config::standard()).unwrap();
            assert_eq!(bytes[0], $id);
            let request = $retrieve::wrap_request($retrieve {
                query,
                fruit: Default::default(),
            });
            let bytes = bincode::encode_to_vec(request, bincode::config::standard()).unwrap();
            assert_eq!(bytes[0], $id + 1);
            for id in [$id, $id + 1] {
                let mut bytes = vec![id];
                bytes.extend(
                    bincode::encode_to_vec(
                        Result::<(), _>::Err(EncodedError {
                            msg: "fixture".into(),
                        }),
                        bincode::config::standard(),
                    )
                    .unwrap(),
                );
                let (response, used): (<SearchService as Service>::Response, _) =
                    bincode::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
                assert_eq!(used, bytes.len());
                assert_eq!(
                    bincode::encode_to_vec(response, bincode::config::standard()).unwrap(),
                    bytes
                );
            }
        }};
    }
    pair!(
        TopKeyPhrasesQuery::new(7),
        TopKeyPhrasesQuery,
        TopKeyPhrasesQueryRetrieve,
        2
    );
    pair!(SizeQuery, SizeQuery, SizeQueryRetrieve, 4);
    pair!(
        GetWebpageQuery::new("https://example.test/path"),
        GetWebpageQuery,
        GetWebpageQueryRetrieve,
        6
    );
    pair!(
        GetHomepageQuery::new("https://example.test/"),
        GetHomepageQuery,
        GetHomepageQueryRetrieve,
        8
    );
    pair!(
        GetSiteUrlsQuery {
            site: "example.test".into(),
            limit: 7,
            offset: Some(3)
        },
        GetSiteUrlsQuery,
        GetSiteUrlsQueryRetrieve,
        10
    );
}

#[tokio::test]
async fn shard_rejects_oversized_preferences() {
    use std::sync::Arc;
    use stract::{
        config::SearchServerConfig,
        distributed::{cluster::Cluster, sonic},
        entrypoint::search_server::Search,
        index::Index,
        inverted_index::ShardId,
    };
    let dir = stract::gen_temp_dir().unwrap();
    let mut index = Index::open(&dir).unwrap();
    index.set_shard_id(ShardId::Backbone(0));
    index.inverted_index.prepare_writer().unwrap();
    index.commit().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let config: SearchServerConfig = toml::from_str(&format!(
        "host = \"{address}\"\ngossip_addr = \"127.0.0.1:0\"\nindex_path = {:?}\nshard = 0\n",
        dir.as_ref().to_str().unwrap()
    ))
    .unwrap();
    let cluster = Arc::new(
        Cluster::join_as_spectator("127.0.0.1:0".parse().unwrap(), vec![])
            .await
            .unwrap(),
    );
    let service = SearchService::new_from_existing(
        config,
        cluster,
        Arc::new(tokio::sync::RwLock::new(index)),
    )
    .await
    .unwrap();
    let server = sonic::service::Server::bind(service, address)
        .await
        .unwrap();
    let task = tokio::spawn(async move {
        server.accept().await.unwrap();
    });
    let mut connection = sonic::service::Connection::<SearchService>::create(address)
        .await
        .unwrap();
    let mut successful_searches = 0;
    for case in 0..3 {
        let mut query = SearchQuery {
            query: "compiler".into(),
            ..Default::default()
        };
        match case {
            0 => {
                query.host_rankings = Some(optics::HostRankings {
                    blocked: vec!["blocked.test".into(); 1025],
                    ..Default::default()
                })
            }
            1 => {
                query.host_rankings = Some(optics::HostRankings {
                    blocked: vec!["x".repeat(8193)],
                    ..Default::default()
                })
            }
            _ => {
                query.optic = Some(optics::Optic {
                    rules: vec![
                        optics::Rule {
                            matches: vec![],
                            action: optics::Action::Boost(1)
                        };
                        1025
                    ],
                    ..Default::default()
                })
            }
        }
        let legacy = connection
            .send(Search {
                query: LegacySearchQuery::from(&query),
            })
            .await
            .unwrap();
        successful_searches += usize::from(legacy.is_some());
        assert!(legacy.is_none(), "legacy preferences case {case}");
        let selector = StageSelector {
            version: 1,
            planner_version: 1,
            stage: 0,
            query: LegacySearchQuery::from(&query),
        };
        assert!(matches!(
            connection
                .send(SearchV2 {
                    selector: selector.clone()
                })
                .await
                .unwrap(),
            Err(QueryServiceError::InvalidPlan)
        ));
        assert!(
            matches!(selector.resolve(), Err(QueryServiceError::InvalidPlan)),
            "resolver must reject before compilation"
        );
    }
    assert_eq!(successful_searches, 0);
    drop(connection);
    task.await.unwrap();
    let mut hosts = optics::HostRankings {
        liked: vec!["x".repeat(8192)],
        disliked: vec!["a".into(); 511],
        blocked: vec!["b".into(); 512],
    };
    assert!(stract::query::planner::bounds::validate_preferences(None, Some(&hosts)).is_ok());
    hosts.liked.push("extra".into());
    assert_eq!(
        stract::query::planner::bounds::validate_preferences(None, Some(&hosts)),
        Err(stract::query::planner::bounds::InputError::PreferencesTooLarge)
    );
}
