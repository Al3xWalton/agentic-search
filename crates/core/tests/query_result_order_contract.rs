// SPDX-License-Identifier: AGPL-3.0-only
//! Pins public two-shard session ordering on real synthetic indexes without labels or networking.

#[path = "support/query_client.rs"]
#[allow(dead_code)]
mod query_client;
#[path = "support/query_index.rs"]
#[allow(dead_code)]
mod query_index;

mod contracts {
    use super::{
        query_client::{TwoShardClient, TwoShardProbe},
        query_index,
    };
    use std::sync::{Arc, Mutex};
    use stract::{
        bangs::Bangs,
        inverted_index::{DocAddress, ShardId},
        ranking::{SignalCoefficients, SignalEnum},
        searcher::{
            api::{ApiSearcher, Config},
            SearchQuery, SearchResult,
        },
    };

    #[tokio::test]
    async fn two_shard_session_preserves_result_order() {
        let urls = [
            "https://a.test/a",
            "https://b.test/a",
            "https://c.test/a",
            "https://d.test/a",
            "https://e.test/a",
            "https://f.test/a",
        ];
        let build = |shard: usize| {
            let docs = [shard, shard + 2, shard + 4]
                .map(|i| (urls[i], "cedar", "cedar synthetic document"));
            query_index::local_on_shard(
                &docs,
                |_, page| page.host_centrality = 1.0,
                Default::default(),
                ShardId::Backbone(shard as u64),
            )
        };
        let (left, _left_directory) = build(0);
        let (right, _right_directory) = build(1);
        let locals = Arc::new([left, right]);
        let fixture_keys = urls
            .iter()
            .enumerate()
            .map(|(i, url)| {
                (
                    stract::prehashed::hash(url).0,
                    DocAddress::new(0, (i / 2) as u32, ShardId::Backbone((i % 2) as u64)),
                    *url,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            fixture_keys
                .iter()
                .map(|(hash, _, _)| *hash)
                .collect::<Vec<_>>(),
            [
                263953970540194784471890255562530562067,
                205011281393184945874030650255866701501,
                310944793279033882541818251763909454673,
                269403178761018794420908724220854614708,
                4185594958092580589253528272225199410,
                34132243146929636409689467329860414657,
            ]
        );
        let expected_addresses = vec![
            DocAddress::new(0, 2, ShardId::Backbone(0)),
            DocAddress::new(0, 2, ShardId::Backbone(1)),
            DocAddress::new(0, 0, ShardId::Backbone(1)),
            DocAddress::new(0, 0, ShardId::Backbone(0)),
            DocAddress::new(0, 1, ShardId::Backbone(1)),
            DocAddress::new(0, 1, ShardId::Backbone(0)),
        ];
        let expected_urls = [
            "https://e.test/a",
            "https://f.test/a",
            "https://b.test/a",
            "https://a.test/a",
            "https://d.test/a",
            "https://c.test/a",
        ];
        for planning in [false, true] {
            for exact in [false, true] {
                let mut observed = Vec::new();
                for reverse_blocks in [false, true] {
                    let probe = Arc::new(Mutex::new(TwoShardProbe::default()));
                    let client = TwoShardClient {
                        locals: locals.clone(),
                        reverse_blocks,
                        probe: probe.clone(),
                    };
                    let mut config = Config {
                        agent_query_planning: planning,
                        ..Default::default()
                    };
                    config.widgets.calculator_fetch_currencies_exchange = false;
                    config.widgets.thesaurus_paths.clear();
                    let api: ApiSearcher<_, stract::webgraph::Webgraph> =
                        ApiSearcher::new(client, None, Bangs::empty(), config).await;
                    let query = SearchQuery {
                        query: "cedar".into(),
                        num_results: 6,
                        count_results_exact: exact,
                        signal_coefficients: SignalCoefficients::new(
                            SignalEnum::all().map(|s| (s, 0.0)),
                        ),
                        ..Default::default()
                    };
                    let SearchResult::Websites(result) = api.search(&query).await.unwrap() else {
                        panic!("expected webpages");
                    };
                    let actual_urls = result
                        .webpages
                        .iter()
                        .map(|page| page.url.clone())
                        .collect::<Vec<_>>();
                    let probe = probe.lock().unwrap();
                    assert_eq!(probe.sessions, 1);
                    assert_eq!(probe.count_paths, [exact]);
                    let shards = if reverse_blocks {
                        vec![ShardId::Backbone(1), ShardId::Backbone(0)]
                    } else {
                        vec![ShardId::Backbone(0), ShardId::Backbone(1)]
                    };
                    assert_eq!(probe.block_orders, [shards]);
                    assert_eq!(probe.usage, [(1, 2, 2)]);
                    assert_eq!(
                        probe.retrieval_addresses.as_slice(),
                        std::slice::from_ref(&expected_addresses)
                    );
                    assert_eq!(actual_urls, expected_urls);
                    observed.push((probe.retrieval_addresses.clone(), actual_urls));
                }
                assert_eq!(observed[0], observed[1]);
            }
        }
    }
}
