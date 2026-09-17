// SPDX-License-Identifier: AGPL-3.0-only
//! Observe and fault the existing API search-client seam while retaining real local matching.
//! State is request-test owned; generic operations delegate to the same local index.
//! TwoShardClient serves two shard-tagged indexes in either block order to pin merge order; its generic operations use shard zero.
//! This fixture does not implement a second planner, renderer, ranking path or network client.

use std::sync::{Arc, Mutex};
use stract::{
    distributed::sonic,
    entrypoint::search_server::{self, SearchService},
    generic_query,
    inverted_index::ShardId,
    query::planner::StageId,
    ranking::pipeline::PrecisionRankingWebpage,
    searcher::{
        distributed::{InitialSearchResultShard, ScoredWebpagePointer, SearchSession},
        wire::QueryServiceError,
        LocalSearcher, SearchClient, SearchQuery,
    },
    Result,
};

/// Per-fixture observations and deterministic failure/delay settings.
#[derive(Default)]
pub struct Probe {
    /// Number of immutable membership acquisitions.
    pub sessions: usize,
    /// Actual selected stages entering matching.
    pub searches: Vec<StageId>,
    /// Actual selected stages entering retrieval.
    pub retrievals: Vec<StageId>,
    /// If set, matching returns this service failure without any candidate result.
    pub failure: Option<QueryServiceError>,
    /// Remove one retrieved page to exercise coordinator cardinality validation.
    pub missing_page: bool,
    /// Time spent within each retrieval operation, in milliseconds.
    pub retrieval_delay_ms: u64,
    /// Exact request bytes at each matching operation, before stage compilation.
    pub original_queries: Vec<String>,
    /// Actual rendered selectors returned by the local production matcher.
    pub rendered_queries: Vec<String>,
    /// Ordered candidate pointers, compared within the same synthetic index lifetime.
    pub candidates: Vec<Vec<String>>,
    /// Exact request bytes at each retrieval operation.
    pub retrieval_queries: Vec<String>,
    /// Ordered URLs returned by actual local retrieval operations.
    pub retrieved_urls: Vec<Vec<String>>,
    /// Searches plus nonempty retrievals requiring RPCs in distributed serving.
    pub rpc_count: usize,
}

/// Instrumented client using the ordinary local search and retrieval implementation.
pub struct Client {
    /// Actual local index searcher.
    pub local: LocalSearcher,
    /// Independent shared fixture observations.
    pub probe: Arc<Mutex<Probe>>,
}
impl SearchClient for Client {
    async fn begin_session(&self) -> Result<SearchSession, QueryServiceError> {
        self.probe.lock().unwrap().sessions += 1;
        SearchSession::for_shards(1)
    }
    async fn search_initial(
        &self,
        query: &SearchQuery,
        session: &mut SearchSession,
    ) -> Result<Vec<InitialSearchResultShard>, QueryServiceError> {
        session.begin_search()?;
        let stage = query.stage_plan.as_ref().unwrap().id;
        {
            let mut probe = self.probe.lock().unwrap();
            probe.searches.push(stage);
            probe.original_queries.push(query.query.clone());
            probe.rpc_count += 1;
            if let Some(error) = probe.failure {
                return Err(error);
            }
        }
        let response = self.local.search_initial_v2(query).await?;
        {
            let mut probe = self.probe.lock().unwrap();
            probe.rendered_queries.push(response.rendered_query.clone());
            probe.candidates.push(
                response
                    .result
                    .websites
                    .iter()
                    .map(|page| format!("{:?}", page.pointer()))
                    .collect(),
            );
        }
        Ok(vec![InitialSearchResultShard {
            local_result: response.result,
            shard: ShardId::Backbone(0),
            rendered_query: response.rendered_query,
        }])
    }
    async fn retrieve_webpages(
        &self,
        pointers: &[ScoredWebpagePointer],
        query: &SearchQuery,
        session: &mut SearchSession,
    ) -> Result<Vec<PrecisionRankingWebpage>, QueryServiceError> {
        session.begin_retrieval(usize::from(!pointers.is_empty()))?;
        let (missing, delay) = {
            let mut probe = self.probe.lock().unwrap();
            probe.retrievals.push(query.stage_plan.as_ref().unwrap().id);
            probe.retrieval_queries.push(query.query.clone());
            probe.rpc_count += usize::from(!pointers.is_empty());
            (probe.missing_page, probe.retrieval_delay_ms)
        };
        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        let positions = pointers
            .iter()
            .map(|p| p.website.pointer().clone())
            .collect::<Vec<_>>();
        let pages = self
            .local
            .retrieve_websites_selected(&positions, query)
            .await
            .map_err(|_| QueryServiceError::RetrievalFailed)?;
        self.probe
            .lock()
            .unwrap()
            .retrieved_urls
            .push(pages.iter().map(|page| page.url.clone()).collect());
        let mut pages = pages
            .into_iter()
            .zip(pointers)
            .map(|(page, pointer)| PrecisionRankingWebpage::new(page, pointer.website.clone()))
            .collect::<Vec<_>>();
        if missing {
            pages.pop();
        }
        Ok(pages)
    }
    async fn search_initial_generic<Q>(
        &self,
        query: Q,
    ) -> Result<<Q::Collector as generic_query::Collector>::Fruit>
    where
        Q: search_server::Query + 'static,
        Result<
            <Q::Collector as generic_query::Collector>::Fruit,
            search_server::EncodedError,
        >: From<<Q as sonic::service::Message<SearchService>>::Response>,
        <<Q::Collector as generic_query::Collector>::Child as tantivy::collector::SegmentCollector>::Fruit:
    From<<Q::Collector as generic_query::Collector>::Fruit>{
        self.local.search_initial_generic(query).await
    }

    async fn retrieve_generic<Q>(
        &self,
        query: Q,
        fruit: <Q::Collector as generic_query::Collector>::Fruit,
    ) -> Result<Vec<Q::IntermediateOutput>>
    where
        Q: search_server::Query,
        <Q::Collector as generic_query::Collector>::Fruit: Clone,
        Result<Q::IntermediateOutput, search_server::EncodedError>:
            From<
                <<Q as search_server::Query>::RetrieveReq as sonic::service::Message<
                    SearchService,
                >>::Response,
            >,
    {
        Ok(vec![self.local.retrieve_generic(query, fruit).await?])
    }

    async fn batch_search_initial_generic<Q>(
        &self,
        queries: Vec<Q>,
    ) -> Result<Vec<<Q::Collector as generic_query::Collector>::Fruit>>
    where
        Q: search_server::Query,
        Result<<<Q::Collector as generic_query::Collector>::Child as tantivy::collector::SegmentCollector>::Fruit, search_server::EncodedError>:
    From<<Q as sonic::service::Message<SearchService>>::Response>{
        let mut res = Vec::new();

        for query in queries {
            res.push(self.local.search_initial_generic(query).await?);
        }

        Ok(res)
    }

    async fn batch_retrieve_generic<Q>(
        &self,
        queries: Vec<(Q, <Q::Collector as generic_query::Collector>::Fruit)>,
    ) -> Result<Vec<Vec<Q::IntermediateOutput>>>
    where
        Q: search_server::Query,
        Result<Q::IntermediateOutput, search_server::EncodedError>:
            From<
                <<Q as search_server::Query>::RetrieveReq as sonic::service::Message<
                    SearchService,
                >>::Response,
            >,
        <Q::Collector as generic_query::Collector>::Fruit: Clone,
    {
        let mut res = Vec::new();

        for (query, fruit) in queries {
            res.push(vec![self.local.retrieve_generic(query, fruit).await?]);
        }

        Ok(res)
    }
}

/// Observations of the actual two-shard session and ordered retrieval fan-out.
#[derive(Default)]
#[allow(
    dead_code,
    reason = "shared support is compiled by single-shard contracts too"
)]
pub struct TwoShardProbe {
    /// Number of immutable two-shard session acquisitions.
    pub sessions: usize,
    /// Exact versus estimated matching flags seen by the two-shard search.
    pub count_paths: Vec<bool>,
    /// Shard blocks passed back to the API before its private merge.
    pub block_orders: Vec<Vec<ShardId>>,
    /// Complete addresses selected by the API for each retrieval.
    pub retrieval_addresses: Vec<Vec<stract::inverted_index::DocAddress>>,
    /// Actual stage, search-RPC and retrieval-RPC charges after retrieval.
    pub usage: Vec<(usize, usize, usize)>,
}

/// Uses two real local indexes for selected webpage matching and retrieval.
/// Index owners must outlive the client. Generic auxiliary operations use shard zero.
#[allow(
    dead_code,
    reason = "shared support is compiled by single-shard contracts too"
)]
pub struct TwoShardClient {
    /// Indexes explicitly built as Backbone(0) and Backbone(1).
    pub locals: Arc<[LocalSearcher; 2]>,
    /// Returns the same candidate blocks in the opposite order when set.
    pub reverse_blocks: bool,
    /// Independent per-session observations.
    pub probe: Arc<Mutex<TwoShardProbe>>,
}

impl SearchClient for TwoShardClient {
    async fn begin_session(&self) -> Result<SearchSession, QueryServiceError> {
        self.probe.lock().unwrap().sessions += 1;
        SearchSession::for_shards(2)
    }

    async fn search_initial(
        &self,
        query: &SearchQuery,
        session: &mut SearchSession,
    ) -> Result<Vec<InitialSearchResultShard>, QueryServiceError> {
        session.begin_search()?;
        let mut blocks = Vec::new();
        for (ordinal, local) in self.locals.iter().enumerate() {
            let response = local.search_initial_v2(query).await?;
            let shard = ShardId::Backbone(ordinal as u64);
            assert!(response
                .result
                .websites
                .iter()
                .all(|p| p.pointer().address.shard_id == shard));
            blocks.push(InitialSearchResultShard {
                shard,
                local_result: response.result,
                rendered_query: response.rendered_query,
            });
        }
        if self.reverse_blocks {
            blocks.reverse();
        }
        let mut probe = self.probe.lock().unwrap();
        probe.count_paths.push(query.count_results_exact);
        probe
            .block_orders
            .push(blocks.iter().map(|b| b.shard).collect());
        Ok(blocks)
    }

    async fn retrieve_webpages(
        &self,
        pointers: &[ScoredWebpagePointer],
        query: &SearchQuery,
        session: &mut SearchSession,
    ) -> Result<Vec<PrecisionRankingWebpage>, QueryServiceError> {
        let groups = [ShardId::Backbone(0), ShardId::Backbone(1)].map(|shard| {
            pointers
                .iter()
                .enumerate()
                .filter(|(_, p)| p.shard == shard)
                .collect::<Vec<_>>()
        });
        assert_eq!(groups.iter().map(Vec::len).sum::<usize>(), pointers.len());
        session.begin_retrieval(groups.iter().filter(|g| !g.is_empty()).count())?;
        {
            let mut probe = self.probe.lock().unwrap();
            probe.retrieval_addresses.push(
                pointers
                    .iter()
                    .map(|p| p.website.pointer().address)
                    .collect(),
            );
            probe.usage.push(session.usage());
        }
        let mut restored = Vec::new();
        for (shard, group) in groups.into_iter().enumerate() {
            if group.is_empty() {
                continue;
            }
            let positions = group
                .iter()
                .map(|(_, p)| {
                    assert_eq!(p.shard, p.website.pointer().address.shard_id);
                    p.website.pointer().clone()
                })
                .collect::<Vec<_>>();
            let pages = self.locals[shard]
                .retrieve_websites_selected(&positions, query)
                .await
                .map_err(|_| QueryServiceError::RetrievalFailed)?;
            assert_eq!(pages.len(), group.len());
            restored.extend(
                pages
                    .into_iter()
                    .zip(group)
                    .map(|(page, (position, pointer))| {
                        (
                            position,
                            PrecisionRankingWebpage::new(page, pointer.website.clone()),
                        )
                    }),
            );
        }
        restored.sort_by_key(|(position, _)| *position);
        Ok(restored.into_iter().map(|(_, page)| page).collect())
    }

    async fn search_initial_generic<Q>(&self, query: Q) -> Result<<Q::Collector as generic_query::Collector>::Fruit>
    where
        Q: search_server::Query + 'static,
        Result<<Q::Collector as generic_query::Collector>::Fruit, search_server::EncodedError>:
            From<<Q as sonic::service::Message<SearchService>>::Response>,
        <<Q::Collector as generic_query::Collector>::Child as tantivy::collector::SegmentCollector>::Fruit:
            From<<Q::Collector as generic_query::Collector>::Fruit>,
    {
        self.locals[0].search_initial_generic(query).await
    }

    async fn retrieve_generic<Q>(
        &self,
        query: Q,
        fruit: <Q::Collector as generic_query::Collector>::Fruit,
    ) -> Result<Vec<Q::IntermediateOutput>>
    where
        Q: search_server::Query,
        <Q::Collector as generic_query::Collector>::Fruit: Clone,
        Result<Q::IntermediateOutput, search_server::EncodedError>:
            From<
                <<Q as search_server::Query>::RetrieveReq as sonic::service::Message<
                    SearchService,
                >>::Response,
            >,
    {
        Ok(vec![self.locals[0].retrieve_generic(query, fruit).await?])
    }

    async fn batch_search_initial_generic<Q>(&self, queries: Vec<Q>) -> Result<Vec<<Q::Collector as generic_query::Collector>::Fruit>>
    where
        Q: search_server::Query,
        Result<<<Q::Collector as generic_query::Collector>::Child as tantivy::collector::SegmentCollector>::Fruit, search_server::EncodedError>:
            From<<Q as sonic::service::Message<SearchService>>::Response>,
    {
        let mut results = Vec::new();
        for query in queries {
            results.push(self.locals[0].search_initial_generic(query).await?);
        }
        Ok(results)
    }

    async fn batch_retrieve_generic<Q>(
        &self,
        queries: Vec<(Q, <Q::Collector as generic_query::Collector>::Fruit)>,
    ) -> Result<Vec<Vec<Q::IntermediateOutput>>>
    where
        Q: search_server::Query,
        Result<Q::IntermediateOutput, search_server::EncodedError>:
            From<
                <<Q as search_server::Query>::RetrieveReq as sonic::service::Message<
                    SearchService,
                >>::Response,
            >,
        <Q::Collector as generic_query::Collector>::Fruit: Clone,
    {
        let mut results = Vec::new();
        for (query, fruit) in queries {
            results.push(vec![self.locals[0].retrieve_generic(query, fruit).await?]);
        }
        Ok(results)
    }
}
