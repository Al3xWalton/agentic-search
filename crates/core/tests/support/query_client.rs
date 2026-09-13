// SPDX-License-Identifier: AGPL-3.0-only
//! Observe and fault the existing API search-client seam while retaining real local matching.
//! State is request-test owned; generic operations delegate to the same local index.
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
            if let Some(error) = probe.failure {
                return Err(error);
            }
        }
        let response = self.local.search_initial_v2(query).await?;
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
