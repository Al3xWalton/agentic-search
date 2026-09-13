// Stract is an open source web search engine.
// Copyright (C) 2024 Stract ApS
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use crate::{
    distributed::{
        cluster::Cluster,
        member::{LiveIndexState, Service},
        sonic::{
            self,
            replication::{
                AllShardsSelector, RandomReplicaSelector, RemoteClient, ReplicatedClient,
                ReusableClientManager, ReusableShardedClient, Shard, ShardIdentifier,
                ShardedClient, SpecificShardSelector,
            },
        },
    },
    entrypoint::{
        entity_search_server,
        live_index::LiveIndexService,
        search_server::{self, RetrieveReq, SearchService},
    },
    generic_query::{self, Collector},
    inverted_index::ShardId,
    ranking::pipeline::{PrecisionRankingWebpage, RecallRankingWebpage},
    Result,
};

use std::{collections::HashMap, sync::Arc};

use futures::{future::join_all, stream::FuturesUnordered, StreamExt};
use itertools::Itertools;
use std::future::Future;
use thiserror::Error;
use tokio::sync::Mutex;

use super::{InitialWebsiteResult, LocalSearcher, SearchQuery};

const CLIENT_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to get search result")]
    SearchFailed,

    #[error("Query cannot be empty")]
    EmptyQuery,

    #[error("Webpage not found")]
    WebpageNotFound,
}

/// One immutable membership and amplification budget shared by every search helper.
pub struct SearchSession {
    client: Option<Arc<ShardedClient<SearchService, ShardId>>>,
    shards: usize,
    stages: usize,
    searches: usize,
    retrievals: usize,
    retrieved: bool,
}

impl SearchSession {
    /// Create a local/fake membership of 1..=8 shards, rejecting empty/excess membership.
    pub fn for_shards(shards: usize) -> Result<Self, super::wire::QueryServiceError> {
        use super::wire::QueryServiceError;
        if shards == 0 {
            return Err(QueryServiceError::NoShards);
        }
        if shards > crate::query::planner::bounds::MAX_SHARDS {
            return Err(QueryServiceError::TooManyShards);
        }
        Ok(Self {
            client: None,
            shards,
            stages: 0,
            searches: 0,
            retrievals: 0,
            retrieved: false,
        })
    }

    /// Charge one stage and one search RPC per captured shard before initiating fan-out.
    pub fn begin_search(&mut self) -> Result<(), super::wire::QueryServiceError> {
        use super::wire::QueryServiceError;
        use crate::query::planner::bounds::{MAX_RPCS, MAX_STAGES};
        if self.stages >= MAX_STAGES
            || self
                .searches
                .checked_add(self.shards)
                .is_none_or(|n| n > MAX_RPCS)
        {
            return Err(QueryServiceError::BudgetExhausted);
        }
        self.stages += 1;
        self.searches += self.shards;
        self.retrieved = false;
        Ok(())
    }

    /// Charge at most one retrieval fan-out per stage, with at most 32 retrieval RPCs total.
    pub fn begin_retrieval(&mut self, shards: usize) -> Result<(), super::wire::QueryServiceError> {
        use super::wire::QueryServiceError;
        if self.stages == 0
            || self.retrieved
            || shards > self.shards
            || self
                .retrievals
                .checked_add(shards)
                .is_none_or(|n| n > crate::query::planner::bounds::MAX_RPCS)
        {
            return Err(QueryServiceError::BudgetExhausted);
        }
        self.retrieved = true;
        self.retrievals += shards;
        Ok(())
    }

    /// Return attempted stages, search RPCs and retrieval RPCs for synthetic budget witnesses.
    pub fn usage(&self) -> (usize, usize, usize) {
        (self.stages, self.searches, self.retrievals)
    }
}

struct FirstReplica;
impl sonic::replication::ReplicaSelector<SearchService> for FirstReplica {
    fn select<'a>(
        &self,
        replicas: &'a [RemoteClient<SearchService>],
    ) -> Vec<&'a RemoteClient<SearchService>> {
        // The captured client's order is immutable, so all stages select the same replica.
        replicas.first().into_iter().collect()
    }
}

pub trait SearchClient {
    fn begin_session(
        &self,
    ) -> impl Future<Output = Result<SearchSession, super::wire::QueryServiceError>> + Send;

    fn search_initial(
        &self,
        query: &SearchQuery,
        session: &mut SearchSession,
    ) -> impl Future<Output = Result<Vec<InitialSearchResultShard>, super::wire::QueryServiceError>> + Send;

    fn retrieve_webpages(
        &self,
        top_websites: &[ScoredWebpagePointer],
        query: &SearchQuery,
        session: &mut SearchSession,
    ) -> impl Future<Output = Result<Vec<PrecisionRankingWebpage>, super::wire::QueryServiceError>> + Send;

    fn search_initial_generic<Q>(
        &self,
        query: Q,
    ) -> impl Future<Output = Result<<Q::Collector as generic_query::Collector>::Fruit>> + Send
    where
        Q: search_server::Query,

        Result<
            <Q::Collector as generic_query::Collector>::Fruit,
            search_server::EncodedError,
        >: From<<Q as sonic::service::Message<SearchService>>::Response>,
        <<Q::Collector as generic_query::Collector>::Child as tantivy::collector::SegmentCollector>::Fruit:
            From<<Q::Collector as generic_query::Collector>::Fruit>;

    fn retrieve_generic<Q>(
        &self,
        query: Q,
        fruit: <Q::Collector as generic_query::Collector>::Fruit,
    ) -> impl Future<Output = Result<Vec<Q::IntermediateOutput>>> + Send
    where
        Q: search_server::Query,
        <Q::Collector as generic_query::Collector>::Fruit: Clone,
        Result<Q::IntermediateOutput, search_server::EncodedError>:
            From<
                <<Q as search_server::Query>::RetrieveReq as sonic::service::Message<
                    SearchService,
                >>::Response,
            >;

    fn search_generic<Q>(&self, query: Q) -> impl Future<Output = Result<Q::Output>> + Send
    where
        Self: Send + Sync,
        Q: search_server::Query,
        Result<
        <Q::Collector as generic_query::Collector>::Fruit,
        search_server::EncodedError,
    >: From<<Q as sonic::service::Message<SearchService>>::Response>,
    <<Q::Collector as generic_query::Collector>::Child as tantivy::collector::SegmentCollector>::Fruit:
        From<<Q::Collector as generic_query::Collector>::Fruit>,
        <Q::Collector as generic_query::Collector>::Fruit: Clone,
        Result<Q::IntermediateOutput, search_server::EncodedError>:
            From<
                <<Q as search_server::Query>::RetrieveReq as sonic::service::Message<
                    SearchService,
                >>::Response,
    >
    {
        async {
            let fruit = self.search_initial_generic(query.clone()).await?;
            let res = self.retrieve_generic(query, fruit).await?;
            let output = Q::merge_results(res);
            Ok(output)
        }
    }

    fn batch_search_initial_generic<Q>(
        &self,
        queries: Vec<Q>,
    ) -> impl Future<Output = Result<Vec<<Q::Collector as generic_query::Collector>::Fruit>>> + Send
    where
        Q: search_server::Query,

        Result<<<Q::Collector as generic_query::Collector>::Child as tantivy::collector::SegmentCollector>::Fruit, search_server::EncodedError>:
            From<<Q as sonic::service::Message<SearchService>>::Response>;

    fn batch_retrieve_generic<Q>(
        &self,
        queries: Vec<(Q, <Q::Collector as generic_query::Collector>::Fruit)>,
    ) -> impl Future<Output = Result<Vec<Vec<Q::IntermediateOutput>>>> + Send
    where
        Q: search_server::Query,
        Result<Q::IntermediateOutput, search_server::EncodedError>:
            From<
                <<Q as search_server::Query>::RetrieveReq as sonic::service::Message<
                    SearchService,
                >>::Response,
            >,
        <Q::Collector as generic_query::Collector>::Fruit: Clone;

    fn batch_search_generic<Q>(&self, queries: Vec<Q>) -> impl Future<Output = Result<Vec<Q::Output>>> + Send
        where
            Q: search_server::Query,
            Self: Send + Sync,
            Result<<<Q::Collector as generic_query::Collector>::Child as tantivy::collector::SegmentCollector>::Fruit, search_server::EncodedError>:
                From<<Q as sonic::service::Message<SearchService>>::Response>,
            Result<Q::IntermediateOutput, search_server::EncodedError>: From<
                <<Q as search_server::Query>::RetrieveReq as sonic::service::Message<
                    SearchService,
                >>::Response,
            >,
            <Q::Collector as generic_query::Collector>::Fruit: Clone
        {
        async {
            let res = self.batch_search_initial_generic(queries.clone()).await?;
            let res = self
                .batch_retrieve_generic(queries.into_iter().zip(res).collect())
                .await?;
            Ok(res.into_iter().map(|v| Q::merge_results(v)).collect())
        }
    }
}

#[derive(Clone, Debug)]
pub struct ScoredWebpagePointer {
    pub website: RecallRankingWebpage,
    pub shard: ShardId,
}

impl ScoredWebpagePointer {
    pub fn as_ranking(&self) -> &RecallRankingWebpage {
        &self.website
    }

    pub fn as_ranking_mut(&mut self) -> &mut RecallRankingWebpage {
        &mut self.website
    }
}

impl ShardIdentifier for ShardId {}

#[derive(Debug)]
pub struct InitialSearchResultShard {
    /// Actual query compilation rendering returned by this shard.
    pub rendered_query: String,
    pub local_result: InitialWebsiteResult,
    pub shard: ShardId,
}

impl ReusableClientManager for SearchService {
    const CLIENT_REFRESH_INTERVAL: std::time::Duration = CLIENT_REFRESH_INTERVAL;

    type Service = SearchService;
    type ShardId = ShardId;

    async fn new_client(cluster: &Cluster) -> ShardedClient<Self::Service, Self::ShardId> {
        let mut shards = HashMap::new();
        for member in cluster.members().await {
            if let Service::Searcher { host, shard } = member.service {
                shards.entry(shard).or_insert_with(Vec::new).push(host);
            } else if let Service::LiveIndex {
                search_host,
                shard,
                state,
                ..
            } = member.service
            {
                if state == LiveIndexState::Ready {
                    shards
                        .entry(shard)
                        .or_insert_with(Vec::new)
                        .push(search_host);
                }
            }
        }

        let mut shard_clients = Vec::new();

        for (id, replicas) in shards {
            let replicated =
                ReplicatedClient::new(replicas.into_iter().map(RemoteClient::new).collect());
            let shard = Shard::new(id, replicated);
            shard_clients.push(shard);
        }

        ShardedClient::new(shard_clients)
    }
}

impl ReusableClientManager for entity_search_server::SearchService {
    const CLIENT_REFRESH_INTERVAL: std::time::Duration = CLIENT_REFRESH_INTERVAL;

    type Service = entity_search_server::SearchService;
    type ShardId = ();

    async fn new_client(cluster: &Cluster) -> ShardedClient<Self::Service, Self::ShardId> {
        let mut replicas = Vec::new();
        for member in cluster.members().await {
            if let Service::EntitySearcher { host } = member.service {
                replicas.push(RemoteClient::new(host));
            }
        }

        let rep = ReplicatedClient::new(replicas);

        if !rep.is_empty() {
            ShardedClient::new(vec![Shard::new((), rep)])
        } else {
            ShardedClient::new(vec![])
        }
    }
}

impl ReusableClientManager for LiveIndexService {
    const CLIENT_REFRESH_INTERVAL: std::time::Duration = CLIENT_REFRESH_INTERVAL;

    type Service = LiveIndexService;

    type ShardId = ShardId;

    async fn new_client(cluster: &Cluster) -> ShardedClient<Self::Service, Self::ShardId> {
        let mut shards = HashMap::new();
        for member in cluster.members().await {
            if let Service::LiveIndex {
                host, shard, state, ..
            } = member.service
            {
                if state == LiveIndexState::Ready {
                    shards.entry(shard).or_insert_with(Vec::new).push(host);
                }
            }
        }

        let mut shard_clients = Vec::new();

        for (id, replicas) in shards {
            let replicated =
                ReplicatedClient::new(replicas.into_iter().map(RemoteClient::new).collect());
            let shard = Shard::new(id, replicated);
            shard_clients.push(shard);
        }

        ShardedClient::new(shard_clients)
    }
}

/// A searcher that runs the search on a remote cluster.
pub struct DistributedSearcher {
    client: Mutex<ReusableShardedClient<SearchService>>,
}

impl DistributedSearcher {
    pub async fn new(cluster: Arc<Cluster>) -> Self {
        Self::from_client(ReusableShardedClient::new(cluster.clone()).await)
    }

    pub fn from_client(client: ReusableShardedClient<SearchService>) -> Self {
        Self {
            client: Mutex::new(client),
        }
    }

    async fn conn(&self) -> Arc<ShardedClient<SearchService, ShardId>> {
        self.client.lock().await.conn().await
    }
}

impl SearchClient for DistributedSearcher {
    async fn begin_session(&self) -> Result<SearchSession, super::wire::QueryServiceError> {
        use super::wire::QueryServiceError;
        let client = self.conn().await;
        let mut session = SearchSession::for_shards(client.shards().len())?;
        if client.shards().iter().any(|s| s.replicas().is_empty()) {
            return Err(QueryServiceError::NoShards);
        }
        session.client = Some(client);
        Ok(session)
    }

    async fn search_initial(
        &self,
        query: &SearchQuery,
        session: &mut SearchSession,
    ) -> Result<Vec<InitialSearchResultShard>, super::wire::QueryServiceError> {
        use super::wire::{QueryServiceError, StageSelector};
        let selector = StageSelector::from_query(query)?;
        let expected =
            crate::query::Query::render_query(query).map_err(|_| QueryServiceError::InvalidPlan)?;
        let client = session.client.clone().ok_or(QueryServiceError::NoShards)?;
        session.begin_search()?;
        let responses = tokio::spawn(async move {
            client
                .send_with_timeout(
                    search_server::SearchV2 { selector },
                    &AllShardsSelector,
                    &FirstReplica,
                    std::time::Duration::from_secs(60),
                )
                .await
        })
        .await
        .map_err(|_| QueryServiceError::WorkerFailed)?
        .map_err(|_| QueryServiceError::ProtocolUnavailable)?;
        if responses.len() != session.shards {
            return Err(QueryServiceError::ShardFailed);
        }
        let mut results = Vec::new();
        for response in responses {
            let (shard, mut replicas) =
                response.map_err(|_| QueryServiceError::ProtocolUnavailable)?;
            if replicas.len() != 1 {
                return Err(QueryServiceError::ShardFailed);
            }
            let (_, response) = replicas.pop().ok_or(QueryServiceError::ShardFailed)?;
            let response = response?;
            if response.rendered_query != expected {
                return Err(QueryServiceError::SchemaMismatch);
            }
            results.push(InitialSearchResultShard {
                local_result: response.result,
                shard,
                rendered_query: response.rendered_query,
            });
        }
        Ok(results)
    }

    async fn retrieve_webpages(
        &self,
        top_websites: &[ScoredWebpagePointer],
        query: &SearchQuery,
        session: &mut SearchSession,
    ) -> Result<Vec<PrecisionRankingWebpage>, super::wire::QueryServiceError> {
        use super::wire::{BoundedPointers, QueryServiceError, StageSelector};
        if top_websites.len() > crate::query::planner::bounds::MAX_CANDIDATES {
            return Err(QueryServiceError::RetrievalFailed);
        }
        let selector = StageSelector::from_query(query)?;
        let mut pointers: HashMap<_, Vec<_>> = HashMap::new();
        for (i, pointer) in top_websites.iter().enumerate() {
            pointers
                .entry(pointer.shard)
                .or_default()
                .push((i, pointer.website.pointer().clone()));
        }
        let client = session.client.clone().ok_or(QueryServiceError::NoShards)?;
        if pointers
            .keys()
            .any(|id| !client.shards().iter().any(|s| s.id() == id))
        {
            return Err(QueryServiceError::RetrievalFailed);
        }
        session.begin_retrieval(pointers.len())?;
        let mut futures = Vec::new();
        for (shard, pointers) in pointers {
            let client = client.clone();
            let selector = selector.clone();
            futures.push(async move {
                let (indices, pointers): (Vec<_>, Vec<_>) = pointers.into_iter().unzip();
                let result = tokio::spawn(async move {
                    client
                        .send_with_timeout(
                            search_server::RetrieveWebsitesV2 {
                                selector,
                                websites: BoundedPointers(pointers),
                            },
                            &SpecificShardSelector(shard),
                            &FirstReplica,
                            std::time::Duration::from_secs(60),
                        )
                        .await
                })
                .await
                .map_err(|_| QueryServiceError::WorkerFailed)?
                .map_err(|_| QueryServiceError::RetrievalFailed)?;
                if result.len() != 1 {
                    return Err(QueryServiceError::RetrievalFailed);
                }
                let (_, mut replicas) = result
                    .into_iter()
                    .next()
                    .ok_or(QueryServiceError::RetrievalFailed)?
                    .map_err(|_| QueryServiceError::RetrievalFailed)?;
                if replicas.len() != 1 {
                    return Err(QueryServiceError::RetrievalFailed);
                }
                let pages = replicas
                    .pop()
                    .ok_or(QueryServiceError::RetrievalFailed)?
                    .1?
                    .webpages;
                if pages.len() != indices.len() {
                    return Err(QueryServiceError::RetrievalFailed);
                }
                Ok(indices.into_iter().zip(pages).collect::<Vec<_>>())
            });
        }
        let mut pages = Vec::new();
        for result in join_all(futures).await {
            pages.extend(result?);
        }
        pages.sort_by_key(|(i, _)| *i);
        if pages.len() != top_websites.len() {
            return Err(QueryServiceError::RetrievalFailed);
        }
        Ok(pages
            .into_iter()
            .map(|(i, page)| PrecisionRankingWebpage::new(page, top_websites[i].website.clone()))
            .collect())
    }

    async fn search_initial_generic<Q>(
        &self,
        query: Q,
    ) -> Result<<Q::Collector as generic_query::Collector>::Fruit>
    where
        Q: search_server::Query,
        Result<
            <Q::Collector as generic_query::Collector>::Fruit,
            search_server::EncodedError,
        >: From<<Q as sonic::service::Message<SearchService>>::Response>,
        <<Q::Collector as generic_query::Collector>::Child as tantivy::collector::SegmentCollector>::Fruit:
    From<<Q::Collector as generic_query::Collector>::Fruit>{
        let collector = query.coordinator_collector();

        let res = self
            .conn()
            .await
            .send(query, &AllShardsSelector, &RandomReplicaSelector)
            .await?;

        let fruits: Vec<<<Q::Collector as generic_query::Collector>::Child as tantivy::collector::SegmentCollector>::Fruit> = res
            .into_iter()
            .flatten()
            .flat_map(|(_, reps)| reps)
            .filter_map(|(_, rep)| {
                Result::<
                    <Q::Collector as generic_query::Collector>::Fruit,
                    search_server::EncodedError,
                >::from(rep)
                .ok()
            })
            .map(|fruit| {
                <<Q::Collector as generic_query::Collector>::Child as tantivy::collector::SegmentCollector>::Fruit::from(fruit)
            })
            .collect();

        collector
            .merge_fruits(fruits)
            .map_err(|_| anyhow::anyhow!("failed to merge fruits"))
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
        let conn = self.conn().await;
        let mut results = FuturesUnordered::new();
        for shard in conn.shards() {
            let fruit = query.filter_fruit_shards(*shard.id(), fruit.clone());
            let req = Q::RetrieveReq::new(query.clone(), fruit);
            results.push(shard.replicas().send(req, &RandomReplicaSelector));
        }
        let mut res = Vec::new();

        while let Some(shard_res) = results.next().await {
            if let Ok(shard_res) = shard_res {
                res.push(shard_res);
            }
        }

        Ok(res
            .into_iter()
            .flatten()
            .filter_map(|(_, res)| {
                Result::<Q::IntermediateOutput, search_server::EncodedError>::from(res).ok()
            })
            .collect())
    }

    async fn batch_search_initial_generic<Q>(
        &self,
        queries: Vec<Q>,
    ) -> Result<Vec<<Q::Collector as generic_query::Collector>::Fruit>>
    where
        Q: search_server::Query,
        Result<<<Q::Collector as generic_query::Collector>::Child as tantivy::collector::SegmentCollector>::Fruit, search_server::EncodedError>:
            From<<Q as sonic::service::Message<SearchService>>::Response>,
        {
        let res = self
            .conn()
            .await
            .batch_send(&queries, &AllShardsSelector, &RandomReplicaSelector)
            .await?;

        let mut fruits = Vec::with_capacity(queries.len());

        for _ in 0..queries.len() {
            fruits.push(Vec::new());
        }

        for (_, replica_results) in res.into_iter() {
            debug_assert_eq!(replica_results.len(), 1);

            for (_, shard_results) in replica_results.into_iter() {
                for (i, shard_result) in shard_results.into_iter().enumerate() {
                    if let Ok(shard_result) =
                        Result::<_, search_server::EncodedError>::from(shard_result)
                    {
                        fruits[i].push(shard_result);
                    }
                }
            }
        }

        queries
            .iter()
            .zip_eq(fruits.into_iter())
            .map(|(query, shard_fruits)| query.coordinator_collector().merge_fruits(shard_fruits))
            .collect::<Result<Vec<_>, _>>()
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
        let conn = self.conn().await;
        let mut results = FuturesUnordered::new();

        for shard in conn.shards() {
            let retrieve_requests: Vec<_> = queries
                .iter()
                .map(|(query, fruit)| {
                    let fruit = query.filter_fruit_shards(*shard.id(), fruit.clone());
                    Q::RetrieveReq::new(query.clone(), fruit)
                })
                .collect();

            results.push(async move {
                let retrieve_requests = retrieve_requests; // move lifetime
                shard
                    .replicas()
                    .batch_send(&retrieve_requests, &RandomReplicaSelector)
                    .await
            });
        }

        let mut res = Vec::new();

        for _ in 0..queries.len() {
            res.push(Vec::new());
        }

        while let Some(shard_res) = results.next().await {
            for (_, shard_res) in shard_res? {
                assert_eq!(shard_res.len(), queries.len());

                for (i, query_res) in shard_res.into_iter().enumerate() {
                    res[i].push(
                        <Result<Q::IntermediateOutput, search_server::EncodedError>>::from(
                            query_res,
                        )
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                    );
                }
            }
        }

        Ok(res)
    }
}

/// This should only be used for testing and benchmarks.
pub struct LocalSearchClient(LocalSearcher);
impl From<LocalSearcher> for LocalSearchClient {
    fn from(searcher: LocalSearcher) -> Self {
        Self(searcher)
    }
}

impl SearchClient for LocalSearchClient {
    async fn begin_session(&self) -> Result<SearchSession, super::wire::QueryServiceError> {
        SearchSession::for_shards(1)
    }

    async fn search_initial(
        &self,
        query: &SearchQuery,
        session: &mut SearchSession,
    ) -> Result<Vec<InitialSearchResultShard>, super::wire::QueryServiceError> {
        session.begin_search()?;
        let response = self.0.search_initial_v2(query).await?;
        Ok(vec![InitialSearchResultShard {
            local_result: response.result,
            shard: ShardId::Backbone(0),
            rendered_query: response.rendered_query,
        }])
    }

    async fn retrieve_webpages(
        &self,
        top_websites: &[ScoredWebpagePointer],
        query: &SearchQuery,
        session: &mut SearchSession,
    ) -> Result<Vec<PrecisionRankingWebpage>, super::wire::QueryServiceError> {
        use super::wire::QueryServiceError;
        session.begin_retrieval(usize::from(!top_websites.is_empty()))?;
        let pointers = top_websites
            .iter()
            .map(|p| p.website.pointer().clone())
            .collect::<Vec<_>>();
        let pages = self
            .0
            .retrieve_websites_selected(&pointers, query)
            .await
            .map_err(|e| {
                e.downcast_ref::<QueryServiceError>()
                    .copied()
                    .unwrap_or(QueryServiceError::RetrievalFailed)
            })?;
        if pages.len() != top_websites.len() {
            return Err(QueryServiceError::RetrievalFailed);
        }
        Ok(pages
            .into_iter()
            .zip(top_websites)
            .map(|(page, ranking)| PrecisionRankingWebpage::new(page, ranking.website.clone()))
            .collect())
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
        self.0.search_initial_generic(query).await
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
        Ok(vec![self.0.retrieve_generic(query, fruit).await?])
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
            res.push(self.0.search_initial_generic(query).await?);
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
            res.push(vec![self.0.retrieve_generic(query, fruit).await?]);
        }

        Ok(res)
    }
}
