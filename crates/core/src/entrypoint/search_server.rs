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

use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::info;

use crate::{
    config,
    distributed::{
        cluster::Cluster,
        member::{Member, Service},
        sonic::{self, service::sonic_service},
    },
    generic_query::{
        self, GetHomepageQuery, GetSiteUrlsQuery, GetWebpageQuery, SizeQuery, TopKeyPhrasesQuery,
    },
    index::Index,
    inverted_index::{self, ShardId},
    models::dual_encoder::DualEncoder,
    ranking::models::linear::LinearRegression,
    searcher::{InitialWebsiteResult, LocalSearcher},
    Result,
};

pub trait RetrieveReq:
    bincode::Encode + bincode::Decode + Clone + sonic::service::Wrapper<SearchService>
{
    type Query: generic_query::GenericQuery + bincode::Encode + bincode::Decode;
    fn new(
        query: Self::Query,
        fruit: <<Self::Query as generic_query::GenericQuery>::Collector as generic_query::Collector>::Fruit,
    ) -> Self;
}

pub trait Query
where
    Self: generic_query::GenericQuery
        + bincode::Encode
        + bincode::Decode
        + sonic::service::Wrapper<SearchService>
        + Send
        + Sync
        + 'static,
{
    type RetrieveReq: RetrieveReq<Query = Self>;
}

#[derive(bincode::Encode, bincode::Decode, Clone)]
pub struct EncodedError {
    pub msg: String,
}

impl std::fmt::Display for EncodedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}

macro_rules! impl_search {
    ([$($q:ident),*$(,)?]) => {
        $(
            impl sonic::service::Message<SearchService> for $q {
                type Response = Result<<<$q as generic_query::GenericQuery>::Collector as generic_query::Collector>::Fruit, EncodedError>;

                async fn handle(self, server: &SearchService) -> Self::Response {
                    server.local_searcher.search_initial_generic(self).await.map_err(|e| EncodedError { msg: e.to_string() })
                }
            }

            paste::item! {
                #[derive(bincode::Encode, bincode::Decode, Clone)]
                pub struct [<$q Retrieve>] {
                    pub query: $q,
                    #[bincode(with_serde)]
                    pub fruit: <<$q as generic_query::GenericQuery>::Collector as generic_query::Collector>::Fruit,
                }

                impl sonic::service::Message<SearchService> for [<$q Retrieve>] {
                    type Response = Result<<$q as generic_query::GenericQuery>::IntermediateOutput, EncodedError>;
                    async fn handle(self, server: &SearchService) -> Self::Response {
                        server
                            .local_searcher
                            .retrieve_generic(self.query, self.fruit)
                            .await
                            .map_err(|e| EncodedError { msg: e.to_string() })
                    }
                }

                impl Query for $q {
                    type RetrieveReq = [<$q Retrieve>];
                }

                impl RetrieveReq for [<$q Retrieve>] {
                    type Query = $q;
                    fn new(query: Self::Query, fruit: <<Self::Query as generic_query::GenericQuery>::Collector as generic_query::Collector>::Fruit) -> Self {
                        Self { query, fruit }
                    }
                }
            }
        )*

        paste::item! {
            sonic_service!(SearchService, [
                RetrieveWebsites,
                Search,
                $(
                    $q,
                    [<$q Retrieve>],
                )*
                SearchV2,
                RetrieveWebsitesV2,
            ]);
        }

    }
}

impl_search!([
    TopKeyPhrasesQuery,
    SizeQuery,
    GetWebpageQuery,
    GetHomepageQuery,
    GetSiteUrlsQuery,
]);

pub struct SearchService {
    local_searcher: LocalSearcher,
    // dropping the handle leaves the cluster
    #[allow(unused)]
    cluster_handle: Arc<Cluster>,
}

impl SearchService {
    pub async fn new_from_existing(
        config: config::SearchServerConfig,
        cluster: Arc<Cluster>,
        index: Arc<RwLock<Index>>,
    ) -> Result<Self> {
        let mut local_searcher = LocalSearcher::builder(index);

        if let Some(model_path) = config.linear_model_path {
            local_searcher = local_searcher.set_linear_model(LinearRegression::open(model_path)?);
        }

        if let Some(model_path) = config.dual_encoder_model_path {
            local_searcher = local_searcher.set_dual_encoder(DualEncoder::open(model_path)?);
        }

        local_searcher = local_searcher.set_collector_config(config.collector);

        Ok(SearchService {
            local_searcher: local_searcher.build(),
            cluster_handle: cluster,
        })
    }

    pub async fn new(config: config::SearchServerConfig, shard: ShardId) -> Result<Self> {
        let host = config.host;
        let gossip_addr = config.gossip_addr;
        let gossip_seed_nodes = config.gossip_seed_nodes.clone().unwrap_or_default();

        let mut search_index = Index::open(&config.index_path)?;
        search_index
            .inverted_index
            .set_snippet_config(config.snippet.clone());
        search_index.set_shard_id(shard);

        let search_index = Arc::new(RwLock::new(search_index));

        let cluster = Arc::new(
            Cluster::join(
                Member::new(Service::Searcher { host, shard }),
                gossip_addr,
                gossip_seed_nodes,
            )
            .await?,
        );

        Self::new_from_existing(config, cluster, search_index).await
    }
}

#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct RetrieveWebsites {
    pub websites: Vec<inverted_index::WebpagePointer>,
    pub query: String,
}
impl sonic::service::Message<SearchService> for RetrieveWebsites {
    type Response = Option<Vec<inverted_index::RetrievedWebpage>>;
    async fn handle(self, server: &SearchService) -> Self::Response {
        server
            .local_searcher
            .retrieve_websites(&self.websites, &self.query)
            .await
            .ok()
    }
}

#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct Search {
    pub query: crate::searcher::wire::LegacySearchQuery,
}
impl sonic::service::Message<SearchService> for Search {
    type Response = Option<InitialWebsiteResult>;
    async fn handle(self, server: &SearchService) -> Self::Response {
        server
            .local_searcher
            .search_initial(&self.query.into(), true)
            .await
            .ok()
    }
}

pub async fn run(config: config::SearchServerConfig) -> Result<()> {
    let addr = config.host;
    let shard = ShardId::Backbone(config.shard);
    let server = SearchService::new(config, shard)
        .await?
        .bind(addr)
        .await
        .unwrap();

    info!("search server is ready to accept requests on {}", addr);

    loop {
        if let Err(e) = server.accept().await {
            tracing::error!("{:?}", e);
        }
    }
}

/// Versioned initial query selected by the coordinator and recomputed by the shard.
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct SearchV2 {
    /// Bounded original request and stage selector; no executable tree crosses the wire.
    pub selector: crate::searcher::wire::StageSelector,
}

impl sonic::service::Message<SearchService> for SearchV2 {
    type Response =
        Result<crate::searcher::wire::SearchV2Result, crate::searcher::wire::QueryServiceError>;
    async fn handle(self, server: &SearchService) -> Self::Response {
        let query = self.selector.resolve()?;
        server.local_searcher.search_initial_v2(&query).await
    }
}

/// Versioned retrieval using the same selected query for snippet analysis.
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct RetrieveWebsitesV2 {
    /// Exactly the selected stage used for initial matching.
    pub selector: crate::searcher::wire::StageSelector,
    /// At most 300 pointers, in the coordinator's requested order.
    pub websites: crate::searcher::wire::BoundedPointers,
}

impl sonic::service::Message<SearchService> for RetrieveWebsitesV2 {
    type Response =
        Result<crate::searcher::wire::RetrieveV2Result, crate::searcher::wire::QueryServiceError>;
    async fn handle(self, server: &SearchService) -> Self::Response {
        use crate::searcher::wire::{QueryServiceError, RetrieveV2Result};
        let query = self.selector.resolve()?;
        if self.websites.0.len() > crate::query::planner::bounds::MAX_CANDIDATES {
            return Err(QueryServiceError::InvalidPlan);
        }
        let webpages = server
            .local_searcher
            .retrieve_websites_selected(&self.websites.0, &query)
            .await
            .map_err(|e| {
                e.downcast_ref::<QueryServiceError>()
                    .copied()
                    .unwrap_or(QueryServiceError::RetrievalFailed)
            })?;
        if webpages.len() != self.websites.0.len() {
            return Err(QueryServiceError::RetrievalFailed);
        }
        Ok(RetrieveV2Result { webpages })
    }
}
