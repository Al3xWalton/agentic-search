// SPDX-License-Identifier: AGPL-3.0-only
//! Build tiny deterministic indexes for real planner, ranking and API-searcher contracts.
//! Documents, scores and URLs are synthetic; no corpus, model or network is loaded.
//! Files remain owned by the returned temporary directory for the entire search lifetime.

use std::sync::Arc;
use stract::{
    bangs::Bangs,
    index::Index,
    searcher::{
        api::{ApiSearcher, Config},
        LocalSearchClient, LocalSearcher,
    },
    webpage::{Html, Webpage},
};
use tokio::sync::RwLock;

/// Build fixed documents with an optional fixture-only attribute adjustment before indexing.
/// The returned directory must outlive the local searcher; malformed fixtures panic.
pub fn local(
    docs: &[(&str, &str, &str)],
    customize: impl FnMut(usize, &mut Webpage),
) -> (LocalSearcher, file_store::temp::TempDir) {
    local_with_collector(docs, customize, Default::default())
}

/// Build deterministic documents with an explicit candidate consideration limit, in documents.
/// The returned directory owns the index; malformed synthetic input or an index operation failure panics.
pub fn local_with_collector(
    docs: &[(&str, &str, &str)],
    mut customize: impl FnMut(usize, &mut Webpage),
    collector: stract::config::CollectorConfig,
) -> (LocalSearcher, file_store::temp::TempDir) {
    let directory = stract::gen_temp_dir().unwrap();
    let mut index = Index::open(&directory).unwrap();
    index.set_shard_id(stract::inverted_index::ShardId::Backbone(0));
    index.inverted_index.prepare_writer().unwrap();
    for (ordinal, (url, title, body)) in docs.iter().enumerate() {
        let html=format!("<html><head><title>{title}</title></head><body><main><p>{body}</p><p>Additional synthetic fixture material for indexing a stable searchable document.</p></main></body></html>");
        let mut webpage = Webpage::from(Html::parse(&html, url).unwrap());
        webpage.host_centrality = (100 - ordinal) as f64;
        webpage.fetch_time_ms = 500;
        webpage.inserted_at = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        customize(ordinal, &mut webpage);
        index.insert(&webpage).unwrap();
    }
    index.commit().unwrap();
    (
        LocalSearcher::builder(Arc::new(RwLock::new(index)))
            .set_collector_config(collector)
            .build(),
        directory,
    )
}

/// Wrap a local fixture with server planning and explicitly supplied local bang definitions.
/// Currency, thesaurus, models and remote graph loading are disabled.
pub async fn api(
    local: LocalSearcher,
    enabled: bool,
    bangs: Bangs,
) -> ApiSearcher<LocalSearchClient, stract::webgraph::Webgraph> {
    let mut config = Config {
        agent_query_planning: enabled,
        ..Default::default()
    };
    config.widgets.calculator_fetch_currencies_exchange = false;
    config.widgets.thesaurus_paths.clear();
    ApiSearcher::new(LocalSearchClient::from(local), None, bangs, config).await
}

/// Build fixed (URL,title,body) documents and an API searcher with the requested server mode.
/// Returns a directory owner that must outlive all searches; malformed fixtures panic in tests.
pub async fn searcher(
    docs: &[(&str, &str, &str)],
    enabled: bool,
) -> (
    ApiSearcher<LocalSearchClient, stract::webgraph::Webgraph>,
    file_store::temp::TempDir,
) {
    let (local, dir) = local(docs, |_, _| {});
    (api(local, enabled, Bangs::empty()).await, dir)
}
