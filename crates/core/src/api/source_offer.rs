//! Exposes the build's source offer without search state, network access or telemetry.
//! Router-wide middleware preserves responses and overwrites any conflicting inner offer.

#![deny(missing_docs)]

use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response, Json};
use serde::Serialize;
use utoipa::ToSchema;

use crate::source_metadata;

/// Public source identity of the running build, with no machine or user information.
#[derive(Serialize, ToSchema)]
pub(super) struct SourceOffer {
    /// SPDX identifier of the service's source offer.
    pub(super) licence: &'static str,
    /// Public pinned source URL, or repository discovery URL for unknown builds.
    pub(super) source_url: String,
    /// Full lowercase Git SHA-1, or unknown.
    pub(super) revision: &'static str,
    /// Observable provenance: git, environment or unknown.
    pub(super) revision_source: &'static str,
}

/// Returns immutable build metadata without authentication or search initialization.
#[utoipa::path(get, path = "/.well-known/ava-search-source", responses((status = 200, description = "Corresponding source for this build", body = SourceOffer)), tag = "stract")]
pub(super) async fn route() -> Json<SourceOffer> {
    let metadata = source_metadata::embedded();
    Json(SourceOffer {
        licence: source_metadata::LICENCE,
        source_url: metadata.source_url,
        revision: metadata.revision,
        revision_source: metadata.revision_source,
    })
}

/// Inserts the source URL after the inner router has produced any response.
pub(super) async fn header(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let value = HeaderValue::from_str(&source_metadata::embedded().source_url)
        .expect("build-validated source URL is a header value");
    response.headers_mut().insert("source-offer", value);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
        Router,
    };
    use std::collections::BTreeMap;
    use tower::ServiceExt;

    const REPOSITORY: &str = "https://github.com/Al3xWalton/agentic-search";
    const PATH: &str = "/.well-known/ava-search-source";
    const TEMPLATE: &str = include_str!("../../../../SOURCE_OFFER.md");

    fn contract(document: &str) -> Option<BTreeMap<&str, &str>> {
        let start = "<!-- source-offer-contract:start -->";
        let end = "<!-- source-offer-contract:end -->";
        let block = document.split(start).nth(1)?.split(end).next()?.trim();
        let block = block.strip_prefix("```text\n")?.strip_suffix("\n```")?;
        let mut fields = BTreeMap::new();
        let mut unique = document.matches(start).count() == 1 && document.matches(end).count() == 1;
        for line in block.lines() {
            let (key, value) = line.split_once('=')?;
            unique &= fields.insert(key, value).is_none();
        }
        if !unique {
            return None;
        }
        (fields.len() == 4
            && ["licence", "source_url", "revision", "revision_source"]
                .iter()
                .all(|key| fields.contains_key(key)))
        .then_some(fields)
    }

    fn template_is_valid(document: &str) -> bool {
        let Some(template) = contract(document) else {
            return false;
        };
        let expected_licence = "AGPL-3.0-only";
        let expected_template_url = "https://github.com/Al3xWalton/agentic-search/tree/{revision}";
        template["licence"] == expected_licence
            && template["source_url"] == expected_template_url
            && template["revision"] == "{revision}"
            && template["revision_source"] == "{revision_source}"
    }

    async fn response() -> (axum::http::HeaderMap, serde_json::Value) {
        let response = super::super::finish_router(Router::new())
            .oneshot(Request::builder().uri(PATH).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        (headers, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn source_offer_consistency() {
        assert!(template_is_valid(TEMPLATE));
        for invalid in [
            TEMPLATE.replace("licence=AGPL-3.0-only", "licence=MIT"),
            TEMPLATE.replace(
                "source_url=https://github.com/Al3xWalton/agentic-search/tree/{revision}",
                "source_url=https://example.invalid/tree/{revision}",
            ),
            TEMPLATE.replace("revision={revision}\n", "revision=HEAD\n"),
            TEMPLATE.replace("revision_source={revision_source}", "revision_source=git"),
            format!("{TEMPLATE}\n{TEMPLATE}"),
            TEMPLATE.replace(
                "revision={revision}\n",
                "revision={revision}\nrevision={revision}\n",
            ),
        ] {
            assert!(
                !template_is_valid(&invalid),
                "invalid template accepted: {invalid}"
            );
        }
        let rendered = contract(source_metadata::RENDERED_OFFER).expect("rendered contract");
        let (headers, json) = response().await;
        let revision = env!("AVA_SEARCH_REVISION");
        let origin = env!("AVA_SEARCH_REVISION_SOURCE");
        let expected_url = if revision == "unknown" {
            REPOSITORY.to_owned()
        } else {
            format!("{REPOSITORY}/tree/{revision}")
        };
        assert_eq!(source_metadata::LICENCE, "AGPL-3.0-only");
        assert_eq!(source_metadata::REPOSITORY, REPOSITORY);
        for (key, value) in [
            ("licence", "AGPL-3.0-only"),
            ("source_url", expected_url.as_str()),
            ("revision", revision),
            ("revision_source", origin),
        ] {
            assert_eq!(rendered[key], value);
            assert_eq!(json[key], value);
        }
        assert_eq!(headers["source-offer"], expected_url);
        assert!(!source_metadata::RENDERED_OFFER.contains("{revision"));
        if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true") {
            assert_eq!(origin, "git", "CI checkout must be clean");
            assert_eq!(revision, std::env::var("GITHUB_SHA").unwrap());
        }
        if let Some(directory) = std::env::var_os("STORY584_ARTIFACT_DIR") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(
                directory.join("SOURCE_OFFER.md"),
                source_metadata::RENDERED_OFFER,
            )
            .unwrap();
            std::fs::write(
                directory.join("source-offer.json"),
                serde_json::to_vec_pretty(&json).unwrap(),
            )
            .unwrap();
        }
    }

    #[tokio::test]
    async fn source_offer_uses_embedded_revision() {
        let (_, json) = response().await;
        assert_eq!(json["revision"], env!("AVA_SEARCH_REVISION"));
        let unknown = source_metadata::metadata("unknown", "unknown");
        assert_eq!(unknown.revision, "unknown");
        assert_eq!(unknown.source_url, REPOSITORY);
    }

    #[test]
    fn source_url_comes_from_manifest() {
        let repository = env!("CARGO_PKG_REPOSITORY");
        assert!(!repository.is_empty());
        assert!(source_metadata::embedded()
            .source_url
            .starts_with(repository));
    }

    #[tokio::test]
    async fn source_offer_origin_is_observable() {
        let (_, json) = response().await;
        assert_eq!(json["revision_source"], env!("AVA_SEARCH_REVISION_SOURCE"));
        assert_eq!(
            source_metadata::metadata("unknown", "unknown").revision_source,
            "unknown"
        );
    }
}
