//! Serves validated crawler policy without cluster state, authentication or network access.
//! Publication text stays visibly pending until founder content is supplied. Configuration is
//! loaded once and escaped on every rendering; this route grants no crawling permission.

#![deny(missing_docs)]

use crate::{config::ingestion::IngestionPolicy, crawler::policy};
use axum::{extract::State, middleware, response::Html, routing::get, Router};
use std::path::Path;

/// Loads one immutable policy before constructing the independent unauthenticated router.
/// Missing configured files and invalid policy fail startup; None uses the embedded template.
pub(super) fn router(config: Option<&Path>) -> anyhow::Result<Router> {
    let policy = match config {
        Some(path) => IngestionPolicy::load(path)?,
        None => policy::template()?,
    };
    Ok(Router::new()
        .route("/.well-known/ava-search-crawler", get(route))
        .with_state(policy::render(&policy))
        .layer(middleware::from_fn(super::source_offer::header)))
}

/// Returns the same policy content as the deterministic Markdown command, escaped as HTML.
#[utoipa::path(get, path = "/.well-known/ava-search-crawler", responses((status = 200, description = "Crawler identity, access policy and pending founder approvals", body = String, content_type = "text/html")), tag = "stract")]
pub(super) async fn route(State(markdown): State<String>) -> Html<String> {
    Html(format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>AVA Search crawler policy</title><body><article><pre>{}</pre></article></body></html>", escape_policy_html(&markdown)))
}

fn escape_policy_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;
    use utoipa::OpenApi;

    #[tokio::test]
    async fn policy_route() {
        let response = router(None)
            .unwrap()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/ava-search-crawler")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers()["source-offer"],
            crate::source_metadata::embedded().source_url
        );
        assert_eq!(
            response.headers()["content-type"],
            "text/html; charset=utf-8"
        );
        let text = String::from_utf8(
            to_bytes(response.into_body(), 65536)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(text.contains("production disabled"));
        assert!(text.contains("P12"));
        let source = include_str!("mod.rs");
        let start = source.split("pub async fn router(").nth(1).unwrap();
        assert!(
            start.contains("crawler_policy::router(config.crawler_policy_config_path.as_deref())?")
        );
        assert!(start.contains(".merge(policy_router)"));
        assert!(router(Some(Path::new("/not-a-policy-file-585"))).is_err());
    }
    #[test]
    fn policy_sync() {
        let original = policy::render(&policy::template().unwrap());
        assert_eq!(original, include_str!("../../../../CRAWLER_POLICY.md"));
        let mut config = policy::template().unwrap().get().clone();
        config.retention.raw_body_max_age_days = 7;
        config.robots.cache_secs = 120;
        config.exclusions.version = "changed-585".into();
        config.exclusions.change_log[0].version = "changed-585".into();
        let changed = policy::render(&config.validate().unwrap());
        assert!(changed.contains("raw bodies: 7 days"));
        assert!(changed.contains("usable robots: 120 seconds"));
        assert!(changed.contains("changed-585"));
        assert_ne!(original, changed);
    }
    #[test]
    fn policy_sections() {
        let text = policy::render(&policy::template().unwrap());
        for n in 1..=12 {
            let marker = format!("## P{n:02} ");
            assert_eq!(text.matches(&marker).count(), 1);
            assert!(!text
                .split(&marker)
                .nth(1)
                .unwrap()
                .split("\n\n")
                .nth(1)
                .unwrap()
                .trim()
                .is_empty());
        }
        for required in [
            "AVASearchBot/0.1.0",
            "500 ms",
            "2 connections",
            "300 seconds",
            "60 seconds",
            "86400 seconds",
            "Source:",
            "Policy version:",
            "cached copy: false",
            "ICO",
        ] {
            assert!(text.contains(required), "missing {required}");
        }
    }
    #[tokio::test]
    async fn policy_escaped() {
        let mut config = policy::template().unwrap().get().clone();
        config.policy_content.controller_identity = Some("<script>alert(\"&'\")</script>".into());
        let text = policy::render(&config.validate().unwrap());
        let Html(html) = route(State(text)).await;
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;alert(&quot;&amp;&#39;&quot;)&lt;/script&gt;"));
    }
    #[test]
    fn policy_api_docs() {
        let docs = super::super::docs::ApiDoc::openapi();
        assert!(docs
            .paths
            .paths
            .contains_key("/.well-known/ava-search-crawler"));
        assert!(docs
            .info
            .description
            .unwrap()
            .contains("[crawler policy](/.well-known/ava-search-crawler)"));
    }
}
