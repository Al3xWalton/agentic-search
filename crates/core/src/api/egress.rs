//! Load-verified immutable egress publication, independent of search state and request-time DNS.
//! Expiry and signatures are checked at startup only; operators must refresh publication
//! separately.

#![deny(missing_docs)]

use anyhow::Context;
use axum::{
    body::Body,
    extract::State,
    http::{header, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::{path::Path, sync::Arc, time::SystemTime};

/// Startup snapshot, which is never reloaded or reserialized during a request.
#[derive(Clone)]
pub(super) enum EgressState {
    /// Both local publication settings are absent.
    Pending,
    /// Exact envelope bytes authenticated at load time.
    Ready(
        /// Original immutable file bytes, including whitespace and newlines.
        Arc<[u8]>,
    ),
}

/// Fixed pending response; it contains no fabricated signed inventory.
#[derive(Serialize, utoipa::ToSchema)]
#[schema(example = json!({
    "status": "pending", "detail": "Signed egress inventory is not configured."
}))]
pub(super) struct PendingBody {
    /// Literal pending state.
    #[schema(example = "pending")]
    pub status: &'static str,
    /// Literal configuration explanation.
    #[schema(example = "Signed egress inventory is not configured.")]
    pub detail: &'static str,
}

impl PendingBody {
    fn new() -> Self {
        Self {
            status: "pending",
            detail: "Signed egress inventory is not configured.",
        }
    }
}

/// Constructs the route once, failing startup for incomplete or invalid configured publication.
pub(super) fn router(file: Option<&Path>, trusted_keys: Option<&Path>) -> anyhow::Result<Router> {
    let state = match (file, trusted_keys) {
        (None, None) => EgressState::Pending,
        (Some(file), Some(keys)) => EgressState::Ready(load(file, keys).context("egress_load")?),
        _ => return Err(anyhow::anyhow!("egress_config_incomplete")),
    };
    Ok(Router::new()
        .route("/.well-known/ava-search-egress.json", get(route))
        .with_state(state)
        .layer(middleware::from_fn(super::source_offer::header)))
}

fn load(file: &Path, trusted_keys: &Path) -> ::egress::Result<Arc<[u8]>> {
    let bytes = ::egress::read_bounded(file, ::egress::MAX_FILE_BYTES)?;
    let keys = ::egress::parse_trusted_keys(&::egress::read_bounded(
        trusted_keys,
        ::egress::MAX_FILE_BYTES,
    )?)?;
    ::egress::verify_file(&bytes, &keys, SystemTime::now())?;
    Ok(bytes.into())
}

/// Returns unchanged startup bytes or an explicit pending response, with the local source offer.
// docs.rs::describe_egress_envelope replaces Object with the real inline envelope schema.
#[utoipa::path(
    get, path = "/.well-known/ava-search-egress.json", tag = "stract",
    responses(
        (status = 200, description = "Signed envelope verified once at startup",
            body = Object, content_type = "application/json",
            headers(("Source-Offer" = String, description = "Corresponding build source URL"))),
        (status = 503, description = "Signed egress publication is not configured",
            body = PendingBody, content_type = "application/json",
            headers(("Source-Offer" = String, description = "Corresponding build source URL")))
    )
)]
pub(super) async fn route(State(state): State<EgressState>) -> Response {
    match state {
        EgressState::Pending => {
            (StatusCode::SERVICE_UNAVAILABLE, Json(PendingBody::new())).into_response()
        }
        EgressState::Ready(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            Body::from(bytes.to_vec()),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::to_bytes, http::Request};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use chrono::{DateTime, SecondsFormat, Utc};
    use ring::{
        digest,
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use serde_json::{json, Value};
    use std::{fs, path::PathBuf, time::Duration};
    use tower::ServiceExt;
    use utoipa::OpenApi;

    const ROUTE: &str = "/.well-known/ava-search-egress.json";

    struct Fixture {
        root: file_store::temp::TempDir,
        key: Ed25519KeyPair,
        id: String,
        payload: Value,
    }

    impl Fixture {
        fn new() -> Self {
            let root = crate::gen_temp_dir().unwrap();
            let der = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            let key = Ed25519KeyPair::from_pkcs8(der.as_ref()).unwrap();
            let id = digest::digest(&digest::SHA256, key.public_key().as_ref())
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let now = SystemTime::now();
            let payload = json!({
                "schema_version":1,
                "generated_at_utc":stamp(now - Duration::from_secs(60)),
                "valid_until_utc":stamp(now + Duration::from_secs(3600)),
                "controlled_domain":"egress.example.net", "ranges":["192.0.2.0/24"],
                "egress_ips":["192.0.2.10"], "policy_version":"test-v1"
            });
            let fixture = Self {
                root,
                key,
                id,
                payload,
            };
            fs::write(
                fixture.keys(),
                serde_json::to_vec(&json!({fixture.id.clone():
                STANDARD.encode(fixture.key.public_key().as_ref())}))
                .unwrap(),
            )
            .unwrap();
            fixture.publish(&serde_json::to_vec(&fixture.payload).unwrap());
            fixture
        }

        fn file(&self) -> PathBuf {
            self.root.as_ref().join("envelope.json")
        }
        fn keys(&self) -> PathBuf {
            self.root.as_ref().join("trusted.json")
        }

        fn signed(&self, payload: &[u8]) -> Value {
            let mut message = b"AVA-SEARCH-EGRESS-V1\n".to_vec();
            for field in [b"1".as_slice(), b"Ed25519", self.id.as_bytes(), payload] {
                let size = u64::try_from(field.len()).unwrap();
                for shift in (0..8).rev() {
                    message.push((size >> (shift * 8)) as u8);
                }
                message.extend_from_slice(field);
            }
            json!({"schema_version":1, "algorithm":"Ed25519", "key_id":self.id,
                "payload_base64":STANDARD.encode(payload),
                "signature_base64":STANDARD.encode(self.key.sign(&message))})
        }

        fn publish(&self, payload: &[u8]) {
            let mut bytes = serde_json::to_vec_pretty(&self.signed(payload)).unwrap();
            bytes.push(b'\n');
            fs::write(self.file(), bytes).unwrap();
        }

        fn router(&self) -> anyhow::Result<Router> {
            router(Some(&self.file()), Some(&self.keys()))
        }

        fn refused(&self, bytes: &[u8], reason: &str) {
            fs::write(self.file(), bytes).unwrap();
            match self.router() {
                Ok(_) => panic!("expected {reason}, router was built"),
                Err(error) => {
                    let error = format!("{error:#}");
                    assert!(
                        error.contains("egress_load") && error.contains(reason),
                        "expected {reason}, got {error}"
                    );
                }
            }
        }
    }

    fn stamp(time: SystemTime) -> String {
        DateTime::<Utc>::from(time).to_rfc3339_opts(SecondsFormat::Nanos, true)
    }

    async fn request(router: Router, status: u16) -> Vec<u8> {
        let response = router
            .oneshot(Request::builder().uri(ROUTE).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            status,
            "egress route must be present with expected state"
        );
        assert_eq!(response.headers()["content-type"], "application/json");
        assert_eq!(
            response
                .headers()
                .get("source-offer")
                .and_then(|value| value.to_str().ok()),
            Some(crate::source_metadata::embedded().source_url.as_str()),
            "egress response must carry Source-Offer"
        );
        to_bytes(response.into_body(), ::egress::MAX_FILE_BYTES)
            .await
            .unwrap()
            .to_vec()
    }

    #[tokio::test]
    async fn egress_pending() {
        assert!(
            request(router(None, None).unwrap(), 503).await
                == br#"{"status":"pending","detail":"Signed egress inventory is not configured."}"#,
            "pending response body differs"
        );
    }

    #[tokio::test]
    async fn egress_configured() {
        let f = Fixture::new();
        let saved = fs::read(f.file()).unwrap();
        assert!(saved.starts_with(b"{\n") && saved.ends_with(b"\n"));
        let router = f.router().unwrap();
        assert!(
            request(router.clone(), 200).await == saved,
            "served envelope differs"
        );
        fs::write(f.file(), b"replaced").unwrap();
        assert!(
            request(router.clone(), 200).await == saved,
            "snapshot changed after replacement"
        );
        fs::remove_file(f.file()).unwrap();
        fs::remove_file(f.keys()).unwrap();
        assert!(
            request(router, 200).await == saved,
            "snapshot changed after deletion"
        );
    }

    fn rejected_payloads(f: &Fixture) {
        let now = SystemTime::now();
        for (field, replacement, reason) in [
            (
                "valid_until_utc",
                json!(stamp(now - Duration::from_secs(1))),
                "expired",
            ),
            (
                "generated_at_utc",
                json!(stamp(now + Duration::from_secs(60))),
                "not_yet_valid",
            ),
            ("schema_version", json!(2), "payload_schema"),
            ("egress_ips", json!([]), "inventory_empty"),
            ("egress_ips", json!(["198.51.100.10"]), "ip_outside_ranges"),
        ] {
            let mut payload = f.payload.clone();
            payload[field] = replacement;
            let signed = f.signed(&serde_json::to_vec(&payload).unwrap());
            f.refused(&serde_json::to_vec(&signed).unwrap(), reason);
        }
        let duplicate =
            serde_json::to_string(&f.payload)
                .unwrap()
                .replacen('{', "{\"schema_version\":1,", 1);
        f.refused(
            &serde_json::to_vec(&f.signed(duplicate.as_bytes())).unwrap(),
            "duplicate_key",
        );
    }

    #[test]
    fn egress_configuration_errors() {
        let f = Fixture::new();
        assert!(f.router().is_ok());
        for (file, keys) in [(Some(f.file()), None), (None, Some(f.keys()))] {
            match router(file.as_deref(), keys.as_deref()) {
                Ok(_) => panic!("expected egress_config_incomplete, router was built"),
                Err(error) => assert_eq!(
                    error.to_string(),
                    "egress_config_incomplete",
                    "expected egress_config_incomplete, got {error}"
                ),
            }
        }
        let missing = f.root.as_ref().join("missing");
        for (file, keys) in [(&missing, f.keys()), (&f.file(), missing.clone())] {
            let result = router(Some(file), Some(&keys));
            assert!(
                result.is_err(),
                "configured missing input must fail startup"
            );
            assert!(format!("{:#}", result.err().unwrap()).contains("io_error"));
        }
        let original = fs::read(f.file()).unwrap();
        let envelope: Value = serde_json::from_slice(&original).unwrap();
        for (field, replacement, reason) in [
            (
                "signature_base64",
                json!(STANDARD.encode([0; 64])),
                "signature_invalid",
            ),
            ("algorithm", json!("none"), "algorithm_unsupported"),
            ("key_id", json!("a".repeat(64)), "untrusted_key"),
            ("schema_version", json!(2), "envelope_schema"),
        ] {
            let mut changed = envelope.clone();
            changed[field] = replacement;
            f.refused(&serde_json::to_vec(&changed).unwrap(), reason);
        }
        let duplicate =
            String::from_utf8(original)
                .unwrap()
                .replacen('{', "{\"schema_version\":1,", 1);
        f.refused(duplicate.as_bytes(), "duplicate_key");
        rejected_payloads(&f);
    }

    fn documented_egress(doc: &Value) {
        let operation = &doc["paths"][ROUTE]["get"];
        assert!(
            operation.is_object(),
            "GET egress publication must be documented"
        );
        for status in ["200", "503"] {
            let response = &operation["responses"][status];
            assert!(response["headers"]["Source-Offer"]["schema"].is_object());
            assert!(response["content"]["application/json"]["schema"].is_object());
        }
        let schema = &operation["responses"]["200"]["content"]["application/json"]["schema"];
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        let required: std::collections::BTreeSet<_> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            required,
            [
                "schema_version",
                "algorithm",
                "key_id",
                "payload_base64",
                "signature_base64"
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(schema["properties"]["schema_version"]["enum"], json!([1]));
        assert_eq!(
            schema["properties"]["algorithm"]["enum"],
            json!(["Ed25519"])
        );
        assert_eq!(schema["properties"]["key_id"]["pattern"], "^[0-9a-f]{64}$");
        assert_eq!(
            doc["components"]["schemas"]["PendingBody"]["example"],
            json!({
            "status":"pending", "detail":"Signed egress inventory is not configured."})
        );
    }

    #[test]
    fn egress_api_docs() {
        let doc = serde_json::to_value(super::super::docs::ApiDoc::openapi()).unwrap();
        documented_egress(&doc);
        let v1 = serde_json::to_value(super::super::v1::openapi()).unwrap();
        assert_eq!(v1["paths"].as_object().unwrap().len(), 25);
        let operations = v1["paths"]
            .as_object()
            .unwrap()
            .values()
            .map(|path| {
                [
                    "get", "post", "put", "patch", "delete", "head", "options", "trace",
                ]
                .iter()
                .filter(|verb| path.get(**verb).is_some())
                .count()
            })
            .sum::<usize>();
        assert_eq!(operations, 26);
        let beta = super::super::docs::BetaApiDoc::openapi();
        documented_egress(&serde_json::to_value(&beta).unwrap());
        if let Some(path) = std::env::var_os("BETA_OPENAPI_ARTIFACT") {
            let bytes = serde_json::to_vec(&beta).unwrap();
            fs::write(path, &bytes).unwrap();
            println!(
                "beta-openapi-sha256: {:?}",
                digest::digest(&digest::SHA256, &bytes).as_ref()
            );
        }
    }

    fn compact(source: &str) -> String {
        source
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<String>()
    }

    #[test]
    fn wiring_source() {
        let source = include_str!("mod.rs");
        let body = &source[source.find("pub async fn router").unwrap()..];
        let end = ["\npub ", "\nfn "]
            .iter()
            .filter_map(|next| body.find(next))
            .min()
            .unwrap_or(body.len());
        let compact_body = compact(&body[..end]);
        for expected in [
            "let policy_router = merge_policy_egress(policy_router, egress_router);",
            "let egress_router = egress::router(config.egress_file_path.as_deref(),
                config.egress_trusted_keys_path.as_deref(),)?;",
        ] {
            assert_eq!(
                compact_body.matches(&compact(expected)).count(),
                1,
                "api::router must contain exactly one {expected}"
            );
        }
        let compact_source = compact(source);
        for expected in [
            "egress::router(config.egress_file_path.as_deref(),
                config.egress_trusted_keys_path.as_deref(),)?",
            ".merge(egress_router)",
            "crawler_policy::router(config.crawler_policy_config_path.as_deref())?",
            ".merge(policy_router)",
        ] {
            assert_eq!(
                compact_source.matches(&compact(expected)).count(),
                1,
                "production wiring must contain exactly one {expected}"
            );
        }
        assert!(source
            .contains("crawler_policy::router(config.crawler_policy_config_path.as_deref())?"));
        assert!(source.contains(".merge(policy_router)"));
    }

    #[tokio::test]
    async fn egress_config_wiring() {
        let f = Fixture::new();
        let policy = super::super::crawler_policy::router(None).unwrap();
        let merged = super::super::merge_policy_egress(policy, f.router().unwrap());
        assert!(
            request(merged, 200).await == fs::read(f.file()).unwrap(),
            "merged route envelope differs"
        );
        let input = include_str!("../../../../configs/api.toml");
        let config: crate::config::ApiConfig = toml::from_str(input).unwrap();
        assert!(config.egress_file_path.is_none() && config.egress_trusted_keys_path.is_none());
        let offset = input.find("[spell_check]").unwrap();
        let configured = format!(
            "{}\negress_file_path = {:?}\negress_trusted_keys_path = {:?}\n{}",
            &input[..offset],
            f.file().to_str().unwrap(),
            f.keys().to_str().unwrap(),
            &input[offset..]
        );
        let config: crate::config::ApiConfig = toml::from_str(&configured).unwrap();
        assert_eq!(config.egress_file_path.as_deref(), Some(f.file().as_path()));
        assert_eq!(
            config.egress_trusted_keys_path.as_deref(),
            Some(f.keys().as_path())
        );
        wiring_source();
    }

    fn policy_sections(text: &str) -> std::collections::BTreeMap<&str, &str> {
        text.split("## ")
            .skip(1)
            .map(|section| {
                let (title, body) = section.split_once('\n').unwrap();
                (title, body)
            })
            .collect()
    }

    #[test]
    fn egress_policy_obligations() {
        use crate::crawler::policy;
        let template = policy::template().unwrap();
        let rendered = policy::render(&template);
        let committed = include_str!("../../../../CRAWLER_POLICY.md");
        for text in [&rendered, committed] {
            assert_eq!(text.matches("[FOUNDER REQUIRED:").count(), 9);
            let sections = policy_sections(text);
            let ids: Vec<_> = sections
                .iter()
                .filter(|(_, body)| body.contains("[FOUNDER REQUIRED:"))
                .map(|(title, _)| &title[..3])
                .collect();
            assert_eq!(
                ids,
                ["P01", "P04", "P05", "P08", "P09", "P10", "P11", "P12"]
            );
            let p08 = sections["P08 Egress verification"];
            assert_eq!(
                p08.matches("[FOUNDER REQUIRED: stable signed egress URL]")
                    .count(),
                1
            );
            for required in [
                "/.well-known/ava-search-egress.json",
                "503 pending",
                "Ed25519 PKCS8",
                "custody outside the repository and CI",
                "real complete egress-IP inventory",
                "forward-confirmed PTR records under a domain the operator controls",
                "DNS alone proves no ownership",
                "verified once at startup and served unchanged",
                "Run nightly re-verification with independently observed outbound IPs:",
                "cargo xtask egress-verify --file <json> --trusted-keys <json> --observed <json>",
                "one day is the engineering lifetime default, not a legal rule",
            ] {
                assert!(
                    p08.contains(required),
                    "P08 must preserve obligation: {required}"
                );
            }
        }
        let mut configured = template.get().clone();
        configured.policy_content.egress_file_url =
            Some("https://egress.example.net/inventory".into());
        let changed = policy::render(&configured.validate().unwrap());
        assert!(
            changed
                == rendered.replace(
                    "[FOUNDER REQUIRED: stable signed egress URL]",
                    "https://egress.example.net/inventory"
                ),
            "configured policy differs beyond the egress URL"
        );
        let old_sections = policy_sections(committed);
        for (title, body) in policy_sections(&rendered) {
            if title != "P08 Egress verification" {
                assert!(
                    old_sections[title] == body,
                    "unrelated policy section changed"
                );
            }
        }
    }
}
