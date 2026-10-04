//! Proves the executable diagnostic boundary and the public Rust provider extension contract.

use axum::{
    body::{to_bytes, Body},
    http::Request,
    Router,
};
use futures::future::BoxFuture;
use serde_json::{json, Value};
use std::{
    path::Path,
    process::Command,
    sync::{Arc, Mutex},
};
use stract::{
    api::v1::{
        self,
        dto::AttributedResult,
        scholarly::{PaperPage, PaperProvider, PaperProviderError, PaperQuery},
        SearchBackend, V1Resources, V1State,
    },
    config::ApiConfig,
};
use tower::ServiceExt;

// Child diagnostics remain in memory even when a mutant deliberately leaks fixture content.
fn must<T, E>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(_) => panic!("paper contract fixture"),
    }
}

// Explicit local paths avoid inheriting any operator configuration.
fn config(root: &Path) -> ApiConfig {
    let mut config: ApiConfig = must(toml::from_str(include_str!("../../../configs/api.toml")));
    config.v1.suppression_store_path = root.join("serving/suppression.json");
    config
}

// The exact executable exit and complete streams define the public diagnostic contract.
fn cli(path: &Path, expected: &str) {
    let output = must(
        Command::new(env!("CARGO_BIN_EXE_stract"))
            .arg("api")
            .arg(path)
            .env("RUST_LOG", "trace")
            .env("RUST_BACKTRACE", "1")
            .output(),
    );
    assert!(output.status.code() == Some(1), "W39 exit");
    assert!(output.stdout.is_empty(), "W39 stdout");
    assert!(
        output.stderr == format!("Error: {expected}\n").as_bytes(),
        "W39 exact stderr"
    );
}

#[test]
fn w39_cli_redaction() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let root = must(stract::gen_temp_dir());
    let path = root.as_ref().join("synthetic-private-config");
    for text in [
        "canary = [".to_owned(),
        "x".repeat(1_048_577),
        "[v1.paper_provider]\nkind='openalex'\napi_key='synthetic-canary'".to_owned(),
    ] {
        must(std::fs::write(&path, text));
        cli(&path, "API configuration is invalid");
    }
    let secret = root.as_ref().join("synthetic-secret");
    must(std::fs::write(&secret, [b'a'; 64]));
    let link = root.as_ref().join("synthetic-link");
    must(symlink(&secret, &link));
    for credential in [&secret, &link] {
        let mode = if credential == &link { 0o600 } else { 0o644 };
        must(std::fs::set_permissions(
            &secret,
            std::fs::Permissions::from_mode(mode),
        ));
        let template = include_str!("../../../configs/api.toml");
        let store = root.as_ref().join("serving/suppression.json");
        let text = template.replace(
            "\"data/v1/suppression.json\"",
            &must(serde_json::to_string(&store)),
        );
        let text = format!(
            "{text}\n[v1.paper_provider]\nkind='openalex'\napi_key_file={}\n",
            must(serde_json::to_string(credential))
        );
        must(std::fs::write(&path, text));
        cli(&path, "Paper provider configuration is invalid");
        must(std::fs::set_permissions(
            &secret,
            std::fs::Permissions::from_mode(0o600),
        ));
    }
    let config_link = root.as_ref().join("synthetic-config-link");
    must(symlink(&path, &config_link));
    cli(&config_link, "Paper provider configuration is invalid");
    let help = must(
        Command::new(env!("CARGO_BIN_EXE_stract"))
            .args(["api", "--help"])
            .output(),
    );
    assert!(help.status.success(), "W39 help exit");
    let text = must(std::str::from_utf8(&help.stdout));
    assert!(
        !text.contains("--api-key") && !text.contains("--bearer"),
        "W39 no secret flags"
    );
}

struct External {
    observed: Mutex<Vec<(String, u16, u8)>>,
    invalid_hint: bool,
}

impl PaperProvider for External {
    // Construct through only exported validation APIs, as an embedding application would.
    fn search(&self, query: PaperQuery) -> BoxFuture<'_, Result<PaperPage, PaperProviderError>> {
        must(self.observed.lock()).push((query.query().into(), query.page(), query.num_results()));
        Box::pin(async move {
            let fixture: Value = must(serde_json::from_slice(include_bytes!(
                "fixtures/papers/http-page.json"
            )));
            let hit: AttributedResult = must(serde_json::from_value(fixture["results"][0].clone()));
            PaperPage::try_new(vec![hit], if self.invalid_hint { Some(7) } else { None })
        })
    }
}

// Exercise the actual router rather than calling extension methods as a substitute for serving.
async fn request(app: Router, method: &str, path: &str, body: Value) -> (u16, Value) {
    let bytes = if method == "DELETE" {
        Vec::new()
    } else {
        must(serde_json::to_vec(&body))
    };
    let response = must(
        app.oneshot(must(
            Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(bytes)),
        ))
        .await,
    );
    let status = response.status().as_u16();
    let body = must(to_bytes(response.into_body(), 4_194_304).await);
    (status, must(serde_json::from_slice(&body)))
}

#[tokio::test]
async fn w40_external_provider() {
    for invalid_hint in [false, true] {
        let root = must(stract::gen_temp_dir());
        let provider = Arc::new(External {
            observed: Mutex::new(Vec::new()),
            invalid_hint,
        });
        let installed = provider.clone();
        let config = config(root.as_ref());
        let state = must(
            tokio::task::spawn_blocking(move || {
                let resources = must(V1Resources::load(&config)).with_paper_provider(installed);
                let web: Arc<dyn SearchBackend> =
                    Arc::new(|_: stract::searcher::SearchQuery| async {
                        panic!("W40 web fallback")
                    });
                Arc::new(V1State::from_resources(&config, web, &resources))
            })
            .await,
        );
        let management = v1::compose_management(state.clone());
        let app = v1::compose_api(Router::new(), state);
        let input = json!({"query":"Élodie Cedar","page":2,"num_results":1,"scholarly":true});
        let (status, body) = request(app.clone(), "POST", "/v1/search", input.clone()).await;
        assert!(
            *must(provider.observed.lock()) == vec![("Élodie Cedar".into(), 2, 1)],
            "W40 original request"
        );
        if invalid_hint {
            assert!(
                status == 500
                    && body
                        == json!({"version":"v1", "error":{
                            "code":"invalid_result", "message":"The search result is invalid"
                        }}),
                "W40 bad page"
            );
        } else {
            assert!(
                status == 200 && body["results"].as_array().unwrap().len() == 1,
                "W40 public provider"
            );
            let id = body["results"][0]["id"].as_str().unwrap();
            assert!(
                request(
                    management,
                    "DELETE",
                    &format!("/v1/documents/{id}"),
                    Value::Null
                )
                .await
                .0 == 200,
                "W40 durable suppression"
            );
            let (status, body) = request(app, "POST", "/v1/search", input).await;
            assert!(
                status == 200 && body["results"] == json!([]),
                "W40 final serving rules"
            );
        }
    }
}
