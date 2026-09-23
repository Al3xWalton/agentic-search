//! Exercises management ingest through production composers, durable owners and one real index.
//! Synthetic inputs and runtime credentials remain in private, owned temporary directories.

#[path = "support/ingest.rs"]
mod support;

mod contracts {
    use super::support::*;
    use axum::{
        body::Body,
        http::{HeaderValue, Request},
    };
    use serde_json::{json, Value};
    use std::{
        fs,
        sync::{atomic::Ordering::SeqCst, Arc},
    };
    use stract::api::v1::{
        ingest_dto::*,
        ingest_register::{IngestRegister, IngestSeams, IngestStage},
    };

    #[test]
    fn unauthenticated_ingest_rejects_before_body_and_admission() {
        for cap in [2_097_152, 65_536] {
            let fixture = Fixture::configured(|config| config.v1.ingest_max_body_bytes = cap);
            runtime().block_on(async {
                let before = tree(fixture.root());
                let opens = fixture.hooks.opens.load(SeqCst);
                let calls = fixture.backend.calls.load(SeqCst);
                let (body, polls) = chunks(vec![vec![b' '; 1_048_576]; 3]);
                let mut request = fixture.request("PUT", &path("https://example.com/page"), body);
                request.headers_mut().remove("authorization");
                let response = send(fixture.router(true), request).await;
                assert_eq!(polls.load(SeqCst), 0);
                assert_eq!(fixture.probe.permits(), 0);
                assert_eq!(
                    fixture.probe.counts(),
                    Counts {
                        auth: 1,
                        verifier: 1,
                        ..Counts::default()
                    }
                );
                assert_eq!(fixture.hooks.opens.load(SeqCst), opens);
                assert!(fixture.hooks.stages().is_empty());
                assert_eq!(tree(fixture.root()), before);
                assert_eq!(fixture.backend.calls.load(SeqCst), calls);
                assert_eq!(calls, 0);
                fixed_unauthorised(&response);
                let control = fixture.put(&input("https://example.com/page")).await;
                assert_eq!(fixture.probe.permits(), 1);
                control.success(1);
                fixture.shutdown().await;
            });
        }
    }

    fn fixed_unauthorised(response: &Observed) {
        headers(response);
        assert_eq!(
            response.bytes.as_slice(),
            concat!(
                r#"{"version":"v1","error":{"code":"unauthorised","#,
                r#""message":"The request is not authorised"}}"#
            )
            .as_bytes()
        );
        assert_eq!(response.status, 401);
    }

    #[test]
    fn unauthenticated_stalled_ingest_does_not_occupy_admission() {
        let fixture = Fixture::configured(|config| {
            config.v1.max_concurrent_requests = Some(1);
            config.v1.request_timeout_ms = 10_000;
        });
        runtime().block_on(async {
            let first = StalledIngest::start(&fixture);
            first.started().await;
            let second = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                fixture.put(&input("https://example.com/page")),
            )
            .await;
            let calls = fixture.backend.calls.load(SeqCst);
            let counts = fixture.probe.counts();
            let stages = fixture.hooks.stages();
            let polls = first.polls.load(SeqCst);
            let permits = fixture.probe.permits();
            let rejected = first.finish();
            assert!(second.is_ok(), "control timeout is a failed experiment");
            assert_eq!(calls, 1);
            assert_eq!((counts.read, counts.write, counts.backend), (1, 2, 1));
            assert_eq!(
                stages.iter().filter(|s| **s == IngestStage::Open).count(),
                2
            );
            assert_eq!(polls, 0);
            assert_eq!(permits, 1);
            second.unwrap().success(1);
            fixed_unauthorised(&rejected);
            fixture.shutdown().await;
        });
    }

    async fn refused(
        fixture: &Fixture,
        request: Request<Body>,
        code: &str,
        reason: Option<&str>,
        status: u16,
    ) -> Observed {
        refused_work(fixture, request, code, reason, status, None).await
    }

    async fn refused_work(
        fixture: &Fixture,
        request: Request<Body>,
        code: &str,
        reason: Option<&str>,
        status: u16,
        expected_decode: Option<usize>,
    ) -> Observed {
        fixture.probe.reset();
        fixture.hooks.reset();
        let before = tree(fixture.root());
        let calls = fixture.backend.calls.load(SeqCst);
        let response = send(fixture.router(true), request).await;
        let counts = fixture.probe.counts();
        if code == "unauthorised" {
            assert_eq!(
                (counts.auth, counts.verifier, counts.decode, counts.enter),
                (1, 1, 0, 0),
                "authentication refusal must precede extraction and JSON work"
            );
        }
        if let Some(expected) = expected_decode {
            assert_eq!(
                counts.decode, expected,
                "raw identifier refusal must precede JSON work"
            );
        }
        assert_eq!(
            (counts.read, counts.write, counts.backend),
            (0, 0, 0),
            "admission refusal must precede register/RPC work"
        );
        assert_eq!(fixture.backend.calls.load(SeqCst), calls);
        assert!(fixture.hooks.stages().is_empty());
        assert_eq!(tree(fixture.root()), before);
        response.error(code, reason, status);
        response
    }

    fn request(fixture: &Fixture, input: &Value) -> Request<Body> {
        fixture.request(
            "PUT",
            &path(input["url"].as_str().unwrap()),
            serde_json::to_vec(input).unwrap(),
        )
    }

    #[test]
    fn put_is_management_only_with_zero_public_work() {
        let fixture = Fixture::new();
        runtime().block_on(async {
            let input = input("https://example.com/page");
            let before = tree(fixture.root());
            for authorised in [true, false] {
                let mut request = request(&fixture, &input);
                if !authorised {
                    request.headers_mut().remove("authorization");
                }
                let response = send(fixture.router(false), request).await;
                assert_eq!(fixture.probe.counts(), Counts::default());
                assert_eq!(fixture.backend.calls.load(SeqCst), 0);
                assert_eq!(tree(fixture.root()), before);
                response.error("not_found", None, 404);
            }
            loopback_put(&fixture, false, &input).await;
            let response = fixture.put(&input).await;
            assert_eq!(
                (
                    fixture.probe.counts().write,
                    fixture.backend.calls.load(SeqCst)
                ),
                (2, 1)
            );
            response.success(1);
            loopback_put(&fixture, true, &input).await;
            fixture.shutdown().await;
        });
    }

    async fn loopback_put(fixture: &Fixture, management: bool, value: &Value) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, receiver) = tokio::sync::oneshot::channel::<()>();
        let router = fixture.router(management);
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = receiver.await;
                })
                .await
        });
        let counts = fixture.probe.counts();
        let before = tree(fixture.root());
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .put(format!(
                "http://{address}{}",
                path(value["url"].as_str().unwrap())
            ))
            .bearer_auth(&fixture.token)
            .json(value)
            .send()
            .await
            .unwrap();
        let mut headers = axum::http::HeaderMap::new();
        for (name, value) in response.headers() {
            headers.append(
                axum::http::HeaderName::from_bytes(name.as_str().as_bytes()).unwrap(),
                HeaderValue::from_bytes(value.as_bytes()).unwrap(),
            );
        }
        let observed = Observed {
            status: response.status().as_u16(),
            headers,
            bytes: response.bytes().await.unwrap().to_vec(),
        };
        let _ = stop.send(());
        assert!(server.await.unwrap().is_ok());
        assert_eq!(
            tree(fixture.root()),
            before,
            "public miss or acknowledged replay does no writes"
        );
        if management {
            assert_eq!(fixture.probe.counts().write, counts.write);
            observed.success(1);
        } else {
            assert_eq!(fixture.probe.counts(), counts);
            observed.error("not_found", None, 404);
        }
    }

    #[test]
    fn authentication_precedes_decode_register_and_rpc() {
        let fixture = Fixture::new();
        runtime().block_on(async {
            let known = path("https://example.com/known");
            let deleted = send(
                fixture.router(true),
                fixture.request("DELETE", &known, Body::empty()),
            )
            .await;
            deleted.success_delete();
            for target in [
                &known,
                &path("https://example.com/unseen"),
                "/v1/documents/%61bad",
            ] {
                for token in [
                    None,
                    Some("Bearer malformed".to_owned()),
                    Some(format!("Bearer {}", fixture.token.to_uppercase())),
                    Some(format!("bearer {}", fixture.token)),
                    Some(format!("Bearer {}", digest(b"unrelated runtime input"))),
                ] {
                    let mut req = fixture.request("PUT", target, b"not json".to_vec());
                    req.headers_mut().remove("authorization");
                    if let Some(token) = token {
                        req.headers_mut()
                            .insert("authorization", token.parse().unwrap());
                    }
                    refused(&fixture, req, "unauthorised", None, 401).await;
                    let counts = fixture.probe.counts();
                    assert_eq!(
                        (counts.auth, counts.verifier, counts.decode, counts.enter),
                        (1, 1, 0, 0)
                    );
                }
            }
            let mut duplicate = fixture.request("PUT", &known, b"bad json".to_vec());
            duplicate.headers_mut().append(
                "authorization",
                HeaderValue::from_str(&format!("Bearer {}", fixture.token)).unwrap(),
            );
            refused(&fixture, duplicate, "unauthorised", None, 401).await;
            fixture.probe.fixed_verifiers();
            refused(
                &fixture,
                fixture.request("PUT", &known, b"bad json".to_vec()),
                "invalid_request",
                None,
                400,
            )
            .await;
            assert_eq!(fixture.probe.counts().decode, 1);
        });
    }

    #[test]
    fn disabled_authentication_never_admits_ingest() {
        for invalid in [false, true] {
            let fixture = Fixture::configured(|config| {
                if invalid {
                    fs::write(
                        config.compliance.admin_token_file.as_ref().unwrap(),
                        b"invalid",
                    )
                    .unwrap();
                } else {
                    config.compliance.admin_token_file = None;
                }
            });
            runtime().block_on(async {
                let mut req = request(&fixture, &input("https://example.com/page"));
                req.headers_mut().insert(
                    "authorization",
                    format!("Bearer {}", "0".repeat(64)).parse().unwrap(),
                );
                refused(&fixture, req, "unauthorised", None, 401).await;
                assert_eq!(
                    (fixture.probe.counts().decode, fixture.probe.counts().enter),
                    (0, 0)
                );
            });
        }
        let fixture = Fixture::new();
        runtime().block_on(async {
            fixture
                .put(&input("https://example.com/page"))
                .await
                .success(1);
        });
    }

    #[test]
    fn raw_document_segments_reject_before_decode() {
        let fixture = Fixture::new();
        runtime().block_on(async {
            for raw in [
                "a".repeat(63),
                "a".repeat(65),
                "A".repeat(64),
                "g".repeat(64),
                format!("%61{}", "a".repeat(63)),
                "%2e%2e".into(),
                format!("%2f{}", "a".repeat(63)),
            ] {
                refused_work(
                    &fixture,
                    fixture.request("PUT", &format!("/v1/documents/{raw}"), b"bad".to_vec()),
                    "invalid_document_id",
                    None,
                    400,
                    Some(0),
                )
                .await;
                assert_eq!(
                    fixture.probe.counts().decode,
                    0,
                    "raw identifier precedes JSON"
                );
            }
            refused(
                &fixture,
                fixture.request(
                    "PUT",
                    &format!("{}/extra", path("https://example.com/page")),
                    b"bad".to_vec(),
                ),
                "not_found",
                None,
                404,
            )
            .await;
            fixture
                .put(&input("https://example.com/page"))
                .await
                .success(1);
        });
    }

    #[test]
    fn path_identifier_must_equal_canonical_url() {
        let fixture = Fixture::new();
        runtime().block_on(async {
            let input = input("https://example.com/page");
            refused(
                &fixture,
                fixture.request(
                    "PUT",
                    &path("https://example.com/other"),
                    serde_json::to_vec(&input).unwrap(),
                ),
                "invalid_document_id",
                None,
                400,
            )
            .await;
            let mut alias = input.clone();
            alias["url"] = json!("https://EXAMPLE.com:443/page#fragment");
            let first = fixture.put(&alias).await;
            assert_eq!(fixture.backend.calls.load(SeqCst), 1);
            let response = first.success(1);
            assert_eq!(
                response["document"]["id"],
                digest(b"https://example.com/page")
            );
            assert_ne!(
                path("https://example.com/?a=1&b=2"),
                path("https://example.com/?b=2&a=1")
            );
        });
    }

    #[test]
    fn ingest_json_is_strict_and_attribution_is_required() {
        let fixture = Fixture::new();
        runtime().block_on(async {
            let valid = input("https://example.com/page");
            for field in [
                "url",
                "body",
                "fetch_time_ms",
                "retrieved_at",
                "source",
                "x_robots_tag",
            ] {
                for replacement in [None, Some(Value::Null), Some(json!({"wrong":"type"}))] {
                    let mut bad = valid.clone();
                    if let Some(value) = replacement {
                        bad[field] = value;
                    } else {
                        bad.as_object_mut().unwrap().remove(field);
                    }
                    refused(
                        &fixture,
                        fixture.request(
                            "PUT",
                            &path("https://example.com/page"),
                            serde_json::to_vec(&bad).unwrap(),
                        ),
                        "invalid_request",
                        None,
                        400,
                    )
                    .await;
                }
            }
            for field in ["unknown", "title", "domain", "snippet"] {
                let mut bad = valid.clone();
                bad[field] = json!("caller supplied");
                refused(
                    &fixture,
                    request(&fixture, &bad),
                    "invalid_request",
                    None,
                    400,
                )
                .await;
            }
            let source = serde_json::to_string(&valid).unwrap();
            for body in [
                String::new(),
                "{".into(),
                source.replace("\"source\":", "\"source\":\"duplicate\",\"source\":"),
                source.replace("\"fetch_time_ms\":100", "\"fetch_time_ms\":1.5"),
                source.replace("\"fetch_time_ms\":100", "\"fetch_time_ms\":1e0"),
                source.replace(
                    "\"fetch_time_ms\":100",
                    "\"fetch_time_ms\":18446744073709551616",
                ),
            ] {
                refused(
                    &fixture,
                    fixture.request("PUT", &path("https://example.com/page"), body),
                    "invalid_request",
                    None,
                    400,
                )
                .await;
            }
            for body in ["<html></html>", "<title> \n\t </title>"] {
                let mut bad = valid.clone();
                bad["body"] = json!(body);
                refused(
                    &fixture,
                    request(&fixture, &bad),
                    "not_admitted",
                    Some("empty_title"),
                    400,
                )
                .await;
            }
            fixture.put(&valid).await.success(1);
        });
    }

    #[test]
    fn ingest_bound_table_is_literal_and_enforced() {
        assert_eq!(
            INGEST_BOUNDS,
            [
                (1, 2048),
                (1, 8388608),
                (0, 86400000),
                (0, 253402300799),
                (1, 64),
                (0, 32),
                (1, 1024)
            ]
        );
        for (bound, minimum, maximum) in [
            (IngestBound::Url, 1, 2048),
            (IngestBound::Body, 1, 8388608),
            (IngestBound::FetchTime, 0, 86400000),
            (IngestBound::Timestamp, 0, 253402300799),
            (IngestBound::Source, 1, 64),
            (IngestBound::HeaderCount, 0, 32),
            (IngestBound::HeaderValue, 1, 1024),
        ] {
            assert!(validate_bound(bound, minimum).is_ok());
            assert!(validate_bound(bound, maximum).is_ok());
            assert!(
                validate_bound(bound, minimum - 1).is_err(),
                "below literal range {bound:?}"
            );
            assert!(
                validate_bound(bound, maximum + 1).is_err(),
                "above literal range {bound:?}"
            );
        }
        let mut typed: V1IngestRequest =
            serde_json::from_value(input("https://example.com/page")).unwrap();
        typed.body = "a".repeat(8_388_608);
        assert!(typed.validate().is_ok());
        typed.body.push('a');
        assert!(typed.validate().is_err());
        typed.body = "é".repeat(4_194_305);
        assert!(typed.validate().is_err(), "UTF-8 bytes");
        let fixture = Fixture::new();
        runtime().block_on(async {
            for (field, value) in [
                ("url", json!("x".repeat(2049))),
                ("body", json!("")),
                ("source", json!("a".repeat(65))),
                ("x_robots_tag", json!(vec!["all"; 33])),
                ("x_robots_tag", json!(["x".repeat(1025)])),
                ("fetch_time_ms", json!(86400001)),
                ("retrieved_at", json!(253402300800_i64)),
            ] {
                let mut bad = input("https://example.com/page");
                bad[field] = value;
                refused(
                    &fixture,
                    fixture.request(
                        "PUT",
                        &path("https://example.com/page"),
                        serde_json::to_vec(&bad).unwrap(),
                    ),
                    "invalid_request",
                    None,
                    400,
                )
                .await;
            }
            let url = format!("https://example.com/{}", "a".repeat(2048 - 20));
            assert_eq!(url.len(), 2048);
            let mut exact = input(&url);
            exact["source"] = json!("a".repeat(64));
            exact["fetch_time_ms"] = json!(86400000);
            exact["x_robots_tag"] = json!(vec!["all"; 32]);
            fixture.put(&exact).await.success(1);
            let mut expanded = input("https://example.com/page");
            expanded["url"] = json!(format!("https://example.com/{}", "é".repeat(600)));
            refused(
                &fixture,
                fixture.request(
                    "PUT",
                    &path("https://example.com/page"),
                    serde_json::to_vec(&expanded).unwrap(),
                ),
                "invalid_request",
                None,
                400,
            )
            .await;
        });
    }

    #[test]
    fn source_labels_cannot_inject_control_or_path_text() {
        let fixture = Fixture::new();
        runtime().block_on(async {
            for label in [
                " a", "a\n", "a/b", "a\"b", "a\0", ".a", "_a", "-a", "A", "é",
            ] {
                let mut bad = input("https://example.com/page");
                bad["source"] = json!(label);
                refused(
                    &fixture,
                    request(&fixture, &bad),
                    "invalid_request",
                    None,
                    400,
                )
                .await;
            }
            let mut valid = input("https://example.com/page");
            valid["source"] = json!("a1._-");
            fixture.put(&valid).await.success(1);
        });
    }

    #[test]
    fn retrieval_time_cannot_be_future_or_renewed() {
        let fixture = Fixture::new();
        runtime().block_on(async {
            let mut valid = input("https://example.com/page");
            valid["retrieved_at"] = json!(1_790_000_000_i64);
            let first = fixture.put(&valid).await;
            let stored = fixture.snapshot();
            let before = tree(fixture.root());
            first.success(1);
            fixture.clock.advance(1_000).unwrap();
            valid["retrieved_at"] = json!(1_790_000_002_i64);
            refused(
                &fixture,
                request(&fixture, &valid),
                "invalid_request",
                None,
                400,
            )
            .await;
            valid["retrieved_at"] = json!(0);
            valid["source"] = json!("changed");
            valid["fetch_time_ms"] = json!(0);
            let replay = fixture.put(&valid).await;
            assert_eq!(fixture.snapshot(), stored);
            assert_eq!(tree(fixture.root()), before);
            assert_eq!(fixture.backend.calls.load(SeqCst), 1);
            assert_eq!(replay.bytes, first.bytes);
            replay.success(1);
            valid["retrieved_at"] = json!(-1);
            refused(
                &fixture,
                request(&fixture, &valid),
                "invalid_request",
                None,
                400,
            )
            .await;
        });
    }

    #[test]
    fn chunked_ingest_limit_fires_before_decode() {
        for cap in [65_536, 2_097_152, 8_388_608] {
            let fixture = Fixture::configured(|config| config.v1.ingest_max_body_bytes = cap);
            runtime().block_on(async {
                let valid = input("https://example.com/page");
                let bytes = wire(&valid, cap);
                let (body, polls) = chunks(vec![bytes[..32768].into(), bytes[32768..].into()]);
                let response = send(
                    fixture.router(true),
                    fixture.request("PUT", &path("https://example.com/page"), body),
                )
                .await;
                assert_eq!(polls.load(SeqCst), 2);
                assert_eq!(fixture.backend.calls.load(SeqCst), 1);
                response.success(1);
                for length in [None, Some("1"), Some("99999999")] {
                    fixture.probe.reset();
                    let before = tree(fixture.root());
                    let bytes = wire(&valid, cap + 1);
                    let (body, polls) = chunks(vec![
                        bytes[..32768].into(),
                        bytes[32768..].into(),
                        vec![b'!'],
                    ]);
                    let mut req = fixture.request("PUT", &path("https://example.com/page"), body);
                    if let Some(length) = length {
                        req.headers_mut()
                            .insert("content-length", length.parse().unwrap());
                    }
                    let response = send(fixture.router(true), req).await;
                    assert_eq!(
                        polls.load(SeqCst),
                        if length == Some("99999999") { 0 } else { 2 },
                        "selected cap rejects without polling a sentinel"
                    );
                    assert_eq!(
                        fixture.probe.counts(),
                        Counts {
                            auth: 1,
                            verifier: 1,
                            ..Counts::default()
                        }
                    );
                    assert_eq!(tree(fixture.root()), before);
                    assert_eq!(fixture.backend.calls.load(SeqCst), 1);
                    response.error("request_too_large", None, 413);
                }
            });
        }
    }

    #[test]
    fn other_routes_keep_the_64k_transport_contract() {
        let fixture = Fixture::new();
        runtime().block_on(async {
            let document = path("https://example.com/page");
            let operations = prior_operations(&document);
            for management in [false, true] {
                for (method, path) in &operations {
                    let (body, polls) =
                        chunks(vec![vec![b' '; 32768], vec![b' '; 32769], vec![b'!']]);
                    let before = tree(fixture.root());
                    fixture.probe.reset();
                    let response = send(
                        fixture.router(management),
                        fixture.request(method, path, body),
                    )
                    .await;
                    assert_eq!(polls.load(SeqCst), 2, "{method} {path}");
                    assert_eq!(fixture.probe.counts(), Counts::default());
                    assert_eq!(tree(fixture.root()), before);
                    response.error("request_too_large", None, 413);
                }
            }
            let (body, polls) = chunks(vec![vec![b' '; 32768], vec![b' '; 32769], vec![b'!']]);
            let response = send(
                fixture.router(false),
                fixture.request("PUT", &document, body),
            )
            .await;
            assert_eq!(polls.load(SeqCst), 2);
            assert_eq!(fixture.probe.counts(), Counts::default());
            response.error("request_too_large", None, 413);
            let response = send(
                fixture.router(false),
                fixture.request(
                    "POST",
                    "/v1/search",
                    wire(&json!({"query":"orchard"}), 65_536),
                ),
            )
            .await;
            headers(&response);
            assert_eq!(response.status, 200);
            let response = send(
                fixture.router(true),
                fixture.request(
                    "PUT",
                    &document,
                    wire(&input("https://example.com/page"), 65_537),
                ),
            )
            .await;
            assert_eq!(fixture.backend.calls.load(SeqCst), 1);
            response.success(1);
        });
    }

    fn prior_operations(document: &str) -> Vec<(&str, String)> {
        let mut operations = vec![
            ("POST", "/v1/search".into()),
            ("GET", "/v1/source".into()),
            ("GET", "/v1/statement".into()),
            ("DELETE", document.into()),
            ("GET", "/v1/reports".into()),
            ("GET", "/v1/reports/status/fixture".into()),
            ("POST", "/v1/compliance/queue".into()),
            ("PUT", "/v1/missing".into()),
            ("GET", "/v1/missing".into()),
            ("POST", document.into()),
        ];
        for route in [
            "illegal-content",
            "harmful-to-children",
            "intimate-images",
            "site-complaints",
            "rights-removal",
            "data-rights",
            "data-protection-complaints",
            "online-safety-complaints",
        ] {
            operations.push(("POST", format!("/v1/reports/{route}")));
        }
        for route in [
            "read",
            "identity",
            "extension",
            "decision",
            "appeal",
            "reversal",
            "uphold",
            "progress",
            "close",
            "purge",
        ] {
            operations.push(("POST", format!("/v1/compliance/tickets/fixture/{route}")));
        }
        operations
    }

    #[test]
    fn indexer_admission_rejects_invalid_noindex_and_title() {
        let fixture = Fixture::new();
        runtime().block_on(async {
            let credential_url = format!("https://{}:{}@example.com/page", "synthetic", "invalid");
            for url in [
                "ftp://example.com/page",
                credential_url.as_str(),
                "https:///",
                "https://example.com/a\\b",
                "https://example.com/a\nb",
            ] {
                let mut bad = input("https://example.com/page");
                bad["url"] = json!(url);
                refused(
                    &fixture,
                    fixture.request(
                        "PUT",
                        &path("https://example.com/page"),
                        serde_json::to_vec(&bad).unwrap(),
                    ),
                    "not_admitted",
                    Some("invalid_url"),
                    400,
                )
                .await;
            }
            for directive in ["noindex", "none", "unavailable_after: invalid"] {
                let mut bad = input("https://example.com/page");
                bad["body"] = json!(format!(
                    "<title>Valid title</title><meta name=robots content='{directive}'>"
                ));
                let page = stract::entrypoint::indexer::IndexableWebpage {
                    record: None,
                    url: bad["url"].as_str().unwrap().into(),
                    body: bad["body"].as_str().unwrap().into(),
                    fetch_time_ms: 0,
                };
                assert_eq!(
                    stract::entrypoint::indexer::IndexingWorker::audit_page(&page).err(),
                    Some("noindex")
                );
                refused(
                    &fixture,
                    request(&fixture, &bad),
                    "not_admitted",
                    Some("noindex"),
                    400,
                )
                .await;
            }
            let mut allowed = input("https://example.com/page");
            allowed["body"] =
                json!("<title>Valid title</title><meta name=otherbot content=noindex>");
            fixture.put(&allowed).await.success(1);
        });
    }

    #[test]
    fn physical_robot_headers_use_the_crawler_parser() {
        let fixture = Fixture::new();
        runtime().block_on(async {
            for values in [
                vec!["noindex"],
                vec!["otherbot: all", "noindex"],
                vec!["*: none"],
                vec!["AVASearchBot: NOINDEX"],
                vec!["none"],
                vec!["noindex\r\n"],
                vec!["é"],
                vec!["unavailable_after: invalid"],
                vec!["unavailable_after: 01 Jan 2020 00:00:00 GMT"],
                vec!["unavailable_after: 01 Jan 2099 00:00:00 GMT"],
                vec!["nosnippet"],
                vec!["max-snippet: 100"],
            ] {
                let mut bad = input("https://example.com/page");
                bad["x_robots_tag"] = json!(values);
                refused(
                    &fixture,
                    request(&fixture, &bad),
                    "not_admitted",
                    Some("header_directive"),
                    400,
                )
                .await;
            }
            let mut excessive = input("https://example.com/page");
            excessive["x_robots_tag"] = json!(vec!["all,".repeat(200); 2]);
            refused(
                &fixture,
                request(&fixture, &excessive),
                "not_admitted",
                Some("header_directive"),
                400,
            )
            .await;
            for (index, values) in [
                vec!["otherbot: noindex"],
                vec!["nofollow, noarchive, noimageindex"],
                vec!["max-snippet: -1"],
                vec!["otherbot: noindex", "all"],
            ]
            .into_iter()
            .enumerate()
            {
                let mut allowed = input(&format!("https://example.com/allowed{index}"));
                allowed["x_robots_tag"] = json!(values);
                fixture.put(&allowed).await.success(1);
            }
        });
    }

    #[test]
    fn normalization_cannot_change_the_served_identifier() {
        let fixture = Fixture::new();
        runtime().block_on(async {
            for query in [
                "?utm_source=fixture",
                "?",
                "?q=a%20b",
                "?q=a/b",
                "?t=10:00",
                "?ids=1,2",
                "?u=~x",
                "?flag",
                "?a=b&",
                "?x=%2f",
                "?x=%41",
            ] {
                let value = input(&format!("https://example.com/page{query}"));
                refused(
                    &fixture,
                    request(&fixture, &value),
                    "not_admitted",
                    Some("invalid_url"),
                    400,
                )
                .await;
            }
            for query in ["?a=1&b=2", "?q=a+b", "?q=a%2Fb", "?q=caf%C3%A9", "?a="] {
                let url = format!("https://example.com/page{query}");
                let response = fixture.put(&input(&url)).await;
                assert_eq!(
                    fixture.snapshot()["entries"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|entry| entry["canonical_url"] == url)
                        .unwrap()["id"],
                    digest(url.as_bytes())
                );
                response.success(1);
            }
            for url in ["http://localhost/page", "http://singlelabel/page"] {
                refused(
                    &fixture,
                    request(&fixture, &input(url)),
                    "not_admitted",
                    Some("invalid_url"),
                    400,
                )
                .await;
            }
        });
    }

    #[test]
    fn response_attribution_is_derived_without_content_retention() {
        let fixture = Fixture::new();
        runtime().block_on(async {
            let mut valid = input("https://example.com/page");
            valid["body"] = json!(concat!(
                "<title>Attribution &quot;quoted&quot; canary</title>",
                "<main>PrivateBodyCanary material</main>"
            ));
            valid["x_robots_tag"] = json!(["otherbot: PrivateHeaderCanary"]);
            let response = fixture.put(&valid).await;
            assert_metadata_absent(
                fixture.root(),
                &["PrivateBodyCanary", "PrivateHeaderCanary", "Attribution"],
            );
            let snapshot = fixture.snapshot();
            assert_eq!(snapshot["entries"][0]["source"], "engine.fetch");
            assert_eq!(
                snapshot["entries"][0]["body_sha256"],
                digest(valid["body"].as_str().unwrap().as_bytes())
            );
            let value = response.success(1);
            assert_eq!(value["document"]["domain"], "example.com");
            assert_eq!(value["document"]["title"], "Attribution \"quoted\" canary");
            assert_eq!(value["document"]["accepted_at"], 1_790_000_000_i64);
        });
    }

    fn assert_metadata_absent(root: &std::path::Path, canaries: &[&str]) {
        for entry in fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                assert_metadata_absent(&path, canaries);
            } else {
                let bytes = fs::read(path).unwrap();
                for canary in canaries {
                    assert!(
                        !bytes
                            .windows(canary.len())
                            .any(|part| part == canary.as_bytes()),
                        "private input persisted in API metadata"
                    );
                }
            }
        }
    }

    #[test]
    fn identical_html_replays_without_write_or_rpc() {
        let fixture = Fixture::new();
        runtime().block_on(async {
            let mut value = input("https://example.com/page");
            let first = fixture.put(&value).await;
            assert_eq!(
                (
                    fixture.probe.counts().write,
                    fixture.backend.calls.load(SeqCst)
                ),
                (2, 1)
            );
            first.success(1);
            let before = tree(fixture.root());
            fixture.clock.advance(1_000).unwrap();
            value["source"] = json!("retry.other");
            value["fetch_time_ms"] = json!(1);
            fixture.probe.reset();
            fixture.hooks.reset();
            let bytes = serde_json::to_string_pretty(&value)
                .unwrap()
                .replace('<', "\\u003c");
            let replay = send(
                fixture.router(true),
                fixture.request("PUT", &path(value["url"].as_str().unwrap()), bytes),
            )
            .await;
            assert_eq!(
                (
                    fixture.probe.counts().write,
                    fixture.backend.calls.load(SeqCst)
                ),
                (0, 1)
            );
            assert!(fixture.hooks.stages().is_empty());
            assert_eq!(
                tree(fixture.root()),
                before,
                "replay must not renew or rewrite metadata"
            );
            headers(&replay);
            assert_eq!(
                replay.bytes, first.bytes,
                "replay must retain the original receipt"
            );
            assert_eq!(replay.status, 200);
            value["body"] = json!(format!("{} changed", value["body"].as_str().unwrap()));
            fixture.put(&value).await.success(2);
            assert_eq!(fixture.backend.calls.load(SeqCst), 2);
        });
    }

    #[test]
    fn changed_html_advances_one_current_register_version() {
        let fixture = Fixture::new();
        runtime().block_on(async {
            let mut value = input("https://example.com/page");
            for version in 1..=3 {
                value["body"] = json!(format!(
                    "<title>Version {version}</title><p>Orchard produce {version}</p>"
                ));
                fixture.probe.reset();
                fixture.hooks.reset();
                let response = fixture.put(&value).await;
                let snapshot = fixture.snapshot();
                assert_eq!(snapshot["entries"].as_array().map(Vec::len), Some(1));
                assert_eq!(
                    snapshot["entries"][0]["body_sha256"],
                    digest(value["body"].as_str().unwrap().as_bytes())
                );
                assert_eq!(snapshot["entries"][0]["version"], version);
                assert_eq!(
                    snapshot["entries"][0]["id"],
                    digest(b"https://example.com/page")
                );
                assert_eq!(
                    (fixture.probe.counts().write, fixture.probe.counts().backend),
                    (2, 1)
                );
                response.success(version);
                if version == 2 {
                    let before = tree(fixture.root());
                    fixture.probe.reset();
                    let replay = fixture.put(&value).await;
                    assert_eq!(fixture.probe.counts().write, 0);
                    assert_eq!(tree(fixture.root()), before);
                    assert_eq!(replay.bytes, response.bytes);
                }
            }
            fixture.shutdown().await;
        });
        let fixture = fixture.reopen_after(|root| {
            let path = root.join("suppression.json.ingest/snapshot.json");
            let mut snapshot: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            snapshot["entries"][0]["version"] = json!(u64::MAX);
            fs::write(path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        });
        runtime().block_on(async {
            let before = tree(fixture.root());
            let response = fixture.put(&input("https://example.com/page")).await;
            assert_eq!(
                (
                    fixture.probe.counts().write,
                    fixture.backend.calls.load(SeqCst)
                ),
                (0, 0)
            );
            assert_eq!(tree(fixture.root()), before);
            response.error("ingest_capacity", None, 503);
        });
    }

    #[test]
    fn concurrent_identical_puts_dispatch_once() {
        for identical in [true, false] {
            let fixture = Fixture::new();
            runtime().block_on(async {
                let first = input("https://example.com/page");
                let mut second = first.clone();
                if !identical {
                    second["body"] = json!("<title>Second</title><p>Other body</p>");
                }
                let barrier = fixture.backend.pause();
                let pending = tokio::spawn(send(fixture.router(true), request(&fixture, &first)));
                barrier.reached().await;
                let next = tokio::spawn(send(fixture.router(true), request(&fixture, &second)));
                tokio::task::yield_now().await;
                assert_eq!(fixture.backend.calls.load(SeqCst), 1);
                assert_eq!(fixture.snapshot()["entries"][0]["delivery"], "recorded");
                drop(barrier);
                let (first, second) = (pending.await.unwrap(), next.await.unwrap());
                assert_eq!(
                    fixture.backend.calls.load(SeqCst),
                    if identical { 1 } else { 2 }
                );
                assert_eq!(fixture.probe.counts().write, if identical { 2 } else { 4 });
                assert_eq!(
                    fixture.snapshot()["entries"][0]["version"],
                    if identical { 1 } else { 2 }
                );
                first.success(1);
                second.success(if identical { 1 } else { 2 });
                if identical {
                    assert_eq!(first.bytes, second.bytes);
                }
                let a_input = input("https://example.com/a");
                let b_input = input("https://example.com/b");
                let (a, b) = tokio::join!(fixture.put(&a_input), fixture.put(&b_input));
                a.success(1);
                b.success(1);
            });
        }
    }

    async fn search(fixture: &Fixture) -> Observed {
        send(
            fixture.router(false),
            fixture.request(
                "POST",
                "/v1/search",
                serde_json::to_vec(&json!({"query":"orchard"})).unwrap(),
            ),
        )
        .await
    }

    fn result_ids(response: &Observed) -> Vec<String> {
        response.value()["results"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| row["id"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn ingest_search_replace_delete_uses_one_real_index() {
        let mut fixture = Fixture::new();
        runtime().block_on(async {
            let backend = fixture.real_index().await;
            let mut a = input("https://example.com/a");
            let b = input("https://example.com/b");
            fixture.put(&a).await.success(1);
            fixture.put(&b).await.success(1);
            let first = search(&fixture).await;
            assert_eq!(result_ids(&first).len(), 2);
            headers(&first);
            assert_eq!(first.status, 200);
            a["body"] = json!(concat!(
                "<title>Changed orchard</title>",
                "<p>Orchard apples grow in a second harvest of trees.</p>"
            ));
            fixture.put(&a).await.success(2);
            let raw = backend
                .search(&stract::searcher::SearchQuery {
                    query: "orchard".into(),
                    num_results: 20,
                    ..Default::default()
                })
                .await
                .unwrap();
            let stract::searcher::SearchResult::Websites(raw) = raw else {
                panic!("website fixture")
            };
            assert_eq!(
                raw.webpages
                    .iter()
                    .filter(|page| page.url == "https://example.com/a")
                    .count(),
                2,
                "the same physical index must contain both accepted versions"
            );
            fixture.probe.reset();
            let collapsed = search(&fixture).await;
            assert_eq!(fixture.probe.counts().construct, 2);
            let ids = result_ids(&collapsed);
            assert_eq!(
                ids.iter()
                    .filter(|id| **id == digest(b"https://example.com/a"))
                    .count(),
                1
            );
            assert!(ids.contains(&digest(b"https://example.com/b")));
            let expected = raw
                .webpages
                .iter()
                .map(|page| digest(page.url.as_bytes()))
                .fold(Vec::new(), |mut ids, id| {
                    if !ids.contains(&id) {
                        ids.push(id);
                    }
                    ids
                });
            assert_eq!(ids, expected);
            headers(&collapsed);
            assert_eq!(collapsed.status, 200);
            send(
                fixture.router(true),
                fixture.request("DELETE", &path("https://example.com/a"), Body::empty()),
            )
            .await
            .success_delete();
            fixture.probe.reset();
            let hidden = search(&fixture).await;
            assert_eq!(fixture.probe.counts().construct, 1);
            assert_eq!(result_ids(&hidden), [digest(b"https://example.com/b")]);
            headers(&hidden);
            assert_eq!(hidden.status, 200);
        });
    }

    #[test]
    fn put_after_delete_is_accepted_and_remains_hidden() {
        let mut fixture = Fixture::new();
        runtime().block_on(async {
            fixture.real_index().await;
            let mut a = input("https://example.com/a");
            send(
                fixture.router(true),
                fixture.request("DELETE", &path("https://example.com/a"), Body::empty()),
            )
            .await
            .success_delete();
            let suppressed = fs::read(&fixture.config.v1.suppression_store_path).unwrap();
            fixture.probe.reset();
            let first = fixture.put(&a).await;
            let replay = fixture.put(&a).await;
            assert_eq!(
                (
                    fixture.probe.counts().write,
                    fixture.backend.calls.load(SeqCst)
                ),
                (2, 1)
            );
            assert_eq!(first.bytes, replay.bytes);
            first.success(1);
            replay.success(1);
            a["body"] = json!("<title>Replacement</title><p>Orchard remains suppressed</p>");
            fixture.put(&a).await.success(2);
            fixture
                .put(&input("https://example.com/b"))
                .await
                .success(1);
            fixture.probe.reset();
            let found = search(&fixture).await;
            assert_eq!(fixture.probe.counts().construct, 1);
            assert_eq!(
                fs::read(&fixture.config.v1.suppression_store_path).unwrap(),
                suppressed
            );
            assert_eq!(result_ids(&found), [digest(b"https://example.com/b")]);
            headers(&found);
            assert_eq!(found.status, 200);
        });
    }

    #[test]
    fn record_is_durable_before_backend_entry() {
        let fixture = Fixture::new();
        runtime().block_on(async {
            let value = input("https://example.com/page");
            let response = fixture.put(&value).await;
            let observed = fixture.backend.observed.lock().unwrap();
            assert_eq!(observed.len(), 1);
            assert_eq!(
                observed[0]["entries"][0]["delivery"], "recorded",
                "backend entry requires the authoritative recorded snapshot"
            );
            assert_eq!(observed[0]["entries"][0]["version"], 1);
            assert_eq!(
                observed[0]["entries"][0]["body_sha256"],
                digest(value["body"].as_str().unwrap().as_bytes())
            );
            let stages = fixture.hooks.stages();
            assert_eq!(
                &stages[..6],
                &[
                    IngestStage::Open,
                    IngestStage::Write,
                    IngestStage::SyncFile,
                    IngestStage::Rename,
                    IngestStage::SyncDirectory,
                    IngestStage::BeforeDispatch
                ]
            );
            assert_eq!(fixture.snapshot()["entries"][0]["delivery"], "acknowledged");
            response.success(1);
        });
        for stage in [IngestStage::Write, IngestStage::SyncFile] {
            let fixture = Fixture::new();
            fixture.hooks.fail(stage, 1);
            runtime().block_on(async {
                let before = tree(fixture.root());
                let response = fixture.put(&input("https://example.com/page")).await;
                assert_eq!(fixture.backend.calls.load(SeqCst), 0);
                assert_eq!(tree(fixture.root()), before);
                response.error("ingest_unavailable", None, 503);
            });
        }
    }

    #[test]
    fn unacknowledged_versions_never_replay_as_success() {
        for mode in [Mode::Failure, Mode::Panic, Mode::Pending] {
            let fixture = Fixture::configured(|config| config.v1.request_timeout_ms = 100);
            fixture.backend.mode(mode);
            runtime().block_on(async {
                let value = input("https://example.com/page");
                let first = fixture.put(&value).await;
                assert_eq!(fixture.snapshot()["entries"][0]["delivery"], "recorded");
                assert_eq!(fixture.probe.counts().write, 1);
                if matches!(mode, Mode::Pending) {
                    assert!([503, 504].contains(&first.status));
                } else {
                    first.error("ingest_unavailable", None, 503);
                }
                fixture
                    .state
                    .ingest_register()
                    .sweep_expired()
                    .await
                    .unwrap();
                fixture.probe.reset();
                fixture.hooks.reset();
                let retry = fixture.put(&value).await;
                assert_eq!(
                    fixture.backend.calls.load(SeqCst),
                    2,
                    "recorded retry must dispatch once"
                );
                assert_eq!(
                    fixture.probe.counts().write,
                    0,
                    "retry must reuse durable recorded metadata"
                );
                assert_eq!(fixture.snapshot()["entries"][0]["version"], 1);
                if matches!(mode, Mode::Pending) {
                    assert!([503, 504].contains(&retry.status));
                } else {
                    retry.error("ingest_unavailable", None, 503);
                }
                fixture.shutdown().await;
            });
            let fixture = fixture.reopen();
            fixture.backend.mode(Mode::Success);
            runtime().block_on(async {
                let mut value = input("https://example.com/page");
                value["source"] = json!("retry.changed");
                value["fetch_time_ms"] = json!(200);
                value["retrieved_at"] = json!(1_789_999_998_i64);
                let mut expected = fixture.snapshot()["entries"][0].clone();
                expected["delivery"] = json!("acknowledged");
                let retry = fixture.put(&value).await;
                assert_eq!(
                    fixture.backend.fetch_times.lock().unwrap().last().copied(),
                    Some(100),
                    "recorded retry must retain the stored fetch duration in its RPC payload"
                );
                assert_eq!(
                    (
                        fixture.probe.counts().write,
                        fixture.backend.calls.load(SeqCst)
                    ),
                    (1, 1)
                );
                assert_eq!(fixture.snapshot()["entries"][0], expected);
                retry.success(1);
                fixture.probe.reset();
                let replay = fixture.put(&value).await;
                assert_eq!(
                    (
                        fixture.probe.counts().write,
                        fixture.backend.calls.load(SeqCst)
                    ),
                    (0, 1)
                );
                assert_eq!(replay.bytes, retry.bytes);
                replay.success(1);
            });
        }
        completion_failure_retry();
    }

    fn completion_failure_retry() {
        let fixture = Fixture::new();
        fixture.hooks.fail(IngestStage::Write, 2);
        runtime().block_on(async {
            let response = fixture.put(&input("https://example.com/page")).await;
            assert_eq!(fixture.backend.calls.load(SeqCst), 1);
            assert_eq!(fixture.snapshot()["entries"][0]["delivery"], "recorded");
            response.error("ingest_unavailable", None, 503);
            let stored = fixture.snapshot()["entries"][0].clone();
            fixture.hooks.reset();
            fixture.probe.reset();
            let retry = fixture.put(&input("https://example.com/page")).await;
            assert_eq!(fixture.backend.calls.load(SeqCst), 2);
            assert_eq!(
                (
                    fixture.probe.counts().read,
                    fixture.probe.counts().backend,
                    fixture.probe.counts().write
                ),
                (1, 1, 1)
            );
            let mut expected = stored.clone();
            expected["delivery"] = json!("acknowledged");
            assert_eq!(fixture.snapshot()["entries"][0], expected);
            headers(&retry);
            assert_eq!(
                retry.value()["document"]["accepted_at"],
                stored["received_at"]
            );
            retry.success(1);
            fixture.shutdown().await;
        });
    }

    #[test]
    fn register_restarts_with_the_same_successful_receipt() {
        let fixture = Fixture::new();
        let value = input("https://example.com/page");
        let first = runtime().block_on(async {
            let first = fixture.put(&value).await;
            assert_eq!(fixture.snapshot()["format_version"], 1);
            fixture.shutdown().await;
            first
        });
        let fixture = fixture.reopen();
        runtime().block_on(async {
            let before = tree(fixture.root());
            let replay = fixture.put(&value).await;
            assert_eq!(
                (
                    fixture.probe.counts().write,
                    fixture.backend.calls.load(SeqCst)
                ),
                (0, 0)
            );
            assert_eq!(tree(fixture.root()), before);
            headers(&replay);
            assert_eq!(replay.bytes, first.bytes);
            replay.success(1);
            let mut changed = value;
            changed["body"] = json!("<title>Changed</title><p>Different</p>");
            fixture.put(&changed).await.success(2);
        });
    }

    fn listed_fixture() -> Fixture {
        Fixture::configured(|config| {
            use std::os::unix::fs::PermissionsExt;
            let path = config
                .v1
                .suppression_store_path
                .with_file_name("listed.json");
            let mut hosts = [
                "listed.example.test",
                "xn--bcher-kva.example",
                "parent.example.test",
            ]
            .map(|host| digest(host.as_bytes()));
            hosts.sort();
            fs::write(
                &path,
                serde_json::to_vec(&json!({"format_version":1,"version":"synthetic.1",
                "url_hashes":[digest(b"https://exact.example.test/page")],"host_hashes":hosts}))
                .unwrap(),
            )
            .unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            config.compliance.listed_hashes_file = Some(path);
        })
    }

    async fn global_exclusion(fixture: &Fixture, url: &str) -> Observed {
        let report = json!({"urls":[url],"suspected_illegality":"Synthetic evidence",
            "report":{"contact":{"method":"email","address":"synthetic@example.test"},
            "description":"Synthetic private narrative","requester_type":"affected_person",
            "nonessential_opt_out":true}});
        let admitted = send(
            fixture.router(false),
            fixture.request(
                "POST",
                "/v1/reports/illegal-content",
                serde_json::to_vec(&report).unwrap(),
            ),
        )
        .await;
        assert_eq!(admitted.status, 200);
        let id = admitted.value()["ticket_id"].as_str().unwrap().to_owned();
        send(
            fixture.router(true),
            fixture.request(
                "POST",
                &format!("/v1/compliance/tickets/{id}/decision"),
                serde_json::to_vec(&json!({"actor":"reviewer","decision":{"kind":"granted",
                "reasons":"Synthetic grant","delivery":{"channel":"manual_api",
                "reference":"synthetic-communication"}}}))
                .unwrap(),
            ),
        )
        .await
    }

    #[test]
    fn listed_url_and_host_have_one_excluded_response() {
        let fixture = listed_fixture();
        runtime().block_on(async {
            let mut expected = None;
            for url in [
                "https://exact.example.test/page",
                "https://listed.example.test/page",
                "https://one.two.parent.example.test/page",
                "https://listed.example.test./page",
                "https://bücher.example/page",
            ] {
                let response = refused(
                    &fixture,
                    request(&fixture, &input(url)),
                    "not_admitted",
                    Some("excluded"),
                    400,
                )
                .await;
                if let Some(bytes) = &expected {
                    assert_eq!(&response.bytes, bytes);
                } else {
                    expected = Some(response.bytes);
                }
            }
            for url in [
                "https://badlisted.example.test/page",
                "https://unlisted.example.test/page",
            ] {
                fixture.put(&input(url)).await.success(1);
            }
            let current = "https://current.example.test/page";
            fixture.put(&input(current)).await.success(1);
            let decision = global_exclusion(&fixture, current).await;
            headers(&decision);
            assert_eq!(decision.status, 200);
            let response = refused(
                &fixture,
                request(&fixture, &input(current)),
                "not_admitted",
                Some("excluded"),
                400,
            )
            .await;
            assert_eq!(Some(response.bytes), expected);
        });
        let fixture = Fixture::new();
        runtime().block_on(async {
            fixture.hooks.rules_fail.store(true, SeqCst);
            global_exclusion(&fixture, "https://current.example.test/page")
                .await
                .error("rules_unavailable", None, 503);
            refused(
                &fixture,
                request(&fixture, &input("https://example.com/page")),
                "rules_unavailable",
                None,
                503,
            )
            .await;
        });
    }

    #[test]
    fn register_faults_fail_closed_after_uncertain_rename() {
        for stage in [
            IngestStage::Open,
            IngestStage::Write,
            IngestStage::SyncFile,
            IngestStage::Rename,
            IngestStage::SyncDirectory,
        ] {
            for occurrence in [1, 2] {
                register_fault(stage, occurrence);
            }
        }
    }

    fn register_fault(stage: IngestStage, occurrence: usize) {
        let fixture = Fixture::new();
        let value = input("https://example.com/page");
        runtime().block_on(async {
            fixture.put(&value).await.success(1);
            let before = fixture.snapshot();
            fixture.probe.reset();
            fixture.hooks.fail(stage, occurrence);
            let mut changed = value.clone();
            changed["body"] = json!("<title>Changed</title><p>Second</p>");
            let failed = fixture.put(&changed).await;
            assert_eq!(
                fixture.backend.calls.load(SeqCst),
                if occurrence == 1 { 1 } else { 2 },
                "a failed recorded publication must never dispatch"
            );
            if occurrence == 1 && stage != IngestStage::SyncDirectory {
                assert_eq!(
                    fixture.snapshot(),
                    before,
                    "failed pre-rename write must not publish"
                );
            } else {
                assert_eq!(fixture.snapshot()["entries"][0]["version"], 2);
                assert_eq!(
                    fixture.snapshot()["entries"][0]["delivery"],
                    if occurrence == 2 && stage == IngestStage::SyncDirectory {
                        "acknowledged"
                    } else {
                        "recorded"
                    }
                );
            }
            failed.error("ingest_unavailable", None, 503);
            fixture.hooks.reset();
            fixture.probe.reset();
            if stage == IngestStage::SyncDirectory {
                let before = tree(fixture.root());
                for candidate in [&value, &changed] {
                    let refused = fixture.put(candidate).await;
                    assert_eq!(
                        (fixture.probe.counts().write, fixture.probe.counts().backend),
                        (0, 0),
                        "uncertain rename must close later puts including replays"
                    );
                    assert_eq!(tree(fixture.root()), before);
                    refused.error("ingest_unavailable", None, 503);
                }
            }
            let search = search(&fixture).await;
            headers(&search);
            assert_eq!(search.status, 200);
            send(
                fixture.router(true),
                fixture.request("DELETE", &path("https://example.com/other"), Body::empty()),
            )
            .await
            .success_delete();
            fixture.shutdown().await;
        });
        let fixture = fixture.reopen();
        runtime().block_on(async {
            fixture
                .put(&input("https://example.com/fresh"))
                .await
                .success(1);
        });
    }

    #[test]
    fn register_owner_survives_tasks_and_unlocks_before_child_exec() {
        use std::os::unix::fs::PermissionsExt;
        for _ in 0..20 {
            let directory = stract::gen_temp_dir().unwrap();
            let root = directory.as_ref().join("private");
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let suppression = root.join("suppression.json");
            let owner = IngestRegister::open(&suppression, IngestSeams::default()).unwrap();
            let second = IngestRegister::open(&suppression, IngestSeams::default());
            assert!(
                second.is_err(),
                "a second register owner must fail while the first owns its lock"
            );
            drop(second);
            assert!(
                IngestRegister::open(&suppression, IngestSeams::default()).is_err(),
                "failed acquisition must not release the first owner's lock"
            );
            let child = PausedChild::start().unwrap();
            drop(owner);
            let reopened = IngestRegister::open(&suppression, IngestSeams::default());
            assert!(
                reopened.is_ok(),
                "paused pre-exec child must not extend ownership"
            );
            assert!(child.finish().unwrap().success());
        }
        timed_out_owner(IngestStage::Write);
    }

    fn timed_out_owner(stage: IngestStage) {
        let fixture = Fixture::configured(|config| {
            config.v1.request_timeout_ms = 25;
            config.v1.max_concurrent_requests = Some(1);
        });
        runtime().block_on(async {
            let barrier = fixture.hooks.pause(stage, 1);
            let pending = tokio::spawn(send(
                fixture.router(true),
                request(&fixture, &input("https://example.com/page")),
            ));
            barrier.reached().await;
            let timed_out = pending.await.unwrap();
            assert_eq!(fixture.backend.calls.load(SeqCst), 0);
            timed_out.error("request_timeout", None, 504);
            let seams = IngestSeams {
                clock: fixture.clock.clone(),
                ..Default::default()
            };
            assert!(
                IngestRegister::open(&fixture.config.v1.suppression_store_path, seams).is_err()
            );
            let (body, polls) = chunks(vec![b"{}".to_vec()]);
            let overloaded = send(
                fixture.router(true),
                fixture.request("PUT", &path("https://example.com/other"), body),
            )
            .await;
            assert_eq!(
                polls.load(SeqCst),
                0,
                "started transaction must retain admission after HTTP timeout"
            );
            overloaded.error("overloaded", None, 503);
            drop(barrier);
            fixture
                .state
                .ingest_register()
                .sweep_expired()
                .await
                .unwrap();
            assert_eq!(fixture.snapshot()["entries"][0]["delivery"], "acknowledged");
            fixture
                .put(&input("https://example.com/page"))
                .await
                .success(1);
            fixture.shutdown().await;
        });
        let fixture = fixture.reopen();
        runtime().block_on(async {
            fixture
                .put(&input("https://example.com/page"))
                .await
                .success(1);
        });
    }

    #[test]
    fn timed_out_transactions_keep_admission_until_completion() {
        for stage in [IngestStage::Write, IngestStage::SyncDirectory] {
            timed_out_owner(stage);
        }
        let fixture = Fixture::configured(|config| config.v1.request_timeout_ms = 25);
        runtime().block_on(async {
            let barrier = fixture.hooks.pause(IngestStage::Write, 1);
            let first = tokio::spawn(send(
                fixture.router(true),
                request(&fixture, &input("https://example.com/a")),
            ));
            barrier.reached().await;
            let waiting = fixture.put(&input("https://example.com/b")).await;
            waiting.error("request_timeout", None, 504);
            first.await.unwrap().error("request_timeout", None, 504);
            drop(barrier);
            fixture
                .state
                .ingest_register()
                .sweep_expired()
                .await
                .unwrap();
            assert_eq!(
                fixture.snapshot()["entries"].as_array().map(Vec::len),
                Some(1)
            );
            assert_eq!(
                fixture.backend.calls.load(SeqCst),
                1,
                "cancelled waiting request must never start"
            );
            fixture
                .put(&input("https://example.com/a"))
                .await
                .success(1);
            fixture.shutdown().await;
        });
    }

    fn set_time(fixture: &Fixture, timestamp: i64) {
        fixture
            .clock
            .set_utc(chrono::DateTime::from_timestamp(timestamp, 0).unwrap())
            .unwrap();
    }

    #[test]
    fn expiry_uses_receipt_age_and_never_renews_on_replay() {
        let received = chrono::DateTime::parse_from_rfc3339("2026-01-20T12:00:00Z")
            .unwrap()
            .timestamp();
        let expires = chrono::DateTime::parse_from_rfc3339("2026-03-21T12:00:00Z")
            .unwrap()
            .timestamp();
        assert_eq!(expires - received, 60 * 24 * 60 * 60);
        for delta in [-1, 0, 1] {
            let fixture = Fixture::at(received);
            runtime().block_on(async {
                let mut value = input("https://example.com/page");
                value["retrieved_at"] = json!(0);
                let first = fixture.put(&value).await;
                first.success(1);
                set_time(&fixture, expires + delta);
                fixture.probe.reset();
                let replay = fixture.put(&value).await;
                assert_eq!(
                    fixture.probe.counts().write,
                    if delta < 0 { 0 } else { 2 },
                    "receipt expiry must include exact elapsed-day equality"
                );
                let entry = &fixture.snapshot()["entries"][0];
                assert_eq!(entry["retrieved_at"], 0);
                assert_eq!(
                    entry["received_at"],
                    if delta < 0 { received } else { expires + delta }
                );
                replay.success(1);
            });
        }
        let fixture = Fixture::at(received);
        runtime().block_on(async {
            let mut value = input("https://example.com/old");
            value["retrieved_at"] = json!(0);
            fixture.put(&value).await.success(1);
            set_time(&fixture, expires - 1);
            value["body"] = json!("<title>Renewed</title><p>Changed body</p>");
            fixture.put(&value).await.success(2);
            set_time(&fixture, expires);
            let before = fixture.snapshot();
            fixture.put(&value).await.success(2);
            assert_eq!(fixture.snapshot(), before);
            set_time(&fixture, expires + 60 * 24 * 60 * 60);
            value["url"] = json!("https://example.com/new");
            fixture.put(&value).await.success(1);
            assert_eq!(
                fixture.snapshot()["entries"].as_array().map(Vec::len),
                Some(1)
            );
            assert_eq!(
                fixture.snapshot()["entries"][0]["canonical_url"],
                "https://example.com/new"
            );
        });
    }

    #[test]
    fn retention_sweeper_runs_without_ingest_traffic() {
        let fixture = Fixture::new();
        runtime().block_on(async {
            fixture
                .put(&input("https://example.com/page"))
                .await
                .success(1);
            let register = fixture.state.ingest_register();
            fixture.probe.reset();
            assert!(register.start_maintenance().await);
            assert!(!register.start_maintenance().await);
            fixture.hooks.wait_for_timer(1).await;
            assert_eq!(fixture.hooks.timer_deadlines(), [(0, 600_000)]);
            assert_eq!(fixture.probe.counts().sweep, 0);
            set_time(&fixture, 1_790_000_000 + 5_184_000);
            fixture.clock.advance(599_999).unwrap();
            assert_eq!(
                (fixture.probe.counts().sweep, fixture.probe.counts().write),
                (0, 0)
            );
            fixture.clock.advance(1).unwrap();
            fixture.hooks.wait_for_timer(2).await;
            assert_eq!(fixture.snapshot()["entries"], json!([]));
            assert_eq!(fixture.probe.counts().sweep, 1);
            assert_eq!(fixture.probe.counts().write, 1);
            assert_eq!(
                fixture.hooks.timer_deadlines(),
                [(0, 600_000), (600_000, 1_200_000)]
            );
            register.sweep_expired().await.unwrap();
            let before = tree(fixture.root());
            register.sweep_expired().await.unwrap();
            assert_eq!(tree(fixture.root()), before);
            register.shutdown().await;
            assert!(!register.start_maintenance().await);
            let sweeps = fixture.probe.counts().sweep;
            fixture.clock.advance(600_000).unwrap();
            tokio::task::yield_now().await;
            assert_eq!(fixture.probe.counts().sweep, sweeps);
            fixture.shutdown().await;
        });
        let fixture = fixture.reopen();
        assert_eq!(fixture.snapshot()["entries"], json!([]));
        startup_and_failed_sweep();
    }

    fn startup_and_failed_sweep() {
        let fixture = Fixture::new();
        runtime().block_on(async {
            fixture
                .put(&input("https://example.com/page"))
                .await
                .success(1);
            fixture.clock.advance(60 * 24 * 60 * 60 * 1_000).unwrap();
            fixture.shutdown().await;
        });
        let fixture = fixture.reopen();
        assert_eq!(
            fixture.snapshot()["entries"],
            json!([]),
            "startup must sweep validated old receipts"
        );
        runtime().block_on(async {
            fixture
                .put(&input("https://example.com/page"))
                .await
                .success(1);
            fixture.clock.advance(60 * 24 * 60 * 60 * 1_000).unwrap();
            fixture.hooks.fail(IngestStage::Write, 1);
            assert!(fixture
                .state
                .ingest_register()
                .sweep_expired()
                .await
                .is_err());
            fixture.hooks.reset();
            fixture.probe.reset();
            let refused = fixture.put(&input("https://example.com/other")).await;
            assert_eq!(
                (fixture.probe.counts().write, fixture.probe.counts().backend),
                (0, 0)
            );
            refused.error("ingest_unavailable", None, 503);
        });
    }

    fn literal_entry(url: &str, delivery: &str) -> Value {
        let value = input(url);
        json!({"id":digest(url.as_bytes()),"canonical_url":url,
            "body_sha256":digest(value["body"].as_str().unwrap().as_bytes()),"version":1,
            "received_at":1_790_000_000_i64,"retrieved_at":1_789_999_999_i64,
            "fetch_time_ms":100,"source":"engine.fetch","admission":"admitted","delivery":delivery})
    }

    fn encoded_entries(mut entries: Vec<Value>) -> Vec<u8> {
        entries.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        let mut bytes = serde_json::to_vec(&json!({"format_version":1,"entries":entries})).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn full_url(index: usize, length: usize) -> String {
        let mut url = format!("https://example.com/{index:05}/");
        assert!(url.len() <= length);
        url.extend(std::iter::repeat_n('x', length - url.len()));
        url
    }

    fn snapshot_of_size(length: usize) -> Vec<u8> {
        let empty = encoded_entries(Vec::new()).len();
        let full = serde_json::to_vec(&literal_entry(&full_url(0, 2048), "acknowledged"))
            .unwrap()
            .len();
        let count = (length - empty) / (full + 1);
        let mut entries = (0..count)
            .map(|index| literal_entry(&full_url(index, 2048), "acknowledged"))
            .collect::<Vec<_>>();
        let current = empty + count * (full + 1) - 1;
        let remaining = length - current;
        let minimum = serde_json::to_vec(&literal_entry(&full_url(count, 64), "acknowledged"))
            .unwrap()
            .len()
            + 1;
        if remaining < minimum {
            entries[0] = literal_entry(&full_url(0, 2048 - (minimum - remaining)), "acknowledged");
            entries.push(literal_entry(&full_url(count, 64), "acknowledged"));
        } else {
            entries.push(literal_entry(
                &full_url(count, 64 + remaining - minimum),
                "acknowledged",
            ));
        }
        let bytes = encoded_entries(entries);
        assert_eq!(bytes.len(), length);
        bytes
    }

    fn seeded(bytes: Vec<u8>) -> Fixture {
        let fixture = Fixture::new();
        runtime().block_on(fixture.shutdown());
        fixture.reopen_after(|root| {
            fs::write(root.join("suppression.json.ingest/snapshot.json"), bytes).unwrap()
        })
    }

    async fn capacity_refusal(fixture: &Fixture, value: &Value) {
        let before = tree(fixture.root());
        fixture.probe.reset();
        fixture.hooks.reset();
        let calls = fixture.backend.calls.load(SeqCst);
        let response = fixture.put(value).await;
        assert_eq!(
            (fixture.probe.counts().write, fixture.probe.counts().backend),
            (0, 0),
            "capacity must reserve both snapshots before any persistence or dispatch"
        );
        assert_eq!(fixture.backend.calls.load(SeqCst), calls);
        assert!(fixture.hooks.stages().is_empty());
        assert_eq!(tree(fixture.root()), before);
        response.error("ingest_capacity", None, 503);
    }

    #[test]
    fn register_capacity_refuses_without_any_mutation() {
        let entries = (0..10_000)
            .map(|index| literal_entry(&format!("https://example.com/{index}"), "acknowledged"))
            .collect::<Vec<_>>();
        let fixture = seeded(encoded_entries(entries));
        runtime().block_on(async {
            capacity_refusal(&fixture, &input("https://example.com/new")).await;
            let replay = fixture.put(&input("https://example.com/0")).await;
            assert_eq!(fixture.probe.counts().write, 0);
            replay.success(1);
            let mut changed = input("https://example.com/0");
            changed["body"] = json!("<title>Changed</title><p>Replacement at count capacity</p>");
            fixture.put(&changed).await.success(2);
        });
        let cap = 16_777_216;
        let recorded = literal_entry("https://example.com/new", "recorded");
        let cost = serde_json::to_vec(&recorded).unwrap().len() + 1;
        for free in [0, cost + 2] {
            let fixture = seeded(snapshot_of_size(cap - free));
            runtime().block_on(async {
                capacity_refusal(&fixture, &input("https://example.com/new")).await;
                let url = full_url(1, 2048);
                let replay = fixture.put(&input(&url)).await;
                assert_eq!(fixture.probe.counts().write, 0);
                replay.success(1);
                if free == 0 {
                    let mut replacement = input(&url);
                    replacement["body"] = json!("<title>Changed</title>");
                    replacement["source"] = json!("x".repeat(64));
                    capacity_refusal(&fixture, &replacement).await;
                }
                let mut smaller = input(&url);
                smaller["body"] = json!("<title>Smaller metadata</title>");
                smaller["source"] = json!("x");
                fixture.put(&smaller).await.success(2);
            });
        }
    }

    #[test]
    fn observer_counts_describe_actual_ingest_work() {
        let fixture = Fixture::new();
        runtime().block_on(async {
            let value = input("https://example.com/page");
            let mut failed_body = Value::Null;
            for (case, expected) in [
                (0, [0, 0, 0, 0, 0, 0, 0]),
                (1, [1, 0, 0, 0, 0, 0, 0]),
                (2, [2, 1, 0, 0, 0, 0, 0]),
                (3, [2, 1, 1, 0, 0, 0, 0]),
                (4, [2, 1, 1, 1, 0, 0, 0]),
                (5, [2, 1, 1, 1, 1, 2, 1]),
                (6, [2, 1, 1, 1, 1, 0, 0]),
                (7, [2, 1, 1, 1, 1, 2, 1]),
                (8, [2, 1, 1, 1, 1, 1, 1]),
                (9, [2, 1, 1, 1, 1, 1, 1]),
            ] {
                fixture.probe.reset();
                fixture.hooks.reset();
                let before = fixture.backend.calls.load(SeqCst);
                let mut candidate = value.clone();
                if case == 4 {
                    candidate["body"] =
                        json!("<title>Denied</title><meta name=robots content=noindex>");
                }
                if case >= 7 {
                    let version_body = case.min(8);
                    candidate["body"] = json!(format!("<title>Version {version_body}</title>"));
                }
                if case == 8 {
                    fixture.backend.mode(Mode::Failure);
                    failed_body = candidate["body"].clone();
                } else if case == 9 {
                    fixture.backend.mode(Mode::Success);
                }
                let stored = retry_stored(&fixture, case, &candidate, &failed_body);
                let mut request = request(&fixture, &candidate);
                if case == 1 {
                    request.headers_mut().remove("authorization");
                }
                if case == 2 {
                    *request.uri_mut() = "/v1/documents/bad".parse().unwrap();
                }
                if case == 3 {
                    *request.body_mut() = Body::from("{");
                }
                let response = send(fixture.router(case != 0), request).await;
                let counts = fixture.probe.counts();
                assert_eq!(
                    [
                        counts.auth,
                        counts.enter,
                        counts.decode,
                        counts.audit,
                        counts.read,
                        counts.write,
                        counts.backend
                    ],
                    expected
                );
                assert_eq!(counts.verifier, counts.auth);
                assert_eq!(counts.journal, 0);
                assert_eq!(fixture.backend.calls.load(SeqCst) - before, counts.backend);
                assert_eq!(
                    fixture
                        .hooks
                        .stages()
                        .iter()
                        .filter(|stage| **stage == IngestStage::Open)
                        .count(),
                    counts.write
                );
                if case == 9 {
                    recorded_retry_trace(&fixture, &response, &stored, before);
                }
                headers(&response);
                assert_eq!(
                    response.status,
                    [404, 401, 400, 400, 400, 200, 200, 200, 503, 200][case]
                );
            }
            observer_other_routes(&fixture).await;
        });
    }

    fn retry_stored(
        fixture: &Fixture,
        case: usize,
        candidate: &Value,
        failed_body: &Value,
    ) -> Value {
        if case != 9 {
            return Value::Null;
        }
        let stored = fixture.snapshot()["entries"][0].clone();
        fixture.clock.advance(1_000).unwrap();
        assert_eq!(stored["delivery"], "recorded");
        assert_eq!(stored["version"], 3);
        assert_eq!(&candidate["body"], failed_body);
        stored
    }

    fn recorded_retry_trace(fixture: &Fixture, response: &Observed, stored: &Value, before: usize) {
        let counts = fixture.probe.counts();
        assert_eq!((counts.read, counts.backend, counts.write), (1, 1, 1));
        assert_eq!(fixture.backend.calls.load(SeqCst) - before, 1);
        assert_eq!(
            fixture.hooks.stages(),
            [
                IngestStage::BeforeDispatch,
                IngestStage::Open,
                IngestStage::Write,
                IngestStage::SyncFile,
                IngestStage::Rename,
                IngestStage::SyncDirectory,
                IngestStage::AfterAcknowledgement,
            ]
        );
        let mut completed = stored.clone();
        completed["delivery"] = json!("acknowledged");
        assert_eq!(fixture.snapshot()["entries"][0], completed);
        headers(response);
        let value = response.value();
        assert_eq!(value["document"]["version"], stored["version"]);
        assert_eq!(value["document"]["accepted_at"], stored["received_at"]);
        assert_eq!(response.status, 200);
    }

    async fn observer_other_routes(fixture: &Fixture) {
        fixture.probe.reset();
        send(
            fixture.router(true),
            fixture.request("DELETE", &path("https://example.com/page"), Body::empty()),
        )
        .await
        .success_delete();
        assert_eq!(fixture.probe.counts().delete, 1);
        let source = send(
            fixture.router(false),
            fixture.request("GET", "/v1/source", Body::empty()),
        )
        .await;
        assert_eq!(fixture.probe.counts().source, 1);
        headers(&source);
        assert_eq!(source.status, 200);
        let found = search(fixture).await;
        assert_eq!(fixture.probe.counts().search, 1);
        headers(&found);
        assert_eq!(found.status, 200);
    }

    #[test]
    fn collapse_keeps_first_allowed_and_every_distinct_id() {
        let mut fixture = Fixture::new();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = calls.clone();
        fixture.search_backend(Arc::new(move |_: stract::searcher::SearchQuery| {
            counter.fetch_add(1, SeqCst);
            async {
                Ok(search_result(&[
                    ("https://example.com/a", "First", "example.com"),
                    ("https://example.com/b", "Same", "example.com"),
                    ("https://example.com:443/a#alias", "Second", "example.com"),
                    ("https://example.com/c", "Same", "example.com"),
                    ("https://example.com/b", "Same", "example.com"),
                ]))
            }
        }));
        runtime().block_on(async {
            let result = search(&fixture).await;
            assert_eq!(
                fixture.probe.counts().construct,
                3,
                "construct once per allowed canonical identifier"
            );
            assert_eq!(
                calls.load(SeqCst),
                1,
                "collapse must not refill or rerun search"
            );
            assert_eq!(
                result_ids(&result),
                ["a", "b", "c"]
                    .map(|suffix| digest(format!("https://example.com/{suffix}").as_bytes()))
            );
            headers(&result);
            let value = result.value();
            assert_eq!(value["results"][0]["title"], "First");
            assert_eq!(value["page"], 0);
            assert_eq!(value["num_results"], 20);
            assert_eq!(value["has_more_results"], true);
            assert_eq!(result.status, 200);
            send(
                fixture.router(true),
                fixture.request("DELETE", &path("https://example.com/a"), Body::empty()),
            )
            .await
            .success_delete();
            global_exclusion(&fixture, "https://example.com/b").await;
            fixture.probe.reset();
            let filtered = search(&fixture).await;
            assert_eq!(fixture.probe.counts().construct, 1);
            assert_eq!(result_ids(&filtered), [digest(b"https://example.com/c")]);
            headers(&filtered);
            assert_eq!(filtered.status, 200);
        });
        fixture.search_backend(Arc::new(|_: stract::searcher::SearchQuery| async {
            Ok(search_result(&[
                ("https://example.com/c", "", "example.com"),
                ("https://example.com/c", "Valid later", "example.com"),
            ]))
        }));
        runtime().block_on(async {
            fixture.probe.reset();
            let invalid = search(&fixture).await;
            assert_eq!(fixture.probe.counts().construct, 1);
            invalid.error("invalid_result", None, 500);
        });
    }

    #[test]
    fn transport_errors_keep_owned_headers_and_delete_behavior() {
        let fixture = Fixture::new();
        runtime().block_on(async {
            let value = input("https://example.com/page");
            let document = path("https://example.com/page");
            for suffix in ["?", "?force=1"] {
                refused(
                    &fixture,
                    fixture.request(
                        "PUT",
                        &format!("{document}{suffix}"),
                        serde_json::to_vec(&value).unwrap(),
                    ),
                    "invalid_request",
                    None,
                    400,
                )
                .await;
            }
            for encoding in [vec!["gzip"], vec!["identity", "identity"]] {
                let mut req = request(&fixture, &value);
                for value in encoding {
                    req.headers_mut()
                        .append("content-encoding", HeaderValue::from_static(value));
                }
                refused(&fixture, req, "unsupported_media_type", None, 415).await;
            }
            let mut wrong = request(&fixture, &value);
            wrong
                .headers_mut()
                .insert("content-type", HeaderValue::from_static("text/plain"));
            refused(&fixture, wrong, "unsupported_media_type", None, 415).await;
            for body in ["", "{", "[]"] {
                refused(
                    &fixture,
                    fixture.request("PUT", &document, body),
                    "invalid_request",
                    None,
                    400,
                )
                .await;
            }
            for method in ["OPTIONS", "GET", "HEAD", "POST"] {
                fixture.probe.reset();
                let mut req = fixture.request(method, &document, Body::empty());
                req.headers_mut().remove("authorization");
                let response = send(fixture.router(true), req).await;
                assert_eq!(
                    fixture.probe.counts(),
                    Counts::default(),
                    "wrong methods must not invoke PUT auth"
                );
                headers(&response);
                assert_eq!(response.headers["allow"], "DELETE,PUT");
                if method == "HEAD" {
                    assert!(response.bytes.is_empty());
                    assert_eq!(response.status, 405);
                } else {
                    response.error("method_not_allowed", None, 405);
                }
            }
            let mut noindex = value.clone();
            noindex["body"] = json!("<title>Denied</title><meta name=robots content=noindex>");
            refused(
                &fixture,
                request(&fixture, &noindex),
                "not_admitted",
                Some("noindex"),
                400,
            )
            .await;
            let mut delete = fixture.request("DELETE", &document, Body::empty());
            delete.headers_mut().remove("authorization");
            send(fixture.router(true), delete).await.success_delete();
            refused(
                &fixture,
                fixture.request("DELETE", &document, "x"),
                "invalid_request",
                None,
                400,
            )
            .await;
            fixture.put(&value).await.success(1);
        });
    }

    #[test]
    fn publisher_limits_never_enter_an_unenforced_ingest() {
        let fixture = Fixture::new();
        runtime().block_on(async {
            let original = input("https://example.com/page");
            fixture.put(&original).await.success(1);
            let before = fixture.snapshot();
            for (directive, reason) in [
                ("nosnippet", "excluded"),
                ("max-snippet: 30", "excluded"),
                ("unavailable_after: 01 Jan 2099 00:00:00 GMT", "excluded"),
                ("unavailable_after: 01 Jan 2000 00:00:00 GMT", "noindex"),
            ] {
                let mut value = original.clone();
                let meta = format!("<meta name=robots content=\"{directive}\">");
                value["body"] = json!(format!("<title>Replacement</title>{meta}<p>Content</p>"));
                refused(
                    &fixture,
                    request(&fixture, &value),
                    "not_admitted",
                    Some(reason),
                    400,
                )
                .await;
                assert_eq!(
                    fixture.snapshot(),
                    before,
                    "refused replacement cannot remove or change old metadata"
                );
                let mut header = original.clone();
                header["x_robots_tag"] = json!([directive]);
                refused(
                    &fixture,
                    request(&fixture, &header),
                    "not_admitted",
                    Some("header_directive"),
                    400,
                )
                .await;
            }
            for (index, meta) in [
                "<meta name=otherbot content=nosnippet>",
                "<meta name=robots content=all>",
                "<meta name=robots content=noarchive>",
                "<meta name=robots content=\"max-snippet: -1\">",
            ]
            .into_iter()
            .enumerate()
            {
                let mut value = input(&format!("https://example.com/control{index}"));
                value["body"] = json!(format!("<title>Allowed</title>{meta}<p>Content</p>"));
                fixture.put(&value).await.success(1);
            }
        });
    }

    #[test]
    fn ingest_errors_and_metadata_do_not_disclose_private_inputs() {
        let logs = TraceCapture::new();
        let fixture = listed_fixture();
        runtime().block_on(async {
            let body = "BodyPrivacyCanary";
            let title = "TitlePrivacyCanary";
            let header = "HeaderPrivacyCanary";
            let mut value = input("https://allowed.example.test/UrlPrivacyCanary");
            value["source"] = json!("sourceprivacycanary");
            value["body"] = json!(format!("<title>{title}</title><p>{body}</p>"));
            value["x_robots_tag"] = json!([format!("otherbot: {header}")]);
            let first = fixture.put(&value).await;
            let replay = fixture.put(&value).await;
            assert_eq!(first.bytes, replay.bytes);
            first.success(1);
            replay.success(1);
            send(
                fixture.router(true),
                fixture.request(
                    "DELETE",
                    &path(value["url"].as_str().unwrap()),
                    Body::empty(),
                ),
            )
            .await
            .success_delete();
            let suppressed = fixture.put(&value).await;
            assert_eq!(suppressed.bytes, first.bytes);
            let mut rejected = value.clone();
            rejected["source"] = json!("SourceRejectedCanary/");
            let response = refused(
                &fixture,
                request(&fixture, &rejected),
                "invalid_request",
                None,
                400,
            )
            .await;
            for marker in [
                body,
                title,
                header,
                "UrlPrivacyCanary",
                "SourceRejectedCanary",
                &fixture.token,
            ] {
                assert!(!String::from_utf8_lossy(&response.bytes).contains(marker));
                assert!(
                    !logs.text().contains(marker),
                    "private input must not appear in process tracing"
                );
            }
            assert_metadata_absent(
                fixture.root(),
                &[body, title, header, "SourceRejectedCanary"],
            );
            let snapshot = fs::read_to_string(fixture.snapshot_path()).unwrap();
            assert!(snapshot.contains("UrlPrivacyCanary"));
            assert!(snapshot.contains("sourceprivacycanary"));
            assert!(!snapshot.contains(&fixture.token));
            privacy_refusals_and_temps(&fixture, &value).await;
            fixture.hooks.fail(IngestStage::Write, 1);
            value["url"] = json!("https://allowed.example.test/failure");
            fixture
                .put(&value)
                .await
                .error("ingest_unavailable", None, 503);
            assert_metadata_absent(fixture.root(), &[body, title, header]);
        });
    }

    async fn privacy_refusals_and_temps(fixture: &Fixture, input: &Value) {
        let global = "https://global.example.test/page";
        let decision = global_exclusion(fixture, global).await;
        headers(&decision);
        assert_eq!(decision.status, 200);
        let mut expected = None;
        for url in [
            "https://exact.example.test/page",
            "https://listed.example.test/page",
            global,
        ] {
            let mut denied = input.clone();
            denied["url"] = json!(url);
            let response = refused(
                fixture,
                request(fixture, &denied),
                "not_admitted",
                Some("excluded"),
                400,
            )
            .await;
            if let Some(bytes) = &expected {
                assert_eq!(&response.bytes, bytes);
            } else {
                expected = Some(response.bytes);
            }
        }
        let mut temporary = input.clone();
        temporary["url"] = json!("https://allowed.example.test/temporary");
        let barrier = fixture.hooks.pause(IngestStage::SyncFile, 1);
        let pending = tokio::spawn(send(fixture.router(true), request(fixture, &temporary)));
        barrier.reached().await;
        let canaries = [
            "BodyPrivacyCanary",
            "TitlePrivacyCanary",
            "HeaderPrivacyCanary",
        ];
        assert_metadata_absent(fixture.root(), &canaries);
        assert!(fixture.hooks.stages().contains(&IngestStage::Write));
        drop(barrier);
        pending.await.unwrap().success(1);
        let document = serde_json::to_string(&stract::api::v1::openapi()).unwrap();
        for canary in canaries {
            assert!(
                !document.contains(canary),
                "private request text must not enter OpenAPI"
            );
        }
        for relative in tree(fixture.root()).keys() {
            let path = fixture.root().join(relative);
            if fixture.config.compliance.admin_token_file.as_ref() == Some(&path) {
                continue;
            }
            assert!(!String::from_utf8_lossy(&fs::read(path).unwrap()).contains(&fixture.token));
        }
    }
}
