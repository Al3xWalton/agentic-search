//! Exercises compliance's bounded HTTP surfaces and injected UTC deadlines against literal
//! contracts.
//! Synthetic private fixtures use reserved example domains and never perform external
//! communication.
//! This harness owns HTTP, clock and contract probes; the store harness owns persistence,
//! crash and hardening probes, and support/compliance.rs supplies shared synthetic fixtures.
//! Assert counters/store state, exact-once headers, body/content/code, then numeric status.

#![deny(missing_docs)]

#[path = "support/compliance.rs"]
/// Shared synthetic fixtures exported for both integration harnesses.
pub mod support;

mod contracts {
    use super::support::{contract_headers, contract_response, report, runtime, tree, HttpFixture};
    use chrono::{DateTime, Utc};
    use serde_json::{json, Value};
    use std::{fs, sync::atomic::Ordering::SeqCst};
    use stract::{
        compliance::clock,
        crawler::politeness::{Clock, ManualClock},
    };

    fn utc(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn at(clock: &ManualClock, text: &str) -> i64 {
        clock.set_utc(utc(text)).unwrap();
        clock.utc().timestamp()
    }

    fn body(fields: Value) -> Value {
        let mut result = fields;
        result["report"] = report();
        result
    }

    fn check_intake(path: &str, category: &str, fields: Value, outcomes: Value) {
        for preference in [false, true] {
            check_intake_preference(path, category, fields.clone(), &outcomes, preference);
        }
    }

    fn literal_timeframe(category: &str) -> &'static str {
        match category {
            "intimate_images" => {
                "Listed URLs are scheduled to be hidden within 48 hours unless a recorded determination excludes this duty"
            }
            "data_rights" => {
                "A decision is due within one calendar month of the relevant time; a reasoned extension may add two calendar months"
            }
            "data_protection_complaint" => {
                "We acknowledge now, within 30 days; we will make enquiries and communicate progress and an outcome without undue delay"
            }
            _ => "We will review this report as soon as possible",
        }
    }

    fn check_intake_preference(
        path: &str,
        category: &str,
        fields: Value,
        outcomes: &Value,
        preference: bool,
    ) {
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let mut input = body(fields);
            input["report"]["nonessential_opt_out"] = json!(preference);
            let response = fixture.send(false, "POST", path, input, false).await;
            let rows = fs::read_to_string(fixture.domain.path("events.jsonl"))
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(
                fixture.probe.writes.load(SeqCst),
                if category == "intimate_images" { 5 } else { 3 }
            );
            assert_eq!(rows.first().unwrap()["event"], "received");
            assert_eq!(rows[rows.len() - 2]["event"], "acknowledged");
            assert_eq!(rows.last().unwrap()["event"], "queued");
            if category == "intimate_images" {
                let rules = super::support::read_json(
                    &fixture.domain.config.rules_dir().join("snapshot.json"),
                );
                assert!(!rules["rules"].as_array().unwrap().is_empty());
            }
            assert!(rows
                .iter()
                .all(|row| row["received_at"] == response.value["received_at"]));
            contract_headers(&response);
            assert_eq!(response.value.as_object().unwrap().len(), 8);
            assert_eq!(response.value["version"], "v1");
            assert_eq!(response.value["nonessential_opt_out"], preference);
            assert_eq!(&response.value["possible_outcomes"], outcomes);
            assert_eq!(
                response.value["indicative_timeframe"],
                literal_timeframe(category)
            );
            assert_eq!(
                response.value["received_at"],
                utc("2026-09-18T12:00:00Z").timestamp()
            );
            assert_eq!(
                response.value["acknowledged_at"],
                response.value["received_at"]
            );
            let id = response.value["ticket_id"].as_str().unwrap();
            assert_eq!(id.len(), 64);
            assert_eq!(
                response.value["status_path"],
                format!("/v1/reports/status/{id}")
            );
            assert_eq!(response.status, 200);
            intake_readback(&fixture, id, category, preference).await;
            fixture.state.compliance().shutdown().await;
        });
    }

    async fn intake_readback(fixture: &HttpFixture, id: &str, category: &str, preference: bool) {
        let before = super::support::tree(fixture.domain.config.store_dir());
        let writes = fixture.probe.writes.load(SeqCst);
        let queue = fixture
            .send(
                true,
                "POST",
                "/v1/compliance/queue",
                json!({"actor":"reviewer"}),
                true,
            )
            .await;
        let status = fixture
            .send(
                false,
                "GET",
                &format!("/v1/reports/status/{id}"),
                Value::Null,
                false,
            )
            .await;
        let read = fixture
            .send(
                true,
                "POST",
                &format!("/v1/compliance/tickets/{id}/read"),
                json!({"actor":"reader"}),
                true,
            )
            .await;
        assert_eq!(
            super::support::tree(fixture.domain.config.store_dir()),
            before
        );
        assert_eq!(fixture.probe.writes.load(SeqCst), writes);
        assert!(!fs::read_to_string(fixture.domain.path("events.jsonl"))
            .unwrap()
            .contains("Synthetic private narrative"));
        contract_headers(&queue);
        assert_eq!(queue.value["items"][0]["ticket_id"], id);
        assert_eq!(queue.value["items"][0]["route"], category);
        assert_eq!(queue.value["items"][0]["state"], "queued");
        assert_eq!(queue.status, 200);
        contract_headers(&status);
        assert_eq!(status.value["state"], "queued");
        assert_eq!(status.status, 200);
        contract_headers(&read);
        assert_eq!(
            read.value["payload_events"][0]["intake"]["report"]["nonessential_opt_out"],
            preference
        );
        assert_eq!(read.status, 200);
    }

    #[test]
    fn illegal_content_intake_acknowledges_and_queues() {
        check_intake(
            "/v1/reports/illegal-content",
            "illegal_content",
            json!({"urls":["https://synthetic.example.test/item"],
            "suspected_illegality":"Synthetic evidence"}),
            json!(["deindexed", "no_action"]),
        );
    }

    #[test]
    fn children_intake_acknowledges_and_queues() {
        check_intake(
            "/v1/reports/harmful-to-children",
            "harmful_to_children",
            json!({"urls":["https://synthetic.example.test/item"],
            "harm_description":"Synthetic harm description"}),
            json!(["deindexed", "no_action"]),
        );
    }

    #[test]
    fn intimate_intake_acknowledges_after_timed_rules() {
        delayed_intake_keeps_receipt_origin();
        let fields = json!({"urls":["https://synthetic.example.test/item",
            "https://second.example.test/item"],
            "intimate_image_content":true,"subject_or_authorised":true,"good_faith":true});
        check_intake(
            "/v1/reports/intimate-images",
            "intimate_images",
            fields.clone(),
            json!(["deindexed", "not_intimate_image", "no_standing"]),
        );
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let before = fs::read(fixture.domain.path("events.jsonl")).unwrap();
            for key in [
                "intimate_image_content",
                "subject_or_authorised",
                "good_faith",
            ] {
                let mut wrong = fields.clone();
                wrong[key] = json!(false);
                let response = fixture
                    .send(
                        false,
                        "POST",
                        "/v1/reports/intimate-images",
                        body(wrong),
                        false,
                    )
                    .await;
                assert_eq!(fixture.probe.writes.load(SeqCst), 0);
                assert_eq!(
                    fs::read(fixture.domain.path("events.jsonl")).unwrap(),
                    before
                );
                contract_headers(&response);
                assert_eq!(response.value["error"]["code"], "invalid_request");
                assert_eq!(response.status, 400);
            }
            fixture.state.compliance().shutdown().await;
        });
    }

    #[test]
    fn site_complaint_acknowledges_without_related_ticket_lookup() {
        related_complaint_does_not_query_other_ticket();
        for interest in ["responsible_uk_person", "uk_incorporated_body"] {
            let related = (0..32)
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            check_intake(
                "/v1/reports/site-complaints",
                "site_complaint",
                json!({"urls":["https://synthetic.example.test/item"],
                "interest":interest,"related_ticket_id":related}),
                json!(["reversed", "upheld", "no_action"]),
            );
        }
    }

    #[test]
    fn rights_removal_intake_acknowledges() {
        check_intake(
            "/v1/reports/rights-removal",
            "rights_removal",
            json!({"urls":["https://synthetic.example.test/item"],
            "rights_basis":"Synthetic rights evidence","authority":"Synthetic authority"}),
            json!(["deindexed", "no_action"]),
        );
    }

    #[test]
    fn data_rights_intake_acknowledges_all_three_requests() {
        for request in ["delisting", "erasure", "objection"] {
            check_intake(
                "/v1/reports/data-rights",
                "data_rights",
                json!({"urls":["https://synthetic.example.test/item"],
                "request_kind":request,
                    "names":[{"name":"Synthetic Person",
                    "kind":"legal_name",
                    "evidence":"Synthetic evidence"},
                    {"name":"Synthetic Alias",
                        "kind":"pseudonym",
                        "evidence":"Synthetic evidence"}]}),
                json!(["name_delisted", "deindexed", "no_action"]),
            );
        }
    }

    #[test]
    fn data_protection_complaint_acknowledges_immediately() {
        check_intake(
            "/v1/reports/data-protection-complaints",
            "data_protection_complaint",
            json!({}),
            json!(["complaint_resolved", "no_action"]),
        );
    }

    #[test]
    fn online_safety_complaint_acknowledges() {
        check_intake(
            "/v1/reports/online-safety-complaints",
            "online_safety_complaint",
            json!({}),
            json!(["complaint_resolved", "no_action"]),
        );
    }

    async fn admitted_id(fixture: &HttpFixture) -> String {
        let response = fixture
            .send(
                false,
                "POST",
                "/v1/reports/illegal-content",
                body(json!({"urls":["https://synthetic.example.test/item"],
                "suspected_illegality":"Synthetic evidence"})),
                false,
            )
            .await;
        admission_id(response)
    }

    async fn unknown_status_ids(fixture: &HttpFixture) {
        let writes = fixture.probe.writes.load(SeqCst);
        let files = super::support::tree(fixture.domain.config.store_dir());
        let lookups = fixture.probe.lookups.load(SeqCst);
        let baseline = fixture
            .send(
                false,
                "GET",
                "/v1/reports/status/missing",
                Value::Null,
                false,
            )
            .await;
        assert_eq!(
            super::support::tree(fixture.domain.config.store_dir()),
            files
        );
        assert_eq!(fixture.probe.writes.load(SeqCst), writes);
        assert_eq!(fixture.probe.lookups.load(SeqCst), lookups);
        contract_headers(&baseline);
        assert_eq!(baseline.value["error"]["code"], "not_found");
        assert_eq!(baseline.status, 404);
        for malformed in [
            "a".repeat(63),
            "b".repeat(65),
            "C".repeat(64),
            format!("%61{}", "b".repeat(63)),
            "../unknown".into(),
        ] {
            let lookups = fixture.probe.lookups.load(SeqCst);
            let response = fixture
                .send(
                    false,
                    "GET",
                    &format!("/v1/reports/status/{malformed}"),
                    Value::Null,
                    false,
                )
                .await;
            assert_eq!(
                super::support::tree(fixture.domain.config.store_dir()),
                files
            );
            assert_eq!(fixture.probe.writes.load(SeqCst), writes);
            assert_eq!(fixture.probe.lookups.load(SeqCst), lookups);
            contract_headers(&response);
            assert_eq!(response.value["error"]["code"], "not_found");
            assert_eq!(response.bytes, baseline.bytes);
            assert_eq!(response.status, 404);
        }
        for number in 0..64 {
            let lookups = fixture.probe.lookups.load(SeqCst);
            let response = fixture
                .send(
                    false,
                    "GET",
                    &format!("/v1/reports/status/{number:064}"),
                    Value::Null,
                    false,
                )
                .await;
            assert_eq!(
                super::support::tree(fixture.domain.config.store_dir()),
                files
            );
            assert_eq!(fixture.probe.writes.load(SeqCst), writes);
            assert_eq!(fixture.probe.lookups.load(SeqCst), lookups + 1);
            contract_headers(&response);
            assert_eq!(response.value["error"]["code"], "not_found");
            assert_eq!(response.bytes, baseline.bytes);
            assert_eq!(response.status, 404);
        }
        assert_eq!(fixture.probe.writes.load(SeqCst), writes);
    }

    #[test]
    fn reports_index_and_minimal_status_resist_enumeration() {
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let id = admitted_id(&fixture).await;
            check_reports_index(&fixture).await;
            let status = fixture
                .send(
                    false,
                    "GET",
                    &format!("/v1/reports/status/{id}"),
                    Value::Null,
                    false,
                )
                .await;
            contract_headers(&status);
            let mut keys = status
                .value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>();
            keys.sort();
            let mut expected = vec![
                "version",
                "state",
                "received_at",
                "acknowledged_at",
                "identity_pending_at",
                "queued_at",
                "decided_at",
                "actioned_at",
                "appealed_at",
                "reversed_at",
                "upheld_at",
                "closed_at",
            ];
            expected.sort();
            assert_eq!(keys, expected);
            assert_eq!(status.status, 200);
            unknown_status_ids(&fixture).await;
            fixture.state.compliance().shutdown().await;
        });
    }

    fn admin_paths(id: &str) -> Vec<String> {
        std::iter::once("/v1/compliance/queue".into())
            .chain(
                [
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
                ]
                .map(|action| format!("/v1/compliance/tickets/{id}/{action}")),
            )
            .collect()
    }

    async fn unauthorised_routes(fixture: &HttpFixture, known: &str) {
        let unknown = (32..64)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let mut baseline = None;
        for id in [known, &unknown, "%61bad"] {
            for path in admin_paths(id) {
                let before = (
                    fixture.probe.decodes.load(SeqCst),
                    fixture.probe.lookups.load(SeqCst),
                    fixture.probe.writes.load(SeqCst),
                );
                let files = super::support::tree(fixture.domain.config.store_dir());
                let response = fixture
                    .send(true, "POST", &path, json!({"unexpected":"body"}), false)
                    .await;
                assert_eq!(
                    super::support::tree(fixture.domain.config.store_dir()),
                    files
                );
                assert_eq!(
                    (
                        fixture.probe.decodes.load(SeqCst),
                        fixture.probe.lookups.load(SeqCst),
                        fixture.probe.writes.load(SeqCst)
                    ),
                    before
                );
                contract_headers(&response);
                assert_eq!(response.value["error"]["code"], "unauthorised");
                assert_eq!(response.value.as_object().unwrap().len(), 2);
                assert_eq!(response.value["error"].as_object().unwrap().len(), 2);
                if let Some(bytes) = &baseline {
                    assert_eq!(&response.bytes, bytes);
                }
                assert_eq!(response.status, 401);
                if baseline.is_none() {
                    baseline = Some(response.bytes.clone());
                }
            }
        }
    }

    #[test]
    fn admin_auth_precedes_lookup_and_uses_constant_time_verifier() {
        auth_dummy_buffers_stay_unauthorised();
        use axum::{body::Body, http::Request};
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let known = admitted_id(&fixture).await;
            unauthorised_routes(&fixture, &known).await;
            for index in [0, 31, 63] {
                let mut wrong = fixture.token.as_bytes().to_vec();
                wrong[index] = if wrong[index] == b'a' { b'b' } else { b'a' };
                let credential = format!("Bearer {}", String::from_utf8(wrong).unwrap());
                let request = Request::builder()
                    .method("POST")
                    .uri("/v1/compliance/queue")
                    .header("authorization", credential)
                    .body(Body::from("bad-json"))
                    .unwrap();
                super::support::rejected_response(
                    fixture.raw(true, request).await,
                    "unauthorised",
                    401,
                );
            }
            for duplicate in [false, true] {
                let mut request = Request::builder()
                    .method("POST")
                    .uri("/v1/compliance/queue")
                    .header(
                        "authorization",
                        if duplicate {
                            format!("Bearer {}", fixture.token)
                        } else {
                            "Bearer malformed".into()
                        },
                    );
                if duplicate {
                    request = request.header("authorization", format!("Bearer {}", fixture.token));
                }
                super::support::rejected_response(
                    fixture
                        .raw(true, request.body(Body::empty()).unwrap())
                        .await,
                    "unauthorised",
                    401,
                );
            }
            let correct = fixture
                .send(
                    true,
                    "POST",
                    "/v1/compliance/queue",
                    json!({"actor":"reviewer"}),
                    true,
                )
                .await;
            contract_headers(&correct);
            assert!(correct.value["items"].is_array());
            assert_eq!(correct.status, 200);
            let writes = fixture.probe.writes.load(SeqCst);
            let files = super::support::tree(fixture.domain.config.store_dir());
            let reserved = fixture
                .send(
                    true,
                    "POST",
                    "/v1/compliance/queue",
                    json!({"actor":"system.intake"}),
                    true,
                )
                .await;
            assert_eq!(
                super::support::tree(fixture.domain.config.store_dir()),
                files
            );
            assert_eq!(fixture.probe.writes.load(SeqCst), writes);
            let verified = fixture.probe.verifier.lock().unwrap();
            assert_eq!(verified.len(), fixture.probe.authentication.load(SeqCst));
            assert!(verified.iter().all(|lengths| *lengths == (32, 32)));
            contract_headers(&reserved);
            assert_eq!(reserved.value["error"]["code"], "invalid_request");
            assert_eq!(reserved.status, 400);
        });
    }

    fn auth_dummy_buffers_stay_unauthorised() {
        use axum::{body::Body, http::Request};
        // Zero is a valid synthetic credential, and also the malformed-input dummy buffer.
        // These cases independently require both configuration and shape predicates.
        for configured in [false, true] {
            let fixture = HttpFixture::configured(|config| {
                if configured {
                    fs::write(
                        config.compliance.admin_token_file.as_ref().unwrap(),
                        "0".repeat(64),
                    )
                    .unwrap();
                } else {
                    config.compliance.admin_token_file = None;
                }
            });
            runtime().block_on(async {
                let mut request = Request::builder()
                    .method("POST")
                    .uri("/v1/compliance/queue")
                    .header("content-type", "application/json");
                if !configured {
                    request = request.header("authorization", format!("Bearer {}", "0".repeat(64)));
                }
                let response = fixture
                    .raw(
                        true,
                        request.body(Body::from(r#"{"actor":"reader"}"#)).unwrap(),
                    )
                    .await;
                assert_eq!(fixture.probe.decodes.load(SeqCst), 0);
                assert_eq!(fixture.probe.lookups.load(SeqCst), 0);
                assert_eq!(fixture.probe.writes.load(SeqCst), 0);
                assert_eq!(*fixture.probe.verifier.lock().unwrap(), [(32, 32)]);
                contract_headers(&response);
                assert_eq!(response.value["error"]["code"], "unauthorised");
                assert_eq!(response.status, 401);
                if configured {
                    let request = Request::builder()
                        .method("POST")
                        .uri("/v1/compliance/queue")
                        .header("content-type", "application/json")
                        .header("authorization", format!("Bearer {}", "0".repeat(64)))
                        .body(Body::from(r#"{"actor":"reader"}"#))
                        .unwrap();
                    super::support::successful_response(fixture.raw(true, request).await);
                }
            });
        }
    }

    #[test]
    fn management_operations_are_unreachable_on_the_api_listener() {
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let id = admitted_id(&fixture).await;
            let writes = fixture.probe.writes.load(SeqCst);
            for path in admin_paths(&id) {
                let files = super::support::tree(fixture.domain.config.store_dir());
                let response = fixture
                    .send(false, "POST", &path, json!({"actor":"reviewer"}), true)
                    .await;
                assert_eq!(
                    super::support::tree(fixture.domain.config.store_dir()),
                    files
                );
                assert_eq!(fixture.probe.writes.load(SeqCst), writes);
                assert_eq!(fixture.probe.authentication.load(SeqCst), 0);
                contract_headers(&response);
                assert_eq!(response.value["error"]["code"], "not_found");
                assert_eq!(response.status, 404);
            }
            assert_eq!(fixture.probe.writes.load(SeqCst), writes);
            assert_eq!(fixture.probe.authentication.load(SeqCst), 0);
            for (method, path, body) in [
                ("POST", "/v1/search".into(), json!({"query":"cedar"})),
                ("POST", "/v1/reports/illegal-content".into(), json!({})),
                ("GET", format!("/v1/reports/status/{id}"), Value::Null),
            ] {
                super::support::rejected_response(
                    fixture.send(true, method, &path, body, true).await,
                    "not_found",
                    404,
                );
            }
            super::support::successful_response(
                fixture
                    .send(
                        true,
                        "POST",
                        &format!("/v1/compliance/tickets/{id}/read"),
                        json!({"actor":"reader"}),
                        true,
                    )
                    .await,
            );
            for management in [false, true] {
                for path in ["/v1/source", "/v1/reports"] {
                    super::support::successful_response(
                        fixture
                            .send(management, "GET", path, Value::Null, false)
                            .await,
                    );
                }
            }
            let document = (64..96)
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            super::support::successful_response(
                fixture
                    .send(
                        true,
                        "DELETE",
                        &format!("/v1/documents/{document}"),
                        Value::Null,
                        false,
                    )
                    .await,
            );
        });
    }

    #[test]
    fn new_bodyless_routes_and_media_types_reject_before_handlers() {
        use axum::{body::Body, http::Request};
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let id = admitted_id(&fixture).await;
            let before = (
                fixture.probe.decodes.load(SeqCst),
                fixture.probe.lookups.load(SeqCst),
                fixture.probe.writes.load(SeqCst),
            );
            for path in ["/v1/reports".into(), format!("/v1/reports/status/{id}")] {
                let request = Request::builder().uri(&path).body(Body::from("x")).unwrap();
                transport_refusal(&fixture, false, request, "invalid_request", 400).await;
                for query in ["?", "?q=ignored"] {
                    let request = Request::builder()
                        .uri(format!("{path}{query}"))
                        .header("content-type", "application/json")
                        .body(Body::empty())
                        .unwrap();
                    transport_refusal(&fixture, false, request, "invalid_request", 400).await;
                }
            }
            for (media, encoding) in [("application/json", "gzip"), ("text/plain", "identity")] {
                let valid = body(json!({"urls":["https://synthetic.example.test/item"],
                    "suspected_illegality":"Synthetic evidence"}));
                let request = Request::builder()
                    .method("POST")
                    .uri("/v1/reports/illegal-content")
                    .header("content-type", media)
                    .header("content-encoding", encoding)
                    .body(Body::from(serde_json::to_vec(&valid).unwrap()))
                    .unwrap();
                transport_refusal(&fixture, false, request, "unsupported_media_type", 415).await;
            }
            let chunks = futures::stream::iter([
                Ok::<_, std::io::Error>(vec![b' '; 32768]),
                Ok(vec![b' '; 32769]),
            ]);
            let request = Request::builder()
                .method("POST")
                .uri("/v1/reports/illegal-content")
                .header("content-type", "application/json")
                .body(Body::from_stream(chunks))
                .unwrap();
            transport_refusal(&fixture, false, request, "request_too_large", 413).await;
            assert_eq!(
                (
                    fixture.probe.decodes.load(SeqCst),
                    fixture.probe.lookups.load(SeqCst),
                    fixture.probe.writes.load(SeqCst)
                ),
                before
            );
            let valid = body(json!({"urls":["https://synthetic.example.test/item"],
                "suspected_illegality":"Synthetic evidence"}));
            let request = Request::builder()
                .method("POST")
                .uri("/v1/reports/illegal-content")
                .header("content-type", "application/json")
                .header("content-encoding", "identity")
                .body(Body::from(serde_json::to_vec(&valid).unwrap()))
                .unwrap();
            let accepted = fixture.raw(false, request).await;
            contract_headers(&accepted);
            assert!(accepted.value["ticket_id"].is_string());
            assert_eq!(accepted.status, 200);
            super::support::successful_response(
                fixture
                    .send(false, "GET", "/v1/reports", Value::Null, false)
                    .await,
            );
        });
    }

    fn references(value: &Value, schemas: &serde_json::Map<String, Value>) {
        match value {
            Value::Object(object) => {
                if let Some(reference) = object.get("$ref") {
                    let name = reference
                        .as_str()
                        .unwrap()
                        .strip_prefix("#/components/schemas/")
                        .unwrap();
                    assert!(name.starts_with("V1") && schemas.contains_key(name));
                }
                for value in object.values() {
                    references(value, schemas);
                }
            }
            Value::Array(values) => {
                for value in values {
                    references(value, schemas);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn compliance_openapi_matches_routes_types_errors_and_listeners() {
        let document = serde_json::to_value(stract::api::v1::openapi()).unwrap();
        assert!(document["info"]["description"].as_str().unwrap().contains(
            "Every operation lists the uniform twelve statuses; 401 and 409 are returned only by /v1/compliance operations."
        ));
        let schemas = document["components"]["schemas"].as_object().unwrap();
        assert!(schemas.keys().all(|key| key.starts_with("V1")));
        references(&document, schemas);
        assert_eq!(schemas["V1ErrorCode"]["enum"].as_array().unwrap().len(), 44);
        literal_operations(&document);
        literal_queue_schemas(schemas);
        for name in [
            "V1Milestones",
            "V1AdminResult",
            "V1OpenQueueItem",
            "V1QueueResponse",
        ] {
            let schema = &schemas[name];
            let required = schema["required"].as_array().unwrap();
            let properties = schema["properties"].as_object().unwrap();
            assert_eq!(required.len(), properties.len(), "{name}");
            assert!(
                properties.keys().all(|key| required.contains(&json!(key))),
                "{name}"
            );
        }
        assert_eq!(schemas["V1TrueDeclaration"]["enum"], json!([true]));
        assert_eq!(
            schemas["V1IllegalContentReport"]["additionalProperties"],
            false
        );
        assert!(document["info"]["description"]
            .as_str()
            .unwrap()
            .contains("whole-name query rules"));
        assert!(!document["info"]["description"]
            .as_str()
            .unwrap()
            .contains("Global suppression applies to every context."));
    }

    async fn administration(
        fixture: &HttpFixture,
        id: &str,
        action: &str,
        mut value: Value,
    ) -> super::support::Observed {
        value["actor"] = json!("reviewer");
        fixture
            .send(
                true,
                "POST",
                &format!("/v1/compliance/tickets/{id}/{action}"),
                value,
                true,
            )
            .await
    }

    fn communication() -> Value {
        json!({"channel":"manual_api","reference":"synthetic-communication"})
    }

    fn assessment() -> Value {
        let mut value = json!({});
        for key in [
            "natural_person",
            "name_search",
            "role_in_public_life",
            "child",
            "accuracy",
            "working_life",
            "hate_speech_or_defamation",
            "sensitive_data",
            "currency",
            "prejudice",
            "risk",
            "original_basis_of_publication",
            "journalistic_context",
            "legal_power_or_obligation_to_publish",
            "criminal_offence",
            "offence_seriousness",
            "time_elapsed",
            "spent_status",
            "reasoned_decision",
        ] {
            value[key] = json!("Synthetic reasoned assessment");
        }
        value
    }

    async fn visible(fixture: &HttpFixture, query: &str, country: &str, adult: Value) -> bool {
        let before = super::support::tree(fixture.domain.config.store_dir());
        let writes = fixture.probe.writes.load(SeqCst);
        let response = fixture
            .send(
                false,
                "POST",
                "/v1/search",
                json!({"query":query,"country":country,"adult_verified":adult}),
                false,
            )
            .await;
        assert_eq!(fixture.probe.writes.load(SeqCst), writes);
        assert_eq!(
            super::support::tree(fixture.domain.config.store_dir()),
            before
        );
        contract_headers(&response);
        assert!(
            response.value["results"].is_array(),
            "search response lacks results array"
        );
        let results = response.value["results"].as_array().unwrap();
        assert!(results
            .iter()
            .any(|page| page["url"] == "https://unrelated.example.test/item"));
        let visible = results
            .iter()
            .any(|page| page["url"] == "https://synthetic.example.test/item");
        assert_eq!(response.status, 200);
        visible
    }

    #[test]
    fn name_delisting_matches_whole_names_and_evidenced_pseudonyms() {
        concurrent_rule_precedes_assembly();
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let response = fixture
                .send(
                    false,
                    "POST",
                    "/v1/reports/data-rights",
                    body(json!({
                "urls":["https://synthetic.example.test/item"],"request_kind":"delisting",
                "names":[{"name":"Elise Dupont",
                    "kind":"legal_name",
                    "evidence":"Synthetic evidence"},
                    {"name":"River Stone",
                        "kind":"pseudonym",
                        "evidence":"Synthetic evidence"}]})),
                    false,
                )
                .await;
            assert!(visible(&fixture, "Elise Dupont", "unknown", Value::Null).await);
            contract_headers(&response);
            let id = response.value["ticket_id"].as_str().unwrap();
            assert_eq!(response.status, 200);
            let granted = administration(
                &fixture,
                id,
                "decision",
                json!({"decision":{"kind":"granted",
                "reasons":"Synthetic delisting grant",
                    "delivery":communication(),
                    "assessment":assessment()}}),
            )
            .await;
            for country in ["UK", "non-UK", "unknown"] {
                for adult in [Value::Null, json!(false), json!(true)] {
                    // Leading decomposable accents must match through the shared normalization.
                    for (query, expected) in [
                        ("cedar", true),
                        ("Elise Dupont", false),
                        ("ELISÉ DÙPONT", false),
                        ("River Stone", false),
                        ("Elise", true),
                        ("Elise Stone", true),
                        ("Elisex Dupont", true),
                        ("ÉLISE DÙPONT", false),
                    ] {
                        assert_eq!(
                            visible(&fixture, query, country, adult.clone()).await,
                            expected,
                            "synthetic query={query}, country={country}, adult={adult}"
                        );
                    }
                }
            }
            let private =
                fs::read_to_string(fixture.domain.config.rules_dir().join("snapshot.json"))
                    .unwrap();
            assert!(
                !private.contains("Elise")
                    && !private.contains("Dupont")
                    && !private.contains("River")
            );
            contract_headers(&granted);
            assert_eq!(granted.value["state"], "actioned");
            assert_eq!(granted.status, 200);
            let global = admitted_id(&fixture).await;
            let observed_effect = administration(
                &fixture,
                &global,
                "decision",
                json!({"decision":{"kind":"granted",
                "reasons":"Independent synthetic ground","delivery":communication()}}),
            )
            .await;
            assert!(!visible(&fixture, "cedar", "non-UK", json!(true)).await);
            super::support::successful_response(observed_effect);
            fixture.state.compliance().shutdown().await;
        });
        additional_name_spellings();
    }

    fn additional_name_spellings() {
        for (name, pseudonym, queries) in [
            (
                "Élise Dupont",
                None,
                vec![
                    ("Elise Dupont", false),
                    ("élise dupont", false),
                    ("news Élise Dupont", false),
                    ("ÉLISE DUPONT", false),
                    ("cedar", true),
                    ("Elise", true),
                ],
            ),
            (
                "Øystein Hansen",
                None,
                vec![
                    ("news Øystein Hansen", false),
                    ("øystein hansen", false),
                    ("Oystein Hansen", true),
                    ("cedar", true),
                    ("Hansen", true),
                ],
            ),
            (
                "Øystein Hansen",
                Some("Oystein Hansen"),
                vec![
                    ("Oystein Hansen", false),
                    ("news Øystein Hansen", false),
                    ("cedar", true),
                ],
            ),
        ] {
            name_spelling_case(name, pseudonym, &queries);
        }
    }

    fn name_spelling_case(name: &str, pseudonym: Option<&str>, queries: &[(&str, bool)]) {
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let mut names = vec![json!({"name":name,
                "kind":"legal_name",
                "evidence":"Synthetic evidence"})];
            if let Some(alias) = pseudonym {
                names.push(json!({"name":alias,
                    "kind":"pseudonym",
                    "evidence":"Synthetic evidence"}));
            }
            let input = body(json!({"urls":["https://synthetic.example.test/item"],
                "request_kind":"delisting",
                "names":names}));
            let admitted = fixture
                .send(false, "POST", "/v1/reports/data-rights", input, false)
                .await;
            contract_headers(&admitted);
            let id = admitted.value["ticket_id"].as_str().unwrap();
            assert_eq!(admitted.status, 200);
            let grant = administration(
                &fixture,
                id,
                "decision",
                json!({"decision":{"kind":"granted",
                "reasons":"Synthetic name grant",
                    "delivery":communication(),
                    "assessment":assessment()}}),
            )
            .await;
            contract_headers(&grant);
            assert_eq!(grant.value["state"], "actioned");
            assert_eq!(grant.status, 200);
            for country in ["UK", "non-UK", "unknown"] {
                for adult in [Value::Null, json!(false), json!(true)] {
                    for (query, expected) in queries {
                        assert_eq!(
                            visible(&fixture, query, country, adult.clone()).await,
                            *expected,
                            "{query}"
                        );
                    }
                }
            }
            fixture.state.compliance().shutdown().await;
        });
    }

    fn concurrent_rule_precedes_assembly() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let id = admitted_id(&fixture).await;
            fixture.probe.hold_assembly.store(true, SeqCst);
            let app = stract::api::v1::compose_api(axum::Router::new(), fixture.state.clone());
            let request = Request::builder()
                .method("POST")
                .uri("/v1/search")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"query":"cedar"}"#))
                .unwrap();
            let pending = tokio::spawn(app.oneshot(request));
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                fixture.probe.assembly_reached.notified(),
            )
            .await
            .unwrap();
            let granted = administration(
                &fixture,
                &id,
                "decision",
                json!({"decision":{"kind":"granted",
                "reasons":"Synthetic concurrent grant","delivery":communication()}}),
            )
            .await;
            let before = tree(fixture.domain.config.store_dir());
            let writes = fixture.probe.writes.load(SeqCst);
            fixture.probe.hold_assembly.store(false, SeqCst);
            fixture.probe.assembly_resume.notify_one();
            let response = tokio::time::timeout(std::time::Duration::from_secs(3), pending)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(tree(fixture.domain.config.store_dir()), before);
            assert_eq!(fixture.probe.writes.load(SeqCst), writes);
            contract_headers(&granted);
            assert_eq!(granted.value["state"], "actioned");
            assert_eq!(granted.status, 200);
            let response = contract_response(response).await;
            let results = response.value["results"].as_array().unwrap();
            assert!(results
                .iter()
                .all(|item| item["url"] != "https://synthetic.example.test/item"));
            assert!(results
                .iter()
                .any(|item| item["url"] == "https://unrelated.example.test/item"));
            assert_eq!(response.status, 200);
            fixture.state.compliance().shutdown().await;
        });
    }

    async fn intimate_id(fixture: &HttpFixture) -> String {
        let response = fixture
            .send(
                false,
                "POST",
                "/v1/reports/intimate-images",
                body(json!({
            "urls":["https://synthetic.example.test/item"],
                "intimate_image_content":true,
                "subject_or_authorised":true,
                "good_faith":true})),
                false,
            )
            .await;
        admission_id(response)
    }

    fn admission_id(response: super::support::Observed) -> String {
        contract_headers(&response);
        let id = response.value["ticket_id"].as_str().unwrap().to_owned();
        assert_eq!(id.len(), 64);
        assert_eq!(
            response.value["status_path"],
            format!("/v1/reports/status/{id}")
        );
        assert_eq!(response.status, 200);
        id
    }

    #[test]
    fn intimate_margin_enforces_without_a_scheduler() {
        let fixture =
            HttpFixture::configured(|config| config.compliance.intimate_margin_seconds = 3600);
        let runtime = runtime();
        runtime.block_on(async {
            intimate_id(&fixture).await;
            for (instant, expected) in [
                ("2026-09-20T10:59:59Z", true),
                ("2026-09-20T11:00:00Z", false),
                ("2026-09-20T11:00:01Z", false),
                ("2026-09-20T11:59:00Z", false),
                ("2026-09-20T12:00:01Z", false),
            ] {
                fixture.domain.clock.set_utc(utc(instant)).unwrap();
                assert_eq!(
                    visible(&fixture, "cedar", "unknown", Value::Null).await,
                    expected
                );
            }
            fixture.state.compliance().shutdown().await;
        });
        let HttpFixture { domain, state, .. } = fixture;
        drop(state);
        domain.clock.set_utc(utc("2026-09-20T12:30:00Z")).unwrap();
        let reopened = domain.store();
        runtime.block_on(async {
            use stract::compliance::{
                listed::HostCache,
                model::DocumentKey,
                rules::{query_tokens, RuleContext, RuleCountry},
            };
            let url = "https://synthetic.example.test/item";
            let key = DocumentKey::parse(&super::support::digest(url.as_bytes())).unwrap();
            let gate = reopened.rules().read().await;
            assert!(!gate.allows(
                &key,
                url,
                &query_tokens("cedar"),
                &RuleContext {
                    country: RuleCountry::Unknown,
                    is_child: true,
                    uk_measures: true
                },
                reopened.rules().serving_now(),
                &mut HostCache::default()
            ));
            drop(gate);
            reopened.shutdown().await;
        });
        let immediate = HttpFixture::new();
        runtime.block_on(async {
            intimate_id(&immediate).await;
            assert!(!visible(&immediate, "cedar", "unknown", Value::Null).await);
        });
    }

    #[test]
    fn intimate_determinations_remove_only_the_provisional_rule() {
        for margin in [None, Some(3600)] {
            for determination in ["not_intimate_image", "no_standing", "granted", "refused"] {
                let fixture = match margin {
                    None => HttpFixture::new(),
                    Some(seconds) => HttpFixture::configured(|config| {
                        config.compliance.intimate_margin_seconds = seconds
                    }),
                };
                runtime().block_on(async {
                    let id = intimate_id(&fixture).await;
                    assert_eq!(
                        visible(&fixture, "cedar", "UK", json!(true)).await,
                        margin.is_some()
                    );
                    let response = administration(
                        &fixture,
                        &id,
                        "decision",
                        json!({"decision":{"kind":determination,
                    "reasons":"Synthetic determination","delivery":communication()}}),
                    )
                    .await;
                    assert_eq!(
                        visible(&fixture, "cedar", "UK", json!(true)).await,
                        matches!(determination, "not_intimate_image" | "no_standing")
                            || (margin.is_some() && determination == "refused")
                    );
                    contract_headers(&response);
                    assert_eq!(
                        response.value["state"],
                        if determination == "granted" {
                            "actioned"
                        } else {
                            "decided"
                        }
                    );
                    assert_eq!(response.status, 200);
                    if determination != "granted" {
                        super::support::successful_response(
                            administration(
                                &fixture,
                                &id,
                                "close",
                                json!({"reasons":"Synthetic closure"}),
                            )
                            .await,
                        );
                    }
                    fixture
                        .domain
                        .clock
                        .set_utc(utc("2026-09-20T12:00:01Z"))
                        .unwrap();
                    assert_eq!(
                        visible(&fixture, "cedar", "unknown", Value::Null).await,
                        matches!(determination, "not_intimate_image" | "no_standing")
                    );
                    let other = admitted_id(&fixture).await;
                    let observed_effect = administration(
                        &fixture,
                        &other,
                        "decision",
                        json!({"decision":{"kind":"granted",
                    "reasons":"Independent synthetic grant","delivery":communication()}}),
                    )
                    .await;
                    assert!(!visible(&fixture, "cedar", "unknown", Value::Null).await);
                    super::support::successful_response(observed_effect);
                });
            }
        }
    }

    #[test]
    fn reversal_restores_rule_and_blocks_same_ground_reapplication() {
        let fixture = HttpFixture::new();
        let runtime = runtime();
        runtime.block_on(async {
            let id = admitted_id(&fixture).await;
            let observed_effect = administration(
                &fixture,
                &id,
                "decision",
                json!({"decision":{"kind":"granted",
                "reasons":"Synthetic grant","delivery":communication()}}),
            )
            .await;
            assert!(!visible(&fixture, "cedar", "unknown", Value::Null).await);
            super::support::successful_response(observed_effect);
            super::support::successful_response(
                administration(
                    &fixture,
                    &id,
                    "appeal",
                    json!({"reasons":"Synthetic appeal"}),
                )
                .await,
            );
            let reversed = administration(
                &fixture,
                &id,
                "reversal",
                json!({"reasons":"Synthetic reversal","delivery":communication()}),
            )
            .await;
            assert!(visible(&fixture, "cedar", "unknown", Value::Null).await);
            contract_headers(&reversed);
            assert_eq!(reversed.value["state"], "reversed");
            assert_eq!(reversed.status, 200);
            let second = admitted_id(&fixture).await;
            let before = fs::read(fixture.domain.path("events.jsonl")).unwrap();
            let files = super::support::tree(fixture.domain.config.store_dir());
            let writes = fixture.probe.writes.load(SeqCst);
            let rejected = administration(
                &fixture,
                &second,
                "decision",
                json!({"decision":{"kind":"granted",
                "reasons":"Synthetic same ground","delivery":communication()}}),
            )
            .await;
            assert_eq!(
                super::support::tree(fixture.domain.config.store_dir()),
                files
            );
            assert_eq!(fixture.probe.writes.load(SeqCst), writes);
            assert_eq!(
                fs::read(fixture.domain.path("events.jsonl")).unwrap(),
                before
            );
            contract_headers(&rejected);
            assert_eq!(rejected.value["error"]["code"], "invalid_transition");
            assert_eq!(rejected.status, 409);
            assert!(visible(&fixture, "cedar", "unknown", Value::Null).await);
            intimate_id(&fixture).await;
            assert!(!visible(&fixture, "cedar", "unknown", Value::Null).await);
            fixture.state.compliance().shutdown().await;
        });
        let HttpFixture { domain, state, .. } = fixture;
        drop(state);
        let before = fs::read(domain.config.rules_dir().join("snapshot.json")).unwrap();
        let reopened = domain.store();
        assert_eq!(
            fs::read(domain.config.rules_dir().join("snapshot.json")).unwrap(),
            before
        );
        runtime.block_on(reopened.shutdown());
    }

    async fn data_id(fixture: &HttpFixture) -> String {
        let response = fixture
            .send(
                false,
                "POST",
                "/v1/reports/data-rights",
                body(json!({"urls":["https://synthetic.example.test/item"],
            "request_kind":"erasure","names":[]})),
                false,
            )
            .await;
        admission_id(response)
    }

    async fn queued_deadline(fixture: &HttpFixture, id: &str) -> i64 {
        let page = fixture
            .send(
                true,
                "POST",
                "/v1/compliance/queue",
                json!({"actor":"reader"}),
                true,
            )
            .await;
        contract_headers(&page);
        let due = page.value["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["ticket_id"] == id)
            .unwrap()["deadline_at"]
            .as_i64()
            .unwrap();
        assert_eq!(page.status, 200);
        due
    }

    #[test]
    fn data_rights_month_clamps_and_moves_relevant_time() {
        calendar_deadline_cases();
        moved_queue_deadlines();
        relevant_time_epochs();
    }

    fn calendar_deadline_cases() {
        for (receipt, due) in [
            ("2026-01-31T10:15:00Z", "2026-02-28T10:15:00Z"),
            ("2024-01-31T10:15:00Z", "2024-02-29T10:15:00Z"),
            ("2026-01-20T12:00:00Z", "2026-02-20T12:00:00Z"),
        ] {
            let fixture = HttpFixture::new();
            fixture.domain.clock.set_utc(utc(receipt)).unwrap();
            runtime().block_on(async {
                let id = data_id(&fixture).await;
                assert_eq!(queued_deadline(&fixture, &id).await, utc(due).timestamp());
                for delta in [-1, 0, 1] {
                    fixture
                        .domain
                        .clock
                        .set_utc(
                            chrono::DateTime::from_timestamp(utc(due).timestamp() + delta, 0)
                                .unwrap(),
                        )
                        .unwrap();
                    assert_queue_clock(&fixture, &id, utc(due).timestamp(), delta == 1).await;
                    assert_eq!(
                        clock::data_rights_overdue(
                            utc(receipt).timestamp(),
                            false,
                            fixture.domain.clock.utc().timestamp()
                        )
                        .unwrap(),
                        delta == 1
                    );
                }
            });
        }
    }

    fn relevant_time_epochs() {
        let fixture = HttpFixture::new();
        fixture
            .domain
            .clock
            .set_utc(utc("2026-01-31T10:15:00Z"))
            .unwrap();
        runtime().block_on(async {
            let id = data_id(&fixture).await;
            let observed_effect = administration(
                &fixture,
                &id,
                "identity",
                json!({"event":"request_identity","reasons":"Synthetic request"}),
            )
            .await;
            assert_eq!(
                queued_deadline(&fixture, &id).await,
                utc("2026-02-28T10:15:00Z").timestamp()
            );
            super::support::successful_response(observed_effect);
            fixture
                .domain
                .clock
                .set_utc(utc("2026-02-02T09:00:00Z"))
                .unwrap();
            let observed_effect = administration(
                &fixture,
                &id,
                "identity",
                json!({"event":"identity_confirmed","reasons":"Synthetic confirmation"}),
            )
            .await;
            assert_eq!(
                queued_deadline(&fixture, &id).await,
                utc("2026-03-02T09:00:00Z").timestamp()
            );
            super::support::successful_response(observed_effect);
            let observed_effect = administration(
                &fixture,
                &id,
                "identity",
                json!({"event":"request_clarification","reasons":"Synthetic enquiry"}),
            )
            .await;
            assert_eq!(
                queued_deadline(&fixture, &id).await,
                utc("2026-03-02T09:00:00Z").timestamp()
            );
            super::support::successful_response(observed_effect);
            fixture
                .domain
                .clock
                .set_utc(utc("2026-02-05T08:00:00Z"))
                .unwrap();
            let observed_effect = administration(
                &fixture,
                &id,
                "identity",
                json!({"event":"clarification_received","reasons":"Synthetic reply"}),
            )
            .await;
            assert_eq!(
                queued_deadline(&fixture, &id).await,
                utc("2026-03-05T08:00:00Z").timestamp()
            );
            super::support::successful_response(observed_effect);
            let status = fixture
                .send(
                    false,
                    "GET",
                    &format!("/v1/reports/status/{id}"),
                    Value::Null,
                    false,
                )
                .await;
            contract_headers(&status);
            assert_eq!(
                status.value["received_at"],
                utc("2026-01-31T10:15:00Z").timestamp()
            );
            assert_eq!(status.status, 200);
        });
    }

    #[test]
    fn extension_requires_notice_inside_first_calendar_month() {
        for delta in [-1, 0, 1] {
            for necessity in ["complexity", "volume"] {
                let fixture = HttpFixture::new();
                fixture
                    .domain
                    .clock
                    .set_utc(utc("2026-01-31T10:15:00Z"))
                    .unwrap();
                runtime().block_on(async {
                    let id = data_id(&fixture).await;
                    fixture
                        .domain
                        .clock
                        .set_utc(
                            chrono::DateTime::from_timestamp(
                                utc("2026-02-28T10:15:00Z").timestamp() + delta,
                                0,
                            )
                            .unwrap(),
                        )
                        .unwrap();
                    let before = fs::read(fixture.domain.path("events.jsonl")).unwrap();
                    let files = super::support::tree(fixture.domain.config.store_dir());
                    let writes = fixture.probe.writes.load(SeqCst);
                    let input = json!({"necessity":necessity,
                        "reasons":"Synthetic extension reasons",
                        "notice":"Synthetic essential notice",
                        "delivery":communication()});
                    let response = administration(&fixture, &id, "extension", input.clone()).await;
                    if delta == 1 {
                        assert_eq!(
                            fs::read(fixture.domain.path("events.jsonl")).unwrap(),
                            before
                        );
                        assert_eq!(
                            super::support::tree(fixture.domain.config.store_dir()),
                            files
                        );
                        assert_eq!(fixture.probe.writes.load(SeqCst), writes);
                        contract_headers(&response);
                        assert_eq!(response.value["error"]["code"], "invalid_transition");
                        assert_eq!(response.status, 409);
                        return;
                    }
                    assert_eq!(
                        queued_deadline(&fixture, &id).await,
                        utc("2026-04-30T10:15:00Z").timestamp()
                    );
                    contract_headers(&response);
                    assert_eq!(response.value["state"], "queued");
                    assert_eq!(response.status, 200);
                    let extended = fs::read(fixture.domain.path("events.jsonl")).unwrap();
                    let repeated = administration(&fixture, &id, "extension", input.clone()).await;
                    assert_eq!(
                        fs::read(fixture.domain.path("events.jsonl")).unwrap(),
                        extended
                    );
                    super::support::rejected_response(repeated, "invalid_transition", 409);
                    super::support::successful_response(
                        administration(
                            &fixture,
                            &id,
                            "identity",
                            json!({"event":"request_identity",
                        "reasons":"Synthetic request"}),
                        )
                        .await,
                    );
                    fixture
                        .domain
                        .clock
                        .set_utc(utc("2026-03-01T09:00:00Z"))
                        .unwrap();
                    let observed_effect = administration(
                        &fixture,
                        &id,
                        "identity",
                        json!({"event":"identity_confirmed",
                        "reasons":"Synthetic confirmation"}),
                    )
                    .await;
                    assert_eq!(
                        queued_deadline(&fixture, &id).await,
                        utc("2026-04-01T09:00:00Z").timestamp()
                    );
                    super::support::successful_response(observed_effect);
                    let observed_effect = administration(&fixture, &id, "extension", input).await;
                    assert_eq!(
                        queued_deadline(&fixture, &id).await,
                        utc("2026-06-01T09:00:00Z").timestamp()
                    );
                    super::support::successful_response(observed_effect);
                });
            }
        }
    }

    #[test]
    fn progress_and_opt_out_preserve_essential_notices_and_deadlines() {
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let id = data_id(&fixture).await;
            let due = queued_deadline(&fixture, &id).await;
            let before = fixture
                .send(
                    false,
                    "GET",
                    &format!("/v1/reports/status/{id}"),
                    Value::Null,
                    false,
                )
                .await;
            contract_headers(&before);
            assert_eq!(before.value["state"], "queued");
            assert_eq!(before.status, 200);
            fixture
                .domain
                .clock
                .set_utc(utc("2026-09-20T12:00:00Z"))
                .unwrap();
            let response = administration(
                &fixture,
                &id,
                "progress",
                json!({"enquiries":"Synthetic enquiries",
                "update":"Synthetic essential progress","delivery":communication()}),
            )
            .await;
            assert_eq!(queued_deadline(&fixture, &id).await, due);
            contract_headers(&response);
            assert_eq!(
                response.value["notice"]["text"],
                "Synthetic essential progress"
            );
            assert_eq!(response.status, 200);
            let after = fixture
                .send(
                    false,
                    "GET",
                    &format!("/v1/reports/status/{id}"),
                    Value::Null,
                    false,
                )
                .await;
            contract_headers(&after);
            assert_eq!(before.bytes, after.bytes);
            assert_eq!(after.status, 200);
            let decision = administration(
                &fixture,
                &id,
                "decision",
                json!({"decision":{"kind":"refused",
                "reasons":"Synthetic refusal with essential notice","delivery":communication()}}),
            )
            .await;
            contract_headers(&decision);
            assert_eq!(
                decision.value["notice"]["remedies"]
                    .as_array()
                    .unwrap()
                    .len(),
                3
            );
            assert_eq!(decision.status, 200);
            let private = administration(&fixture, &id, "read", json!({})).await;
            contract_headers(&private);
            assert_eq!(
                private.value["payload_events"][0]["intake"]["report"]["nonessential_opt_out"],
                true
            );
            assert_eq!(private.value["payload_events"][1]["kind"], "progress");
            assert_eq!(private.status, 200);
        });
    }

    #[test]
    fn purge_due_view_lists_exactly_the_eligible_closed_tickets() {
        let fixture = HttpFixture::new();
        fixture
            .domain
            .clock
            .set_utc(utc("2024-02-29T12:00:00Z"))
            .unwrap();
        runtime().block_on(async {
            let closed = admitted_id(&fixture).await;
            super::support::successful_response(
                administration(
                    &fixture,
                    &closed,
                    "decision",
                    json!({"decision":{
                        "kind":"refused",
                        "reasons":"Synthetic refusal",
                        "delivery":communication()
                    }}),
                )
                .await,
            );
            super::support::successful_response(
                administration(
                    &fixture,
                    &closed,
                    "close",
                    json!({"reasons":"Synthetic closure"}),
                )
                .await,
            );
            let open = admitted_id(&fixture).await;
            for (instant, count) in [
                ("2027-02-28T11:59:59Z", 0),
                ("2027-02-28T12:00:00Z", 1),
                ("2027-02-28T12:00:01Z", 1),
            ] {
                fixture.domain.clock.set_utc(utc(instant)).unwrap();
                let files = super::support::tree(fixture.domain.config.store_dir());
                let writes = fixture.probe.writes.load(SeqCst);
                let response = fixture
                    .send(
                        true,
                        "POST",
                        "/v1/compliance/queue",
                        json!({"actor":"reader", "view":"purge_due"}),
                        true,
                    )
                    .await;
                assert_eq!(
                    super::support::tree(fixture.domain.config.store_dir()),
                    files
                );
                assert_eq!(fixture.probe.writes.load(SeqCst), writes);
                contract_headers(&response);
                assert!(
                    response.value["items"].is_array(),
                    "purge_due response lacks items array"
                );
                assert_eq!(response.value["items"].as_array().unwrap().len(), count);
                if count == 1 {
                    assert_eq!(
                        response.value["items"][0],
                        json!({"ticket_id":closed,
                        "closed_at":utc("2024-02-29T12:00:00Z").timestamp(),
                        "eligible_at":utc("2027-02-28T12:00:00Z").timestamp()})
                    );
                }
                assert_eq!(response.status, 200);
                default_queue_is_open(&fixture, &open).await;
            }
            super::support::successful_response(
                administration(&fixture, &closed, "purge", json!({})).await,
            );
            let files = super::support::tree(fixture.domain.config.store_dir());
            let writes = fixture.probe.writes.load(SeqCst);
            let due = fixture
                .send(
                    true,
                    "POST",
                    "/v1/compliance/queue",
                    json!({"actor":"reader",
                "view":"purge_due"}),
                    true,
                )
                .await;
            assert_eq!(
                super::support::tree(fixture.domain.config.store_dir()),
                files
            );
            assert_eq!(fixture.probe.writes.load(SeqCst), writes);
            contract_headers(&due);
            assert_eq!(due.value["items"], json!([]));
            assert_eq!(due.status, 200);
        });
    }

    async fn default_queue_is_open(fixture: &HttpFixture, open: &str) {
        let files = super::support::tree(fixture.domain.config.store_dir());
        let writes = fixture.probe.writes.load(SeqCst);
        let default = fixture
            .send(
                true,
                "POST",
                "/v1/compliance/queue",
                json!({"actor":"reader"}),
                true,
            )
            .await;
        assert_eq!(
            super::support::tree(fixture.domain.config.store_dir()),
            files
        );
        assert_eq!(fixture.probe.writes.load(SeqCst), writes);
        let explicit = fixture
            .send(
                true,
                "POST",
                "/v1/compliance/queue",
                json!({"actor":"reader",
            "view":"open"}),
                true,
            )
            .await;
        assert_eq!(
            super::support::tree(fixture.domain.config.store_dir()),
            files
        );
        assert_eq!(fixture.probe.writes.load(SeqCst), writes);
        contract_headers(&default);
        contract_headers(&explicit);
        for response in [&default, &explicit] {
            assert!(response.value["items"].is_array());
            assert_eq!(response.value["items"].as_array().unwrap().len(), 1);
            assert_eq!(response.value["items"][0]["ticket_id"], open);
        }
        assert_eq!(default.bytes, explicit.bytes);
        assert_eq!(default.status, 200);
        assert_eq!(explicit.status, 200);
    }

    const EXPECTED_BOUNDS: &[(
        stract::compliance::bounds::BoundKey,
        Option<u64>,
        u64,
        u64,
        &str,
    )] = {
        use stract::compliance::bounds::BoundKey::*;
        &[
            (Contact, None, 1, 254, "bytes"),
            (Narrative, None, 1, 4096, "bytes"),
            (Reason, None, 1, 2048, "bytes"),
            (Evidence, None, 1, 1024, "bytes"),
            (Url, None, 1, 2048, "bytes"),
            (Urls, None, 1, 16, "items"),
            (Name, None, 1, 128, "bytes"),
            (RequiredNames, None, 1, 8, "items"),
            (OptionalNames, None, 0, 8, "items"),
            (NameTokens, None, 1, 16, "items"),
            (Actor, None, 1, 64, "bytes"),
            (Label, None, 1, 128, "bytes"),
            (Slug, None, 1, 64, "bytes"),
            (DeliveryRef, None, 1, 128, "bytes"),
            (QueueLimit, Some(20), 1, 50, "items"),
            (JournalRow, None, 1, 8192, "bytes"),
            (PayloadFile, None, 1, 65536, "bytes"),
            (ServiceNotice, None, 1, 65536, "bytes"),
            (TicketPayload, None, 0, 1048576, "bytes"),
            (ListFile, None, 1, 16777216, "bytes"),
            (ListEntries, None, 0, 100000, "items"),
            (TokenBytes, None, 32, 32, "bytes"),
            (IdBytes, None, 32, 32, "bytes"),
            (SaltBytes, None, 32, 32, "bytes"),
            (HexBytes, None, 64, 64, "bytes"),
            (TokenFile, None, 64, 65, "bytes"),
            (RecordItems, None, 1, 64, "items"),
            (OptionalRecordItems, None, 0, 64, "items"),
            (RecordHistory, None, 1, 32, "items"),
            (OptionalHistory, None, 0, 32, "items"),
            (PriorityKinds, None, 17, 17, "items"),
            (ChildrenClasses, None, 3, 3, "items"),
            (MeasureRows, None, 28, 28, "items"),
            (ReleaseChanges, None, 0, 10, "items"),
            (IntimateMargin, Some(172800), 1, 172800, "seconds"),
            (RetentionMonths, Some(36), 36, 120, "months"),
            (MaxTickets, Some(10000), 1, 100000, "items"),
            (MaxTicketEvents, Some(256), 16, 256, "events"),
            (
                MaxJournalBytes,
                Some(268435456),
                1048576,
                2684354560,
                "bytes",
            ),
            (
                MaxPayloadBytes,
                Some(268435456),
                1048576,
                2684354560,
                "bytes",
            ),
            (MaxRules, Some(100000), 1, 100000, "items"),
            (MaxRulesBytes, Some(16777216), 4096, 16777216, "bytes"),
            (MaxRecords, Some(10000), 1, 10000, "items"),
            (MaxRecordBytes, Some(1048576), 4096, 1048576, "bytes"),
            (
                MaxRecordsBytes,
                Some(268435456),
                1048576,
                2684354560,
                "bytes",
            ),
            (ReadingAge, Some(12), 8, 16, "years"),
            (ReservedEvents, Some(4), 4, 4, "events"),
            (ReservedJournalBytes, Some(65536), 65536, 65536, "bytes"),
        ]
    };

    #[test]
    fn compliance_bounds_table_matches_literal_contract() {
        use stract::compliance::bounds::RANGE_SPECS;
        let actual = RANGE_SPECS
            .iter()
            .map(|row| row.key)
            .collect::<std::collections::BTreeSet<_>>();
        let expected = EXPECTED_BOUNDS
            .iter()
            .map(|row| row.0)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual.len(), RANGE_SPECS.len());
        assert_eq!(expected.len(), EXPECTED_BOUNDS.len());
        assert_eq!(actual, expected);
        for (key, default, min, max, unit) in EXPECTED_BOUNDS {
            let row = RANGE_SPECS.iter().find(|row| row.key == *key).unwrap();
            assert_eq!(
                (row.default, row.min, row.max, row.unit),
                (*default, *min, *max, *unit)
            );
        }
        let fixture = super::support::DomainFixture::new();
        let sample: stract::config::ApiConfig =
            toml::from_str(include_str!("../../../configs/api.toml")).unwrap();
        assert!(sample
            .compliance
            .validate(
                &fixture
                    .config
                    .store_dir()
                    .parent()
                    .unwrap()
                    .join("suppression.json")
            )
            .is_ok());
        let mut nondefault = sample.compliance;
        nondefault.intimate_margin_seconds = 3600;
        nondefault.retention_months = 48;
        nondefault.max_tickets = 15000;
        assert!(nondefault
            .validate(
                &fixture
                    .config
                    .store_dir()
                    .parent()
                    .unwrap()
                    .join("suppression.json")
            )
            .is_ok());
    }

    #[test]
    fn compliance_defaults_and_configuration_are_finite() {
        use stract::config::compliance::ComplianceConfig;
        let fixture = super::support::DomainFixture::new();
        let suppression = fixture
            .config
            .store_dir()
            .parent()
            .unwrap()
            .join("suppression.json");
        let default = serde_json::to_value(ComplianceConfig::default()).unwrap();
        assert_eq!(default["deployment_mode"], "local");
        assert_eq!(default["store_dir"], Value::Null);
        for (field, initial, low, high) in [
            ("intimate_margin_seconds", 172800u64, 1u64, 172800u64),
            ("retention_months", 36, 36, 120),
            ("max_tickets", 10000, 1, 100000),
            ("max_ticket_events", 256, 16, 256),
            ("max_journal_bytes", 268435456, 1048576, 2684354560),
            ("max_payload_bytes", 268435456, 1048576, 2684354560),
            ("max_rules", 100000, 1, 100000),
            ("max_rules_bytes", 16777216, 4096, 16777216),
            ("max_records", 10000, 1, 10000),
            ("max_record_bytes", 1048576, 4096, 1048576),
            ("max_records_bytes", 268435456, 1048576, 2684354560),
            ("reading_age", 12, 8, 16),
        ] {
            assert_eq!(default[field], initial);
            for (value, valid) in [
                (low, true),
                (high, true),
                (low - 1, false),
                (high + 1, false),
            ] {
                let mut changed = default.clone();
                changed[field] = json!(value);
                // Keep the independent per-file cap compatible while testing aggregate bounds.
                if field == "max_records_bytes" {
                    changed["max_record_bytes"] = json!(4096);
                }
                let config: ComplianceConfig = serde_json::from_value(changed).unwrap();
                assert_eq!(
                    config.validate(&suppression).is_ok(),
                    valid,
                    "{field} at {value}"
                );
            }
        }
        for field in [
            "public_contact",
            "priority_catalog_version",
            "priority_catalog_source",
            "ico_complaints_url",
            "statement_proactive",
            "statement_complaints",
            "statement_children_primary",
            "statement_children_priority",
            "statement_children_other",
        ] {
            let mut changed = default.clone();
            changed[field] = json!("");
            assert!(serde_json::from_value::<ComplianceConfig>(changed)
                .unwrap()
                .validate(&suppression)
                .is_err());
        }
        let mut hosted = default.clone();
        hosted["deployment_mode"] = json!("hosted");
        assert!(serde_json::from_value::<ComplianceConfig>(hosted)
            .unwrap()
            .validate(&suppression)
            .is_ok());
        for (field, value) in [
            ("statement_version", json!("other-version")),
            ("store_dir", json!(suppression)),
            ("records_dir", json!(fixture.config.rules_dir())),
            ("admin_token_file", json!(suppression)),
            (
                "listed_hashes_file",
                json!(fixture.config.journal_dir().join("listed.json")),
            ),
        ] {
            let mut changed = default.clone();
            changed[field] = value;
            assert!(serde_json::from_value::<ComplianceConfig>(changed)
                .unwrap()
                .validate(&suppression)
                .is_err());
        }
        let mut unknown = default.clone();
        unknown["unrecognised"] = json!(true);
        assert!(serde_json::from_value::<ComplianceConfig>(unknown).is_err());
        let mut missing = default;
        missing["statement_changes"] = json!([{"version":"619.1"}]);
        assert!(serde_json::from_value::<ComplianceConfig>(missing.clone())
            .unwrap()
            .validate(&suppression)
            .is_ok());
        missing["statement_changes"][0]["unrecognised"] = json!(true);
        assert!(serde_json::from_value::<ComplianceConfig>(missing).is_err());
        assert!(!fixture.config.store_dir().exists());
    }

    async fn rejects_without_writes(fixture: &HttpFixture, path: &str, request: Value) {
        let before = super::support::tree(fixture.domain.config.store_dir());
        let writes = fixture.probe.writes.load(SeqCst);
        let response = fixture
            .send(
                path.starts_with("/v1/compliance/"),
                "POST",
                path,
                request,
                true,
            )
            .await;
        assert_eq!(fixture.probe.writes.load(SeqCst), writes);
        assert_eq!(
            super::support::tree(fixture.domain.config.store_dir()),
            before
        );
        contract_headers(&response);
        assert_eq!(response.value["error"]["code"], "invalid_request");
        assert_eq!(response.status, 400);
    }

    #[test]
    fn all_intake_and_admin_bounds_precede_every_write() {
        explicit_declarations_and_body_cap();
        every_text_field_has_byte_boundaries();
        nested_request_shapes();
        name_and_url_boundaries();
        use stract::compliance::bounds::{self, BoundKey, TextClass};
        for (key, _, low, high, _) in EXPECTED_BOUNDS {
            assert!(key.validate(*low).is_ok());
            assert!(key.validate(*high).is_ok());
            if *low > 0 {
                assert!(key.validate(low - 1).is_err());
            }
            assert!(key.validate(high + 1).is_err());
        }
        assert!(bounds::text(&"x".repeat(128), BoundKey::Label, TextClass::Label).is_ok());
        assert!(bounds::text(&"x".repeat(129), BoundKey::Label, TextClass::Label).is_err());
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let base = body(json!({"urls":["https://synthetic.example.test/item"],
                "suspected_illegality":"Synthetic evidence"}));
            for (pointer, max) in [
                ("/report/contact/address", 254),
                ("/report/description", 4096),
                ("/suspected_illegality", 1024),
            ] {
                for value in [
                    "".into(),
                    " \t\n".into(),
                    "x".repeat(max + 1),
                    "é".repeat(max / 2 + 1),
                    "x\0y".into(),
                    "x\u{1b}y".into(),
                ] {
                    let mut input = base.clone();
                    *input.pointer_mut(pointer).unwrap() = json!(value);
                    rejects_without_writes(&fixture, "/v1/reports/illegal-content", input).await;
                }
                let mut input = base.clone();
                *input.pointer_mut(pointer).unwrap() = json!("x".repeat(max));
                super::support::successful_response(
                    fixture
                        .send(false, "POST", "/v1/reports/illegal-content", input, false)
                        .await,
                );
            }
            for urls in [
                json!([]),
                json!([
                    "https://synthetic.example.test/item",
                    "https://synthetic.example.test/item#fragment"
                ]),
                json!((0..17)
                    .map(|index| format!("https://synthetic.example.test/{index}"))
                    .collect::<Vec<_>>()),
                json!(["not a URL"]),
                json!([format!(
                    "https://{}:{}@example.test/",
                    "synthetic", "invalid"
                )]),
                json!(["file:///tmp/synthetic"]),
            ] {
                let mut input = base.clone();
                input["urls"] = urls;
                rejects_without_writes(&fixture, "/v1/reports/illegal-content", input).await;
            }
            for pointer in ["", "/report", "/report/contact"] {
                let mut input = base.clone();
                input.pointer_mut(pointer).unwrap()["unknown"] = json!(true);
                rejects_without_writes(&fixture, "/v1/reports/illegal-content", input).await;
            }
            for pointer in [
                "/report/nonessential_opt_out",
                "/report/requester_type",
                "/report/contact/method",
                "/urls",
                "/suspected_illegality",
            ] {
                let mut input = base.clone();
                *input.pointer_mut(pointer).unwrap() = Value::Null;
                rejects_without_writes(&fixture, "/v1/reports/illegal-content", input).await;
            }
            let id = admitted_id(&fixture).await;
            for reasons in ["".into(), " ".into(), "x".repeat(2049), "x\0".into()] {
                rejects_without_writes(
                    &fixture,
                    &format!("/v1/compliance/tickets/{id}/decision"),
                    json!({"actor":"reviewer",
                    "decision":{"kind":"refused",
                        "reasons":reasons,
                        "delivery":communication()}}),
                )
                .await;
            }
            rejects_without_writes(
                &fixture,
                "/v1/compliance/queue",
                json!({"actor":"reviewer",
                "limit":51}),
            )
            .await;
            rejects_without_writes(
                &fixture,
                "/v1/compliance/queue",
                json!({"actor":"reviewer",
                "limit":0}),
            )
            .await;
        });
    }

    fn shape_requests(id: &str) -> Vec<(String, Value)> {
        let mut requests = intake_shape_requests(id);
        requests.extend(admin_shape_requests(id));
        requests.extend(decision_shape_requests(id));
        requests
    }

    fn intake_shape_requests(id: &str) -> Vec<(String, Value)> {
        vec![
            (
                "/v1/reports/illegal-content".into(),
                body(json!({"urls":["https://synthetic.example.test/item"],
                        "suspected_illegality":"evidence"})),
            ),
            (
                "/v1/reports/harmful-to-children".into(),
                body(json!({"urls":["https://synthetic.example.test/item"],
                        "harm_description":"evidence"})),
            ),
            (
                "/v1/reports/intimate-images".into(),
                body(json!({"urls":["https://synthetic.example.test/item"],
                        "intimate_image_content":true,
                        "subject_or_authorised":true,
                        "good_faith":true})),
            ),
            (
                "/v1/reports/site-complaints".into(),
                body(json!({"urls":["https://synthetic.example.test/item"],
                        "interest":"responsible_uk_person",
                        "related_ticket_id":id})),
            ),
            (
                "/v1/reports/rights-removal".into(),
                body(json!({"urls":["https://synthetic.example.test/item"],
                        "rights_basis":"evidence",
                        "authority":"evidence"})),
            ),
            (
                "/v1/reports/data-rights".into(),
                body(json!({"urls":["https://synthetic.example.test/item"],
                        "request_kind":"delisting",
                        "names":[{"name":"River Stone",
                        "kind":"pseudonym",
                        "evidence":"evidence"}]})),
            ),
            (
                "/v1/reports/data-protection-complaints".into(),
                body(json!({})),
            ),
            (
                "/v1/reports/online-safety-complaints".into(),
                body(json!({})),
            ),
        ]
    }

    fn admin_shape_requests(id: &str) -> Vec<(String, Value)> {
        let mut requests = vec![(
            "/v1/compliance/queue".into(),
            json!({"actor":"reviewer","view":"open","limit":20,"after_ticket_id":id}),
        )];
        for (action, value) in [
            ("read", json!({})),
            ("purge", json!({})),
            (
                "identity",
                json!({"event":"request_identity","reasons":"evidence"}),
            ),
            (
                "extension",
                json!({"necessity":"complexity",
                    "reasons":"evidence",
                    "notice":"notice",
                    "delivery":communication()}),
            ),
            (
                "appeal",
                json!({"reasons":"evidence","related_ticket_id":id}),
            ),
            (
                "reversal",
                json!({"reasons":"evidence","delivery":communication()}),
            ),
            (
                "uphold",
                json!({"reasons":"evidence","delivery":communication()}),
            ),
            (
                "progress",
                json!({"enquiries":"enquiries","update":"update","delivery":communication()}),
            ),
            ("close", json!({"reasons":"evidence"})),
        ] {
            let mut value = value;
            value["actor"] = json!("reviewer");
            requests.push((format!("/v1/compliance/tickets/{id}/{action}"), value));
        }
        requests
    }

    fn decision_shape_requests(id: &str) -> Vec<(String, Value)> {
        let mut requests = Vec::new();
        for kind in [
            "granted",
            "refused",
            "not_intimate_image",
            "no_standing",
            "manifestly_unfounded",
        ] {
            let mut decision = json!({"kind":kind,"reasons":"evidence","delivery":communication()});
            if kind == "granted" {
                decision["assessment"] = assessment();
            }
            if kind == "manifestly_unfounded" {
                decision["policy_version"] = json!("619.1");
                decision["policy_clause"] = json!("duplicate_without_new_information");
                decision["duplicate_of"] = json!(id);
            }
            requests.push((
                format!("/v1/compliance/tickets/{id}/decision"),
                json!({"actor":"reviewer","decision":decision}),
            ));
        }
        requests
    }

    fn object_paths(value: &Value, pointer: String, output: &mut Vec<String>) {
        match value {
            Value::Object(fields) => {
                output.push(pointer.clone());
                for (key, child) in fields {
                    object_paths(child, format!("{pointer}/{key}"), output);
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    object_paths(child, format!("{pointer}/{index}"), output);
                }
            }
            _ => {}
        }
    }

    async fn rejects_raw_without_writes(fixture: &HttpFixture, path: &str, bytes: Vec<u8>) {
        use axum::{body::Body, http::Request};
        let before = super::support::tree(fixture.domain.config.store_dir());
        let writes = fixture.probe.writes.load(SeqCst);
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", fixture.token))
            .body(Body::from(bytes))
            .unwrap();
        let response = fixture
            .raw(path.starts_with("/v1/compliance/"), request)
            .await;
        assert_eq!(fixture.probe.writes.load(SeqCst), writes);
        assert_eq!(
            super::support::tree(fixture.domain.config.store_dir()),
            before
        );
        contract_headers(&response);
        assert_eq!(response.value["error"]["code"], "invalid_request");
        assert_eq!(response.status, 400, "shape path={path}");
    }

    fn nested_request_shapes() {
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let id = admitted_id(&fixture).await;
            for (path, base) in shape_requests(&id) {
                let mut objects = Vec::new();
                object_paths(&base, String::new(), &mut objects);
                for pointer in objects {
                    let mut extra = base.clone();
                    extra.pointer_mut(&pointer).unwrap()["unexpected"] = json!(true);
                    rejects_without_writes(&fixture, &path, extra).await;
                    for (key, value) in base.pointer(&pointer).unwrap().as_object().unwrap() {
                        let mut wrong = base.clone();
                        wrong.pointer_mut(&pointer).unwrap()[key] = if value.is_array() {
                            json!({})
                        } else {
                            json!([])
                        };
                        rejects_without_writes(&fixture, &path, wrong).await;
                        let optional = matches!(
                            key.as_str(),
                            "after_ticket_id"
                                | "related_ticket_id"
                                | "assessment"
                                | "limit"
                                | "view"
                        );
                        if !optional {
                            let mut absent = base.clone();
                            absent
                                .pointer_mut(&pointer)
                                .unwrap()
                                .as_object_mut()
                                .unwrap()
                                .remove(key);
                            rejects_without_writes(&fixture, &path, absent).await;
                            let mut null = base.clone();
                            null.pointer_mut(&pointer).unwrap()[key] = Value::Null;
                            rejects_without_writes(&fixture, &path, null).await;
                        }
                        let needle = format!("\"{key}\":");
                        let duplicate = serde_json::to_string(&base).unwrap().replacen(
                            &needle,
                            &format!("\"{key}\":null,{needle}"),
                            1,
                        );
                        rejects_raw_without_writes(&fixture, &path, duplicate.into_bytes()).await;
                    }
                }
            }
        });
    }

    fn name_and_url_boundaries() {
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let base = body(json!({"urls":["https://synthetic.example.test/item"],
                "request_kind":"delisting",
                "names":[{"name":"River Stone",
                    "kind":"pseudonym",
                    "evidence":"Synthetic evidence"}]}));
            for names in [
                json!([]),
                json!((0..9).map(|_| base["names"][0].clone()).collect::<Vec<_>>()),
            ] {
                let mut input = base.clone();
                input["names"] = names;
                rejects_without_writes(&fixture, "/v1/reports/data-rights", input).await;
            }
            for name in [
                "".into(),
                " ".into(),
                "!!!".into(),
                "x".repeat(129),
                "é".repeat(65),
                (0..17)
                    .map(|index| format!("word{index}"))
                    .collect::<Vec<_>>()
                    .join(" "),
            ] {
                let mut input = base.clone();
                input["names"][0]["name"] = json!(name);
                rejects_without_writes(&fixture, "/v1/reports/data-rights", input).await;
            }
            let name = (0..16)
                .map(|index| format!("word{index}"))
                .collect::<Vec<_>>()
                .join(" ");
            for names in [
                vec![base["names"][0].clone(); 8],
                vec![json!({"name":name,
                "kind":"legal_name",
                "evidence":"evidence"})],
            ] {
                let mut input = base.clone();
                input["names"] = json!(names);
                super::support::successful_response(
                    fixture
                        .send(false, "POST", "/v1/reports/data-rights", input, false)
                        .await,
                );
            }
            let mut input = base.clone();
            let urls = (0..16)
                .map(|index| format!("https://synthetic.example.test/{index}"))
                .collect::<Vec<_>>();
            input["urls"] = json!(urls);
            super::support::successful_response(
                fixture
                    .send(false, "POST", "/v1/reports/data-rights", input, false)
                    .await,
            );
            for length in [2048, 2049] {
                let prefix = "https://synthetic.example.test/";
                let mut input = base.clone();
                input["urls"] = json!([format!("{prefix}{}", "a".repeat(length - prefix.len()))]);
                let files = super::support::tree(fixture.domain.config.store_dir());
                let writes = fixture.probe.writes.load(SeqCst);
                let response = fixture
                    .send(false, "POST", "/v1/reports/data-rights", input, false)
                    .await;
                if length == 2049 {
                    assert_eq!(
                        super::support::tree(fixture.domain.config.store_dir()),
                        files
                    );
                    assert_eq!(fixture.probe.writes.load(SeqCst), writes);
                }
                contract_headers(&response);
                if length == 2048 {
                    let id = response.value["ticket_id"].as_str().unwrap();
                    assert_eq!(id.len(), 64);
                    assert!(id
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
                } else {
                    assert_eq!(response.value["error"]["code"], "invalid_request");
                }
                assert_eq!(response.status, if length == 2048 { 200 } else { 400 });
            }
        });
    }

    #[test]
    fn ticket_ids_use_full_random_entropy_and_strict_types() {
        use std::sync::{Arc, Mutex};
        use stract::compliance::{
            disk::NoHooks,
            model::{Entropy, IntakeKind, TicketId},
            rules::NoRulesHooks,
            tickets::{ComplianceStore, NoObserver},
            Error,
        };
        struct Fixed {
            widths: Mutex<Vec<usize>>,
            fail: bool,
        }
        impl Entropy for Fixed {
            fn fill(&self, bytes: &mut [u8]) -> stract::compliance::Result<()> {
                self.widths.lock().unwrap().push(bytes.len());
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = index as u8;
                }
                if self.fail {
                    Err(Error::Unavailable)
                } else {
                    Ok(())
                }
            }
        }
        for fail in [false, true] {
            let fixture = super::support::DomainFixture::new();
            let entropy = Arc::new(Fixed {
                widths: Mutex::new(Vec::new()),
                fail,
            });
            let store = ComplianceStore::open(
                &fixture.config,
                fixture.clock.clone(),
                entropy.clone(),
                Arc::new(NoHooks),
                Arc::new(NoRulesHooks),
                Arc::new(NoObserver),
                false,
            )
            .unwrap();
            let runtime = runtime();
            let before = super::support::tree(fixture.config.store_dir());
            let input = super::support::intake(IntakeKind::IllegalContent {
                suspected_illegality: "Synthetic evidence".into(),
            });
            let first = runtime.block_on(store.admit(input.clone(), Arc::new(())));
            if fail {
                assert!(matches!(first, Err(Error::Unavailable)));
                assert_eq!(super::support::tree(fixture.config.store_dir()), before);
                assert_eq!(*entropy.widths.lock().unwrap(), [32]);
            } else {
                let first = first.unwrap();
                let expected = (0..32)
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                assert_eq!(first.ticket.id.as_str(), expected);
                assert_eq!(*entropy.widths.lock().unwrap(), [32, 32]);
                let before = super::support::tree(fixture.config.store_dir());
                assert!(matches!(
                    runtime.block_on(store.admit(input, Arc::new(()))),
                    Err(Error::Unavailable)
                ));
                assert_eq!(super::support::tree(fixture.config.store_dir()), before);
            }
            runtime.block_on(store.shutdown());
        }
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let mut ids = std::collections::BTreeSet::new();
            for _ in 0..8 {
                let id = admitted_id(&fixture).await;
                assert!(TicketId::parse(&id).is_ok());
                assert!(ids.insert(id));
            }
        });
    }

    #[test]
    fn decisions_require_assessments_reasons_and_remedies() {
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let response = fixture
                .send(
                    false,
                    "POST",
                    "/v1/reports/data-rights",
                    body(json!({"urls":["https://synthetic.example.test/item"],
                "request_kind":"delisting",
                    "names":[{"name":"Synthetic Name",
                    "kind":"pseudonym",
                    "evidence":"Synthetic support"}]})),
                    false,
                )
                .await;
            contract_headers(&response);
            let id = response.value["ticket_id"].as_str().unwrap();
            assert_eq!(response.status, 200);
            let path = format!("/v1/compliance/tickets/{id}/decision");
            for field in assessment().as_object().unwrap().keys() {
                let mut missing = assessment();
                missing.as_object_mut().unwrap().remove(field);
                let mut blank = assessment();
                blank[field] = json!(" ");
                for value in [missing, blank] {
                    rejects_without_writes(
                        &fixture,
                        &path,
                        json!({"actor":"reviewer","decision":{
                        "kind":"granted",
                            "reasons":"Synthetic grant",
                            "delivery":communication(),
                            "assessment":value}}),
                    )
                    .await;
                }
            }
            rejects_without_writes(
                &fixture,
                &path,
                json!({"actor":"reviewer",
                "decision":{"kind":"granted",
                "reasons":"Synthetic grant",
                "delivery":communication()}}),
            )
            .await;
            super::support::successful_response(
                administration(
                    &fixture,
                    id,
                    "decision",
                    json!({"decision":{"kind":"granted",
                "reasons":"Synthetic grant",
                "delivery":communication(),
                "assessment":assessment()}}),
                )
                .await,
            );
            let illegal = admitted_id(&fixture).await;
            for kind in ["not_intimate_image", "no_standing"] {
                rejects_without_writes(
                    &fixture,
                    &format!("/v1/compliance/tickets/{illegal}/decision"),
                    json!({"actor":"reviewer",
                    "decision":{"kind":kind,
                        "reasons":"Synthetic incompatible decision",
                        "delivery":communication()}}),
                )
                .await;
            }
            let refused = administration(
                &fixture,
                &illegal,
                "decision",
                json!({"decision":{"kind":"refused",
                "reasons":"Synthetic refusal",
                "delivery":communication()}}),
            )
            .await;
            contract_headers(&refused);
            assert_eq!(
                refused.value["notice"]["remedies"],
                json!([
                    "You may complain to AVA through Reports and requests",
                    "You may complain to the Information Commissioner's Office",
                    "You may seek a judicial remedy"
                ])
            );
            assert_eq!(refused.status, 200);
            check_unfounded(&fixture, &illegal).await;
        });
    }

    async fn check_unfounded(fixture: &HttpFixture, unrelated: &str) {
        let closed = administration(
            fixture,
            unrelated,
            "close",
            json!({"reasons":"Synthetic concluded refusal"}),
        )
        .await;
        contract_headers(&closed);
        assert_eq!(closed.value["state"], "closed");
        assert_eq!(closed.status, 200);
        let first = fixture
            .send(
                false,
                "POST",
                "/v1/reports/online-safety-complaints",
                body(json!({})),
                false,
            )
            .await;
        let prior = first.value["ticket_id"].as_str().unwrap();
        let second = fixture
            .send(
                false,
                "POST",
                "/v1/reports/online-safety-complaints",
                body(json!({})),
                false,
            )
            .await;
        let id = second.value["ticket_id"].as_str().unwrap();
        let base = json!({"actor":"reviewer",
            "decision":{"kind":"manifestly_unfounded",
            "reasons":"Synthetic absence of new information",
            "delivery":communication(),
                "policy_version":"619.1",
                "policy_clause":"duplicate_without_new_information",
                "duplicate_of":prior}});
        let path = format!("/v1/compliance/tickets/{id}/decision");
        rejects_without_writes(fixture, &path, base.clone()).await;
        super::support::successful_response(
            administration(
                fixture,
                prior,
                "decision",
                json!({"decision":{"kind":"granted",
            "reasons":"Synthetic resolution",
            "delivery":communication()}}),
            )
            .await,
        );
        super::support::successful_response(
            administration(
                fixture,
                prior,
                "close",
                json!({"reasons":"Synthetic conclusion"}),
            )
            .await,
        );
        for (field, value) in [
            ("policy_version", "other-version"),
            ("policy_clause", "disagreement"),
            ("duplicate_of", unrelated),
        ] {
            let mut wrong = base.clone();
            wrong["decision"][field] = json!(value);
            rejects_without_writes(fixture, &path, wrong).await;
        }
        super::support::successful_response(fixture.send(true, "POST", &path, base, true).await);
    }

    #[test]
    fn new_errors_are_closed_sanitized_and_registered() {
        literal_codes();
        use axum::{
            body::{to_bytes, Body},
            http::Request,
            routing::get,
            Router,
        };
        use stract::api::v1::{
            error::{V1Error, V1Failure},
            finish_v1_router,
        };
        use tower::ServiceExt;
        let config: stract::config::ApiConfig =
            toml::from_str(include_str!("../../../configs/api.toml")).unwrap();
        runtime().block_on(async {
            for (failure, status, code, message) in [
                (
                    V1Failure::Unauthorised,
                    401,
                    "unauthorised",
                    "The request is not authorised",
                ),
                (
                    V1Failure::InvalidTransition,
                    409,
                    "invalid_transition",
                    "The ticket cannot make that transition",
                ),
                (
                    V1Failure::RetentionNotDue,
                    409,
                    "retention_not_due",
                    "The payload is not eligible for purge",
                ),
                (
                    V1Failure::ComplianceUnavailable,
                    503,
                    "compliance_unavailable",
                    "The compliance service is unavailable",
                ),
                (
                    V1Failure::ComplianceCapacity,
                    503,
                    "compliance_capacity",
                    "The compliance store is full",
                ),
                (
                    V1Failure::RulesUnavailable,
                    503,
                    "rules_unavailable",
                    "The serving rules are unavailable",
                ),
            ] {
                let router = finish_v1_router(
                    Router::new().route(
                        "/error",
                        get(move || async move { V1Error::failure(failure) }),
                    ),
                    &config.v1,
                );
                let response = router
                    .oneshot(
                        Request::builder()
                            .uri("/error")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let numeric_status = response.status().as_u16();
                let headers = response.headers().clone();
                let bytes = to_bytes(response.into_body(), 65536)
                    .await
                    .unwrap()
                    .to_vec();
                let observed = super::support::Observed {
                    status: numeric_status,
                    headers,
                    bytes,
                    value: Value::Null,
                };
                contract_headers(&observed);
                let value: Value = serde_json::from_slice(&observed.bytes).unwrap();
                assert_eq!(
                    value,
                    json!({"version":"v1","error":{"code":code,"message":message}})
                );
                assert_eq!(observed.status, status);
            }
        });
    }

    #[test]
    fn listed_matcher_blocks_url_host_and_every_parent_in_all_contexts() {
        use stract::compliance::{
            disk::NoHooks,
            listed::{HostCache, ListedMatcher},
            model::DocumentKey,
        };
        let exact = format!("https://{}.example.test/item", "url-only");
        let fixture = HttpFixture::configured(|config| {
            super::support::configure_list(
                config,
                std::slice::from_ref(&exact),
                &[
                    "listed.example.test".into(),
                    "xn--bcher-kva.example.test".into(),
                    "127.0.0.1".into(),
                    "[2001:db8::1]".into(),
                ],
            )
        });
        let matcher = ListedMatcher::load(&fixture.domain.config, &NoHooks).unwrap();
        for (url, expected) in [
            (exact.as_str(), true),
            ("https://url-only.example.test/other", false),
            ("https://listed.example.test/item", true),
            ("https://one.two.three.listed.example.test/item", true),
            ("https://listed.example.test./item", true),
            ("https://badlisted.example.test/item", false),
            ("https://bücher.example.test/item", true),
            ("https://127.0.0.1/item", true),
            ("https://127.0.0.2/item", false),
            ("https://[2001:db8:0:0::1]/item", true),
            ("https://[2001:db8::2]/item", false),
        ] {
            let (canonical, id) = stract::api::v1::suppression::canonical_identity(url).unwrap();
            let key = DocumentKey::parse(id.as_str()).unwrap();
            assert_eq!(
                matcher.denies(&key, &canonical, &mut HostCache::default()),
                expected
            );
        }
        let listed = HttpFixture::configured(|config| {
            super::support::configure_list(
                config,
                &[format!("https://{}.example.test/item", "synthetic")],
                &[],
            )
        });
        runtime().block_on(async {
            for country in ["UK", "non-UK", "unknown"] {
                for adult in [Value::Null, json!(false), json!(true)] {
                    assert!(!visible(&listed, "cedar", country, adult).await);
                }
            }
        });
        let path = fixture
            .domain
            .config
            .settings()
            .listed_hashes_file
            .as_ref()
            .unwrap();
        let original = fs::read(path).unwrap();
        for bytes in [
            b"not-json".to_vec(),
            serde_json::to_vec(&json!({"format_version":2,
            "version":"synthetic.1",
            "url_hashes":[],
            "host_hashes":[]}))
            .unwrap(),
        ] {
            fs::write(path, bytes).unwrap();
            assert!(ListedMatcher::load(&fixture.domain.config, &NoHooks).is_err());
        }
        fs::write(path, original).unwrap();
        assert!(ListedMatcher::load(&fixture.domain.config, &NoHooks).is_ok());
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ListedMatcher::load(&fixture.domain.config, &NoHooks).is_err());
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn listed_membership_never_enters_logs_errors_or_documents() {
        let trace = super::support::TraceCapture::new();
        tracing::info!("synthetic capture control");
        let url = format!("https://{}.example.test/item", "synthetic");
        let host = format!("{}.example.test", "host-listed");
        let hash = super::support::digest(url.as_bytes());
        let host_hash = super::support::digest(host.as_bytes());
        let fixture = HttpFixture::configured(|config| {
            super::support::configure_list(
                config,
                std::slice::from_ref(&url),
                std::slice::from_ref(&host),
            )
        });
        runtime().block_on(async {
            let mut input = body(json!({"urls":["https://unrelated.example.test/item"],
                "suspected_illegality":"Synthetic evidence"}));
            input["report"]["description"] = json!(format!("Synthetic private marker {url}"));
            let admitted = fixture
                .send(false, "POST", "/v1/reports/illegal-content", input, false)
                .await;
            contract_headers(&admitted);
            let id = admitted.value["ticket_id"].as_str().unwrap();
            assert_eq!(admitted.status, 200);
            let mut outputs = listed_public_outputs(&fixture, id).await;
            outputs.push(admitted.bytes.clone());
            outputs.push(serde_json::to_vec(&stract::api::v1::openapi()).unwrap());
            outputs.push(fs::read(fixture.domain.path("events.jsonl")).unwrap());
            let logs = trace.text();
            assert!(logs.contains("synthetic capture control"));
            outputs.push(logs.into_bytes());
            for output in outputs {
                let text = String::from_utf8(output).unwrap();
                assert!(!text.contains(&url));
                assert!(!text.contains(&hash));
                assert!(!text.contains(&host));
                assert!(!text.contains(&host_hash));
            }
            let rows = fs::read_to_string(fixture.domain.path("events.jsonl"))
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .collect::<Vec<_>>();
            let access = rows
                .iter()
                .filter(|row| row["event"] == "list_accessed")
                .collect::<Vec<_>>();
            assert_eq!(access.len(), 1);
            assert_eq!(access[0]["list_version"], "synthetic.1");
            assert_eq!(access[0]["url_count"], 1);
            assert_eq!(access[0]["host_count"], 1);
            assert_eq!(access[0]["asset_ids"], "");
            let private = administration(&fixture, id, "read", json!({})).await;
            contract_headers(&private);
            assert!(String::from_utf8(private.bytes).unwrap().contains(&url));
            assert_eq!(private.status, 200);
        });
    }

    async fn listed_public_outputs(fixture: &HttpFixture, id: &str) -> Vec<Vec<u8>> {
        let before = super::support::tree(fixture.domain.config.store_dir());
        let writes = fixture.probe.writes.load(SeqCst);
        let search = fixture
            .send(false, "POST", "/v1/search", json!({"query":"cedar"}), false)
            .await;
        assert_eq!(
            super::support::tree(fixture.domain.config.store_dir()),
            before
        );
        assert_eq!(fixture.probe.writes.load(SeqCst), writes);
        contract_headers(&search);
        let results = search.value["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["url"], "https://unrelated.example.test/item");
        let mut outputs = vec![search.bytes];
        assert_eq!(search.status, 200);
        for management in [false, true] {
            let index = fixture
                .send(management, "GET", "/v1/reports", Value::Null, false)
                .await;
            contract_headers(&index);
            assert!(index.value["routes"].is_array());
            outputs.push(index.bytes);
            assert_eq!(index.status, 200);
            let rejected = fixture
                .send(
                    management,
                    "POST",
                    "/v1/compliance/queue",
                    json!({"actor":"reader"}),
                    false,
                )
                .await;
            contract_headers(&rejected);
            assert_eq!(
                rejected.value["error"]["code"],
                if management {
                    "unauthorised"
                } else {
                    "not_found"
                }
            );
            outputs.push(rejected.bytes);
            assert_eq!(rejected.status, if management { 401 } else { 404 });
        }
        let status = fixture
            .send(
                false,
                "GET",
                &format!("/v1/reports/status/{id}"),
                Value::Null,
                false,
            )
            .await;
        assert_eq!(
            super::support::tree(fixture.domain.config.store_dir()),
            before
        );
        assert_eq!(fixture.probe.writes.load(SeqCst), writes);
        contract_headers(&status);
        assert_eq!(status.value["state"], "queued");
        outputs.push(status.bytes);
        assert_eq!(status.status, 200);
        outputs
    }

    #[test]
    fn report_text_is_inert_and_excluded_from_public_outputs() {
        let trace = super::support::TraceCapture::new();
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let marker = "<script>synthetic()</script> **private-marker**\nlog=pretend\t<&>";
            let mut input = body(json!({"urls":["https://synthetic.example.test/item"],
                "suspected_illegality":"Synthetic evidence"}));
            input["report"]["description"] = json!(marker);
            let admitted = fixture
                .send(false, "POST", "/v1/reports/illegal-content", input, false)
                .await;
            assert!(!fs::read_to_string(fixture.domain.path("events.jsonl"))
                .unwrap()
                .contains("private-marker"));
            contract_headers(&admitted);
            let id = admitted.value["ticket_id"].as_str().unwrap();
            assert_eq!(admitted.status, 200);
            let read = administration(&fixture, id, "read", json!({})).await;
            contract_headers(&read);
            assert_eq!(
                read.value["payload_events"][0]["intake"]["report"]["description"],
                marker
            );
            assert_eq!(read.status, 200);
            for response in [
                fixture
                    .send(false, "GET", "/v1/reports", Value::Null, false)
                    .await,
                fixture
                    .send(
                        false,
                        "GET",
                        &format!("/v1/reports/status/{id}"),
                        Value::Null,
                        false,
                    )
                    .await,
                admitted,
            ] {
                contract_headers(&response);
                assert!(!String::from_utf8(response.bytes.clone())
                    .unwrap()
                    .contains("private-marker"));
                assert_eq!(response.status, 200);
            }
            assert!(!fs::read_to_string(fixture.domain.path("events.jsonl"))
                .unwrap()
                .contains("private-marker"));
            assert!(!trace.text().contains("private-marker"));
        });
    }

    #[test]
    fn journal_replay_reconstructs_ticket_state_without_a_side_database() {
        cold_open_payload_counts();
        complete_history_replay();
        replay_refuses_unknown_or_inconsistent_rows();
        let fixture = HttpFixture::new();
        let runtime = runtime();
        let (id, expected, queue) = runtime.block_on(async {
            let id = data_id(&fixture).await;
            administration(
                &fixture,
                &id,
                "identity",
                json!({"event":"request_identity","reasons":"Synthetic request"}),
            )
            .await;
            fixture
                .domain
                .clock
                .set_utc(utc("2026-09-20T12:00:00Z"))
                .unwrap();
            super::support::successful_response(
                administration(
                    &fixture,
                    &id,
                    "identity",
                    json!({"event":"identity_confirmed","reasons":"Synthetic confirmation"}),
                )
                .await,
            );
            let status = fixture
                .send(
                    false,
                    "GET",
                    &format!("/v1/reports/status/{id}"),
                    Value::Null,
                    false,
                )
                .await;
            let queue = fixture
                .send(
                    true,
                    "POST",
                    "/v1/compliance/queue",
                    json!({"actor":"reader"}),
                    true,
                )
                .await;
            assert_eq!(
                status.value["received_at"],
                utc("2026-09-18T12:00:00Z").timestamp()
            );
            assert_eq!(
                status.value["queued_at"],
                utc("2026-09-20T12:00:00Z").timestamp()
            );
            assert_eq!(
                queue.value["items"][0]["deadline_at"],
                utc("2026-10-20T12:00:00Z").timestamp()
            );
            fixture.state.compliance().shutdown().await;
            (id, status.bytes, queue.bytes)
        });
        let before = super::support::tree(fixture.domain.config.store_dir());
        let reopened = fixture.reopen();
        assert_eq!(
            super::support::tree(reopened.domain.config.store_dir()),
            before
        );
        runtime.block_on(async {
            assert_eq!(
                reopened
                    .send(
                        false,
                        "GET",
                        &format!("/v1/reports/status/{id}"),
                        Value::Null,
                        false
                    )
                    .await
                    .bytes,
                expected
            );
            assert_eq!(
                reopened
                    .send(
                        true,
                        "POST",
                        "/v1/compliance/queue",
                        json!({"actor":"reader"}),
                        true
                    )
                    .await
                    .bytes,
                queue
            );
        });
    }

    #[test]
    fn transition_matrix_allows_only_declared_pairs() {
        reachable_transition_histories();
        transition_membership_table();
    }

    fn transition_states() -> [&'static str; 10] {
        [
            "received",
            "acknowledged",
            "identity_pending",
            "queued",
            "decided",
            "actioned",
            "appealed",
            "reversed",
            "upheld",
            "closed",
        ]
    }

    fn transition_events() -> [&'static str; 25] {
        [
            "received",
            "acknowledged",
            "queued",
            "identity_requested",
            "identity_confirmed",
            "clarification_requested",
            "clarification_received",
            "extension_notified",
            "decided",
            "action_intent",
            "rules_committed",
            "actioned",
            "appealed",
            "reversal_intent",
            "reversed",
            "upheld",
            "progress_communicated",
            "closed",
            "purge_intent",
            "purged",
            "list_accessed",
            "record_intent",
            "record_added",
            "review_opened",
            "tail_recovered",
        ]
    }

    fn allowed_transitions() -> [(&'static str, &'static str, &'static str); 30] {
        [
            ("received", "acknowledged", "acknowledged"),
            ("acknowledged", "queued", "queued"),
            ("queued", "identity_requested", "identity_pending"),
            ("queued", "clarification_requested", "identity_pending"),
            ("identity_pending", "identity_confirmed", "queued"),
            ("identity_pending", "clarification_received", "queued"),
            ("queued", "decided", "decided"),
            ("decided", "actioned", "actioned"),
            ("actioned", "appealed", "appealed"),
            ("decided", "appealed", "appealed"),
            ("appealed", "reversed", "reversed"),
            ("appealed", "upheld", "upheld"),
            ("decided", "closed", "closed"),
            ("actioned", "closed", "closed"),
            ("reversed", "closed", "closed"),
            ("upheld", "closed", "closed"),
            ("queued", "extension_notified", "queued"),
            ("identity_pending", "extension_notified", "identity_pending"),
            ("queued", "progress_communicated", "queued"),
            (
                "identity_pending",
                "progress_communicated",
                "identity_pending",
            ),
            ("decided", "progress_communicated", "decided"),
            ("actioned", "progress_communicated", "actioned"),
            ("appealed", "progress_communicated", "appealed"),
            ("closed", "purge_intent", "closed"),
            ("closed", "purged", "closed"),
            ("received", "action_intent", "received"),
            ("received", "rules_committed", "received"),
            ("decided", "action_intent", "decided"),
            ("decided", "rules_committed", "decided"),
            ("appealed", "reversal_intent", "appealed"),
        ]
    }

    fn transition_membership_table() {
        use stract::compliance::{journal::EventName, model::TicketState, transitions::successor};
        let allowed = allowed_transitions();
        for state in transition_states() {
            for event in transition_events() {
                let parsed: EventName = serde_json::from_value(json!(event)).unwrap();
                let actual = successor(TicketState::parse(state).unwrap(), parsed)
                    .ok()
                    .map(|state| state.as_str());
                let expected = allowed
                    .iter()
                    .find(|(from, action, _)| *from == state && *action == event)
                    .map(|(_, _, to)| *to);
                assert_eq!(actual, expected, "{state}/{event}");
            }
        }
        transition_history_after_close();
    }

    fn transition_history_after_close() {
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let id = admitted_id(&fixture).await;
            for action in ["close", "appeal", "reversal", "uphold"] {
                let before = super::support::tree(fixture.domain.config.store_dir());
                let input = if matches!(action, "reversal" | "uphold") {
                    json!({"reasons":"Synthetic reasons",
                    "delivery":communication()})
                } else {
                    json!({"reasons":"Synthetic reasons"})
                };
                let response = administration(&fixture, &id, action, input).await;
                assert_eq!(
                    super::support::tree(fixture.domain.config.store_dir()),
                    before
                );
                super::support::rejected_response(response, "invalid_transition", 409);
            }
            super::support::successful_response(
                administration(
                    &fixture,
                    &id,
                    "decision",
                    json!({"decision":{"kind":"refused",
                "reasons":"Synthetic refusal",
                "delivery":communication()}}),
                )
                .await,
            );
            super::support::successful_response(
                administration(
                    &fixture,
                    &id,
                    "appeal",
                    json!({"reasons":"Synthetic appeal"}),
                )
                .await,
            );
            super::support::rejected_response(
                administration(
                    &fixture,
                    &id,
                    "reversal",
                    json!({"reasons":"Synthetic impermissible grant",
                "delivery":communication()}),
                )
                .await,
                "invalid_transition",
                409,
            );
            super::support::successful_response(
                administration(
                    &fixture,
                    &id,
                    "uphold",
                    json!({"reasons":"Synthetic disposal",
                "delivery":communication()}),
                )
                .await,
            );
            super::support::successful_response(
                administration(
                    &fixture,
                    &id,
                    "close",
                    json!({"reasons":"Synthetic closure"}),
                )
                .await,
            );
            super::support::rejected_response(
                administration(
                    &fixture,
                    &id,
                    "progress",
                    json!({"enquiries":"Synthetic enquiry",
                "update":"Synthetic update",
                "delivery":communication()}),
                )
                .await,
                "invalid_transition",
                409,
            );
        });
    }

    #[test]
    fn all_response_classes_keep_entry_and_source_headers() {
        let fixture = HttpFixture::new();
        let capacity = HttpFixture::configured(|config| config.compliance.max_tickets = 1);
        runtime().block_on(async {
            let id = admitted_id(&fixture).await;
            for management in [false, true] {
                for (method, path, code, status) in [
                    ("GET", "/v1/source", None, 200),
                    ("GET", "/v1/reports", None, 200),
                    ("GET", "/v1/missing", Some("not_found"), 404),
                    ("GET", "/v1", Some("not_found"), 404),
                    ("GET", "/v1/", Some("not_found"), 404),
                    ("POST", "/v1/source", Some("method_not_allowed"), 405),
                    ("HEAD", "/v1/reports", None, 405),
                    ("GET", "/v1/reports?", Some("invalid_request"), 400),
                ] {
                    let before = super::support::tree(fixture.domain.config.store_dir());
                    let writes = fixture.probe.writes.load(SeqCst);
                    let response = fixture
                        .send(management, method, path, Value::Null, false)
                        .await;
                    assert_eq!(fixture.probe.writes.load(SeqCst), writes);
                    assert_eq!(
                        super::support::tree(fixture.domain.config.store_dir()),
                        before
                    );
                    contract_headers(&response);
                    if method == "HEAD" {
                        assert!(response.bytes.is_empty());
                    } else {
                        assert_eq!(response.value["version"], "v1");
                        if let Some(code) = code {
                            assert_eq!(response.value["error"]["code"], code);
                        }
                    }
                    assert_eq!(response.status, status);
                }
            }
            header_transport_classes(&fixture).await;
            let unauthorised = fixture
                .send(true, "POST", "/v1/compliance/queue", json!({}), false)
                .await;
            contract_headers(&unauthorised);
            assert_eq!(unauthorised.value["error"]["code"], "unauthorised");
            assert_eq!(unauthorised.status, 401);
            forbidden_admin_call(
                &fixture,
                &id,
                "close",
                json!({"reasons":"Synthetic invalid closure"}),
            )
            .await;
            admitted_id(&capacity).await;
            let before = super::support::tree(capacity.domain.config.store_dir());
            let writes = capacity.probe.writes.load(SeqCst);
            let full = capacity
                .send(
                    false,
                    "POST",
                    "/v1/reports/illegal-content",
                    body(json!({
                "urls":["https://synthetic.example.test/item"],
                    "suspected_illegality":"Synthetic evidence"})),
                    false,
                )
                .await;
            assert_eq!(capacity.probe.writes.load(SeqCst), writes);
            assert_eq!(
                super::support::tree(capacity.domain.config.store_dir()),
                before
            );
            contract_headers(&full);
            assert_eq!(full.value["error"]["code"], "compliance_capacity");
            assert_eq!(full.status, 503);
        });
        standalone_headers();
    }

    async fn header_transport_classes(fixture: &HttpFixture) {
        use axum::{body::Body, http::Request};
        for management in [false, true] {
            let (path, input) = if management {
                ("/v1/compliance/queue", json!({"actor":"reader"}))
            } else {
                (
                    "/v1/reports/illegal-content",
                    body(json!({"urls":["https://synthetic.example.test/item"],
                            "suspected_illegality":"Synthetic evidence"})),
                )
            };
            for oversized in [true, false] {
                let mut bytes = serde_json::to_vec(&input).unwrap();
                if oversized {
                    bytes.resize(65537, b' ');
                }
                let request = Request::builder()
                    .method("POST")
                    .uri(path)
                    .header(
                        "content-type",
                        if oversized {
                            "application/json"
                        } else {
                            "text/plain"
                        },
                    )
                    .header("authorization", format!("Bearer {}", fixture.token))
                    .body(Body::from(bytes))
                    .unwrap();
                let (code, status) = if oversized {
                    ("request_too_large", 413)
                } else {
                    ("unsupported_media_type", 415)
                };
                transport_refusal(fixture, management, request, code, status).await;
            }
        }
    }

    fn standalone_headers() {
        use axum::{
            body::{to_bytes, Body},
            http::{HeaderValue, Request, StatusCode},
            response::IntoResponse,
            routing::get,
            Router,
        };
        use stract::api::v1::{
            error::{V1Error, V1Failure},
            finish_v1_router,
        };
        use tower::ServiceExt;
        let mut config: stract::config::ApiConfig =
            toml::from_str(include_str!("../../../configs/api.toml")).unwrap();
        config.v1.request_timeout_ms = 10;
        runtime().block_on(async {
            let routes = Router::new()
                .route("/bare", get(|| async { StatusCode::CONFLICT }))
                .route("/panic", get(|| async { boundary_panic() }))
                .route(
                    "/slow",
                    get(|| async {
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        StatusCode::OK
                    }),
                )
                .route(
                    "/conflict",
                    get(|| async {
                        let mut response =
                            V1Error::failure(V1Failure::InvalidTransition).into_response();
                        for name in ["reports-and-requests", "source-offer", "x-api-version"] {
                            response
                                .headers_mut()
                                .append(name, HeaderValue::from_static("conflicting"));
                            response
                                .headers_mut()
                                .append(name, HeaderValue::from_static("duplicate"));
                        }
                        response
                    }),
                );
            let router = finish_v1_router(routes, &config.v1);
            for (path, status) in [
                ("/bare", 500),
                ("/panic", 500),
                ("/slow", 504),
                ("/conflict", 409),
            ] {
                let response = router
                    .clone()
                    .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                let observed = super::support::Observed {
                    status: response.status().as_u16(),
                    headers: response.headers().clone(),
                    value: Value::Null,
                    bytes: to_bytes(response.into_body(), 65536)
                        .await
                        .unwrap()
                        .to_vec(),
                };
                contract_headers(&observed);
                let value: Value = serde_json::from_slice(&observed.bytes).unwrap();
                let code = match path {
                    "/slow" => "request_timeout",
                    "/conflict" => "invalid_transition",
                    _ => "internal_error",
                };
                assert_eq!(value["error"]["code"], code);
                assert_eq!(observed.status, status);
            }
        });
    }

    #[test]
    fn clock_regression_and_overflow_never_create_permissive_state() {
        restart_before_last_journal_row();
        receipts_can_finish_in_reverse_order();
        cross_ticket_clock_regression_is_rejected();
        assert!(clock::instant(i64::MAX).is_err());
        assert!(clock::add_seconds(i64::MAX, i64::MAX).is_err());
        assert!(clock::add_months(chrono::DateTime::<Utc>::MAX_UTC.timestamp(), 1).is_err());
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let id = intimate_id(&fixture).await;
            assert!(!visible(&fixture, "cedar", "unknown", Value::Null).await);
            let before = super::support::tree(fixture.domain.config.store_dir());
            fixture
                .domain
                .clock
                .set_utc(utc("2026-09-17T12:00:00Z"))
                .unwrap();
            assert!(!visible(&fixture, "cedar", "unknown", Value::Null).await);
            let writes = fixture.probe.writes.load(SeqCst);
            let rejected = administration(
                &fixture,
                &id,
                "progress",
                json!({"enquiries":"Synthetic enquiry",
                "update":"Synthetic update",
                "delivery":communication()}),
            )
            .await;
            assert_eq!(
                super::support::tree(fixture.domain.config.store_dir()),
                before
            );
            assert_eq!(fixture.probe.writes.load(SeqCst), writes);
            contract_headers(&rejected);
            assert_eq!(rejected.value["error"]["code"], "compliance_unavailable");
            assert_eq!(rejected.status, 503);
            assert!(!visible(&fixture, "cedar", "unknown", Value::Null).await);
        });
    }

    fn cross_ticket_clock_regression_is_rejected() {
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let first = admitted_id(&fixture).await;
            at(&fixture.domain.clock, "2026-09-18T12:10:00Z");
            let progress = json!({
                "enquiries": "Synthetic enquiry",
                "update": "Synthetic update",
                "delivery": communication()
            });
            let accepted = administration(&fixture, &first, "progress", progress.clone()).await;
            contract_headers(&accepted);
            assert_eq!(accepted.value["state"], "queued");
            assert_eq!(accepted.status, 200);
            at(&fixture.domain.clock, "2026-09-18T13:00:00Z");
            let second = admitted_id(&fixture).await;
            assert_ne!(first, second);
            let before = super::support::tree(fixture.domain.config.store_dir());
            let writes = fixture.probe.writes.load(SeqCst);
            // The first ticket can advance from 12:10 to 12:30, but the journal cannot
            // regress behind the second ticket's 13:00 event. This isolates the global guard.
            at(&fixture.domain.clock, "2026-09-18T12:30:00Z");
            let rejected = administration(&fixture, &first, "progress", progress).await;
            assert_eq!(fixture.probe.writes.load(SeqCst), writes);
            assert_eq!(
                super::support::tree(fixture.domain.config.store_dir()),
                before
            );
            contract_headers(&rejected);
            assert_eq!(rejected.value["error"]["code"], "compliance_unavailable");
            assert_eq!(rejected.status, 503);
            assert!(visible(&fixture, "cedar", "unknown", Value::Null).await);
            fixture.state.compliance().shutdown().await;
        });
    }

    #[test]
    fn journal_and_rules_have_independent_availability() {
        runtime_journal_corruption();
        required_payload_corruption();
        bad_rules_startup();
        legacy_suppression_availability();
        let fixture = HttpFixture::new();
        let runtime = runtime();
        runtime.block_on(async {
            intimate_id(&fixture).await;
            fixture.state.compliance().shutdown().await;
        });
        let path = fixture.domain.path("events.jsonl");
        let mut bytes = fs::read(&path).unwrap();
        bytes[2] ^= 1;
        fs::write(path, bytes).unwrap();
        let reopened = fixture.reopen();
        runtime.block_on(async {
            let index = reopened
                .send(false, "GET", "/v1/reports", Value::Null, false)
                .await;
            contract_headers(&index);
            assert_eq!(index.value["error"]["code"], "compliance_unavailable");
            assert_eq!(index.status, 503);
            assert!(!visible(&reopened, "cedar", "unknown", Value::Null).await);
            super::support::successful_response(
                reopened
                    .send(false, "GET", "/v1/source", Value::Null, false)
                    .await,
            );
            super::support::rejected_response(
                reopened
                    .send(
                        true,
                        "POST",
                        "/v1/compliance/queue",
                        json!({"actor":"reader"}),
                        false,
                    )
                    .await,
                "unauthorised",
                401,
            );
        });
        uncertain_rules_fixture();
    }

    fn uncertain_rules_fixture() {
        use std::sync::{atomic::AtomicBool, Arc};
        use stract::compliance::rules::{RulesHooks, RulesStage};
        struct Fault(AtomicBool);
        impl RulesHooks for Fault {
            fn at(&self, stage: RulesStage) -> std::io::Result<()> {
                if stage == RulesStage::SyncDirectory && self.0.load(SeqCst) {
                    return Err(std::io::Error::other("synthetic uncertainty"));
                }
                Ok(())
            }
        }
        let hooks = Arc::new(Fault(AtomicBool::new(false)));
        let fixture = HttpFixture::instrumented(|_| {}, |seams| seams.rules_hooks = hooks.clone());
        runtime().block_on(async {
            let id = admitted_id(&fixture).await;
            hooks.0.store(true, SeqCst);
            let action = administration(
                &fixture,
                &id,
                "decision",
                json!({"decision":{"kind":"granted",
                "reasons":"Synthetic grant",
                "delivery":communication()}}),
            )
            .await;
            contract_headers(&action);
            assert_eq!(action.value["error"]["code"], "rules_unavailable");
            assert_eq!(action.status, 503);
            let before = fixture.probe.backend.load(SeqCst);
            let search = fixture
                .send(false, "POST", "/v1/search", json!({"query":"cedar"}), false)
                .await;
            assert_eq!(fixture.probe.backend.load(SeqCst), before);
            contract_headers(&search);
            assert_eq!(search.value["error"]["code"], "rules_unavailable");
            assert_eq!(search.status, 503);
        });
    }

    #[test]
    fn beta_bytes_and_delete_contract_remain_unchanged() {
        let golden = include_bytes!("fixtures/api_v1/beta-openapi.json");
        let expected = [
            177u8, 164, 46, 156, 148, 157, 87, 237, 172, 113, 111, 228, 243, 70, 216, 23, 51, 239,
            177, 175, 44, 253, 253, 130, 101, 173, 248, 114, 251, 235, 167, 43,
        ];
        assert_eq!(
            ring::digest::digest(&ring::digest::SHA256, golden).as_ref(),
            expected
        );
        let search = include_bytes!("fixtures/api_v1/beta-search.json");
        let expected = [
            215u8, 49, 155, 93, 83, 112, 192, 132, 162, 119, 192, 183, 53, 192, 167, 156, 3, 245,
            53, 45, 0, 156, 70, 230, 214, 42, 232, 136, 247, 27, 97, 131,
        ];
        assert_eq!(
            ring::digest::digest(&ring::digest::SHA256, search).as_ref(),
            expected
        );
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let (_, id) = stract::api::v1::suppression::canonical_identity(
                "https://synthetic.example.test/item",
            )
            .unwrap();
            let path = format!("/v1/documents/{}", id.as_str());
            let first = fixture
                .send(true, "DELETE", &path, Value::Null, false)
                .await;
            let suppression = fixture
                .domain
                .config
                .store_dir()
                .parent()
                .unwrap()
                .join("suppression.json");
            let bytes = fs::read(&suppression).unwrap();
            assert_eq!(
                bytes,
                format!("{{\"format_version\":1,\"ids\":[\"{}\"]}}\n", id.as_str()).as_bytes()
            );
            contract_headers(&first);
            assert_eq!(
                first.value,
                json!({"version":"v1","id":id.as_str(),"suppressed":true})
            );
            assert_eq!(first.status, 200);
            let repeat = fixture
                .send(true, "DELETE", &path, Value::Null, false)
                .await;
            assert_eq!(fs::read(suppression).unwrap(), bytes);
            contract_headers(&repeat);
            assert_eq!(repeat.bytes, first.bytes);
            assert_eq!(repeat.status, 200);
            assert!(!visible(&fixture, "cedar", "unknown", Value::Null).await);
            let legacy = fixture
                .send(false, "GET", "/beta/not-a-route", Value::Null, false)
                .await;
            assert!(!legacy.headers.contains_key("reports-and-requests"));
            assert_eq!(legacy.status, 404);
        });
    }

    #[test]
    fn intimate_clock_is_48_hours_from_receipt() {
        queue_clock_boundary(
            "intimate-images",
            "2026-09-18T12:00:00Z",
            "2026-09-20T12:00:00Z",
        );
        delayed_intimate_grants();
        let manual = ManualClock::new(utc("2026-09-18T12:00:00Z"));
        let received = manual.utc().timestamp();
        assert_eq!(
            clock::intimate_due(received).unwrap(),
            utc("2026-09-20T12:00:00Z").timestamp()
        );
        for (value, expected) in [
            ("2026-09-20T11:59:59Z", true),
            ("2026-09-20T12:00:00Z", true),
            ("2026-09-20T12:00:01Z", false),
        ] {
            assert_eq!(
                clock::intimate_on_time(received, at(&manual, value)).unwrap(),
                expected
            );
            assert_eq!(received, utc("2026-09-18T12:00:00Z").timestamp());
        }
        assert!(clock::intimate_on_time(received, received).unwrap());
    }

    #[test]
    fn complaint_ack_clock_is_30_days() {
        queue_clock_boundary(
            "data-protection-complaints",
            "2026-01-20T12:00:00Z",
            "2026-02-19T12:00:00Z",
        );
        no_fixed_deadline_control();
        reconstructed_complaint_acknowledgements();
        let manual = ManualClock::new(utc("2026-01-20T12:00:00Z"));
        let received = manual.utc().timestamp();
        assert_eq!(
            clock::complaint_ack_due(received).unwrap(),
            utc("2026-02-19T12:00:00Z").timestamp()
        );
        for (value, expected) in [
            ("2026-02-19T11:59:59Z", true),
            ("2026-02-19T12:00:00Z", true),
            ("2026-02-19T12:00:01Z", false),
        ] {
            assert_eq!(
                clock::complaint_ack_on_time(received, at(&manual, value)).unwrap(),
                expected
            );
        }
        assert!(clock::complaint_ack_on_time(received, received).unwrap());
    }
    fn no_fixed_deadline_control() {
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let admitted = fixture
                .send(
                    false,
                    "POST",
                    "/v1/reports/online-safety-complaints",
                    body(json!({})),
                    false,
                )
                .await;
            contract_headers(&admitted);
            let id = admitted.value["ticket_id"].as_str().unwrap();
            assert_eq!(admitted.status, 200);
            let before = super::support::tree(fixture.domain.config.store_dir());
            let page = fixture
                .send(
                    true,
                    "POST",
                    "/v1/compliance/queue",
                    json!({"actor":"reader"}),
                    true,
                )
                .await;
            assert_eq!(
                super::support::tree(fixture.domain.config.store_dir()),
                before
            );
            contract_headers(&page);
            assert_eq!(page.value["items"][0]["ticket_id"], id);
            assert_eq!(page.value["items"][0]["deadline_at"], Value::Null);
            assert_eq!(page.value["items"][0]["overdue"], false);
            assert_eq!(page.status, 200);
        });
    }
    fn every_text_field_has_byte_boundaries() {
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            for (path, mut request) in shape_requests(&"a".repeat(64)) {
                if path == "/v1/compliance/queue" {
                    request.as_object_mut().unwrap().remove("after_ticket_id");
                }
                let mut objects = Vec::new();
                object_paths(&request, String::new(), &mut objects);
                for parent in objects {
                    for (field, original) in request.pointer(&parent).unwrap().as_object().unwrap()
                    {
                        let Some(maximum) = text_field_maximum(&parent, field) else {
                            continue;
                        };
                        assert!(original.is_string());
                        let pointer = format!("{parent}/{field}");
                        for value in [
                            String::new(),
                            " \t\n".into(),
                            "x".repeat(maximum + 1),
                            "é".repeat(maximum / 2 + 1),
                            "x\0y".into(),
                            "x\u{1b}y".into(),
                        ] {
                            let mut wrong = request.clone();
                            *wrong.pointer_mut(&pointer).unwrap() = json!(value);
                            rejects_without_writes(&fixture, &path, wrong).await;
                        }
                        for value in ["x".into(), "x".repeat(maximum)] {
                            let mut valid = request.clone();
                            *valid.pointer_mut(&pointer).unwrap() = json!(value);
                            let admin = path.starts_with("/v1/compliance/");
                            let response = fixture.send(admin, "POST", &path, valid, true).await;
                            let expected = if admin && path != "/v1/compliance/queue" {
                                404
                            } else {
                                200
                            };
                            contract_headers(&response);
                            if expected == 404 {
                                assert_eq!(response.value["error"]["code"], "not_found");
                            } else if admin {
                                assert!(response.value["items"].is_array());
                            } else {
                                assert!(response.value["ticket_id"].is_string());
                            }
                            assert_eq!(
                                response.status, expected,
                                "{path}{pointer}: {}",
                                response.value
                            );
                        }
                    }
                }
            }
        });
    }

    fn text_field_maximum(parent: &str, field: &str) -> Option<usize> {
        if parent == "/decision/assessment" {
            return Some(2048);
        }
        match field {
            "address" => Some(254),
            "description" | "notice" | "enquiries" | "update" => Some(4096),
            "reasons" => Some(2048),
            "suspected_illegality"
            | "harm_description"
            | "rights_basis"
            | "authority"
            | "evidence" => Some(1024),
            "name" | "reference" => Some(128),
            "actor" | "policy_version" | "policy_clause" => Some(64),
            _ => None,
        }
    }

    fn replay_refuses_unknown_or_inconsistent_rows() {
        for unknown in [false, true] {
            let fixture = HttpFixture::new();
            runtime().block_on(async {
                admitted_id(&fixture).await;
                fixture.state.compliance().shutdown().await;
            });
            let mut rows = fs::read_to_string(fixture.domain.path("events.jsonl"))
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .collect::<Vec<_>>();
            let last = rows.last_mut().unwrap();
            last[if unknown { "event" } else { "state" }] =
                json!(if unknown { "unknown_event" } else { "actioned" });
            super::support::rehash(last);
            let bytes = rows
                .iter()
                .flat_map(|row| super::support::encoded_row(row, true))
                .collect::<Vec<_>>();
            fs::write(fixture.domain.path("events.jsonl"), &bytes).unwrap();
            fs::write(
                fixture.domain.path("head.json"),
                super::support::checkpoint(rows.last().unwrap(), bytes.len()),
            )
            .unwrap();
            let before = super::support::tree(fixture.domain.config.store_dir());
            let reopened = fixture.reopen();
            runtime().block_on(async {
                let response = reopened
                    .send(false, "GET", "/v1/reports", Value::Null, false)
                    .await;
                assert_eq!(
                    super::support::tree(reopened.domain.config.store_dir()),
                    before
                );
                contract_headers(&response);
                assert_eq!(response.value["error"]["code"], "compliance_unavailable");
                assert_eq!(response.status, 503);
                assert!(visible(&reopened, "cedar", "unknown", Value::Null).await);
                reopened.state.compliance().shutdown().await;
            });
            assert_eq!(
                super::support::tree(reopened.domain.config.store_dir()),
                before
            );
        }
    }

    fn receipts_can_finish_in_reverse_order() {
        use std::sync::{atomic::AtomicBool, Arc, Condvar, Mutex};
        use stract::{compliance::model::IntakeKind, crawler::politeness::WaitFuture};
        struct PausedClock {
            inner: ManualClock,
            armed: AtomicBool,
            reached: tokio::sync::Notify,
            released: Mutex<bool>,
            wake: Condvar,
        }
        impl Clock for PausedClock {
            fn utc(&self) -> DateTime<Utc> {
                let captured = self.inner.utc();
                if self.armed.swap(false, SeqCst) {
                    self.reached.notify_one();
                    let released = self.released.lock().unwrap();
                    let (released, _) = self
                        .wake
                        .wait_timeout_while(released, std::time::Duration::from_secs(5), |ready| {
                            !*ready
                        })
                        .unwrap();
                    assert!(*released, "bounded receipt hold expired");
                }
                captured
            }
            fn ticks(&self) -> u64 {
                self.inner.ticks()
            }
            fn wait_until(&self, deadline: u64) -> WaitFuture<'_> {
                self.inner.wait_until(deadline)
            }
        }
        let clock = Arc::new(PausedClock {
            inner: ManualClock::new(utc("2026-09-18T12:00:00Z")),
            armed: AtomicBool::new(false),
            reached: tokio::sync::Notify::new(),
            released: Mutex::new(false),
            wake: Condvar::new(),
        });
        let fixture = HttpFixture::instrumented(|_| {}, |seams| seams.clock = clock.clone());
        runtime().block_on(async {
            let first_store = fixture.state.compliance();
            clock.armed.store(true, SeqCst);
            let first = tokio::spawn(async move {
                first_store
                    .admit(
                        super::support::intake(IntakeKind::OnlineSafetyComplaint),
                        Arc::new(()),
                    )
                    .await
                    .unwrap()
            });
            tokio::time::timeout(std::time::Duration::from_secs(2), clock.reached.notified())
                .await
                .unwrap();
            clock.inner.set_utc(utc("2026-09-18T12:00:10Z")).unwrap();
            let second = fixture
                .state
                .compliance()
                .admit(
                    super::support::intake(IntakeKind::OnlineSafetyComplaint),
                    Arc::new(()),
                )
                .await
                .unwrap();
            *clock.released.lock().unwrap() = true;
            clock.wake.notify_one();
            let first = first.await.unwrap();
            assert_eq!(
                first.ticket.times.received_at,
                utc("2026-09-18T12:00:00Z").timestamp()
            );
            assert_eq!(
                second.ticket.times.received_at,
                utc("2026-09-18T12:00:10Z").timestamp()
            );
            let rows = fs::read_to_string(fixture.domain.path("events.jsonl"))
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(rows[0]["ticket_id"], second.ticket.id.as_str());
            assert_eq!(rows[3]["ticket_id"], first.ticket.id.as_str());
            assert!(rows
                .windows(2)
                .all(|pair| pair[0]["at"].as_i64().unwrap() <= pair[1]["at"].as_i64().unwrap()));
            fixture.state.compliance().shutdown().await;
        });
    }

    fn related_complaint_does_not_query_other_ticket() {
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let known = admitted_id(&fixture).await;
            for related in [known, "a".repeat(64)] {
                let before = fixture.probe.lookups.load(SeqCst);
                let response = fixture
                    .send(
                        false,
                        "POST",
                        "/v1/reports/site-complaints",
                        body(json!({"urls":["https://synthetic.example.test/item"],
                        "interest":"responsible_uk_person", "related_ticket_id":related})),
                        false,
                    )
                    .await;
                // Admission retrieves its own newly published ticket once; the related id adds
                // none.
                assert_eq!(fixture.probe.lookups.load(SeqCst), before + 1);
                contract_headers(&response);
                assert_eq!(response.value.as_object().unwrap().len(), 8);
                assert_eq!(response.status, 200);
            }
        });
    }

    fn delayed_intake_keeps_receipt_origin() {
        use std::sync::{Arc, Mutex};
        use stract::compliance::disk::{ComplianceHooks, ComplianceStage as S};
        struct Delay {
            clock: Arc<ManualClock>,
            stages: Mutex<Vec<S>>,
        }
        impl ComplianceHooks for Delay {
            fn at(&self, stage: S) -> std::io::Result<()> {
                self.stages.lock().unwrap().push(stage);
                if stage == S::AfterPayloadSync {
                    self.clock.set_utc(utc("2026-09-20T12:00:01Z")).unwrap();
                }
                Ok(())
            }
        }
        let clock = Arc::new(ManualClock::new(utc("2026-09-18T12:00:00Z")));
        let delay = Arc::new(Delay {
            clock: clock.clone(),
            stages: Mutex::new(Vec::new()),
        });
        let fixture = HttpFixture::instrumented(
            |_| {},
            |seams| {
                seams.clock = clock;
                seams.hooks = delay.clone();
            },
        );
        delay.stages.lock().unwrap().clear();
        runtime().block_on(async {
            let response = fixture
                .send(
                    false,
                    "POST",
                    "/v1/reports/intimate-images",
                    body(json!({
                "urls":["https://synthetic.example.test/item", "https://second.example.test/item"],
                "intimate_image_content":true, "subject_or_authorised":true, "good_faith":true})),
                    false,
                )
                .await;
            let stages = delay.stages.lock().unwrap();
            let rule = stages
                .iter()
                .position(|stage| *stage == S::AfterRulesSync)
                .unwrap();
            assert_eq!(
                stages[..rule]
                    .iter()
                    .filter(|stage| **stage == S::AfterJournalSync)
                    .count(),
                2
            );
            assert_eq!(
                stages[rule..]
                    .iter()
                    .filter(|stage| **stage == S::AfterJournalSync)
                    .count(),
                3
            );
            let rules =
                super::support::read_json(&fixture.domain.config.rules_dir().join("snapshot.json"));
            assert_eq!(rules["rules"].as_array().unwrap().len(), 2);
            for rule in rules["rules"].as_array().unwrap() {
                assert_eq!(rule["effective_at"], response.value["received_at"]);
            }
            contract_headers(&response);
            assert_eq!(
                response.value["received_at"],
                utc("2026-09-18T12:00:00Z").timestamp()
            );
            assert_eq!(response.status, 200);
        });
    }

    fn delayed_intimate_grants() {
        for (instant, timely) in [
            ("2026-09-18T12:00:00Z", true),
            ("2026-09-20T11:59:59Z", true),
            ("2026-09-20T12:00:00Z", true),
            ("2026-09-20T12:00:01Z", false),
        ] {
            let fixture = HttpFixture::new();
            runtime().block_on(async {
                let id = intimate_id(&fixture).await;
                let receipt = utc("2026-09-18T12:00:00Z").timestamp();
                fixture.domain.clock.set_utc(utc(instant)).unwrap();
                let result = administration(
                    &fixture,
                    &id,
                    "decision",
                    json!({"decision":{
                    "kind":"granted",
                        "reasons":"Synthetic delayed review",
                        "delivery":communication()}}),
                )
                .await;
                let id = stract::compliance::model::TicketId::parse(&id).unwrap();
                let ticket = fixture.state.compliance().status(&id).await.unwrap();
                assert_eq!(ticket.times.received_at, receipt);
                assert_eq!(ticket.times.actioned_at, Some(utc(instant).timestamp()));
                assert_eq!(
                    clock::intimate_on_time(receipt, ticket.times.actioned_at.unwrap()).unwrap(),
                    timely
                );
                assert_eq!(
                    stract::compliance::transitions::deadline(&ticket).unwrap(),
                    Some(utc("2026-09-20T12:00:00Z").timestamp())
                );
                contract_headers(&result);
                assert_eq!(result.value["state"], "actioned");
                assert_eq!(result.status, 200);
            });
        }
    }

    fn reconstructed_complaint_acknowledgements() {
        use stract::compliance::{journal::JournalRow, transitions::Ticket};
        let fixture = HttpFixture::new();
        fixture
            .domain
            .clock
            .set_utc(utc("2026-01-20T12:00:00Z"))
            .unwrap();
        runtime().block_on(async {
            super::support::successful_response(
                fixture
                    .send(
                        false,
                        "POST",
                        "/v1/reports/data-protection-complaints",
                        body(json!({})),
                        false,
                    )
                    .await,
            );
            fixture.state.compliance().shutdown().await;
        });
        let rows = fs::read_to_string(fixture.domain.path("events.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<JournalRow>(line).unwrap())
            .collect::<Vec<_>>();
        for (elapsed, timely) in [(2_591_999, true), (2_592_000, true), (2_592_001, false)] {
            let mut ticket = Ticket::received(&rows[0]).unwrap();
            let mut acknowledgement = rows[1].clone();
            acknowledgement.at = ticket.times.received_at + elapsed;
            ticket
                .apply(&acknowledgement, &fixture.domain.config)
                .unwrap();
            assert_eq!(ticket.times.acknowledged_at, Some(acknowledgement.at));
            assert_eq!(
                clock::complaint_ack_on_time(
                    ticket.times.received_at,
                    ticket.times.acknowledged_at.unwrap()
                )
                .unwrap(),
                timely
            );
        }
    }

    fn reachable_transition_histories() {
        for (path, request) in shape_requests(&"a".repeat(64)).into_iter().take(8) {
            for granted in [false, true] {
                let fixture = HttpFixture::new();
                runtime().block_on(async {
                    let response = fixture
                        .send(false, "POST", &path, request.clone(), false)
                        .await;
                    contract_headers(&response);
                    let id = response.value["ticket_id"].as_str().unwrap();
                    assert_eq!(response.status, 200, "{path}");
                    let data = path.ends_with("data-rights");
                    forbidden_admin_pairs(&fixture, id, "queued", data).await;
                    if data {
                        evidence_history(&fixture, id).await;
                    }
                    progress_history(&fixture, id).await;
                    let mut decision = json!({"kind":if granted {"granted"} else {"refused"},
                        "reasons":"Synthetic decision", "delivery":communication()});
                    if data && granted {
                        decision["assessment"] = assessment();
                    }
                    let result =
                        administration(&fixture, id, "decision", json!({"decision":decision}))
                            .await;
                    contract_headers(&result);
                    let state = result.value["state"].as_str().unwrap();
                    assert_eq!(result.status, 200, "{path}");
                    forbidden_admin_pairs(&fixture, id, state, data).await;
                    progress_history(&fixture, id).await;
                    super::support::successful_response(
                        administration(
                            &fixture,
                            id,
                            "appeal",
                            json!({"reasons":"Synthetic appeal"}),
                        )
                        .await,
                    );
                    forbidden_admin_pairs(&fixture, id, "appealed", data).await;
                    progress_history(&fixture, id).await;
                    let (action, state) = if state == "actioned" {
                        ("reversal", "reversed")
                    } else {
                        ("uphold", "upheld")
                    };
                    super::support::successful_response(
                        administration(
                            &fixture,
                            id,
                            action,
                            json!({"reasons":"Synthetic disposal",
                        "delivery":communication()}),
                        )
                        .await,
                    );
                    forbidden_admin_pairs(&fixture, id, state, data).await;
                    super::support::successful_response(
                        administration(
                            &fixture,
                            id,
                            "close",
                            json!({"reasons":"Synthetic closure"}),
                        )
                        .await,
                    );
                    forbidden_admin_pairs(&fixture, id, "closed", data).await;
                    fixture
                        .domain
                        .clock
                        .set_utc(utc("2030-09-18T12:00:00Z"))
                        .unwrap();
                    super::support::successful_response(
                        administration(&fixture, id, "purge", json!({})).await,
                    );
                    purged_administration_stays_healthy(&fixture, id).await;
                    fixture.state.compliance().shutdown().await;
                });
                replay_reachable_rows(&fixture);
            }
        }
    }

    async fn progress_history(fixture: &HttpFixture, id: &str) {
        super::support::successful_response(
            administration(
                fixture,
                id,
                "progress",
                json!({"enquiries":"Synthetic enquiry",
            "update":"Synthetic update", "delivery":communication()}),
            )
            .await,
        );
    }

    async fn evidence_history(fixture: &HttpFixture, id: &str) {
        for (request, reply, instant) in [
            (
                "request_identity",
                "identity_confirmed",
                "2026-09-19T12:00:00Z",
            ),
            (
                "request_clarification",
                "clarification_received",
                "2026-09-20T12:00:00Z",
            ),
        ] {
            super::support::successful_response(
                administration(
                    fixture,
                    id,
                    "extension",
                    json!({"necessity":"complexity",
                "reasons":"Synthetic complexity",
                    "notice":"Synthetic extension",
                    "delivery":communication()}),
                )
                .await,
            );
            super::support::successful_response(
                administration(
                    fixture,
                    id,
                    "identity",
                    json!({"event":request,
                "reasons":"Synthetic request"}),
                )
                .await,
            );
            forbidden_admin_pairs(fixture, id, "identity_pending", true).await;
            progress_history(fixture, id).await;
            fixture.domain.clock.set_utc(utc(instant)).unwrap();
            super::support::successful_response(
                administration(
                    fixture,
                    id,
                    "identity",
                    json!({"event":reply,
                "reasons":"Synthetic response"}),
                )
                .await,
            );
        }
    }

    async fn forbidden_admin_pairs(fixture: &HttpFixture, id: &str, state: &str, data: bool) {
        let reasons = json!({"reasons":"Synthetic reasons"});
        let actions = [
            (
                "decision",
                state == "queued",
                json!({"decision":{"kind":"refused",
                    "reasons":"Synthetic refusal",
                    "delivery":communication()}}),
            ),
            (
                "appeal",
                matches!(state, "decided" | "actioned"),
                reasons.clone(),
            ),
            (
                "reversal",
                state == "appealed",
                json!({"reasons":"Synthetic reversal", "delivery":communication()}),
            ),
            (
                "uphold",
                state == "appealed",
                json!({"reasons":"Synthetic disposal", "delivery":communication()}),
            ),
            (
                "close",
                matches!(state, "decided" | "actioned" | "reversed" | "upheld"),
                reasons.clone(),
            ),
            (
                "progress",
                matches!(
                    state,
                    "queued" | "identity_pending" | "decided" | "actioned" | "appealed"
                ),
                json!({"enquiries":"Synthetic enquiry",
                    "update":"Synthetic update",
                    "delivery":communication()}),
            ),
            (
                "extension",
                data && matches!(state, "queued" | "identity_pending"),
                json!({"necessity":"complexity",
                    "reasons":"Synthetic complexity",
                    "notice":"Synthetic notice",
                    "delivery":communication()}),
            ),
        ];
        for (action, allowed, input) in actions {
            if !allowed {
                forbidden_admin_call(fixture, id, action, input).await;
            }
        }
        for event in [
            "request_identity",
            "request_clarification",
            "identity_confirmed",
            "clarification_received",
        ] {
            let permitted = data
                && if event.starts_with("request_") {
                    state == "queued"
                } else {
                    state == "identity_pending"
                };
            if !permitted {
                forbidden_admin_call(
                    fixture,
                    id,
                    "identity",
                    json!({"event":event, "reasons":"Synthetic evidence"}),
                )
                .await;
            }
        }
        if state != "closed" {
            forbidden_admin_call(fixture, id, "purge", json!({})).await;
        }
    }

    async fn forbidden_admin_call(fixture: &HttpFixture, id: &str, action: &str, input: Value) {
        let before = super::support::tree(fixture.domain.config.store_dir());
        let writes = fixture.probe.writes.load(SeqCst);
        let response = administration(fixture, id, action, input).await;
        assert_eq!(fixture.probe.writes.load(SeqCst), writes);
        assert_eq!(
            super::support::tree(fixture.domain.config.store_dir()),
            before
        );
        contract_headers(&response);
        assert_eq!(response.value["error"]["code"], "invalid_transition");
        assert_eq!(response.status, 409);
    }

    fn replay_reachable_rows(fixture: &HttpFixture) {
        use stract::compliance::{journal::JournalRow, transitions::Ticket};
        let rows = fs::read_to_string(fixture.domain.path("events.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<JournalRow>(line).unwrap())
            .collect::<Vec<_>>();
        let rows = rows
            .iter()
            .filter(|row| row.ticket_id == rows[0].ticket_id)
            .collect::<Vec<_>>();
        let mut ticket = Ticket::received(rows[0]).unwrap();
        for row in &rows[1..] {
            ticket.apply(row, &fixture.domain.config).unwrap();
            assert_eq!(ticket.state.as_str(), row.state);
            assert_eq!(ticket.times.received_at, rows[0].received_at);
        }
        assert_eq!(ticket.state.as_str(), "closed");
        assert!(ticket.purged && ticket.pending.is_none());
        assert_eq!(ticket.events, rows.len() as u64);
    }

    fn boundary_panic() -> axum::response::Response {
        panic!("synthetic boundary panic");
    }

    fn explicit_declarations_and_body_cap() {
        use axum::{body::Body, http::Request};
        let fixture = HttpFixture::new();
        runtime().block_on(async {
            let input = body(json!({"urls":["https://synthetic.example.test/item"],
                "suspected_illegality":"Synthetic evidence"}));
            let mut bytes = serde_json::to_vec(&input).unwrap();
            bytes.resize(65536, b' ');
            let mut overflow = bytes.clone();
            overflow.push(b' ');
            let request = Request::builder()
                .method("POST")
                .uri("/v1/reports/illegal-content")
                .header("content-type", "application/json")
                .body(Body::from(overflow))
                .unwrap();
            transport_refusal(&fixture, false, request, "request_too_large", 413).await;
            let request = Request::builder()
                .method("POST")
                .uri("/v1/reports/illegal-content")
                .header("content-type", "application/json")
                .body(Body::from(bytes))
                .unwrap();
            let response = fixture.raw(false, request).await;
            assert_eq!(fixture.probe.writes.load(SeqCst), 3);
            contract_headers(&response);
            assert!(response.value["ticket_id"].is_string());
            assert_eq!(response.status, 200);
            for field in [
                "intimate_image_content",
                "subject_or_authorised",
                "good_faith",
            ] {
                let mut input = body(json!({"urls":["https://synthetic.example.test/item"],
                    "intimate_image_content":true,"subject_or_authorised":true,"good_faith":true}));
                input[field] = json!(false);
                rejects_without_writes(&fixture, "/v1/reports/intimate-images", input).await;
            }
            fixture.state.compliance().shutdown().await;
        });
    }

    async fn transport_refusal(
        fixture: &HttpFixture,
        management: bool,
        request: axum::http::Request<axum::body::Body>,
        code: &str,
        status: u16,
    ) {
        let before = super::support::tree(fixture.domain.config.store_dir());
        let counts = (
            fixture.probe.decodes.load(SeqCst),
            fixture.probe.lookups.load(SeqCst),
            fixture.probe.writes.load(SeqCst),
        );
        let response = fixture.raw(management, request).await;
        assert_eq!(
            super::support::tree(fixture.domain.config.store_dir()),
            before
        );
        assert_eq!(
            (
                fixture.probe.decodes.load(SeqCst),
                fixture.probe.lookups.load(SeqCst),
                fixture.probe.writes.load(SeqCst)
            ),
            counts
        );
        contract_headers(&response);
        assert_eq!(response.value["error"]["code"], code);
        assert_eq!(response.status, status);
    }

    fn moved_queue_deadlines() {
        for (request, reply, observed, due) in [
            (
                "request_identity",
                "identity_confirmed",
                "2026-02-02T09:00:00Z",
                "2026-03-02T09:00:00Z",
            ),
            (
                "request_clarification",
                "clarification_received",
                "2026-02-05T08:00:00Z",
                "2026-03-05T08:00:00Z",
            ),
        ] {
            let fixture = HttpFixture::new();
            fixture
                .domain
                .clock
                .set_utc(utc("2026-01-31T10:15:00Z"))
                .unwrap();
            runtime().block_on(async {
                let id = data_id(&fixture).await;
                let pending = administration(
                    &fixture,
                    &id,
                    "identity",
                    json!({"event":request,"reasons":"Synthetic request"}),
                )
                .await;
                contract_headers(&pending);
                assert_eq!(pending.value["state"], "identity_pending");
                assert_eq!(pending.status, 200);
                fixture.domain.clock.set_utc(utc(observed)).unwrap();
                let confirmed = administration(
                    &fixture,
                    &id,
                    "identity",
                    json!({"event":reply,"reasons":"Synthetic reply"}),
                )
                .await;
                contract_headers(&confirmed);
                assert_eq!(confirmed.value["state"], "queued");
                assert_eq!(confirmed.status, 200);
                for delta in [0, 1] {
                    fixture
                        .domain
                        .clock
                        .set_utc(DateTime::from_timestamp(utc(due).timestamp() + delta, 0).unwrap())
                        .unwrap();
                    assert_queue_clock(&fixture, &id, utc(due).timestamp(), delta == 1).await;
                }
                let status = fixture
                    .send(
                        false,
                        "GET",
                        &format!("/v1/reports/status/{id}"),
                        Value::Null,
                        false,
                    )
                    .await;
                contract_headers(&status);
                assert_eq!(
                    status.value["received_at"],
                    utc("2026-01-31T10:15:00Z").timestamp()
                );
                assert_eq!(status.status, 200);
                fixture.state.compliance().shutdown().await;
            });
        }
    }

    async fn case_read_controls(fixture: &HttpFixture, id: &str, available: bool) {
        let before = super::support::tree(fixture.domain.config.store_dir());
        let writes = fixture.probe.writes.load(SeqCst);
        for path in ["/v1/reports".to_owned(), format!("/v1/reports/status/{id}")] {
            let response = fixture.send(false, "GET", &path, Value::Null, false).await;
            assert_eq!(fixture.probe.writes.load(SeqCst), writes);
            assert_eq!(
                super::support::tree(fixture.domain.config.store_dir()),
                before
            );
            contract_headers(&response);
            assert_eq!(response.value["version"], "v1");
            if available {
                assert!(response.value.get("error").is_none());
                assert_eq!(response.status, 200);
            } else {
                assert_eq!(response.value["error"]["code"], "compliance_unavailable");
                assert_eq!(response.status, 503);
            }
        }
    }

    fn restart_before_last_journal_row() {
        let fixture = HttpFixture::new();
        let runtime = runtime();
        let id = runtime.block_on(async {
            let id = intimate_id(&fixture).await;
            assert!(!visible(&fixture, "cedar", "unknown", Value::Null).await);
            at(&fixture.domain.clock, "2026-09-18T13:00:00Z");
            admitted_id(&fixture).await;
            fixture.state.compliance().shutdown().await;
            id
        });
        let before = super::support::tree(fixture.domain.config.store_dir());
        at(&fixture.domain.clock, "2026-09-18T12:59:59Z");
        let fixture = fixture.reopen();
        assert_eq!(
            super::support::tree(fixture.domain.config.store_dir()),
            before
        );
        runtime.block_on(async {
            case_read_controls(&fixture, &id, false).await;
            assert!(!visible(&fixture, "cedar", "unknown", Value::Null).await);
            fixture.state.compliance().shutdown().await;
        });
        at(&fixture.domain.clock, "2026-09-18T13:00:00Z");
        let fixture = fixture.reopen();
        assert_eq!(
            super::support::tree(fixture.domain.config.store_dir()),
            before
        );
        runtime.block_on(async {
            case_read_controls(&fixture, &id, true).await;
            assert!(!visible(&fixture, "cedar", "unknown", Value::Null).await);
        });
    }

    struct CorruptWrittenJournal {
        armed: std::sync::atomic::AtomicBool,
        path: std::sync::Mutex<Option<std::path::PathBuf>>,
    }
    impl stract::compliance::disk::ComplianceHooks for CorruptWrittenJournal {
        fn at(&self, stage: stract::compliance::disk::ComplianceStage) -> std::io::Result<()> {
            use std::io::Write;
            if stage == stract::compliance::disk::ComplianceStage::AfterJournalSync
                && self.armed.swap(false, SeqCst)
            {
                let path = self.path.lock().unwrap().clone().unwrap();
                let mut bytes = fs::read(&path)?;
                let start = bytes[..bytes.len() - 1]
                    .iter()
                    .rposition(|byte| *byte == b'\n')
                    .map_or(0, |index| index + 1);
                bytes[start + 2] ^= 1;
                let mut file = fs::OpenOptions::new().write(true).open(path)?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                return Err(std::io::Error::other(
                    "synthetic post-write journal failure",
                ));
            }
            Ok(())
        }
    }

    fn runtime_journal_corruption() {
        use std::sync::{atomic::AtomicBool, Arc, Mutex};
        let hooks = Arc::new(CorruptWrittenJournal {
            armed: AtomicBool::new(false),
            path: Mutex::new(None),
        });
        let fixture = HttpFixture::instrumented(|_| {}, |seams| seams.hooks = hooks.clone());
        *hooks.path.lock().unwrap() = Some(fixture.domain.path("events.jsonl"));
        let runtime = runtime();
        let id = runtime.block_on(async {
            let id = intimate_id(&fixture).await;
            let head = fs::read(fixture.domain.path("head.json")).unwrap();
            hooks.armed.store(true, SeqCst);
            let rejected = administration(
                &fixture,
                &id,
                "progress",
                json!({"enquiries":"Synthetic enquiry",
                "update":"Synthetic progress",
                "delivery":communication()}),
            )
            .await;
            assert_eq!(fs::read(fixture.domain.path("head.json")).unwrap(), head);
            contract_headers(&rejected);
            assert_eq!(rejected.value["error"]["code"], "compliance_unavailable");
            assert_eq!(rejected.status, 503);
            case_read_controls(&fixture, &id, false).await;
            assert!(!visible(&fixture, "cedar", "unknown", Value::Null).await);
            fixture.state.compliance().shutdown().await;
            id
        });
        let before = super::support::tree(fixture.domain.config.store_dir());
        let fixture = fixture.reopen();
        assert_eq!(
            super::support::tree(fixture.domain.config.store_dir()),
            before
        );
        runtime.block_on(async {
            case_read_controls(&fixture, &id, false).await;
            assert!(!visible(&fixture, "cedar", "unknown", Value::Null).await);
        });
    }

    fn required_payload_corruption() {
        let fixture = HttpFixture::new();
        let runtime = runtime();
        let id = runtime.block_on(async {
            let id = intimate_id(&fixture).await;
            let path = fixture
                .domain
                .path("payloads")
                .join(&id)
                .join(format!("{:020}.json", 1));
            let mut bytes = fs::read(&path).unwrap();
            bytes[2] ^= 1;
            fs::write(&path, bytes).unwrap();
            let before = super::support::tree(fixture.domain.config.store_dir());
            let writes = fixture.probe.writes.load(SeqCst);
            let rejected = administration(&fixture, &id, "read", json!({})).await;
            assert_eq!(
                super::support::tree(fixture.domain.config.store_dir()),
                before
            );
            assert_eq!(fixture.probe.writes.load(SeqCst), writes);
            contract_headers(&rejected);
            assert_eq!(rejected.value["error"]["code"], "compliance_unavailable");
            assert_eq!(rejected.status, 503);
            case_read_controls(&fixture, &id, true).await;
            assert!(!visible(&fixture, "cedar", "unknown", Value::Null).await);
            fixture.state.compliance().shutdown().await;
            id
        });
        let before = super::support::tree(fixture.domain.config.store_dir());
        let fixture = fixture.reopen();
        assert_eq!(
            super::support::tree(fixture.domain.config.store_dir()),
            before
        );
        runtime.block_on(async {
            case_read_controls(&fixture, &id, false).await;
            assert!(!visible(&fixture, "cedar", "unknown", Value::Null).await);
        });
    }

    fn bad_rules_startup() {
        use std::sync::Arc;
        use stract::compliance::{
            disk::NoHooks,
            model::SystemEntropy,
            rules::NoRulesHooks,
            tickets::{ComplianceStore, NoObserver},
            Error,
        };
        let fixture = HttpFixture::new();
        runtime().block_on(fixture.state.compliance().shutdown());
        let HttpFixture { domain, state, .. } = fixture;
        drop(state);
        let path = domain.config.rules_dir().join("snapshot.json");
        let mut bytes = fs::read(&path).unwrap();
        bytes[2] ^= 1;
        fs::write(path, bytes).unwrap();
        let before = super::support::tree(domain.config.store_dir());
        let opened = ComplianceStore::open(
            &domain.config,
            domain.clock.clone(),
            Arc::new(SystemEntropy),
            Arc::new(NoHooks),
            Arc::new(NoRulesHooks),
            Arc::new(NoObserver),
            false,
        );
        assert_eq!(super::support::tree(domain.config.store_dir()), before);
        assert!(matches!(opened, Err(Error::RulesUnavailable)));
    }

    fn legacy_suppression_availability() {
        use std::sync::{atomic::AtomicBool, Arc};
        use stract::api::v1::suppression::{StoreHooks, StoreStage};
        struct Fault(AtomicBool);
        impl StoreHooks for Fault {
            fn at(&self, stage: StoreStage) -> std::io::Result<()> {
                if stage == StoreStage::SyncDirectory && self.0.load(SeqCst) {
                    return Err(std::io::Error::other("synthetic legacy uncertainty"));
                }
                Ok(())
            }
        }
        let fixture = HttpFixture::new();
        let runtime = runtime();
        runtime.block_on(fixture.state.compliance().shutdown());
        let hooks = Arc::new(Fault(AtomicBool::new(false)));
        let fixture = fixture.reopen_with_legacy_hooks(hooks.clone());
        runtime.block_on(async {
            hooks.0.store(true, SeqCst);
            let id = super::support::digest(b"https://synthetic.example.test/item");
            let deleted = fixture
                .send(
                    true,
                    "DELETE",
                    &format!("/v1/documents/{id}"),
                    Value::Null,
                    false,
                )
                .await;
            contract_headers(&deleted);
            assert_eq!(deleted.value["error"]["code"], "suppression_unavailable");
            assert_eq!(deleted.status, 503);
            let counts = (
                fixture.probe.backend.load(SeqCst),
                fixture.probe.attribution.load(SeqCst),
            );
            let search = fixture
                .send(false, "POST", "/v1/search", json!({"query":"cedar"}), false)
                .await;
            assert_eq!(
                (
                    fixture.probe.backend.load(SeqCst),
                    fixture.probe.attribution.load(SeqCst)
                ),
                counts
            );
            contract_headers(&search);
            assert_eq!(search.value["error"]["code"], "suppression_unavailable");
            assert_eq!(search.status, 503);
            let index = fixture
                .send(false, "GET", "/v1/reports", Value::Null, false)
                .await;
            contract_headers(&index);
            assert!(index.value["routes"].is_array());
            assert_eq!(index.status, 200);
        });
    }

    fn complete_history_replay() {
        let fixture = HttpFixture::new();
        let runtime = runtime();
        let (ids, before) = runtime.block_on(async {
            let mut ids = Vec::new();
            for (route, receipt, decision_at, closed_at) in [
                (
                    "illegal-content",
                    "2026-09-18T12:00:00Z",
                    "2026-09-18T12:10:00Z",
                    "2026-09-18T12:20:00Z",
                ),
                (
                    "online-safety-complaints",
                    "2026-09-18T12:30:00Z",
                    "2026-09-18T12:40:00Z",
                    "2026-09-18T12:50:00Z",
                ),
            ] {
                at(&fixture.domain.clock, receipt);
                let path = format!("/v1/reports/{route}");
                let request = shape_requests(&"a".repeat(64))
                    .into_iter()
                    .find(|(candidate, _)| candidate == &path)
                    .unwrap()
                    .1;
                let response = fixture.send(false, "POST", &path, request, false).await;
                contract_headers(&response);
                let id = response.value["ticket_id"].as_str().unwrap().to_owned();
                assert_eq!(response.status, 200);
                at(&fixture.domain.clock, decision_at);
                let decision = administration(
                    &fixture,
                    &id,
                    "decision",
                    json!({"decision":{"kind":"granted",
                    "reasons":"Synthetic grant",
                    "delivery":communication()}}),
                )
                .await;
                contract_headers(&decision);
                assert_eq!(
                    decision.value["state"],
                    if route == "illegal-content" {
                        "actioned"
                    } else {
                        "decided"
                    }
                );
                assert_eq!(decision.status, 200);
                at(&fixture.domain.clock, closed_at);
                let closed = administration(
                    &fixture,
                    &id,
                    "close",
                    json!({"reasons":"Synthetic closure"}),
                )
                .await;
                contract_headers(&closed);
                assert_eq!(closed.value["recorded_at"], utc(closed_at).timestamp());
                assert_eq!(closed.status, 200);
                ids.push(id);
            }
            let before = full_history_projection(&fixture, &ids).await;
            fixture.state.compliance().shutdown().await;
            (ids, before)
        });
        let fixture = fixture.reopen();
        let rules =
            super::support::read_json(&fixture.domain.config.rules_dir().join("snapshot.json"));
        assert_eq!(rules["rules"].as_array().unwrap().len(), 1);
        assert_eq!(rules["rules"][0]["ticket_id"], ids[0]);
        runtime.block_on(async {
            assert_eq!(full_history_projection(&fixture, &ids).await, before);
        });
    }

    async fn full_history_projection(fixture: &HttpFixture, ids: &[String]) -> Vec<Value> {
        let before = super::support::tree(fixture.domain.config.store_dir());
        let writes = fixture.probe.writes.load(SeqCst);
        let mut projection = Vec::new();
        for (index, id) in ids.iter().enumerate() {
            let status = fixture
                .send(
                    false,
                    "GET",
                    &format!("/v1/reports/status/{id}"),
                    Value::Null,
                    false,
                )
                .await;
            let private = administration(fixture, id, "read", json!({})).await;
            assert_eq!(fixture.probe.writes.load(SeqCst), writes);
            assert_eq!(
                super::support::tree(fixture.domain.config.store_dir()),
                before
            );
            contract_headers(&status);
            assert_eq!(status.value["state"], "closed");
            closed_history_times(&status.value, index);
            contract_headers(&private);
            assert_eq!(private.value["payload_events"].as_array().unwrap().len(), 3);
            assert_eq!(private.status, 200);
            projection.extend([status.value, private.value]);
            assert_eq!(status.status, 200);
        }
        let queue = fixture
            .send(
                true,
                "POST",
                "/v1/compliance/queue",
                json!({"actor":"reader"}),
                true,
            )
            .await;
        assert_eq!(fixture.probe.writes.load(SeqCst), writes);
        assert_eq!(
            super::support::tree(fixture.domain.config.store_dir()),
            before
        );
        contract_headers(&queue);
        assert_eq!(queue.value["items"], json!([]));
        projection.push(queue.value);
        assert_eq!(queue.status, 200);
        projection
    }

    fn closed_history_times(status: &Value, index: usize) {
        let (received, decided, closed) = if index == 0 {
            (
                "2026-09-18T12:00:00Z",
                "2026-09-18T12:10:00Z",
                "2026-09-18T12:20:00Z",
            )
        } else {
            (
                "2026-09-18T12:30:00Z",
                "2026-09-18T12:40:00Z",
                "2026-09-18T12:50:00Z",
            )
        };
        assert_eq!(status["received_at"], utc(received).timestamp());
        assert_eq!(status["acknowledged_at"], utc(received).timestamp());
        assert_eq!(status["decided_at"], utc(decided).timestamp());
        assert_eq!(status["closed_at"], utc(closed).timestamp());
        assert_eq!(
            status["actioned_at"],
            if index == 0 {
                json!(utc(decided).timestamp())
            } else {
                Value::Null
            }
        );
    }

    fn index_clause(index: &Value) {
        let common =
            "You can report even if you do not use AVA. Required object. Form and email availability is pending deployment.";
        let clause =
            "A complaint may be treated as manifestly unfounded only when it repeats a concluded complaint without new information. A reviewer must identify the earlier complaint and explain why no new information changes the decision. Disagreement alone is not enough.";
        for route in index["routes"].as_array().unwrap() {
            let fields = route["fields"].as_array().unwrap();
            let report = fields
                .iter()
                .find(|field| field["name"] == "report")
                .unwrap();
            let complaint = matches!(
                route["route"].as_str().unwrap(),
                "site_complaint" | "data_protection_complaint" | "online_safety_complaint"
            );
            let expected = if complaint {
                format!("{common} {clause}")
            } else {
                common.into()
            };
            assert_eq!(report["description"], expected);
            if !complaint {
                assert!(!serde_json::to_string(fields).unwrap().contains(clause));
            }
        }
    }

    async fn purged_administration_stays_healthy(fixture: &HttpFixture, id: &str) {
        let prefix = format!("/v1/compliance/tickets/{id}/");
        let mut commands = shape_requests(id)
            .into_iter()
            .filter(|(path, value)| {
                path.starts_with(&prefix)
                    && !path.ends_with("/read")
                    && !path.ends_with("/purge")
                    && (value.get("decision").is_none() || value["decision"]["kind"] == "refused")
            })
            .collect::<Vec<_>>();
        for event in [
            "request_clarification",
            "identity_confirmed",
            "clarification_received",
        ] {
            commands.push((
                format!("{prefix}identity"),
                json!({"actor":"reviewer", "event":event, "reasons":"Synthetic evidence"}),
            ));
        }
        for (path, command) in commands {
            let before = super::support::tree(fixture.domain.config.store_dir());
            let writes = fixture.probe.writes.load(SeqCst);
            let response = fixture.send(true, "POST", &path, command, true).await;
            assert_eq!(fixture.probe.writes.load(SeqCst), writes);
            assert_eq!(
                super::support::tree(fixture.domain.config.store_dir()),
                before
            );
            contract_headers(&response);
            assert_eq!(response.value["error"]["code"], "invalid_transition");
            assert_eq!(response.status, 409);
            let index = fixture
                .send(false, "GET", "/v1/reports", Value::Null, false)
                .await;
            contract_headers(&index);
            assert!(index.value["routes"].is_array());
            assert_eq!(index.status, 200);
            let status = fixture
                .send(
                    false,
                    "GET",
                    &format!("/v1/reports/status/{id}"),
                    Value::Null,
                    false,
                )
                .await;
            contract_headers(&status);
            assert_eq!(status.value["state"], "closed");
            assert_eq!(status.status, 200);
        }
        let fresh = fixture
            .send(
                false,
                "POST",
                "/v1/reports/online-safety-complaints",
                body(json!({})),
                false,
            )
            .await;
        contract_headers(&fresh);
        assert!(fresh.value["ticket_id"].is_string());
        assert_ne!(fresh.value["ticket_id"], id);
        let fresh_id = fresh.value["ticket_id"].as_str().unwrap();
        assert_eq!(fresh.status, 200);
        let queued = fixture
            .send(
                false,
                "GET",
                &format!("/v1/reports/status/{fresh_id}"),
                Value::Null,
                false,
            )
            .await;
        contract_headers(&queued);
        assert_eq!(queued.value["state"], "queued");
        assert_eq!(queued.status, 200);
    }

    async fn assert_queue_clock(fixture: &HttpFixture, id: &str, due: i64, overdue: bool) {
        let before = super::support::tree(fixture.domain.config.store_dir());
        let writes = fixture.probe.writes.load(SeqCst);
        let page = fixture
            .send(
                true,
                "POST",
                "/v1/compliance/queue",
                json!({"actor":"reader"}),
                true,
            )
            .await;
        assert_eq!(fixture.probe.writes.load(SeqCst), writes);
        assert_eq!(
            super::support::tree(fixture.domain.config.store_dir()),
            before
        );
        contract_headers(&page);
        let item = page.value["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["ticket_id"] == id)
            .unwrap();
        assert_eq!(item["deadline_at"], due);
        assert_eq!(item["overdue"], overdue);
        assert_eq!(page.status, 200);
    }

    fn queue_clock_boundary(route: &str, receipt: &str, due: &str) {
        let fixture = HttpFixture::new();
        fixture.domain.clock.set_utc(utc(receipt)).unwrap();
        runtime().block_on(async {
            let path = format!("/v1/reports/{route}");
            let request = shape_requests(&"a".repeat(64))
                .into_iter()
                .find(|(candidate, _)| candidate == &path)
                .unwrap()
                .1;
            let admitted = fixture.send(false, "POST", &path, request, false).await;
            contract_headers(&admitted);
            let id = admitted.value["ticket_id"].as_str().unwrap();
            assert_eq!(admitted.status, 200);
            for delta in [-1, 0, 1] {
                fixture
                    .domain
                    .clock
                    .set_utc(DateTime::from_timestamp(utc(due).timestamp() + delta, 0).unwrap())
                    .unwrap();
                assert_queue_clock(&fixture, id, utc(due).timestamp(), delta == 1).await;
            }
            fixture.state.compliance().shutdown().await;
        });
    }

    fn cold_open_payload_counts() {
        use std::sync::Arc;
        use stract::compliance::{
            model::{IntakeKind, SystemEntropy},
            tickets::{ComplianceStore, NoObserver},
        };
        for (n, k) in [(2, 3), (4, 3), (4, 5)] {
            let fixture = super::support::DomainFixture::new();
            let counts = Arc::new(super::support::StartupCounts::default());
            let open = || {
                ComplianceStore::open(
                    &fixture.config,
                    fixture.clock.clone(),
                    Arc::new(SystemEntropy),
                    counts.clone(),
                    counts.clone(),
                    Arc::new(NoObserver),
                    false,
                )
                .unwrap()
            };
            let store = open();
            let runtime = runtime();
            runtime.block_on(async {
                for _ in 0..n {
                    let kind = if k == 3 {
                        IntakeKind::OnlineSafetyComplaint
                    } else {
                        IntakeKind::IntimateImages {
                            intimate_image_content: true,
                            subject_or_authorised: true,
                            good_faith: true,
                        }
                    };
                    store
                        .admit(super::support::intake(kind), Arc::new(()))
                        .await
                        .unwrap();
                }
                store.shutdown().await;
            });
            drop(store);
            counts.compliance.store(0, SeqCst);
            counts.rules.store(0, SeqCst);
            let reopened = open();
            let compliance_decodes = counts.compliance.load(SeqCst);
            let payload_decodes = compliance_decodes.checked_sub(1 + n * k);
            assert_eq!(payload_decodes, Some(n), "one intake decode per ticket");
            assert_eq!(compliance_decodes, 1 + n * k + n);
            assert_eq!(counts.rules.load(SeqCst), 1);
            runtime.block_on(reopened.shutdown());
        }
    }

    async fn check_reports_index(fixture: &HttpFixture) {
        for management in [false, true] {
            let index = fixture
                .send(management, "GET", "/v1/reports", Value::Null, false)
                .await;
            contract_headers(&index);
            index_clause(&index.value);
            assert_eq!(index.value.as_object().unwrap().len(), 4);
            let routes = index.value["routes"].as_array().unwrap();
            assert_eq!(
                routes
                    .iter()
                    .map(|route| route["route"].as_str().unwrap())
                    .collect::<Vec<_>>(),
                [
                    "illegal_content",
                    "harmful_to_children",
                    "intimate_images",
                    "site_complaint",
                    "rights_removal",
                    "data_rights",
                    "data_protection_complaint",
                    "online_safety_complaint"
                ]
            );
            assert!(index
                .value
                .to_string()
                .contains("You can report even if you do not use AVA"));
            assert!(routes
                .iter()
                .all(|route| route["method"] == "POST"
                    && route["fields"].as_array().unwrap().len() >= 7));
            assert_eq!(index.status, 200);
        }
    }

    fn literal_operations(document: &Value) {
        use std::collections::BTreeSet;
        let expected = [
            ("/v1/search", "post", "api"),
            ("/v1/source", "get", "api-and-management"),
            ("/v1/statement", "get", "api"),
            ("/v1/documents/{id}", "delete", "management"),
            ("/v1/reports", "get", "api-and-management"),
            ("/v1/reports/status/{ticket_id}", "get", "api"),
            ("/v1/reports/illegal-content", "post", "api"),
            ("/v1/reports/harmful-to-children", "post", "api"),
            ("/v1/reports/intimate-images", "post", "api"),
            ("/v1/reports/site-complaints", "post", "api"),
            ("/v1/reports/rights-removal", "post", "api"),
            ("/v1/reports/data-rights", "post", "api"),
            ("/v1/reports/data-protection-complaints", "post", "api"),
            ("/v1/reports/online-safety-complaints", "post", "api"),
            ("/v1/compliance/queue", "post", "management"),
            (
                "/v1/compliance/tickets/{ticket_id}/read",
                "post",
                "management",
            ),
            (
                "/v1/compliance/tickets/{ticket_id}/identity",
                "post",
                "management",
            ),
            (
                "/v1/compliance/tickets/{ticket_id}/extension",
                "post",
                "management",
            ),
            (
                "/v1/compliance/tickets/{ticket_id}/decision",
                "post",
                "management",
            ),
            (
                "/v1/compliance/tickets/{ticket_id}/appeal",
                "post",
                "management",
            ),
            (
                "/v1/compliance/tickets/{ticket_id}/reversal",
                "post",
                "management",
            ),
            (
                "/v1/compliance/tickets/{ticket_id}/uphold",
                "post",
                "management",
            ),
            (
                "/v1/compliance/tickets/{ticket_id}/progress",
                "post",
                "management",
            ),
            (
                "/v1/compliance/tickets/{ticket_id}/close",
                "post",
                "management",
            ),
            (
                "/v1/compliance/tickets/{ticket_id}/purge",
                "post",
                "management",
            ),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        let mut observed = BTreeSet::new();
        for (path, item) in document["paths"].as_object().unwrap() {
            for (method, operation) in item.as_object().unwrap() {
                if [
                    "get", "post", "delete", "put", "patch", "options", "head", "trace",
                ]
                .contains(&method.as_str())
                {
                    observed.insert((
                        path.as_str(),
                        method.as_str(),
                        operation["x-listener"].as_str().unwrap(),
                    ));
                }
            }
        }
        assert_eq!(observed, expected);
        assert_eq!(observed.len(), 25);
        assert_eq!(document["paths"].as_object().unwrap().len(), 25);
        let mut protected = 0;
        for (path, method, listener) in expected {
            let operation = &document["paths"][path][method];
            literal_operation_responses(operation);
            if method == "post" && listener == "management" {
                protected += 1;
                assert_eq!(operation["security"], json!([{"V1ComplianceBearer":[]}]));
            } else {
                assert!(operation.get("security").is_none());
            }
            if listener == "management" {
                assert_eq!(operation["servers"][0]["url"], "{management_base}");
            } else {
                assert_eq!(document["servers"][0]["url"], "{api_base}");
            }
        }
        assert_eq!(protected, 11);
    }

    fn literal_operation_responses(operation: &Value) {
        let expected = [
            "200", "400", "401", "404", "405", "409", "413", "415", "500", "503", "504", "default",
        ];
        let responses = operation["responses"].as_object().unwrap();
        assert_eq!(
            responses.keys().map(String::as_str).collect::<Vec<_>>(),
            expected
        );
        for code in expected {
            for header in ["Reports-And-Requests", "Source-Offer", "X-Api-Version"] {
                assert!(responses[code]["headers"][header].is_object());
            }
        }
    }

    fn literal_queue_schemas(schemas: &serde_json::Map<String, Value>) {
        use std::collections::BTreeSet;
        for (name, fields) in [
            (
                "V1OpenQueueItem",
                vec![
                    "deadline_at",
                    "overdue",
                    "received_at",
                    "route",
                    "state",
                    "ticket_id",
                ],
            ),
            (
                "V1PurgeDueItem",
                vec!["closed_at", "eligible_at", "ticket_id"],
            ),
        ] {
            let expected = fields.into_iter().collect::<BTreeSet<_>>();
            let schema = &schemas[name];
            assert_eq!(
                schema["properties"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>(),
                expected
            );
            assert_eq!(
                schema["required"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_str().unwrap())
                    .collect::<BTreeSet<_>>(),
                expected
            );
            assert_eq!(schema["required"].as_array().unwrap().len(), expected.len());
        }
        assert_eq!(
            schemas["V1OpenQueueItem"]["properties"]["overdue"]["type"],
            "boolean"
        );
    }

    fn literal_codes() {
        use std::collections::BTreeSet;
        let old = "invalid_request request_too_large empty_query query_too_long too_many_terms
term_too_long phrase_too_long empty_phrase invalid_quotes invalid_operator
invalid_query_syntax too_many_operators no_searchable_terms forbidden_character
excessive_repetition invalid_result_count invalid_page plan_too_complex
preferences_too_large no_shards too_many_shards budget_exhausted
protocol_unavailable invalid_plan schema_mismatch shard_failed retrieval_failed
worker_failed invalid_document_id not_found no_bang_target method_not_allowed
unsupported_media_type internal_error invalid_result overloaded
suppression_unavailable request_timeout"
            .split_whitespace()
            .collect::<BTreeSet<_>>();
        let new =
            "unauthorised invalid_transition retention_not_due compliance_unavailable compliance_capacity rules_unavailable"
            .split_whitespace().collect::<BTreeSet<_>>();
        assert_eq!(old.len(), 38);
        assert_eq!(new.len(), 6);
        assert!(old.is_disjoint(&new));
        let document = serde_json::to_value(stract::api::v1::openapi()).unwrap();
        let codes = document["components"]["schemas"]["V1ErrorCode"]["enum"]
            .as_array()
            .unwrap();
        let observed = codes
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(codes.len(), 44);
        assert_eq!(observed.len(), 44);
        assert_eq!(observed, old.union(&new).copied().collect());
    }
}
