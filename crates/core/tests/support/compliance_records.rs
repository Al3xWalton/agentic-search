//! Supplies independent prefix fixtures without invoking a recovery constructor in readers.
//! Controlled writer changes are distinguished from the observed reader's filesystem effects.

#![deny(missing_docs)]

use crate::support::{self, DomainFixture, FileCounts, HttpFixture};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs, io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering::SeqCst},
        mpsc, Arc, Mutex,
    },
    time::Duration,
};
use stract::compliance::{
    disk::{ComplianceHooks, ComplianceStage},
    journal::view::{read_committed, CommittedJournal},
    model::{Decision, IntakeKind},
    record_types::RecordEnvelope,
    records::{read_view, RecordStore, StoredRecord},
    tickets::AdministrationEvent,
    Error, Result,
};

const RECORD_TIME: i64 = 1789732800;

/// Preserves immutable history while current admission and selection advance independently.
pub fn history_upgrade_contract() {
    let mut fixture = approved_store(false, false, false);
    startup_result(
        &fixture,
        &api_config(&fixture, true),
        Ok(()),
        "original approval",
    );
    let saved = saved_wrappers(&fixture);
    let original = upgrade_export(&fixture, "original-export");
    let original_text = stract::compliance::statement::render(
        &fixture.domain.config,
        &checked_record_view(&fixture),
    );
    assert!(original_text.contains("Synthetic service"));
    assert!(original_text.contains("Synthetic individual"));
    let before = facts(fixture.domain.config.records_dir());
    let draws = fixture.draws();
    upgrade_configuration(&mut fixture);
    let view = read_view(
        &fixture.domain.config,
        fixture.domain.clock.as_ref(),
        fixture.probe.as_ref(),
    );
    assert_eq!(facts(fixture.domain.config.records_dir()), before);
    assert_eq!(fixture.draws(), draws);
    assert_eq!(
        view.as_ref().map(|_| ()).map_err(|error| *error),
        Ok(()),
        "configuration upgrade closed immutable history"
    );
    assert_eq!(view.unwrap().records().len(), 4);
    startup_result(
        &fixture,
        &api_config(&fixture, true),
        Err(Error::InvalidInput),
        "upgrade gap retains history but refuses hosted selection",
    );
    startup_result(
        &fixture,
        &api_config(&fixture, false),
        Ok(()),
        "local upgrade gap",
    );
    assert!(stract::compliance::statement::render(
        &fixture.domain.config,
        &checked_record_view(&fixture)
    )
    .contains("Synthetic service"));
    let exported = upgrade_export(&fixture, "upgrade-export");
    assert_eq!(
        exported, original,
        "upgrade changed historical envelope or HTML bytes"
    );
    assert_eq!(saved_wrappers(&fixture), saved);
    upgrade_assessments(&fixture);
    assert_saved_wrappers(&fixture, &saved);
    upgrade_stale_admission(&fixture);
    upgrade_stale_selection();
    history_lower_caps();
    oversized_historical_wrapper();
    let mut owner = fixture.owner();
    let mut unselected = record_input("icra");
    unselected["id"] = json!("sample.unselected");
    add_record(&mut owner, unselected);
    assert!(
        !stract::compliance::statement::render(&fixture.domain.config, owner.view())
            .contains("sample — not an approval"),
        "inactive input labelled the active statement"
    );
}

fn oversized_historical_wrapper() {
    let fixture = RecordsFixture::new();
    let mut owner = fixture.owner();
    add_record(&mut owner, record_input("icra"));
    drop(owner);
    let path = fixture.path("assessment.icra/0000000001.json");
    let bytes = fs::read(&path).unwrap();
    let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.set_len(1048577).unwrap();
    drop(file);
    refused_record_view(&fixture, "above-static-maximum historical wrapper accepted");
    fs::write(path, bytes).unwrap();
    assert_eq!(checked_record_view(&fixture).records().len(), 1);
}

fn upgrade_configuration(fixture: &mut RecordsFixture) {
    let mut settings = fixture.domain.config.settings().clone();
    settings.statement_version = "next.statement".into();
    settings
        .statement_changes
        .push(stract::config::compliance::StatementChange {
            version: "next.statement".into(),
            at: RECORD_TIME,
            summary: "Synthetic statement update".into(),
        });
    settings.priority_catalog_version = Some("next.catalog".into());
    fixture.domain.config = settings
        .validate(
            &fixture
                .domain
                .config
                .store_dir()
                .parent()
                .unwrap()
                .join("suppression.json"),
        )
        .unwrap();
}

fn saved_wrappers(fixture: &RecordsFixture) -> BTreeMap<PathBuf, Vec<u8>> {
    checked_record_view(fixture)
        .records()
        .keys()
        .map(|reference| {
            let path = fixture.path(&format!("{}/{:010}.json", reference.id, reference.version));
            (path.clone(), fs::read(path).unwrap())
        })
        .collect()
}

fn assert_saved_wrappers(fixture: &RecordsFixture, saved: &BTreeMap<PathBuf, Vec<u8>>) {
    let view = checked_record_view(fixture);
    for (path, bytes) in saved {
        assert_eq!(
            &fs::read(path).unwrap(),
            bytes,
            "upgrade rewrote an immutable wrapper"
        );
        let stored: StoredRecord = serde_json::from_slice(bytes).unwrap();
        assert!(view.get(&stored.record.reference()).is_some());
    }
}

fn upgrade_export(fixture: &RecordsFixture, name: &str) -> BTreeMap<String, (Vec<u8>, Value)> {
    let out = fixture
        .domain
        .config
        .store_dir()
        .parent()
        .unwrap()
        .join(name);
    let config = cli_config(fixture);
    let before = facts(fixture.domain.config.records_dir());
    let draws = fixture.draws();
    let result = real_cli(&config, &["records", "export"], &[("--out", &out)]);
    assert_eq!(facts(fixture.domain.config.records_dir()), before);
    assert_eq!(fixture.draws(), draws);
    let view = checked_record_view(fixture);
    assert_eq!(cli_success(result)["versions"], view.records().len());
    let receipt = support::read_json(&out.join("export-receipt.json"));
    verify_exported_records(&view, &out, &receipt);
    let measures = fs::read_to_string(out.join("assessment.measures-1.html")).unwrap();
    assert_eq!(
        measures.matches("voluntary_pending_legal_review").count(),
        7,
        "export lost the final voluntary adoption value"
    );
    receipt["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let reference = entry["record_ref"].as_str().unwrap();
            let (id, version) = reference.split_once(':').unwrap();
            (
                reference.into(),
                (
                    fs::read(out.join(format!("{id}-{version}.html"))).unwrap(),
                    entry["sha256"].clone(),
                ),
            )
        })
        .collect()
}

fn next_version(mut value: Value, version: u32) -> Value {
    value["version"] = json!(version);
    value["supersedes"] = json!(format!("{}:{}", value["id"].as_str().unwrap(), version - 1));
    value
}

fn upgraded_record(kind: &str) -> Value {
    let mut value = next_version(approved_record(kind), 2);
    value["body"]["service"] = json!("Updated synthetic service");
    if matches!(kind, "icra" | "caa") {
        value["body"]["priority_catalog_version"] = json!("next.catalog");
        value["body"]["responsible_person"] = json!("Updated synthetic individual");
    }
    if kind == "manifest" {
        value["body"]["accountable_person"] = json!("Updated synthetic individual");
        value["body"]["statement_version"] = json!("next.statement");
        for field in ["icra", "caa", "measures"] {
            value["body"][field] = json!(format!("assessment.{field}:2"));
        }
    }
    value
}

fn upgrade_assessments(fixture: &RecordsFixture) {
    let mut owner = fixture.owner();
    for (offset, kind) in ["icra", "caa", "measures", "manifest"]
        .into_iter()
        .enumerate()
    {
        let draws = fixture.draws();
        let result = owner.add(typed(upgraded_record(kind)), "synthetic.operator");
        assert_eq!(fixture.draws(), draws + 1, "{kind}: upgrade salt count");
        assert_eq!(
            result.map(|(reference, seq)| (reference.to_string(), seq)),
            Ok((format!("assessment.{kind}:2"), 10 + 2 * offset as u64))
        );
    }
    drop(owner);
    startup_result(
        fixture,
        &api_config(fixture, true),
        Ok(()),
        "upgraded approval",
    );
    let text = stract::compliance::statement::render(
        &fixture.domain.config,
        &checked_record_view(fixture),
    );
    assert!(text.contains("Updated synthetic service"));
    assert!(text.contains("Updated synthetic individual"));
    assert!(!text.contains("Synthetic service") && !text.contains("Synthetic individual"));
    assert!(text.contains("next&#46;statement"));
}

fn upgrade_stale_admission(fixture: &RecordsFixture) {
    let mut owner = fixture.owner();
    for (kind, field, stale, current) in [
        ("manifest", "statement_version", "619.1", "next.statement"),
        (
            "icra",
            "priority_catalog_version",
            "catalog.synthetic",
            "next.catalog",
        ),
    ] {
        let mut value = next_version(upgraded_record(kind), 3);
        value["body"][field] = json!(stale);
        assert_addition_refused(
            fixture,
            &mut owner,
            value.clone(),
            Error::InvalidInput,
            &format!("stale admission {kind}/{field}"),
        );
        value["body"][field] = json!(current);
        add_record(&mut owner, value);
    }
}

fn upgrade_stale_selection() {
    let mut fixture = approved_store(false, false, false);
    upgrade_configuration(&mut fixture);
    let mut value = next_version(approved_record("manifest"), 2);
    value["body"]["statement_version"] = json!("next.statement");
    let mut owner = fixture.owner();
    add_record(&mut owner, value);
    drop(owner);
    assert_eq!(checked_record_view(&fixture).records().len(), 5);
    startup_result(
        &fixture,
        &api_config(&fixture, true),
        Err(Error::InvalidInput),
        "new manifest still selects retired catalog",
    );
}

fn sized_record(size: u64) -> Value {
    let mut value = record_input("icra");
    value["body"]["risk_factors"] = json!((0..64)
        .map(|n| format!("{n:04}{}", "a".repeat(2044)))
        .collect::<Vec<_>>());
    value["body"]["additional_characteristics"] = json!((0..64)
        .map(|n| format!("{n:04}{}", "b".repeat(2044)))
        .collect::<Vec<_>>());
    value["body"]["questionnaire_outcomes"] = json!((0..64)
        .map(|n| json!({"id":format!("question.{n}"),"answer":"c".repeat(2048)}))
        .collect::<Vec<_>>());
    let before = wrapper_size(value.clone());
    assert!(before < size);
    let mut remaining = size - before - 24;
    let mut controls = Vec::new();
    for n in 0..64 {
        if remaining < 80 {
            break;
        }
        let description = format!("Control {n}");
        let fixed = serde_json::to_vec(&json!({"description":description,"effect":""}))
            .unwrap()
            .len() as u64
            + u64::from(n > 0);
        let length = remaining.saturating_sub(fixed).min(2048);
        controls.push(json!({"description":description,"effect":"d".repeat(length as usize)}));
        remaining -= fixed + length;
    }
    value["body"]["existing_controls"] = json!(controls);
    let current = wrapper_size(value.clone());
    let original = value["body"]["reasoning"].as_str().unwrap().len() as u64;
    value["body"]["reasoning"] = json!("e".repeat((original + size - current) as usize));
    assert_eq!(
        wrapper_size(value.clone()),
        size,
        "independently sized wrapper"
    );
    assert!(
        typed(value.clone()).validate(RECORD_TIME).is_ok(),
        "sized record intrinsic shape"
    );
    value
}

fn history_lower_caps() {
    let mut fixture = approved_store(false, false, false);
    let saved = saved_wrappers(&fixture);
    let mut owner = fixture.owner();
    for n in 0..5 {
        let mut value = sized_record(524288);
        value["id"] = json!(format!("padding.record{n}"));
        add_record(&mut owner, value);
    }
    drop(owner);
    let original = fixture.domain.config.clone();
    let original_exports = upgrade_export(&fixture, "caps-original");
    for cap in ["count", "wrapper", "aggregate"] {
        let mut settings = original.settings().clone();
        match cap {
            "count" => settings.max_records = 1,
            "wrapper" => settings.max_record_bytes = 4096,
            "aggregate" => settings.max_records_bytes = 2187388,
            _ => unreachable!(),
        }
        fixture.domain.config = settings
            .validate(
                &original
                    .store_dir()
                    .parent()
                    .unwrap()
                    .join("suppression.json"),
            )
            .unwrap();
        let before = facts(fixture.domain.config.records_dir());
        let draws = fixture.draws();
        let mut owner = fixture.owner();
        assert_eq!(facts(fixture.domain.config.records_dir()), before);
        assert_eq!(fixture.draws(), draws);
        assert_eq!(owner.view().records().len(), 9);
        let mut value = sized_record(524288);
        value["id"] = json!("padding.next");
        assert_addition_refused(
            &fixture,
            &mut owner,
            value,
            Error::Capacity,
            &format!("lowered historical cap {cap}"),
        );
        drop(owner);
        assert_eq!(
            upgrade_export(&fixture, &format!("caps-{cap}")),
            original_exports
        );
        assert_saved_wrappers(&fixture, &saved);
    }
}

fn publication_config(fixture: &RecordsFixture) -> (stract::config::ApiConfig, String) {
    use stract::compliance::model::{Entropy, SystemEntropy};
    let mut bytes = [0u8; 32];
    SystemEntropy.fill(&mut bytes).unwrap();
    let token = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut config = api_config(fixture, false);
    let path = fixture
        .domain
        .config
        .store_dir()
        .parent()
        .unwrap()
        .join("admin.token");
    private_record_file(&path, token.as_bytes());
    config.compliance.admin_token_file = Some(path);
    (config, token)
}

async fn record_http(
    fixture: &RecordsFixture,
    state: &Arc<stract::api::v1::V1State>,
    management: bool,
    request: axum::http::Request<axum::body::Body>,
) -> support::Observed {
    use tower::ServiceExt;
    let statement = request.uri().path() == "/v1/statement";
    let before = facts(fixture.domain.config.records_dir());
    let opens = fixture.probe.counts.opens.load(SeqCst);
    let draws = fixture.draws();
    let app = if management {
        stract::api::v1::compose_management(state.clone())
    } else {
        stract::api::v1::compose_api(axum::Router::new(), state.clone())
    };
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(facts(fixture.domain.config.records_dir()), before);
    if statement {
        assert_eq!(fixture.draws(), draws, "statement request drew entropy");
        assert_eq!(
            fixture.probe.counts.opens.load(SeqCst),
            opens,
            "statement request probed runtime record files"
        );
    }
    support::contract_response(response).await
}

fn request(
    method: &str,
    path: &str,
    value: Value,
    token: Option<&str>,
) -> axum::http::Request<axum::body::Body> {
    let mut request = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let bytes = if value.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(&value).unwrap()
    };
    request.body(axum::body::Body::from(bytes)).unwrap()
}

fn corrupt_publication(fixture: &RecordsFixture, fault: &str) {
    match fault {
        "missing-final" => {
            fs::remove_file(fixture.path("assessment.icra/0000000001.json")).unwrap()
        }
        "wrapper" => fs::write(
            fixture.path("assessment.icra/0000000001.json"),
            b"{corrupt private record",
        )
        .unwrap(),
        "index" => fs::write(fixture.path("index.jsonl"), b"{corrupt index").unwrap(),
        "head" => fs::write(fixture.path("head.json"), b"{corrupt head").unwrap(),
        _ => unreachable!(),
    }
}

/// Keeps record failure within cached publication while ticket administration and rules stay live.
pub fn publication_failure_contract() {
    for fault in ["missing-final", "wrapper", "index", "head"] {
        let fixture = approved_store(false, false, false);
        let (config, token) = publication_config(&fixture);
        corrupt_publication(&fixture, fault);
        let before = facts(fixture.domain.config.records_dir());
        let state = record_state(&fixture, &config);
        assert_eq!(facts(fixture.domain.config.records_dir()), before);
        support::runtime().block_on(async {
            let response = record_http(
                &fixture,
                &state,
                false,
                request("GET", "/v1/statement", Value::Null, None),
            )
            .await;
            support::rejected_response(response, "compliance_unavailable", 503);
            publication_service_control(&fixture, &state, &token).await;
            state.compliance().shutdown().await;
        });
        drop(state);
        startup_result(
            &fixture,
            &api_config(&fixture, true),
            Err(Error::Unavailable),
            "corrupt local publication",
        );
    }
    cached_publication_control();
    let fixture = approved_store(false, false, false);
    let config = api_config(&fixture, true);
    let state = record_state(&fixture, &config);
    support::runtime().block_on(async {
        let response = record_http(
            &fixture,
            &state,
            false,
            request("GET", "/v1/statement", Value::Null, None),
        )
        .await;
        assert!(response.value.is_object());
        assert!(response.value["markdown"].is_string());
        assert_eq!(response.status, 200, "fresh valid publication refused");
        state.compliance().shutdown().await;
    });
}

fn cached_publication_control() {
    let fixture = approved_store(false, false, false);
    let (config, token) = publication_config(&fixture);
    let state = record_state(&fixture, &config);
    support::runtime().block_on(async {
        let original = record_http(
            &fixture,
            &state,
            false,
            request("GET", "/v1/statement", Value::Null, None),
        )
        .await;
        assert!(original.value.is_object());
        assert!(original.value["markdown"].is_string());
        assert_eq!(original.status, 200);
        corrupt_publication(&fixture, "wrapper");
        let response = record_http(
            &fixture,
            &state,
            false,
            request("GET", "/v1/statement", Value::Null, None),
        )
        .await;
        assert_eq!(
            response.bytes, original.bytes,
            "cached statement changed without restart"
        );
        assert_eq!(response.status, 200);
        let cli_config = cli_config(&fixture);
        let before = facts(fixture.domain.config.store_dir());
        let output = real_cli(&cli_config, &["review", "check"], &[]);
        assert_eq!(facts(fixture.domain.config.store_dir()), before);
        cli_refused(output, Error::Unavailable);
        publication_service_control(&fixture, &state, &token).await;
        state.compliance().shutdown().await;
    });
    drop(state);
    let reloaded = record_state(&fixture, &config);
    support::runtime().block_on(async {
        let response = record_http(
            &fixture,
            &reloaded,
            false,
            request("GET", "/v1/statement", Value::Null, None),
        )
        .await;
        support::rejected_response(response, "compliance_unavailable", 503);
        reloaded.compliance().shutdown().await;
    });
    drop(reloaded);
    startup_result(
        &fixture,
        &api_config(&fixture, true),
        Err(Error::Unavailable),
        "corrupt publication restart",
    );
}

async fn publication_service_control(
    fixture: &RecordsFixture,
    state: &Arc<stract::api::v1::V1State>,
    token: &str,
) {
    let response = record_http(
        fixture,
        state,
        false,
        request(
            "POST",
            "/v1/reports/intimate-images",
            json!({"report":support::report(),"urls":["https://synthetic.example.test/item"],
            "intimate_image_content":true,"subject_or_authorised":true,"good_faith":true}),
            None,
        ),
    )
    .await;
    assert!(response.value.is_object());
    assert!(response.value["ticket_id"].is_string());
    let id = response.value["ticket_id"].as_str().unwrap().to_owned();
    assert_eq!(
        response.status, 200,
        "record corruption stopped public intake"
    );
    let response = record_http(
        fixture,
        state,
        false,
        request(
            "GET",
            &format!("/v1/reports/status/{id}"),
            Value::Null,
            None,
        ),
    )
    .await;
    assert!(response.value.is_object());
    assert_eq!(response.value["state"], "queued");
    assert_eq!(
        response.status, 200,
        "record corruption stopped ticket status"
    );
    let response = record_http(
        fixture,
        state,
        true,
        request(
            "POST",
            &format!("/v1/compliance/tickets/{id}/read"),
            json!({"actor":"synthetic.operator"}),
            Some(token),
        ),
    )
    .await;
    assert!(response.value.is_object());
    assert!(response.value["payload_events"].is_array());
    assert_eq!(
        response.status, 200,
        "record corruption stopped authenticated ticket access"
    );
    let response = record_http(
        fixture,
        state,
        false,
        request("POST", "/v1/search", json!({"query":"synthetic"}), None),
    )
    .await;
    assert!(response.value.is_object());
    assert!(response.value["results"].is_array());
    assert_eq!(response.value["results"].as_array().unwrap().len(), 2);
    assert!(
        response.value["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| { item["url"] != "https://synthetic.example.test/item" }),
        "record corruption bypassed an active serving rule"
    );
    assert_eq!(response.status, 200, "record corruption stopped search");
}

fn closed_metric_ticket(number: u64, closed: i64) -> MetricTicket {
    let mut ticket = MetricTicket::new(number, "illegal_content", closed);
    ticket.queued(0);
    ticket.decision(0, "refused", "");
    ticket.row("closed", "closed", 0);
    ticket
}

/// Pins calendar eligibility through the command runner and keeps all record versions across purge.
pub fn retention_contract() {
    let fixture = RecordsFixture::new();
    let mut settings = fixture.domain.config.settings().clone();
    settings.retention_months = 35;
    let suppression = fixture
        .domain
        .config
        .store_dir()
        .parent()
        .unwrap()
        .join("suppression.json");
    assert!(matches!(
        settings.validate(&suppression),
        Err(Error::InvalidInput)
    ));
    settings.retention_months = 36;
    assert!(settings.validate(&suppression).is_ok());
    for (months, due) in [(36, "2027-02-28T12:00:00Z"), (48, "2028-02-29T12:00:00Z")] {
        retention_boundaries(months, due);
    }
    retention_exclusions();
    retention_preserves_records();
}

fn retention_boundaries(months: u32, due: &str) {
    let closed = support::utc("2024-02-29T12:00:00Z").timestamp();
    let due = support::utc(due).timestamp();
    let mut fixture = RecordsFixture::new();
    let mut settings = fixture.domain.config.settings().clone();
    settings.retention_months = months;
    fixture.domain.config = settings
        .validate(
            &fixture
                .domain
                .config
                .store_dir()
                .parent()
                .unwrap()
                .join("suppression.json"),
        )
        .unwrap();
    let config = cli_config(&fixture);
    let closed_ticket = closed_metric_ticket(60, closed);
    let id = closed_ticket.id.clone();
    let mut open = MetricTicket::new(61, "illegal_content", closed);
    open.queued(0);
    let _snapshot = metric_prefix(&fixture.domain, vec![closed_ticket, open], due - 1);
    for (now, count) in [(due - 1, 0), (due, 1), (due + 1, 1)] {
        set_record_clock(&fixture, now);
        let before = facts(fixture.domain.config.store_dir());
        let draws = fixture.draws();
        let result = injected_cli(&fixture, &config, &["retention", "due"], &[]);
        assert_eq!(fixture.draws(), draws);
        assert_eq!(facts(fixture.domain.config.store_dir()), before);
        let value = injected_success(result);
        assert!(value.is_object());
        assert_eq!(value.as_object().unwrap().len(), 2);
        assert_eq!(value["as_of_sequence"], 8);
        assert!(value["items"].is_array());
        assert_eq!(
            value["items"].as_array().unwrap().len(),
            count,
            "retention command eligibility mismatch"
        );
        if count == 1 {
            assert_eq!(
                value["items"][0],
                json!({"ticket_id":id,
                "closed_at":closed,"eligible_at":due})
            );
        }
    }
}

fn retention_exclusions() {
    let closed = support::utc("2024-02-29T12:00:00Z").timestamp();
    let due = support::utc("2027-02-28T12:00:00Z").timestamp();
    let fixture = RecordsFixture::new();
    let config = cli_config(&fixture);
    let retained = closed_metric_ticket(70, closed);
    let id = retained.id.clone();
    let mut purged = closed_metric_ticket(71, closed);
    purged.row("purge_intent", "closed", due - closed);
    purged.row("purged", "closed", due - closed);
    let mut pending = closed_metric_ticket(72, closed);
    pending.row("purge_intent", "closed", due - closed);
    let mut open = MetricTicket::new(73, "illegal_content", closed);
    open.queued(0);
    let _snapshot = metric_prefix(&fixture.domain, vec![retained, purged, pending, open], due);
    let before = facts(fixture.domain.config.store_dir());
    let result = injected_cli(&fixture, &config, &["retention", "due"], &[]);
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert_eq!(
        injected_success(result),
        json!({"as_of_sequence":21,
        "items":[{"ticket_id":id,"closed_at":closed,"eligible_at":due}]})
    );
}

async fn http_admin(
    fixture: &HttpFixture,
    id: &str,
    action: &str,
    mut value: Value,
) -> support::Observed {
    value["actor"] = json!("synthetic.operator");
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

async fn closed_http_ticket(fixture: &HttpFixture) -> String {
    let result = fixture
        .send(
            false,
            "POST",
            "/v1/reports/illegal-content",
            json!({
        "report":support::report(),"urls":["https://synthetic.example.test/item"],
        "suspected_illegality":"Synthetic retained report"}),
            false,
        )
        .await;
    support::contract_headers(&result);
    assert!(result.value.is_object());
    assert!(result.value["ticket_id"].is_string());
    let id = result.value["ticket_id"].as_str().unwrap().to_owned();
    assert_eq!(result.status, 200);
    support::successful_response(
        http_admin(
            fixture,
            &id,
            "decision",
            json!({
        "decision":{"kind":"refused","reasons":"Synthetic refusal",
            "delivery":{"channel":"manual_api","reference":"synthetic-delivery"}}}),
        )
        .await,
    );
    support::successful_response(
        http_admin(
            fixture,
            &id,
            "close",
            json!({
        "reasons":"Synthetic closure"}),
        )
        .await,
    );
    id
}

fn retention_preserves_records() {
    use stract::compliance::{disk::NoHooks, export, model::SystemEntropy};
    let fixture = HttpFixture::new();
    fixture
        .domain
        .clock
        .set_utc(support::utc("2024-02-29T12:00:00Z"))
        .unwrap();
    let mut records = RecordStore::open(
        &fixture.domain.config,
        fixture.domain.clock.clone(),
        Arc::new(SystemEntropy),
        Arc::new(NoHooks),
    )
    .unwrap();
    let at = support::utc("2024-02-29T12:00:00Z").timestamp();
    add_record(&mut records, dated(record_input("icra"), at));
    let mut next = dated(record_input("icra"), at);
    next["version"] = json!(2);
    next["supersedes"] = json!("assessment.icra:1");
    add_record(&mut records, next);
    let record_files = facts(fixture.domain.config.records_dir());
    support::runtime().block_on(async {
        let id = closed_http_ticket(&fixture).await;
        fixture
            .domain
            .clock
            .set_utc(support::utc("2027-02-28T12:00:00Z"))
            .unwrap();
        let journal = fs::read(fixture.domain.path("events.jsonl")).unwrap();
        let payloads = fixture.domain.path(&format!("payloads/{id}"));
        assert!(!facts(&payloads).is_empty());
        let response = http_admin(&fixture, &id, "purge", json!({})).await;
        assert_eq!(
            facts(fixture.domain.config.records_dir()),
            record_files,
            "payload purge changed immutable records or their index"
        );
        assert!(fs::read(fixture.domain.path("events.jsonl"))
            .unwrap()
            .starts_with(&journal));
        assert!(
            facts(&payloads)
                .values()
                .all(|entry| entry.bytes.is_empty()),
            "payload purge retained personal revision bytes"
        );
        support::successful_response(response);
        let after = read_committed(
            &fixture.domain.config,
            fixture.domain.clock.as_ref(),
            &NoHooks,
        );
        assert!(after.is_ok(), "purged ticket chain stopped projecting");
        assert!(after
            .unwrap()
            .tickets()
            .values()
            .all(|ticket| ticket.purged));
        fixture.state.compliance().shutdown().await;
    });
    let out = fixture
        .domain
        .config
        .store_dir()
        .parent()
        .unwrap()
        .join("retained-export");
    let exported = export::export(
        records.view(),
        &out,
        fixture.domain.clock.as_ref(),
        &NoHooks,
    );
    assert_eq!(facts(fixture.domain.config.records_dir()), record_files);
    assert!(
        exported.is_ok(),
        "superseded versions could not be re-exported after purge"
    );
    assert_eq!(exported.unwrap().versions, 2);
    assert!(out.join("assessment.icra-1.html").exists());
    assert!(out.join("assessment.icra-2.html").exists());
}

/// Sends marked untrusted text through private records, actual export, statement and JSON wrapping.
pub fn injection_contract() {
    use stract::compliance::{export, records::RecordView, statement};
    let marker = "Probe<&\"'><script> [link](javascript:probe) `code` # Heading";
    let fixture = RecordsFixture::new();
    let mut owner = fixture.owner();
    let mut value = record_input("icra");
    value["body"]["author"] = json!(marker);
    value["body"]["evidence"][0]["source"] = json!(marker);
    value["body"]["reasoning"] = json!(format!("{marker}\n\t# Injected heading"));
    add_record(&mut owner, value);
    let out = fixture
        .domain
        .config
        .store_dir()
        .parent()
        .unwrap()
        .join("escaped-export");
    let before = facts(fixture.domain.config.store_dir());
    let result = export::export(
        owner.view(),
        &out,
        fixture.domain.clock.as_ref(),
        fixture.probe.as_ref(),
    );
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert!(result.is_ok(), "marked inert export refused");
    let html = fs::read_to_string(out.join("assessment.icra-1.html")).unwrap();
    assert!(
        html.contains("Probe&lt;&amp;&quot;&#39;&gt;&lt;script&gt;"),
        "export inserted raw HTML text"
    );
    assert!(!html.contains("<script>"));
    assert!(!html.contains("href=") && !html.contains("src="));
    let index = fs::read_to_string(fixture.path("index.jsonl")).unwrap();
    assert!(!index.contains("Probe") && !index.contains("Injected heading"));
    assert!(
        fs::read_to_string(fixture.path("assessment.icra/0000000001.json"))
            .unwrap()
            .contains("Probe")
    );
    let (mut config, mut records) = sample_inputs();
    inject_service_identity(&mut records, marker);
    config.compliance.statement_proactive = Some(format!("{marker}\n\t# Injected heading"));
    config.compliance.priority_kind_labels[0] = Some(marker.into());
    let validated = config
        .compliance
        .validate(&config.v1.suppression_store_path)
        .unwrap();
    let view = RecordView::validated(records, 1789689600);
    assert!(
        view.is_ok(),
        "marked service identity broke record validation"
    );
    let markdown = statement::render(&validated, &view.unwrap());
    assert_escaped_manifest_service(&markdown, marker);
    assert!(
        !markdown.contains("<script>"),
        "statement inserted raw HTML text"
    );
    assert!(
        !markdown.contains("[link](javascript:"),
        "statement inserted an active Markdown link"
    );
    assert!(
        !markdown.contains("\n# Injected heading"),
        "statement inserted an untrusted heading"
    );
    assert!(
        !markdown.contains("`code`"),
        "statement inserted untrusted code markup"
    );
    assert!(markdown.contains("Probe&lt;&amp;&quot;&#39;&gt;&lt;script&gt;"));
    assert!(markdown.contains("&#91;link&#93;&#40;javascript&#58;probe&#41;"));
    let encoded = serde_json::to_vec(&json!({"version":"v1","statement_version":"619.1",
        "markdown":markdown}))
    .unwrap();
    let decoded: Value = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded["markdown"], markdown);
    assert_eq!(
        export::escape_html("Safe ordinary text"),
        "Safe ordinary text"
    );
    assert_eq!(
        statement::escape_markdown("Safe ordinary text"),
        "Safe ordinary text"
    );
    let missing = fixture
        .domain
        .config
        .store_dir()
        .parent()
        .unwrap()
        .join("sensitive-path-marker");
    let config = cli_config(&fixture);
    let output = real_cli(&config, &["records", "validate"], &[("--input", &missing)]);
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    cli_refused(output, Error::Unavailable);
    injection_http(marker);
}

fn inject_service_identity(records: &mut [RecordEnvelope], marker: &str) {
    use stract::compliance::record_types::RecordBody;
    for record in records {
        let service = match &mut record.body {
            RecordBody::Manifest(manifest) => &mut manifest.service,
            RecordBody::Icra(assessment)
            | RecordBody::Caa(assessment)
            | RecordBody::Cra(assessment) => &mut assessment.service,
            RecordBody::Measures(measures) => &mut measures.service,
            _ => continue,
        };
        *service = marker.into();
    }
}

fn assert_escaped_manifest_service(markdown: &str, marker: &str) {
    let about = markdown.split_once("## About this service\n\n");
    assert!(about.is_some(), "manifest service section missing");
    let section = about.unwrap().1.split_once("\n## ");
    assert!(
        section.is_some(),
        "manifest service section has no closing heading"
    );
    let section = section.unwrap().0;
    let prefix = section.split_once(" is AVA's web-retrieval service.");
    assert!(prefix.is_some(), "manifest service sentence missing");
    assert_eq!(prefix.unwrap().0,
        "Probe&lt;&amp;&quot;&#39;&gt;&lt;script&gt; &#91;link&#93;&#40;javascript&#58;probe&#41; &#96;code&#96; &#35; Heading",
        "manifest service escaped prefix differs");
    for raw in [marker, "<script>", "[link](javascript:", "`", "# Heading"] {
        assert!(
            !section.contains(raw),
            "manifest service inserted active markup: {raw}"
        );
    }
}

fn injection_http(marker: &str) {
    let fixture = HttpFixture::configured(|config| {
        config.compliance.statement_proactive = Some(format!("{marker}\n\t# Injected heading"));
        config.compliance.priority_kind_labels[0] = Some(marker.into());
    });
    support::runtime().block_on(async {
        let response = fixture
            .send(false, "GET", "/v1/statement", Value::Null, false)
            .await;
        support::contract_headers(&response);
        assert!(response.value.is_object());
        assert!(response.value["markdown"].is_string());
        let text = response.value["markdown"].as_str().unwrap();
        assert!(!text.contains("<script>") && !text.contains("[link](javascript:"));
        assert!(text.contains("Probe&lt;&amp;&quot;&#39;&gt;&lt;script&gt;"));
        assert_eq!(response.status, 200);
        fixture.state.compliance().shutdown().await;
    });
}

fn cli_config(fixture: &RecordsFixture) -> PathBuf {
    let path = fixture
        .domain
        .config
        .store_dir()
        .parent()
        .unwrap()
        .join("operator.toml");
    let config = api_config(fixture, false);
    let mut value = serde_json::to_value(config).unwrap();
    if value["compliance"]["priority_kind_labels"]
        .as_array()
        .unwrap()
        .iter()
        .all(Value::is_null)
    {
        value["compliance"]
            .as_object_mut()
            .unwrap()
            .remove("priority_kind_labels");
    }
    omit_null_fields(&mut value);
    private_record_file(&path, toml::to_string(&value).unwrap().as_bytes());
    path
}

fn omit_null_fields(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            fields.retain(|_, value| !value.is_null());
            fields.values_mut().for_each(omit_null_fields);
        }
        Value::Array(values) => values.iter_mut().for_each(omit_null_fields),
        _ => {}
    }
}

fn capture_real_clock(fixture: &RecordsFixture) {
    use stract::crawler::politeness::{Clock, SystemClock};
    fixture
        .domain
        .clock
        .set_utc(SystemClock::default().utc())
        .unwrap();
}

fn cli_input(fixture: &RecordsFixture, name: &str, value: &Value) -> PathBuf {
    let path = fixture
        .domain
        .config
        .store_dir()
        .parent()
        .unwrap()
        .join(name);
    private_record_file(&path, &serde_json::to_vec(value).unwrap());
    path
}

fn cli_args(config: &Path, words: &[&str], paths: &[(&str, &Path)]) -> Vec<std::ffi::OsString> {
    let mut arguments = words
        .iter()
        .map(std::ffi::OsString::from)
        .collect::<Vec<_>>();
    arguments.extend(["--config".into(), config.as_os_str().to_owned()]);
    for (name, path) in paths {
        arguments.extend([(*name).into(), path.as_os_str().to_owned()]);
    }
    arguments
}

fn real_cli_command(
    config: &Path,
    words: &[&str],
    paths: &[(&str, &Path)],
) -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_stract"));
    command
        .arg("compliance")
        .args(cli_args(config, words, paths))
        .stdin(std::process::Stdio::null())
        .env("RUST_BACKTRACE", "1")
        .env("RUST_LIB_BACKTRACE", "1");
    command
}

fn real_cli(config: &Path, words: &[&str], paths: &[(&str, &Path)]) -> std::process::Output {
    real_cli_command(config, words, paths).output().unwrap()
}

fn cli_success(output: std::process::Output) -> Value {
    assert!(output.stderr.is_empty(), "successful command wrote stderr");
    assert!(output.stdout.ends_with(b"\n"), "command omitted final LF");
    let parsed = serde_json::from_slice::<Value>(&output.stdout);
    assert!(
        parsed.is_ok(),
        "command stdout was not exactly one JSON value"
    );
    let value = parsed.unwrap();
    assert!(value.is_object(), "command success was not an object");
    assert_eq!(output.status.code(), Some(0), "valid real command refused");
    value
}

fn cli_refused(output: std::process::Output, error: Error) {
    assert!(output.stdout.is_empty(), "failed command wrote stdout");
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!("Error: {error}\n"),
        "command exposed more than the fixed domain error"
    );
    assert_eq!(output.status.code(), Some(1));
}

#[derive(clap::Parser)]
struct InjectedCli {
    #[command(subcommand)]
    command: stract::compliance::cli::Command,
}

fn injected_cli(
    fixture: &RecordsFixture,
    config: &Path,
    words: &[&str],
    paths: &[(&str, &Path)],
) -> (Result<()>, Vec<u8>) {
    use clap::Parser;
    let args = std::iter::once(std::ffi::OsString::from("compliance"))
        .chain(cli_args(config, words, paths));
    let parsed = InjectedCli::try_parse_from(args);
    assert!(parsed.is_ok(), "valid injected command syntax refused");
    let mut stdout = Vec::new();
    let result = parsed.unwrap().command.run_with(
        &stract::compliance::cli::Seams {
            clock: fixture.domain.clock.clone(),
            entropy: fixture.entropy.clone(),
            hooks: fixture.probe.clone(),
        },
        &mut stdout,
    );
    (result, stdout)
}

fn injected_success(result: (Result<()>, Vec<u8>)) -> Value {
    assert!(result.0.is_ok(), "valid injected command refused");
    let value = serde_json::from_slice::<Value>(&result.1);
    assert!(
        value.is_ok(),
        "injected command output was not one JSON value"
    );
    value.unwrap()
}

fn record_state(
    fixture: &RecordsFixture,
    config: &stract::config::ApiConfig,
) -> Arc<stract::api::v1::V1State> {
    use stract::api::v1::{compliance_adapter::ComplianceSeams, V1Resources, V1State};
    let before = safe_tree(fixture.domain.config.records_dir());
    let resources = V1Resources::with_compliance_seams(
        config,
        ComplianceSeams {
            clock: fixture.domain.clock.clone(),
            entropy: fixture.entropy.clone(),
            hooks: fixture.probe.clone(),
            ..Default::default()
        },
    );
    assert_eq!(safe_tree(fixture.domain.config.records_dir()), before);
    assert!(
        resources.is_ok(),
        "record-backed resource initializer refused"
    );
    let backend =
        Arc::new(|_: stract::searcher::SearchQuery| async { Ok(support::search_result()) });
    Arc::new(V1State::from_resources(
        config,
        backend,
        &resources.unwrap(),
    ))
}

/// Runs every real binary form, then proves independent writer exclusion and read-only admission.
pub fn cli_contract() {
    let mut fixture = RecordsFixture::new();
    approved_config(&mut fixture.domain);
    let config = cli_config(&fixture);
    let input = cli_input(&fixture, "input.json", &approved_record("icra"));
    let before = facts(fixture.domain.config.store_dir());
    let validated = real_cli(&config, &["records", "validate"], &[("--input", &input)]);
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert_eq!(cli_success(validated), json!({"valid":true}));
    private_record_file(&fixture.domain.config.records_lock(), b"");
    for (index, kind) in ["icra", "caa", "measures", "manifest"]
        .into_iter()
        .enumerate()
    {
        let input = cli_input(&fixture, "input.json", &approved_record(kind));
        let output = real_cli(
            &config,
            &["records", "add", "--actor", "synthetic.operator"],
            &[("--input", &input)],
        );
        assert!(
            !fixture.domain.config.journal_dir().exists(),
            "record import initialized tickets"
        );
        assert_eq!(
            cli_success(output),
            json!({"record_ref":format!("assessment.{kind}:1"),
            "sequence":2 * (index + 1)})
        );
    }
    assert_eq!(
        fixture.domain.config.records_dir(),
        fixture.domain.config.store_dir().join("records")
    );
    let before = facts(fixture.domain.config.records_dir());
    capture_real_clock(&fixture);
    let state = record_state(&fixture, &api_config(&fixture, true));
    assert_eq!(facts(fixture.domain.config.records_dir()), before);
    live_cli_forms(&fixture, &config);
    capture_real_clock(&fixture);
    let owner = fixture.owner();
    let mut next = record_input("icra");
    next["id"] = json!("independent.draft");
    let input = cli_input(&fixture, "input.json", &next);
    let before = facts(fixture.domain.config.store_dir());
    let refused = real_cli(
        &config,
        &["records", "add", "--actor", "synthetic.operator"],
        &[("--input", &input)],
    );
    assert_eq!(
        facts(fixture.domain.config.store_dir()),
        before,
        "contending command wrote records"
    );
    cli_refused(refused, Error::Unavailable);
    let read = real_cli(&config, &["records", "validate"], &[("--input", &input)]);
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert_eq!(cli_success(read), json!({"valid":true}));
    drop(owner);
    assert_eq!(
        cli_success(real_cli(
            &config,
            &["records", "add", "--actor", "synthetic.operator"],
            &[("--input", &input)]
        ))["record_ref"],
        "independent.draft:1"
    );
    capture_real_clock(&fixture);
    cli_read_counts(&fixture, &config);
    cli_errors(&fixture, &config);
    prove_service_healthy(&fixture, state);
    owner_release_during_child_spawn();
    moving_record_heads();
}

fn owner_release_during_child_spawn() {
    let fixture = RecordsFixture::new();
    private_record_file(&fixture.domain.config.records_lock(), b"");
    let owner = fixture.owner();
    let before = facts(fixture.domain.config.store_dir());
    let draws = fixture.draws();
    let writes = fixture.probe.writes.load(SeqCst);
    let child = support::PausedChild::start().unwrap();
    let first = fixture.open().map(|_| ());
    let second = fixture.open().map(|_| ());
    drop(owner);
    let reopened = fixture.open();
    let status = child.finish();
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert_eq!(fixture.draws(), draws);
    assert_eq!(fixture.probe.writes.load(SeqCst), writes);
    assert_eq!(first, Err(Error::Unavailable), "record: first contention");
    assert_eq!(
        second,
        Err(Error::Unavailable),
        "record: failed acquire unlocked owner"
    );
    assert!(
        reopened.is_ok(),
        "child inherited a dropped record owner's lock"
    );
    assert!(
        status.is_ok_and(|status| status.success()),
        "record: child failed"
    );
    drop(reopened);
}

fn live_cli_forms(fixture: &RecordsFixture, config: &Path) {
    let before = facts(fixture.domain.config.store_dir());
    let check = real_cli(config, &["review", "check"], &[]);
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    let checked = cli_success(check);
    assert!(checked["items"].is_array());
    assert_eq!(
        checked
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["items", "late_completions"]
    );
    assert_eq!(checked["late_completions"], json!([]));
    let due = real_cli(
        config,
        &["review", "open-due", "--actor", "synthetic.operator"],
        &[],
    );
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert_eq!(
        cli_success(due),
        json!({"created":0,"existing":0,"record_refs":[]})
    );
    let trigger = real_cli(
        config,
        &[
            "review",
            "trigger",
            "--actor",
            "synthetic.operator",
            "--kind",
            "risk-profile-changed",
            "--reference",
            "synthetic-change",
        ],
        &[],
    );
    assert_eq!(cli_success(trigger)["created"], 2);
    let metrics = real_cli(
        config,
        &[
            "metrics",
            "--month",
            "2026-09",
            "--actor",
            "synthetic.operator",
        ],
        &[],
    );
    assert_eq!(
        cli_success(metrics),
        json!({"record_ref":"metrics.2026-09:1","as_of_sequence":0})
    );
    let input = cli_input(
        fixture,
        "release.json",
        &json!({"format_version":1,
        "release_id":"synthetic-empty","service":"Synthetic service","planned_at":RECORD_TIME,
        "changes":[],"assessment_updates":[]}),
    );
    let before = facts(fixture.domain.config.store_dir());
    let release = real_cli(config, &["release", "validate"], &[("--input", &input)]);
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert_eq!(cli_success(release), json!({"valid":true}));
    let retention = real_cli(config, &["retention", "due"], &[]);
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert_eq!(
        cli_success(retention),
        json!({"as_of_sequence":0,"items":[]})
    );
    let parent = fixture.domain.config.store_dir().parent().unwrap();
    let out = parent.join("export");
    let export = real_cli(config, &["records", "export"], &[("--out", &out)]);
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert_eq!(cli_success(export), json!({"versions":7,"files":9}));
    let out = parent.join("statement.md");
    let rendered = real_cli(config, &["statement", "render"], &[("--out", &out)]);
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    let result = cli_success(rendered);
    assert_eq!(result["statement_version"], "619.1");
    assert_eq!(result["bytes"], fs::metadata(out).unwrap().len());
}

fn cli_read_counts(fixture: &RecordsFixture, config: &Path) {
    let view = checked_record_view(fixture);
    let before = facts(fixture.domain.config.store_dir());
    let opens = fixture.probe.counts.opens.load(SeqCst);
    let draws = fixture.draws();
    let result = injected_cli(fixture, config, &["review", "check"], &[]);
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert_eq!(fixture.draws(), draws);
    assert_eq!(
        fixture.probe.counts.opens.load(SeqCst) - opens,
        view.records().len() + 4,
        "read-only command did not read each published version exactly once"
    );
    assert!(injected_success(result)["items"].is_array());
}

fn cli_errors(fixture: &RecordsFixture, config: &Path) {
    cli_bad_config(config);
    let input = fixture
        .domain
        .config
        .store_dir()
        .parent()
        .unwrap()
        .join("bad-input.json");
    private_record_file(&input, b"{malicious private input excerpt");
    let before = facts(fixture.domain.config.store_dir());
    let output = real_cli(config, &["records", "validate"], &[("--input", &input)]);
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    cli_refused(output, Error::InvalidInput);
    fs::remove_file(&input).unwrap();
    let output = real_cli(config, &["records", "validate"], &[("--input", &input)]);
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    cli_refused(output, Error::Unavailable);
    let output = real_cli_command(config, &["records", "validate"], &[("--input", &input)])
        .env("RUST_BACKTRACE", "full")
        .output()
        .unwrap();
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    cli_refused(output, Error::Unavailable);
    for words in [
        vec!["records"],
        vec!["review"],
        vec!["release"],
        vec!["statement"],
        vec!["retention"],
        vec![
            "review",
            "trigger",
            "--kind",
            "annual",
            "--reference",
            "x",
            "--actor",
            "synthetic.operator",
        ],
    ] {
        let output = real_cli(config, &words, &[]);
        assert_eq!(facts(fixture.domain.config.store_dir()), before);
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8(output.stderr).unwrap().contains("error:"));
        assert_eq!(
            output.status.code(),
            Some(2),
            "invalid command syntax accepted"
        );
    }
}

fn cli_bad_config(config: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let parent = config.parent().unwrap();
    let bad = parent.join("invalid-operator.toml");
    for content in [b"invalid = [".to_vec(), vec![b' '; 1048577]] {
        private_record_file(&bad, &content);
        let before = facts(parent);
        let output = real_cli(&bad, &["review", "check"], &[]);
        assert_eq!(facts(parent), before);
        cli_refused(output, Error::InvalidInput);
    }
    fs::write(&bad, fs::read(config).unwrap()).unwrap();
    fs::set_permissions(&bad, fs::Permissions::from_mode(0o644)).unwrap();
    let before = facts(parent);
    let output = real_cli(&bad, &["review", "check"], &[]);
    assert_eq!(facts(parent), before);
    cli_refused(output, Error::Unavailable);
    fs::remove_file(&bad).unwrap();
    let before = facts(parent);
    let output = real_cli(&bad, &["review", "check"], &[]);
    assert_eq!(facts(parent), before);
    cli_refused(output, Error::Unavailable);
}

fn prove_service_healthy(fixture: &RecordsFixture, state: Arc<stract::api::v1::V1State>) {
    use tower::ServiceExt;
    support::runtime().block_on(async {
        let result = state
            .compliance()
            .admit(
                support::intake(IntakeKind::IllegalContent {
                    suspected_illegality: "Synthetic report after live record commands".into(),
                }),
                Arc::new(()),
            )
            .await;
        assert!(result.is_ok(), "live commands stopped report intake");
        let before = facts(fixture.domain.config.store_dir());
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/search")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(r#"{"query":"synthetic"}"#))
            .unwrap();
        let response = stract::api::v1::compose_api(axum::Router::new(), state.clone())
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(facts(fixture.domain.config.store_dir()), before);
        let response = support::contract_response(response).await;
        assert!(response.value.is_object());
        assert!(response.value["results"].is_array());
        assert_eq!(response.status, 200, "live commands stopped search");
        state.compliance().shutdown().await;
    });
}

fn moving_record_heads() {
    for regressed in [false, true] {
        let fixture = RecordsFixture::new();
        let mut owner = fixture.owner();
        let mut heads = Vec::new();
        for kind in ["icra", "caa", "cra"] {
            add_record(&mut owner, record_input(kind));
            heads.push(fs::read(fixture.path("head.json")).unwrap());
        }
        let initial = if regressed { &heads[1] } else { &heads[0] };
        fs::write(fixture.path("head.json"), initial).unwrap();
        let changes = if regressed {
            BTreeMap::from([(5, heads[0].clone())])
        } else {
            BTreeMap::from([(4, heads[1].clone()), (8, heads[2].clone())])
        };
        let mut expected = facts(fixture.domain.config.store_dir());
        expected.get_mut(&fixture.path("head.json")).unwrap().bytes =
            changes.last_key_value().unwrap().1.clone();
        let hooks = HeadChanges {
            path: fixture.path("head.json"),
            changes,
            counts: FileCounts::default(),
        };
        let draws = fixture.draws();
        let result = read_view(
            &fixture.domain.config,
            fixture.domain.clock.as_ref(),
            &hooks,
        );
        assert_eq!(hooks.counts.writes.load(SeqCst), 0);
        assert_eq!(fixture.draws(), draws);
        assert_eq!(facts(fixture.domain.config.store_dir()), expected);
        if regressed {
            assert!(
                matches!(result, Err(Error::Unavailable)),
                "regressed record head accepted"
            );
        } else {
            assert_eq!(
                hooks.counts.opens.load(SeqCst),
                8,
                "record retry reread an immutable version"
            );
            assert!(result.is_ok(), "two advancing record heads refused");
            assert_eq!(result.unwrap().sequence, 4);
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SampleBundle {
    format_version: u64,
    records: Vec<RecordEnvelope>,
}

fn sample_inputs() -> (stract::config::ApiConfig, Vec<RecordEnvelope>) {
    let config = toml::from_str(include_str!("../../../../configs/api.toml")).unwrap();
    let bundle: SampleBundle = serde_json::from_str(include_str!(
        "../../../../configs/compliance/sample-records.json"
    ))
    .unwrap();
    assert_eq!(bundle.format_version, 1);
    assert_eq!(bundle.records.len(), 3);
    let mut records = bundle.records;
    records.push(
        serde_json::from_str(include_str!("../../../../configs/compliance/manifest.json")).unwrap(),
    );
    (config, records)
}

fn policy_clause() -> &'static str {
    "A complaint may be treated as manifestly unfounded only when it \
        repeats a concluded complaint without new information. A reviewer \
        must identify the earlier complaint and explain why no new \
        information changes the decision. Disagreement alone is not enough."
}

fn statement_sections(text: &str) {
    let headings = text
        .lines()
        .filter(|line| line.starts_with("## "))
        .collect::<Vec<_>>();
    assert_eq!(
        headings,
        [
            "## About this service",
            "## Reports and requests",
            "## Complaints and appeals",
            "## Manifestly unfounded complaints",
            "## Proactive technology",
            "## Illegal content",
            "## Children: primary priority content",
            "## Children: priority content",
            "## Children: non-designated content",
            "## Accountable person",
            "## Retention and records",
            "## Version and change log"
        ]
    );
    for heading in headings {
        let body = text
            .split(heading)
            .nth(1)
            .unwrap()
            .split("\n## ")
            .next()
            .unwrap();
        assert!(!body.trim().is_empty(), "empty statement section");
    }
    let priorities = text
        .lines()
        .filter(|line| line.starts_with("### P"))
        .collect::<Vec<_>>();
    assert_eq!(priorities.len(), 17);
    for (index, heading) in priorities.into_iter().enumerate() {
        assert_eq!(heading, format!("### P{:02}", index + 1));
    }
    assert!(
        text.contains(policy_clause()),
        "statement altered the written complaint clause"
    );
}

/// Pins the API-only wrapper, all transport controls and the literal documented operation set.
pub fn statement_http_contract() {
    cached_statement_repeats();
    let (sample_config, sample_records) = sample_inputs();
    public_statement_wording(&sample_render(&sample_config, sample_records));
    let fixture = HttpFixture::new();
    support::runtime().block_on(async {
        let response = fixture
            .send(false, "GET", "/v1/statement", Value::Null, false)
            .await;
        support::contract_headers(&response);
        assert!(
            response.value.is_object(),
            "statement wrapper is not an object"
        );
        assert_eq!(response.value.as_object().unwrap().len(), 3);
        assert_eq!(response.value["version"], "v1");
        assert_eq!(response.value["statement_version"], "619.1");
        assert!(response.value["markdown"].is_string());
        statement_sections(response.value["markdown"].as_str().unwrap());
        assert_eq!(
            response.status, 200,
            "unauthenticated public statement unavailable"
        );
        for management in [false, true] {
            for authorised in [false, true] {
                let obsolete = fixture
                    .send(
                        management,
                        "GET",
                        "/v1/compliance/statement",
                        Value::Null,
                        authorised,
                    )
                    .await;
                support::rejected_response(obsolete, "not_found", 404);
            }
        }
        for credential in [None, Some(fixture.token.clone()), Some("01".repeat(32))] {
            let mut request = axum::http::Request::builder().uri("/v1/statement");
            if let Some(credential) = credential {
                request = request.header("authorization", format!("Bearer {credential}"));
            }
            let response = fixture
                .raw(true, request.body(axum::body::Body::empty()).unwrap())
                .await;
            support::rejected_response(response, "not_found", 404);
        }
        check_live_clause(&fixture).await;
        statement_transport(&fixture).await;
        fixture.state.compliance().shutdown().await;
    });
    statement_openapi();
}

fn cached_statement_repeats() {
    let fixture = approved_store(false, false, false);
    let state = record_state(&fixture, &api_config(&fixture, false));
    let opens = fixture.probe.counts.opens.load(SeqCst);
    let draws = fixture.draws();
    let before = facts(fixture.domain.config.store_dir());
    support::runtime().block_on(async {
        let mut first = None;
        for _ in 0..3 {
            let response = record_http(
                &fixture,
                &state,
                false,
                request("GET", "/v1/statement", Value::Null, None),
            )
            .await;
            assert_eq!(facts(fixture.domain.config.store_dir()), before);
            assert_eq!(fixture.probe.counts.opens.load(SeqCst), opens);
            assert_eq!(fixture.draws(), draws);
            support::contract_headers(&response);
            assert!(
                response.value["markdown"].is_string(),
                "API listener returned no statement markdown"
            );
            if let Some(bytes) = &first {
                assert_eq!(&response.bytes, bytes);
            }
            first = Some(response.bytes.clone());
            assert!(response.value["markdown"]
                .as_str()
                .unwrap()
                .contains("within 48 hours"));
            assert!(response.value["markdown"]
                .as_str()
                .unwrap()
                .contains("within 30 days"));
            assert_eq!(response.status, 200);
        }
        state.compliance().shutdown().await;
    });
}

async fn check_live_clause(fixture: &HttpFixture) {
    let response = fixture
        .send(false, "GET", "/v1/reports", Value::Null, false)
        .await;
    support::contract_headers(&response);
    assert!(response.value.is_object());
    assert!(response.value["routes"].is_array());
    let mut complaints = 0;
    for route in response.value["routes"].as_array().unwrap() {
        assert!(route.is_object());
        assert!(route["fields"].is_array());
        if [
            "site_complaint",
            "data_protection_complaint",
            "online_safety_complaint",
        ]
        .contains(&route["route"].as_str().unwrap())
        {
            let report = route["fields"]
                .as_array()
                .unwrap()
                .iter()
                .find(|field| field["name"] == "report");
            assert!(report.is_some());
            let description = report.unwrap()["description"].as_str().unwrap();
            assert!(
                description.ends_with(policy_clause()),
                "live index complaint clause changed"
            );
            complaints += 1;
        }
    }
    assert_eq!(complaints, 3);
    assert_eq!(response.status, 200);
}

async fn statement_transport(fixture: &HttpFixture) {
    for (method, path, bytes, encoding, code, status) in [
        (
            "GET",
            "/v1/statement",
            vec![b'x'],
            "identity",
            "invalid_request",
            400,
        ),
        (
            "GET",
            "/v1/statement",
            vec![b' '; 65536],
            "identity",
            "invalid_request",
            400,
        ),
        (
            "GET",
            "/v1/statement",
            vec![b' '; 65537],
            "identity",
            "request_too_large",
            413,
        ),
        (
            "GET",
            "/v1/statement?extra=1",
            vec![],
            "identity",
            "invalid_request",
            400,
        ),
        (
            "GET",
            "/v1/statement",
            vec![],
            "gzip",
            "unsupported_media_type",
            415,
        ),
        (
            "OPTIONS",
            "/v1/statement",
            vec![],
            "identity",
            "method_not_allowed",
            405,
        ),
        (
            "GET",
            "/v1/statement/missing",
            vec![],
            "identity",
            "not_found",
            404,
        ),
    ] {
        let request = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("content-encoding", encoding)
            .body(axum::body::Body::from(bytes))
            .unwrap();
        let response = fixture.raw(false, request).await;
        support::rejected_response(response, code, status);
    }
    let response = fixture
        .send(false, "HEAD", "/v1/statement", Value::Null, false)
        .await;
    support::contract_headers(&response);
    assert!(response.bytes.is_empty());
    assert_eq!(response.status, 405);
}

fn documented_operations() -> std::collections::BTreeSet<(&'static str, &'static str, &'static str)>
{
    [
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
    .collect()
}

fn statement_openapi() {
    let doc = serde_json::to_value(stract::api::v1::openapi()).unwrap();
    assert!(doc.is_object());
    assert!(doc["paths"].is_object());
    let mut observed = std::collections::BTreeSet::new();
    for (path, item) in doc["paths"].as_object().unwrap() {
        assert!(item.is_object());
        for (method, operation) in item.as_object().unwrap() {
            if [
                "get", "post", "delete", "put", "patch", "options", "head", "trace",
            ]
            .contains(&method.as_str())
            {
                assert!(operation.is_object());
                observed.insert((
                    path.as_str(),
                    method.as_str(),
                    operation["x-listener"].as_str().unwrap(),
                ));
                assert!(operation["responses"].is_object());
                assert_eq!(
                    operation["responses"]
                        .as_object()
                        .unwrap()
                        .keys()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    [
                        "200", "400", "401", "404", "405", "409", "413", "415", "500", "503",
                        "504", "default"
                    ]
                );
            }
        }
    }
    assert_eq!(observed, documented_operations());
    assert_eq!(observed.len(), 25);
    assert_eq!(doc["paths"].as_object().unwrap().len(), 25);
    let schema = &doc["components"]["schemas"];
    assert!(schema.is_object());
    assert!(schema
        .as_object()
        .unwrap()
        .keys()
        .all(|key| key.starts_with("V1")));
    assert!(schema["V1StatementResponse"]["properties"].is_object());
    assert_eq!(
        schema["V1StatementResponse"]["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["markdown", "statement_version", "version"]
    );
    assert!(doc["info"]["description"].as_str().unwrap().contains(
        "Every operation lists the uniform twelve statuses; 401 and 409 are \
            returned only by /v1/compliance operations."
    ));
    statement_codes(schema);
}

fn statement_codes(schema: &Value) {
    let expected = concat!(
        "invalid_request request_too_large empty_query query_too_long too_many_terms ",
        "term_too_long phrase_too_long empty_phrase invalid_quotes invalid_operator ",
        "invalid_query_syntax too_many_operators no_searchable_terms forbidden_character ",
        "excessive_repetition invalid_result_count invalid_page plan_too_complex ",
        "preferences_too_large no_shards too_many_shards budget_exhausted protocol_unavailable ",
        "invalid_plan schema_mismatch shard_failed retrieval_failed worker_failed ",
        "invalid_document_id not_found no_bang_target method_not_allowed unsupported_media_type ",
        "internal_error invalid_result overloaded suppression_unavailable request_timeout ",
        "unauthorised invalid_transition retention_not_due compliance_unavailable ",
        "compliance_capacity rules_unavailable"
    )
    .split_whitespace()
    .collect::<std::collections::BTreeSet<_>>();
    assert!(schema["V1ErrorCode"]["enum"].is_array());
    let codes = schema["V1ErrorCode"]["enum"].as_array().unwrap();
    assert_eq!(codes.len(), 44);
    let actual = codes
        .iter()
        .map(|code| code.as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(actual, expected);
}

fn sample_render(config: &stract::config::ApiConfig, records: Vec<RecordEnvelope>) -> String {
    use stract::compliance::{records::RecordView, statement};
    let config = config
        .compliance
        .validate(&config.v1.suppression_store_path)
        .unwrap();
    let view = RecordView::validated(records, 1789689600);
    assert!(view.is_ok(), "committed draft inputs refused");
    statement::render(&config, &view.unwrap())
}

/// Locks the shipped statement to strict inert inputs and independent policy configuration changes.
pub fn sample_statement_contract() {
    let (config, records) = sample_inputs();
    let original = sample_render(&config, records.clone());
    assert!(
        original.ends_with('\n') && !original.ends_with("\n\n"),
        "statement must end with exactly one newline"
    );
    public_statement_wording(&original);
    assert_eq!(
        original,
        include_str!("../../../../COMPLIANCE_STATEMENT.md"),
        "sample statement differs from its validated inputs"
    );
    assert!(original.contains("sample — not an approval"));
    assert!(original.contains("Draft assessment; approval pending"));
    assert!(original.contains("[FOUNDER REQUIRED: named accountable person]"));
    assert!(original.contains("at least 36 calendar months"));
    let mut changed = config.clone();
    changed.compliance.retention_months = 48;
    let rendered = sample_render(&changed, records.clone());
    assert!(
        rendered.contains("at least 48 calendar months"),
        "retention policy ignored configuration"
    );
    assert_ne!(rendered, original);
    let mut changed = config.clone();
    changed.compliance.statement_version = "revised".into();
    changed.compliance.statement_changes[0].version = "revised".into();
    changed.compliance.statement_changes[0].summary = "Changed synthetic explanation".into();
    let mut versions = records.clone();
    let stract::compliance::record_types::RecordBody::Manifest(manifest) = &mut versions[3].body
    else {
        panic!("sample manifest body")
    };
    manifest.statement_version = "revised".into();
    let rendered = sample_render(&changed, versions);
    assert!(rendered.contains("Statement version: revised."));
    assert!(rendered.contains("Changed synthetic explanation"));
    assert_ne!(rendered, original);
    let mut people = records.clone();
    for record in &mut people {
        use stract::compliance::record_types::RecordBody;
        match &mut record.body {
            RecordBody::Icra(assessment) | RecordBody::Caa(assessment) => {
                assessment.responsible_person = "Named synthetic individual".into();
            }
            RecordBody::Manifest(manifest) => {
                manifest.accountable_person = "Named synthetic individual".into();
            }
            _ => {}
        }
    }
    assert!(sample_render(&config, people).contains("Named synthetic individual"));
    assert_eq!(sample_render(&config, records), original);
    for input in [
        include_str!("../../../../configs/compliance/sample-records.json"),
        include_str!("../../../../configs/compliance/manifest.json"),
    ] {
        assert!(input.contains("sample — not an approval"));
        assert!(
            !input.contains("\"salt\"")
                && !input.contains("\"commitment\"")
                && !input.contains("\"token\"")
        );
        assert!(!input
            .as_bytes()
            .windows(64)
            .any(|bytes| bytes.iter().all(u8::is_ascii_hexdigit)));
    }
}

fn public_statement_wording(text: &str) {
    assert_eq!(
        text.matches(
            "adopted voluntarily; whether it is required for a service of this size \
        is under legal review"
        )
        .count(),
        7,
        "public adoption prose"
    );
    assert!(
        !text.contains("Q-24"),
        "internal counsel identifier in public statement"
    );
    statement_sections(text);
    assert!(text.contains("within 30 days"));
    assert!(text.contains("within 48 hours"));
    assert!(text.contains("receipt plus 172800 seconds"));
    assert_eq!(stract::compliance::clock::COMPLAINT_ACK_SECONDS % 86400, 0);
    assert_eq!(stract::compliance::clock::INTIMATE_PERIOD_SECONDS % 3600, 0);
}

struct MetricTicket {
    rows: Vec<Value>,
    id: String,
    route: &'static str,
    received: i64,
    revision: u64,
}

impl MetricTicket {
    fn new(number: u64, route: &'static str, received: i64) -> Self {
        let mut ticket = Self {
            rows: Vec::new(),
            id: support::digest(&number.to_be_bytes()),
            route,
            received,
            revision: 0,
        };
        ticket.row("received", "received", 0);
        ticket
    }
    fn row(&mut self, event: &str, state: &str, offset: i64) -> &mut Value {
        let personal = matches!(
            event,
            "received"
                | "decided"
                | "action_intent"
                | "appealed"
                | "reversal_intent"
                | "closed"
                | "identity_requested"
                | "identity_confirmed"
        );
        if personal {
            self.revision += 1;
        }
        self.rows.push(json!({
            "format_version":1,"sequence":0,"previous_hash":"0".repeat(64),
            "at":self.received + offset,"received_at":self.received,"event":event,
            "ticket_id":self.id,"route":self.route,"requester_type":"self","state":state,
            "actor":"synthetic.operator","decision":"","reason_code":"","policy_version":"",
            "asset_ids":"","payload_sequence":if personal { self.revision } else { 0 },
            "commitment":if personal { support::digest(&self.revision.to_be_bytes()) }
                else { String::new() },
            "intent_sequence":0,"effective_at":-1,"related_ticket_id":"","record_ref":"",
            "list_version":"","url_count":0,"host_count":0,"quarantined_bytes":0,
            "quarantine_hash":"","hash":""
        }));
        self.rows.last_mut().unwrap()
    }
    fn queued(&mut self, ack: i64) {
        self.row("acknowledged", "acknowledged", ack);
        self.row("queued", "queued", ack);
    }
    fn decision(&mut self, at: i64, kind: &str, ground: &str) {
        let row = self.row("decided", "decided", at);
        row["decision"] = json!(kind);
        row["reason_code"] = json!(ground);
    }
    fn action(&mut self, at: i64, effective: i64, decision: &str, ground: &str, complete: bool) {
        let state = if decision.is_empty() {
            "received"
        } else {
            "decided"
        };
        let mut events = vec![("action_intent", state)];
        if complete {
            events.push(if decision == "granted" {
                ("actioned", "actioned")
            } else {
                ("rules_committed", state)
            });
        }
        let effective = self.received + effective;
        for (event, state) in events {
            let row = self.row(event, state, at);
            row["decision"] = json!(decision);
            row["reason_code"] = json!(ground);
            row["asset_ids"] = json!(support::digest(b"synthetic metric document"));
            row["effective_at"] = json!(effective);
        }
    }
    fn reversal(&mut self, at: i64, ground: &str) {
        self.row("appealed", "appealed", at);
        let effective = self.received + at;
        for (event, state) in [("reversal_intent", "appealed"), ("reversed", "reversed")] {
            let row = self.row(event, state, at);
            row["decision"] = json!("granted");
            row["reason_code"] = json!(ground);
            row["asset_ids"] = json!(support::digest(b"synthetic metric document"));
            row["effective_at"] = json!(effective);
        }
    }
}

fn metric_prefix(
    fixture: &DomainFixture,
    tickets: Vec<MetricTicket>,
    observed_at: i64,
) -> CommittedJournal {
    drop(fixture.journal());
    let mut rows = tickets
        .into_iter()
        .flat_map(|ticket| ticket.rows)
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| row["at"].as_i64().unwrap());
    let mut pending = BTreeMap::new();
    let mut previous = "0".repeat(64);
    let mut bytes = Vec::new();
    for (index, row) in rows.iter_mut().enumerate() {
        let sequence = index as u64 + 1;
        let event = row["event"].as_str().unwrap();
        let id = row["ticket_id"].as_str().unwrap().to_owned();
        if matches!(event, "action_intent" | "reversal_intent" | "purge_intent") {
            pending.insert(id.clone(), sequence);
            row["intent_sequence"] = json!(sequence);
        } else if matches!(
            event,
            "rules_committed" | "actioned" | "reversed" | "purged"
        ) {
            row["intent_sequence"] = json!(pending.remove(&id).unwrap());
        }
        row["sequence"] = json!(sequence);
        row["previous_hash"] = json!(previous);
        support::rehash(row);
        previous = row["hash"].as_str().unwrap().into();
        bytes.extend(support::encoded_row(row, true));
    }
    if let Some(last) = rows.last() {
        fs::write(fixture.path("events.jsonl"), &bytes).unwrap();
        fs::write(
            fixture.path("head.json"),
            support::checkpoint(last, bytes.len()),
        )
        .unwrap();
    }
    fixture
        .clock
        .set_utc(chrono::DateTime::from_timestamp(observed_at, 0).unwrap())
        .unwrap();
    let (result, counts) = observed(fixture);
    assert_eq!(
        counts.opens.load(SeqCst),
        3,
        "metrics source opened personal payloads"
    );
    assert!(result.is_ok(), "independent metric history refused");
    result.unwrap()
}

fn metric_five_tickets() -> Vec<MetricTicket> {
    let mut intimate = MetricTicket::new(1, "intimate_images", RECORD_TIME);
    intimate.action(0, 15, "", "intimate_images", true);
    intimate.queued(0);
    intimate.decision(10, "granted", "intimate_images");
    intimate.action(20, 20, "granted", "intimate_images", true);
    let mut illegal = MetricTicket::new(2, "illegal_content", RECORD_TIME);
    illegal.queued(1);
    illegal.decision(20, "granted", "illegal_content");
    illegal.action(25, 25, "granted", "illegal_content", true);
    illegal.reversal(60, "illegal_content");
    let mut data = MetricTicket::new(3, "data_rights", RECORD_TIME);
    data.queued(2);
    data.row("identity_requested", "identity_pending", 3);
    data.row("identity_confirmed", "queued", 4);
    data.decision(30, "granted", "data_delisting");
    data.action(35, 35, "granted", "data_delisting", true);
    let mut refused = MetricTicket::new(4, "illegal_content", RECORD_TIME);
    refused.queued(3);
    refused.decision(40, "refused", "");
    let mut complaint = MetricTicket::new(5, "data_protection_complaint", RECORD_TIME);
    complaint.queued(4);
    complaint.decision(50, "granted", "");
    vec![intimate, illegal, data, refused, complaint]
}

/// Pins cohort boundaries, completed effective actions, integer ranks and immutable cutoffs.
pub fn metrics_contract() {
    use stract::compliance::metrics;
    for (values, expected) in [
        (vec![], json!({"n":0,"median":null,"p95":null})),
        (vec![7], json!({"n":1,"median":7,"p95":7})),
        (vec![9, 2], json!({"n":2,"median":2,"p95":9})),
        ((0..20).collect(), json!({"n":20,"median":9,"p95":18})),
    ] {
        let result = metrics::durations(values);
        assert!(result.is_ok(), "valid integer ranks refused");
        assert_eq!(
            serde_json::to_value(result.unwrap()).unwrap(),
            expected,
            "nearest-rank literal mismatch"
        );
    }
    let mut fixture = RecordsFixture::new();
    let mut settings = fixture.domain.config.settings().clone();
    settings.intimate_margin_seconds = 172785;
    fixture.domain.config = settings
        .validate(
            &fixture
                .domain
                .config
                .store_dir()
                .parent()
                .unwrap()
                .join("suppression.json"),
        )
        .unwrap();
    let snapshot = metric_prefix(&fixture.domain, metric_five_tickets(), RECORD_TIME + 172800);
    let before = facts(fixture.domain.config.store_dir());
    let result = metrics::monthly(&snapshot, "2026-09");
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert!(result.is_ok(), "five-ticket monthly metrics refused");
    let value = serde_json::to_value(result.unwrap()).unwrap();
    assert!(value.is_object());
    assert_eq!(
        value["counts_by_route"],
        json!([
        {"route":"illegal_content","count":2},{"route":"harmful_to_children","count":0},
        {"route":"intimate_images","count":1},{"route":"site_complaint","count":0},
        {"route":"rights_removal","count":0},{"route":"data_rights","count":1},
        {"route":"data_protection_complaint","count":1},
        {"route":"online_safety_complaint","count":0}])
    );
    assert_eq!(value["ack_seconds"], json!({"n":5,"median":2,"p95":4}));
    assert_eq!(
        value["decision_seconds"],
        json!({"n":5,"median":30,"p95":50})
    );
    assert_eq!(value["action_seconds"], json!({"n":3,"median":25,"p95":35}));
    assert_eq!(
        value["actions_by_type"],
        json!([{"kind":"global_deindex","count":2},
        {"kind":"name_delisting","count":1}])
    );
    assert_eq!(value["reversals"], 1);
    assert_eq!(
        value["intimate"],
        json!({"due":1,"met":1,"missed":0,"pending":0,"exempt":0})
    );
    let mut owner = fixture.owner();
    for version in [1, 2] {
        let result = metrics::persist(&mut owner, &snapshot, "2026-09", "synthetic.operator");
        assert!(result.is_ok(), "monthly version persistence refused");
        assert_eq!(
            result.unwrap().to_string(),
            format!("metrics.2026-09:{version}")
        );
    }
    assert_eq!(owner.view().records().len(), 2);
    metric_empty_and_months();
    metric_intimate_boundaries();
    metric_unfounded();
    metric_uncommitted_suffixes();
}

fn metric_uncommitted_suffixes() {
    use stract::compliance::metrics;
    let fixture = DomainFixture::new();
    let mut ticket = MetricTicket::new(70, "illegal_content", RECORD_TIME);
    ticket.queued(1);
    ticket.decision(10, "refused", "");
    ticket.row("closed", "closed", 11);
    let initial = metric_prefix(&fixture, vec![ticket], RECORD_TIME + 100);
    let original = fs::read(fixture.path("events.jsonl")).unwrap();
    let mut unpublished = MetricTicket::new(71, "illegal_content", RECORD_TIME + 20)
        .rows
        .remove(0);
    unpublished["sequence"] = json!(initial.sequence + 1);
    unpublished["previous_hash"] = json!(initial.hash);
    support::rehash(&mut unpublished);
    let complete = support::encoded_row(&unpublished, true);
    for suffix in [
        complete.clone(),
        b"{\"partial\":".to_vec(),
        [complete, b"{".to_vec()].concat(),
    ] {
        fs::write(
            fixture.path("events.jsonl"),
            [&original[..], &suffix].concat(),
        )
        .unwrap();
        let (snapshot, counts) = observed(&fixture);
        assert_eq!(counts.opens.load(SeqCst), 3);
        assert!(
            snapshot.is_ok(),
            "metrics suffix changed committed snapshot"
        );
        let result = metrics::monthly(&snapshot.unwrap(), "2026-09");
        assert!(
            result.is_ok(),
            "metrics rejected captured prefix with suffix"
        );
        let result = result.unwrap();
        assert_eq!(result.as_of_sequence, 5);
        assert_eq!(
            result.counts_by_route[0].count, 1,
            "unpublished receipt entered cohort"
        );
        assert_eq!(result.ack_seconds.median, Some(1));
        assert_eq!(result.decision_seconds.median, Some(10));
        assert_eq!(result.action_seconds.n, 0);
    }
}

fn metric_empty_and_months() {
    use stract::compliance::metrics;
    let fixture = DomainFixture::new();
    let snapshot = metric_prefix(&fixture, Vec::new(), RECORD_TIME);
    let result = metrics::monthly(&snapshot, "2026-09");
    assert!(result.is_ok(), "origin metrics refused");
    let result = result.unwrap();
    assert_eq!(result.as_of_sequence, 0);
    assert!(result.counts_by_route.iter().all(|row| row.count == 0));
    assert_eq!(result.ack_seconds.n, 0);
    assert_eq!(result.action_seconds.median, None);
    assert!(metrics::retention_due(&snapshot, &fixture.config)
        .unwrap()
        .is_empty());
    for month in [
        "",
        "2026-9",
        "2026-00",
        "2026-13",
        "2026-01extra",
        "+026-01",
    ] {
        assert!(matches!(
            metrics::monthly(&snapshot, month),
            Err(Error::InvalidInput)
        ));
    }
    let start = support::utc("2026-09-01T00:00:00Z").timestamp();
    let end = support::utc("2026-10-01T00:00:00Z").timestamp();
    for (received, included) in [
        (start - 1, false),
        (start, true),
        (start + 1, true),
        (end - 1, true),
        (end, false),
        (end + 1, false),
    ] {
        let fixture = DomainFixture::new();
        let mut ticket = MetricTicket::new(10, "illegal_content", received);
        ticket.queued(0);
        ticket.decision(end + 10 - received, "refused", "");
        let snapshot = metric_prefix(&fixture, vec![ticket], end + 11);
        let metrics = metrics::monthly(&snapshot, "2026-09").unwrap();
        assert_eq!(
            metrics.counts_by_route[0].count,
            u64::from(included),
            "receipt-month cohort mismatch"
        );
    }
}

fn metric_intimate_boundaries() {
    for offset in [172799, 172800, 172801] {
        for effective in [172799, 172800, 172801] {
            intimate_metric_case(offset, effective, None, true);
        }
    }
    intimate_metric_case(172800, 172800, None, false);
    for determination in [172799, 172800, 172801] {
        intimate_metric_case(
            172802,
            200000,
            Some(("not_intimate_image", determination)),
            true,
        );
        intimate_metric_case(172802, 200000, Some(("no_standing", determination)), true);
    }
}

fn intimate_metric_case(
    observed_offset: i64,
    effective: i64,
    determination: Option<(&str, i64)>,
    complete: bool,
) {
    use stract::compliance::metrics;
    let fixture = DomainFixture::new();
    let mut ticket = MetricTicket::new(20, "intimate_images", RECORD_TIME);
    ticket.action(0, effective, "", "intimate_images", complete);
    if complete {
        ticket.queued(0);
        if let Some((kind, at)) = determination {
            ticket.decision(at, kind, "intimate_images");
            ticket.action(at, at, kind, "intimate_images", true);
        }
    }
    let snapshot = metric_prefix(&fixture, vec![ticket], RECORD_TIME + observed_offset);
    let result = metrics::monthly(&snapshot, "2026-09");
    assert!(result.is_ok(), "intimate metrics refused");
    let value = serde_json::to_value(result.unwrap()).unwrap();
    let exempt = determination.is_some_and(|(_, at)| at <= 172800);
    let due = !exempt && observed_offset >= 172800;
    let met = due && complete && effective <= 172800;
    assert_eq!(
        value["intimate"],
        json!({"due":u64::from(due),"met":u64::from(met),
        "missed":u64::from(due && !met),"pending":u64::from(!exempt && !due),
        "exempt":u64::from(exempt)}),
        "intimate deadline literal mismatch"
    );
    assert_eq!(
        value["action_seconds"]["n"],
        u64::from(complete && effective <= observed_offset)
    );
    if complete && effective <= observed_offset {
        assert_eq!(
            value["action_seconds"]["median"], effective,
            "completed timed action lost its persisted effective instant"
        );
    }
}

fn metric_unfounded() {
    use stract::compliance::metrics;
    let fixture = DomainFixture::new();
    let mut original = MetricTicket::new(30, "site_complaint", RECORD_TIME);
    original.queued(0);
    original.decision(1, "refused", "");
    original.row("closed", "closed", 2);
    let mut duplicate = MetricTicket::new(31, "site_complaint", RECORD_TIME + 3);
    duplicate.queued(0);
    duplicate.decision(
        1,
        "manifestly_unfounded",
        "duplicate_without_new_information",
    );
    let last = duplicate.rows.last_mut().unwrap();
    last["policy_version"] = json!("619.1");
    last["related_ticket_id"] = json!(original.id);
    let snapshot = metric_prefix(&fixture, vec![original, duplicate], RECORD_TIME + 5);
    let result = metrics::monthly(&snapshot, "2026-09");
    assert!(result.is_ok(), "valid unfounded aggregate refused");
    assert_eq!(
        serde_json::to_value(result.unwrap().unfounded_by_clause).unwrap(),
        json!([{"policy_version":"619.1","policy_clause":"duplicate_without_new_information",
            "count":1}])
    );
}

fn every_record_kind() -> RecordsFixture {
    let fixture = RecordsFixture::new();
    let mut owner = fixture.owner();
    for kind in [
        "icra", "caa", "cra", "measures", "metrics", "review", "manifest",
    ] {
        add_record(&mut owner, record_input(kind));
    }
    let mut second = record_input("icra");
    second["version"] = json!(2);
    second["supersedes"] = json!("assessment.icra:1");
    second["body"]["reasoning"] = json!("A second synthetic version");
    add_record(&mut owner, second);
    drop(owner);
    fixture
}

fn checked_record_view(fixture: &RecordsFixture) -> stract::compliance::records::RecordView {
    let result = read_view(
        &fixture.domain.config,
        fixture.domain.clock.as_ref(),
        fixture.probe.as_ref(),
    );
    assert!(result.is_ok(), "healthy record view refused");
    result.unwrap()
}

/// Exports every kind and superseded version with private modes and independent envelope hashes.
pub fn export_contract() {
    use stract::compliance::export;
    oversized_export();
    let fixture = every_record_kind();
    let view = checked_record_view(&fixture);
    let out = fixture
        .domain
        .config
        .store_dir()
        .parent()
        .unwrap()
        .join("private-export");
    let before = facts(fixture.domain.config.store_dir());
    let draws = fixture.draws();
    let result = export::export(
        &view,
        &out,
        fixture.domain.clock.as_ref(),
        fixture.probe.as_ref(),
    );
    assert_eq!(fixture.draws(), draws);
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert_eq!(fs::symlink_metadata(&out).unwrap().mode() & 0o777, 0o700);
    assert!(result.is_ok(), "safe all-version export refused");
    let receipt = serde_json::to_value(result.unwrap()).unwrap();
    assert!(receipt.is_object());
    assert_eq!(receipt["format_version"], 1);
    assert_eq!(receipt["versions"], 8);
    assert_eq!(receipt["started_at"], RECORD_TIME);
    assert_eq!(receipt["ended_at"], RECORD_TIME);
    assert!(receipt["elapsed_ms"].is_u64());
    assert!(receipt["records"].is_array());
    assert!(receipt["outputs"].is_array());
    assert_eq!(receipt["records"].as_array().unwrap().len(), 8);
    assert_eq!(receipt["outputs"].as_array().unwrap().len(), 9);
    assert_eq!(fs::read_dir(&out).unwrap().count(), 10);
    for item in receipt["outputs"].as_array().unwrap() {
        assert!(item.is_object());
        let path = out.join(item["file"].as_str().unwrap());
        assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o777, 0o600);
        let bytes = fs::read(path).unwrap();
        assert_eq!(item["sha256"], support::digest(&bytes));
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("lang=\"en\"") && text.contains("charset=\"utf-8\""));
        assert!(!text.contains("href=") && !text.contains("<script"));
        assert!(!text.contains("salt") && !text.contains("commitment"));
    }
    assert_eq!(
        fs::symlink_metadata(out.join("export-receipt.json"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        support::read_json(&out.join("export-receipt.json")),
        receipt
    );
    verify_exported_records(&view, &out, &receipt);
    let original = facts(&out);
    let repeated = export::export(
        &view,
        &out,
        fixture.domain.clock.as_ref(),
        fixture.probe.as_ref(),
    );
    assert_eq!(facts(&out), original);
    assert!(
        matches!(repeated, Err(Error::Unavailable)),
        "existing export overwritten"
    );
    unsafe_export_outputs();
    assert_eq!(export::export_budget(1).unwrap(), 65544);
    assert!(matches!(
        export::export_budget(u64::MAX),
        Err(Error::Capacity)
    ));
}

fn oversized_export() {
    use stract::compliance::{export, records::RecordView};
    let mut fixture = RecordsFixture::new();
    configured_record_caps(&mut fixture, 32768, 1048576);
    let inputs: Vec<_> = (0..512)
        .map(|number| {
            let mut value = record_input("icra");
            value["id"] = json!(format!("export.{number}"));
            value["body"]["reasoning"] = json!("&".repeat(4096));
            typed(value)
        })
        .collect();
    let view = RecordView::validated(inputs, RECORD_TIME);
    assert!(view.is_ok(), "bounded envelope collection refused");
    let view = view.unwrap();
    let parent = fixture.domain.config.store_dir().parent().unwrap();
    let before = facts(fixture.domain.config.records_dir());
    let opens = fixture.probe.counts.opens.load(SeqCst);
    let draws = fixture.draws();
    let result = export::export(
        &view,
        &parent.join("oversized-export"),
        fixture.domain.clock.as_ref(),
        fixture.probe.as_ref(),
    );
    assert_eq!(fixture.draws(), draws);
    assert_eq!(fixture.probe.counts.opens.load(SeqCst), opens + 514);
    assert_eq!(
        facts(fixture.domain.config.records_dir()),
        before,
        "historical export changed its inputs"
    );
    assert!(
        result.is_ok(),
        "reduced admission cap prevented historical export"
    );
    let receipt = serde_json::to_value(result.unwrap()).unwrap();
    assert_eq!(receipt["versions"], 512);
    verify_exported_records(&view, &parent.join("oversized-export"), &receipt);
}

fn verify_exported_records(
    view: &stract::compliance::records::RecordView,
    out: &Path,
    receipt: &Value,
) {
    for (reference, record) in view.records() {
        let output =
            fs::read_to_string(out.join(format!("{}-{}.html", reference.id, reference.version)))
                .unwrap();
        let record = serde_json::to_value(record).unwrap();
        let mut paths = Vec::new();
        object_fields(&record, &mut paths);
        for label in paths {
            assert!(
                output.contains(&format!("<dt>{label}</dt>")),
                "record field missing from export"
            );
        }
        let item = receipt["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["record_ref"] == reference.to_string());
        assert!(item.is_some(), "superseded export missing from receipt");
        assert_eq!(
            item.unwrap()["sha256"],
            support::digest(&serde_json::to_vec(&record).unwrap())
        );
    }
}

fn object_fields(value: &Value, fields: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (field, value) in object {
                fields.push(field.clone());
                object_fields(value, fields);
            }
        }
        Value::Array(values) => values.iter().for_each(|value| object_fields(value, fields)),
        _ => {}
    }
}

fn unsafe_export_outputs() {
    use std::os::unix::fs::PermissionsExt;
    use stract::compliance::export;
    for fault in [
        "empty-directory",
        "sentinel-directory",
        "symlink",
        "file",
        "parent-mode",
        "parent-link",
        "interrupted",
    ] {
        let fixture = every_record_kind();
        let view = checked_record_view(&fixture);
        let parent = fixture.domain.config.store_dir().parent().unwrap();
        let private = parent.join("export-parent");
        fs::create_dir(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        let out = private.join("new-export");
        match fault {
            "empty-directory" | "sentinel-directory" => {
                fs::create_dir(&out).unwrap();
                fs::set_permissions(&out, fs::Permissions::from_mode(0o700)).unwrap();
                if fault == "sentinel-directory" {
                    private_record_file(&out.join("sentinel"), b"private sentinel");
                }
            }
            "symlink" => {
                std::os::unix::fs::symlink(fixture.domain.config.records_dir(), &out).unwrap()
            }
            "file" => private_record_file(&out, b"private sentinel"),
            "parent-mode" => {
                fs::set_permissions(&private, fs::Permissions::from_mode(0o755)).unwrap()
            }
            "parent-link" => {
                fs::remove_dir(&private).unwrap();
                std::os::unix::fs::symlink(fixture.domain.config.records_dir(), &private).unwrap();
            }
            "interrupted" => {
                *fixture.probe.fail.lock().unwrap() = Some((ComplianceStage::BeforeOpen, 1));
            }
            _ => unreachable!(),
        }
        let before = safe_tree(parent);
        let draws = fixture.draws();
        let opens = fixture.probe.counts.opens.load(SeqCst);
        let result = export::export(
            &view,
            &out,
            fixture.domain.clock.as_ref(),
            fixture.probe.as_ref(),
        );
        assert_eq!(fixture.draws(), draws);
        if matches!(fault, "empty-directory" | "sentinel-directory") {
            assert_eq!(
                fixture.probe.counts.opens.load(SeqCst),
                opens,
                "existing private export destination received new output"
            );
        }
        if fault == "interrupted" {
            assert_eq!(fs::symlink_metadata(&out).unwrap().mode() & 0o777, 0o700);
            assert_eq!(fs::read_dir(&out).unwrap().count(), 0);
        } else {
            assert_eq!(safe_tree(parent), before);
        }
        assert!(
            matches!(result, Err(Error::Unavailable)),
            "unsafe or interrupted export accepted"
        );
    }
}

fn dated(mut value: Value, at: i64) -> Value {
    fn replace(value: &mut Value, at: i64) {
        match value {
            Value::Number(number) if number.as_i64() == Some(RECORD_TIME) => *value = json!(at),
            Value::Object(fields) => fields.values_mut().for_each(|value| replace(value, at)),
            Value::Array(values) => values.iter_mut().for_each(|value| replace(value, at)),
            _ => {}
        }
    }
    replace(&mut value, at);
    value
}

fn set_record_clock(fixture: &RecordsFixture, at: i64) {
    fixture
        .domain
        .clock
        .set_utc(chrono::DateTime::from_timestamp(at, 0).unwrap())
        .unwrap();
}

fn approved_config(fixture: &mut DomainFixture) {
    let mut settings = fixture.config.settings().clone();
    settings.priority_catalog_version = Some("catalog.synthetic".into());
    settings.priority_catalog_source = Some("Synthetic catalog source".into());
    settings.priority_kind_labels = std::array::from_fn(|at| Some(format!("Synthetic kind {at}")));
    fixture.config = settings
        .validate(
            &fixture
                .config
                .store_dir()
                .parent()
                .unwrap()
                .join("suppression.json"),
        )
        .unwrap();
}

fn approved_record(kind: &str) -> Value {
    let mut value = record_input(kind);
    value["body"]["approval_status"] = json!("approved");
    if kind != "measures" {
        value["body"]["approved_at"] = json!(RECORD_TIME);
    }
    if matches!(kind, "icra" | "caa" | "cra") {
        value["body"]["risk_profiles_consulted"] = json!("yes");
        value["body"]["governance_reporting"] = json!("yes");
        value["body"]["priority_catalog_version"] = json!("catalog.synthetic");
    }
    value
}

fn release_update(kind: &str) -> Value {
    let mut value = approved_record(kind);
    value["body"]["review_triggers"] = json!([{"kind":"significant_change",
        "at":RECORD_TIME,"reference":"synthetic-release"}]);
    value
}

fn release_input() -> Value {
    json!({"format_version":1,"release_id":"synthetic-release","service":"Synthetic service",
        "planned_at":RECORD_TIME,"changes":["ranking_model"],
        "assessment_updates":["assessment.icra:1","assessment.caa:1"]})
}

fn api_config(fixture: &RecordsFixture, hosted: bool) -> stract::config::ApiConfig {
    use stract::config::compliance::DeploymentMode;
    let mut config: stract::config::ApiConfig =
        toml::from_str(include_str!("../../../../configs/api.toml")).unwrap();
    config.v1.suppression_store_path = fixture
        .domain
        .config
        .store_dir()
        .parent()
        .unwrap()
        .join("suppression.json");
    config.compliance = fixture.domain.config.settings().clone();
    config.compliance.deployment_mode = if hosted {
        DeploymentMode::Hosted
    } else {
        DeploymentMode::Local
    };
    config
}

fn startup_result(
    fixture: &RecordsFixture,
    config: &stract::config::ApiConfig,
    expected: Result<()>,
    case: &'static str,
) {
    use stract::api::v1::{compliance_adapter::ComplianceSeams, V1Resources};
    let journal = facts(fixture.domain.config.journal_dir());
    let records = facts(fixture.domain.config.records_dir());
    let draws = fixture.draws();
    let result = V1Resources::with_compliance_seams(
        config,
        ComplianceSeams {
            clock: fixture.domain.clock.clone(),
            entropy: fixture.entropy.clone(),
            hooks: fixture.probe.clone(),
            ..Default::default()
        },
    );
    assert_eq!(
        facts(fixture.domain.config.records_dir()),
        records,
        "{case}: startup wrote records"
    );
    assert_eq!(
        fixture.draws(),
        draws,
        "{case}: startup drew record entropy"
    );
    if expected.is_err() {
        assert_eq!(
            facts(fixture.domain.config.journal_dir()),
            journal,
            "{case}: refused hosted gate opened ticket journal"
        );
    }
    let actual = result.as_ref().map(|_| ()).map_err(|error| {
        *error
            .downcast_ref::<Error>()
            .unwrap_or_else(|| panic!("{case}: fixed domain startup error"))
    });
    assert_eq!(actual, expected, "{case}: startup result");
}

fn approved_store(sample: bool, likely: bool, cra: bool) -> RecordsFixture {
    let mut fixture = RecordsFixture::new();
    approved_config(&mut fixture.domain);
    let mut owner = fixture.owner();
    for kind in ["icra", "caa", "measures", "cra", "manifest"] {
        if kind == "cra" && !cra {
            continue;
        }
        let mut value = approved_record(kind);
        if kind == "caa" && likely {
            value["body"]["access"]["conclusion"] = json!("likely");
        }
        if kind == "manifest" && cra {
            value["body"]["cra"] = json!("assessment.cra:1");
        }
        if sample {
            value["id"] = json!(format!("sample.{kind}"));
            if kind == "manifest" {
                for field in ["icra", "caa", "measures"] {
                    value["body"][field] = json!(format!("sample.{field}:1"));
                }
                if cra {
                    value["body"]["cra"] = json!("sample.cra:1");
                }
            }
        }
        add_record(&mut owner, value);
    }
    drop(owner);
    fixture
}

fn rewrite_record(fixture: &RecordsFixture, kind: &str, change: impl FnOnce(&mut Value)) {
    let path = fixture.path(&format!("assessment.{kind}/0000000001.json"));
    let mut stored: Value = support::read_json(&path);
    change(&mut stored["record"]);
    let record = serde_json::to_vec(&stored["record"]).unwrap();
    let salt = stored["salt"]
        .as_str()
        .unwrap()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    let mut bytes = b"AVA619-RECORD-v1\0".to_vec();
    bytes.extend(salt);
    bytes.extend((record.len() as u64).to_be_bytes());
    bytes.extend(record);
    stored["commitment"] = json!(support::digest(&bytes));
    let mut wrapper = serde_json::to_vec(&stored).unwrap();
    wrapper.push(b'\n');
    fs::write(path, wrapper).unwrap();
    let index = fs::read(fixture.path("index.jsonl")).unwrap();
    let mut rows = index
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    let reference = format!("assessment.{kind}:1");
    let mut previous = "0".repeat(64);
    let mut bytes = Vec::new();
    for row in &mut rows {
        if row["record_ref"] == reference {
            row["commitment"] = stored["commitment"].clone();
        }
        row["previous_hash"] = json!(previous);
        rehash_index(row);
        previous = row["hash"].as_str().unwrap().into();
        bytes.extend(encoded_index(row, true));
    }
    fs::write(fixture.path("index.jsonl"), &bytes).unwrap();
    fs::write(
        fixture.path("head.json"),
        support::checkpoint(rows.last().unwrap(), bytes.len()),
    )
    .unwrap();
}

/// Exercises actual before-listener startup with private approved records and isolated bad facts.
pub fn hosted_contract() {
    manifest_identity_admission();
    hosted_sample_admission();
    for hosted in [false, true] {
        let fixture = RecordsFixture::new();
        startup_result(
            &fixture,
            &api_config(&fixture, hosted),
            if hosted {
                Err(Error::InvalidInput)
            } else {
                Ok(())
            },
            "missing manifest",
        );
        assert!(!fixture.domain.config.records_dir().exists());
        assert!(!fixture.domain.config.records_lock().exists());
    }
    let fixture = approved_store(false, false, false);
    startup_result(
        &fixture,
        &api_config(&fixture, true),
        Ok(()),
        "approved hosted",
    );
    let fixture = approved_store(true, false, false);
    startup_result(
        &fixture,
        &api_config(&fixture, true),
        Err(Error::InvalidInput),
        "sample policy",
    );
    hosted_bad_facts();
    hosted_path_and_catalog_cases();
    hosted_deadline_cases();
    let fixture = approved_store(false, false, false);
    let mut second = approved_record("manifest");
    second["id"] = json!("manifest.other");
    append_historical_record(&fixture, second);
    assert_eq!(checked_record_view(&fixture).records().len(), 5);
    startup_result(
        &fixture,
        &api_config(&fixture, true),
        Err(Error::InvalidInput),
        "ambiguous manifest identities",
    );
    let fixture = RecordsFixture::new();
    let mut owner = fixture.owner();
    for kind in ["icra", "caa", "measures", "manifest"] {
        add_record(&mut owner, record_input(kind));
    }
    drop(owner);
    startup_result(
        &fixture,
        &api_config(&fixture, false),
        Ok(()),
        "local draft",
    );
    startup_result(
        &fixture,
        &api_config(&fixture, true),
        Err(Error::InvalidInput),
        "draft selected manifest authorized hosted startup",
    );
}

fn hosted_sample_admission() {
    use stract::config::compliance::DeploymentMode;
    for hosted in [false, true] {
        for (prefix, marker) in [(false, false), (true, false), (false, true), (true, true)] {
            let mut fixture = RecordsFixture::new();
            let mut settings = fixture.domain.config.settings().clone();
            settings.deployment_mode = if hosted {
                DeploymentMode::Hosted
            } else {
                DeploymentMode::Local
            };
            fixture.domain.config = settings
                .validate(
                    &fixture
                        .domain
                        .config
                        .store_dir()
                        .parent()
                        .unwrap()
                        .join("suppression.json"),
                )
                .unwrap();
            let mut value = record_input("icra");
            if prefix {
                value["id"] = json!("sample.icra");
            }
            if marker {
                value["body"]["reasoning"] = json!("sample — not an approval");
            }
            let config = cli_config(&fixture);
            if hosted {
                let text = fs::read_to_string(&config).unwrap();
                assert_eq!(text.matches("deployment_mode = \"local\"").count(), 1);
                fs::write(
                    &config,
                    text.replace(
                        "deployment_mode = \"local\"",
                        "deployment_mode = \"hosted\"",
                    ),
                )
                .unwrap();
            }
            let input = cli_input(&fixture, "admission.json", &value);
            let before = facts(fixture.domain.config.store_dir());
            let draws = fixture.draws();
            let result = injected_cli(
                &fixture,
                &config,
                &["records", "validate"],
                &[("--input", &input)],
            );
            assert_eq!(facts(fixture.domain.config.store_dir()), before);
            assert_eq!(fixture.draws(), draws);
            let expected = if hosted && (prefix || marker) {
                Err(Error::InvalidInput)
            } else {
                Ok(())
            };
            assert_eq!(
                result.0, expected,
                "sample hosted validation: {prefix}/{marker}"
            );
            let mut owner = fixture.owner();
            if expected.is_err() {
                assert_addition_refused(
                    &fixture,
                    &mut owner,
                    value,
                    Error::InvalidInput,
                    &format!("sample admission hosted={hosted} prefix={prefix} marker={marker}"),
                );
            } else {
                add_record(&mut owner, value);
            }
        }
    }
}

fn refresh_wrapper(stored: &mut Value) -> Vec<u8> {
    let record = serde_json::to_vec(&stored["record"]).unwrap();
    let mut framed = b"AVA619-RECORD-v1\0".to_vec();
    for pair in stored["salt"]
        .as_str()
        .unwrap()
        .as_bytes()
        .as_chunks::<2>()
        .0
    {
        framed.push(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
    }
    framed.extend((record.len() as u64).to_be_bytes());
    framed.extend(record);
    stored["commitment"] = json!(support::digest(&framed));
    let mut bytes = serde_json::to_vec(stored).unwrap();
    bytes.push(b'\n');
    bytes
}

fn write_historical_index(fixture: &RecordsFixture, mut rows: Vec<Value>) {
    let mut previous = "0".repeat(64);
    let mut bytes = Vec::new();
    for row in &mut rows {
        row["previous_hash"] = json!(previous);
        rehash_index(row);
        previous = row["hash"].as_str().unwrap().into();
        bytes.extend(encoded_index(row, true));
    }
    fs::write(fixture.path("index.jsonl"), &bytes).unwrap();
    fs::write(
        fixture.path("head.json"),
        support::checkpoint(rows.last().unwrap(), bytes.len()),
    )
    .unwrap();
}

fn append_historical_record(fixture: &RecordsFixture, record: Value) {
    let reference = format!("{}:{}", record["id"].as_str().unwrap(), record["version"]);
    let path = fixture.path(&format!(
        "{}/{:010}.json",
        record["id"].as_str().unwrap(),
        record["version"].as_u64().unwrap()
    ));
    let mut stored = json!({"format_version":1,"salt":"41".repeat(32),
        "commitment":"","record":record});
    let bytes = refresh_wrapper(&mut stored);
    private_record_file(&path, &bytes);
    let mut rows = record_rows(fixture);
    let sequence = rows.len() as u64 + 1;
    let mut intent = json!({"format_version":1,"sequence":sequence,"previous_hash":"",
        "at":RECORD_TIME,"event":"record_intent","actor":"synthetic.operator",
        "record_ref":reference,"record_kind":stored["record"]["kind"],
        "commitment":stored["commitment"],"intent_sequence":0,"quarantined_bytes":0,
        "quarantine_hash":"","hash":""});
    rows.push(intent.clone());
    intent["sequence"] = json!(sequence + 1);
    intent["intent_sequence"] = json!(sequence);
    intent["event"] = json!("record_added");
    rows.push(intent);
    write_historical_index(fixture, rows);
}

fn replace_historical_version(fixture: &RecordsFixture, reference: &str, record: Value) {
    let (id, version) = reference.split_once(':').unwrap();
    let old_path = fixture.path(&format!(
        "{id}/{:010}.json",
        version.parse::<u64>().unwrap()
    ));
    let mut stored = support::read_json(&old_path);
    stored["record"] = record;
    let bytes = refresh_wrapper(&mut stored);
    let path = fixture.path(&format!(
        "{}/{:010}.json",
        stored["record"]["id"].as_str().unwrap(),
        stored["record"]["version"].as_u64().unwrap()
    ));
    if old_path != path {
        fs::remove_file(old_path).unwrap();
    }
    private_record_file(&path, &bytes);
    let mut rows = record_rows(fixture);
    for row in &mut rows {
        if row["record_ref"] == reference {
            row["record_ref"] = json!(format!(
                "{}:{}",
                stored["record"]["id"].as_str().unwrap(),
                stored["record"]["version"]
            ));
            row["record_kind"] = stored["record"]["kind"].clone();
            row["commitment"] = stored["commitment"].clone();
        }
    }
    write_historical_index(fixture, rows);
}

fn hosted_bad_facts() {
    for (kind, path, bad) in [
        (
            "manifest",
            "/body/accountable_person",
            json!("Different synthetic person"),
        ),
        ("manifest", "/body/governance_body", json!("")),
        ("manifest", "/body/approval_status", json!("draft")),
        ("manifest", "/body/icra", json!("assessment.caa:1")),
        ("manifest", "/body/icra", json!("assessment.icra:2")),
        ("manifest", "/body/service", json!("Different service")),
        (
            "manifest",
            "/body/statement_version",
            json!("different-version"),
        ),
        ("icra", "/body/approval_status", json!("draft")),
        ("caa", "/body/approval_status", json!("draft")),
        ("measures", "/body/approval_status", json!("draft")),
        ("icra", "/body/risk_profiles_consulted", json!("no")),
        ("icra", "/body/author", json!("[FOUNDER REQUIRED: author]")),
        ("icra", "/body/approved_at", json!(RECORD_TIME + 1)),
        ("icra", "/body/reasoning", json!("sample — not an approval")),
    ] {
        let fixture = approved_store(false, false, false);
        rewrite_record(&fixture, kind, |record| {
            *record.pointer_mut(path).unwrap() = bad
        });
        let (expected, case) = match (kind, path) {
            ("manifest", "/body/approval_status") => (
                Err(Error::InvalidInput),
                "draft selected manifest authorized hosted startup",
            ),
            ("manifest", "/body/statement_version") => (
                Err(Error::InvalidInput),
                "selected statement configuration mismatch",
            ),
            ("icra", "/body/reasoning") => (Err(Error::InvalidInput), "sample marker"),
            _ => (Err(Error::Unavailable), path),
        };
        startup_result(&fixture, &api_config(&fixture, true), expected, case);
    }
}

fn hosted_path_and_catalog_cases() {
    for field in [
        "suppression",
        "store_dir",
        "records_dir",
        "admin_token_file",
        "listed_hashes_file",
    ] {
        let fixture = approved_store(false, false, false);
        let mut config = api_config(&fixture, true);
        let relative = PathBuf::from("relative-private-input");
        match field {
            "suppression" => config.v1.suppression_store_path = relative,
            "store_dir" => config.compliance.store_dir = Some(relative),
            "records_dir" => config.compliance.records_dir = Some(relative),
            "admin_token_file" => config.compliance.admin_token_file = Some(relative),
            "listed_hashes_file" => config.compliance.listed_hashes_file = Some(relative),
            _ => unreachable!(),
        }
        let before = facts(fixture.domain.config.store_dir());
        let result = config
            .compliance
            .validate(&config.v1.suppression_store_path);
        assert_eq!(facts(fixture.domain.config.store_dir()), before);
        assert!(
            matches!(result, Err(Error::InvalidInput)),
            "relative hosted path accepted"
        );
    }
    for field in ["version", "source", "label", "stale"] {
        let fixture = approved_store(false, false, false);
        let mut config = api_config(&fixture, true);
        match field {
            "version" => config.compliance.priority_catalog_version = None,
            "source" => config.compliance.priority_catalog_source = None,
            "label" => config.compliance.priority_kind_labels[0] = None,
            "stale" => config.compliance.priority_catalog_version = Some("other.catalog".into()),
            _ => unreachable!(),
        }
        let validated = config
            .compliance
            .validate(&config.v1.suppression_store_path)
            .unwrap();
        let before = facts(fixture.domain.config.records_dir());
        let view = read_view(
            &validated,
            fixture.domain.clock.as_ref(),
            fixture.probe.as_ref(),
        );
        assert_eq!(facts(fixture.domain.config.records_dir()), before);
        assert_eq!(
            view.as_ref().map(|_| ()).map_err(|error| *error),
            Ok(()),
            "{field}: current catalog rebounded intrinsic history"
        );
        startup_result(
            &fixture,
            &config,
            Err(Error::InvalidInput),
            "incomplete or stale catalog",
        );
    }
}

fn hosted_deadline_cases() {
    let due = support::utc("2026-12-18T12:00:00Z").timestamp();
    for delta in [-1, 0, 1] {
        let fixture = approved_store(false, true, false);
        set_record_clock(&fixture, due + delta);
        startup_result(
            &fixture,
            &api_config(&fixture, true),
            if delta <= 0 {
                Ok(())
            } else {
                Err(Error::InvalidInput)
            },
            "overdue likely access without CRA authorized hosted startup",
        );
    }
    let fixture = approved_store(false, true, true);
    set_record_clock(&fixture, due + 1);
    startup_result(
        &fixture,
        &api_config(&fixture, true),
        Ok(()),
        "approved hosted",
    );
    let fixture = approved_store(false, false, false);
    set_record_clock(&fixture, support::utc("2028-09-19T12:00:00Z").timestamp());
    startup_result(
        &fixture,
        &api_config(&fixture, true),
        Ok(()),
        "approved hosted",
    );
}

fn release_result(input: Value, records: Vec<Value>, valid: bool) {
    use stract::compliance::{records::RecordView, release};
    let mut fixture = DomainFixture::new();
    approved_config(&mut fixture);
    let before = facts(fixture.config.store_dir());
    let view = RecordView::validated(records.into_iter().map(typed), RECORD_TIME);
    assert_eq!(facts(fixture.config.store_dir()), before);
    assert!(view.is_ok(), "release fixture records refused");
    let input = serde_json::from_value(input);
    let result = input
        .map_err(|_| Error::InvalidInput)
        .and_then(|manifest| release::validate_release(&manifest, &view.unwrap()));
    assert_eq!(facts(fixture.config.store_dir()), before);
    if valid {
        assert!(result.is_ok(), "valid release update refused");
    } else {
        assert!(
            matches!(result, Err(Error::InvalidInput)),
            "invalid release update accepted"
        );
    }
}

/// Checks every significant-change kind and linked approval boundaries without writes.
pub fn release_contract() {
    release_latest_cases();
    let updates = || {
        vec![
            release_update("icra"),
            release_update("caa"),
            release_update("cra"),
        ]
    };
    for kind in [
        "ranking_model",
        "index_content_classes",
        "index_geographies",
        "index_images",
        "autocomplete",
        "advertising",
        "cached_copies",
        "ai_answer_synthesis",
        "age_controls",
        "access_controls",
    ] {
        let mut input = release_input();
        input["changes"] = json!([kind]);
        release_result(input, updates(), true);
    }
    for refs in [
        json!([]),
        json!(["assessment.icra:1"]),
        json!(["assessment.caa:1"]),
        json!(["assessment.icra:1", "assessment.caa:1", "assessment.icra:1"]),
        json!(["assessment.icra:2", "assessment.caa:1"]),
    ] {
        let mut input = release_input();
        input["assessment_updates"] = refs;
        release_result(input, updates(), false);
    }
    for (field, bad) in [
        ("unknown", json!(1)),
        ("format_version", json!(2)),
        ("planned_at", json!(1.5)),
        ("service", json!("Other service")),
        ("changes", json!(["unrecognised"])),
        ("changes", json!(["ranking_model", "ranking_model"])),
    ] {
        let mut input = release_input();
        input[field] = bad;
        release_result(input, updates(), false);
    }
    for (field, bad) in [
        ("approval_status", json!("draft")),
        ("service", json!("Other synthetic service")),
        ("review_triggers", json!([])),
        (
            "review_triggers",
            json!([{"kind":"significant_change","at":RECORD_TIME,
            "reference":"different-release"}]),
        ),
    ] {
        let mut records = updates();
        records[0]["body"][field] = bad;
        release_result(release_input(), records, false);
    }
    let mut records = updates();
    records.push(record_input("measures"));
    let mut input = release_input();
    input["assessment_updates"] = json!(["assessment.measures:1", "assessment.caa:1"]);
    release_result(input, records, false);
    for delta in [-1, 0, 1] {
        let mut input = release_input();
        input["planned_at"] = json!(RECORD_TIME + delta);
        release_result(input, updates(), delta >= 0);
    }
    for with_cra in [false, true] {
        let mut records = updates();
        records[1]["body"]["access"]["conclusion"] = json!("likely");
        let mut input = release_input();
        if with_cra {
            input["assessment_updates"] =
                json!(["assessment.icra:1", "assessment.caa:1", "assessment.cra:1"]);
        }
        release_result(input, records, with_cra);
    }
    for refs in [json!([]), json!(["assessment.icra:1"])] {
        let mut input = release_input();
        input["changes"] = json!([]);
        input["assessment_updates"] = refs;
        release_result(input, updates(), true);
    }
}

fn release_latest_cases() {
    use stract::compliance::release;
    for kind in ["icra", "caa", "cra"] {
        for latest_approved in [false, true] {
            let mut fixture = RecordsFixture::new();
            approved_config(&mut fixture.domain);
            let mut owner = fixture.owner();
            for current in ["icra", "caa", "cra"] {
                let mut value = release_update(current);
                if current == "caa" {
                    value["body"]["access"]["conclusion"] = json!("likely");
                }
                add_record(&mut owner, value);
            }
            let mut latest = next_version(release_update(kind), 2);
            if kind == "caa" {
                latest["body"]["access"]["conclusion"] = json!("likely");
            }
            if !latest_approved {
                latest["body"]["approval_status"] = json!("draft");
            }
            add_record(&mut owner, latest);
            let mut input = release_input();
            input["assessment_updates"] =
                json!(["assessment.icra:1", "assessment.caa:1", "assessment.cra:1"]);
            let before = facts(fixture.domain.config.store_dir());
            let draws = fixture.draws();
            let stale = release::validate_release(
                &serde_json::from_value(input.clone()).unwrap(),
                owner.view(),
            );
            assert_eq!(facts(fixture.domain.config.store_dir()), before);
            assert_eq!(fixture.draws(), draws);
            assert_eq!(
                stale,
                Err(Error::InvalidInput),
                "{kind}: superseded approved update accepted"
            );
            drop(owner);
            let config = cli_config(&fixture);
            let path = cli_input(&fixture, "stale-release.json", &input);
            let before = facts(fixture.domain.config.store_dir());
            let output = real_cli(&config, &["release", "validate"], &[("--input", &path)]);
            assert_eq!(facts(fixture.domain.config.store_dir()), before);
            cli_refused(output, Error::InvalidInput);
            input["assessment_updates"] = json!(["icra", "caa", "cra"].map(|current| format!(
                "assessment.{current}:{}",
                if kind == current { 2 } else { 1 }
            )));
            let view = checked_record_view(&fixture);
            let before = facts(fixture.domain.config.store_dir());
            let result = release::validate_release(&serde_json::from_value(input).unwrap(), &view);
            assert_eq!(facts(fixture.domain.config.store_dir()), before);
            assert_eq!(fixture.draws(), draws);
            assert_eq!(
                result,
                if latest_approved {
                    Ok(())
                } else {
                    Err(Error::InvalidInput)
                },
                "{kind}: latest release approval"
            );
        }
    }
}

/// Pins elapsed annual thresholds through real idempotent review additions.
pub fn annual_reviews_contract() {
    use stract::compliance::clock;
    for (reviewed, due) in [
        ("2026-09-19T12:00:00Z", "2027-09-19T12:00:00Z"),
        ("2024-02-29T12:00:00Z", "2025-02-28T12:00:00Z"),
        ("2027-09-19T12:00:00Z", "2028-09-18T12:00:00Z"),
    ] {
        for kind in ["measures", "icra", "cra"] {
            cli_review_boundaries(kind, reviewed, due, false);
            annual_review_case(kind, reviewed, due);
        }
    }
    assert!(
        matches!(
            clock::review_fresh(RECORD_TIME + 1, RECORD_TIME),
            Err(Error::InvalidInput)
        ),
        "future review accepted"
    );
    trigger_reviews_case("risk_profile_changed", &["measures", "icra", "cra"]);
    cli_trigger_repeat("risk-profile-changed", 3);
    let fixture = approved_store(false, false, false);
    set_record_clock(&fixture, support::utc("2028-09-19T12:00:00Z").timestamp());
    startup_result(
        &fixture,
        &api_config(&fixture, true),
        Ok(()),
        "approved hosted",
    );
    assert_eq!(clock::REVIEW_FRESHNESS_SECONDS, 31536000);
}

fn cli_review_boundaries(kind: &str, reviewed: &str, due: &str, likely: bool) {
    let reviewed = support::utc(reviewed).timestamp();
    let due = support::utc(due).timestamp();
    let fixture = RecordsFixture::new();
    set_record_clock(&fixture, reviewed);
    let mut owner = fixture.owner();
    let mut input = dated(record_input(kind), reviewed);
    if likely {
        input["body"]["access"]["conclusion"] = json!("likely");
    }
    add_record(&mut owner, input);
    drop(owner);
    let config = cli_config(&fixture);
    for (now, overdue) in [(due - 1, false), (due, false), (due + 1, true)] {
        set_record_clock(&fixture, now);
        let before = facts(fixture.domain.config.store_dir());
        let draws = fixture.draws();
        let checked = injected_cli(&fixture, &config, &["review", "check"], &[]);
        assert_eq!(fixture.draws(), draws);
        assert_eq!(facts(fixture.domain.config.store_dir()), before);
        let checked = injected_success(checked);
        let items = checked["items"].as_array();
        assert!(items.is_some(), "review check items shape");
        let items = items.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["due_at"], due, "command review due instant");
        assert_eq!(items[0]["overdue"], overdue, "command review threshold");
        let written = injected_cli(
            &fixture,
            &config,
            &["review", "open-due", "--actor", "synthetic.operator"],
            &[],
        );
        assert_eq!(fixture.draws(), draws + usize::from(overdue));
        if !overdue {
            assert_eq!(facts(fixture.domain.config.store_dir()), before);
        }
        assert_eq!(injected_success(written)["created"], u64::from(overdue));
    }
    set_record_clock(&fixture, due + 20);
    let before = facts(fixture.domain.config.store_dir());
    let draws = fixture.draws();
    let repeated = injected_cli(
        &fixture,
        &config,
        &["review", "open-due", "--actor", "synthetic.operator"],
        &[],
    );
    assert_eq!(fixture.draws(), draws, "repeated command drew entropy");
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert!(
        repeated.0.is_ok(),
        "idempotent existing review command refused: kind={kind} reviewed={reviewed} \
         due={due} result={:?} draws={} root={}",
        repeated.0,
        fixture.draws(),
        fixture.domain.config.records_dir().display()
    );
    let repeated = injected_success(repeated);
    assert_eq!(repeated["created"], 0);
    assert_eq!(repeated["existing"], 1);
}

fn annual_review_case(kind: &str, reviewed: &str, due: &str) {
    use stract::compliance::reviews;
    let reviewed = support::utc(reviewed).timestamp();
    let due = support::utc(due).timestamp();
    let fixture = RecordsFixture::new();
    set_record_clock(&fixture, reviewed);
    let mut owner = fixture.owner();
    add_record(&mut owner, dated(record_input(kind), reviewed));
    for (now, overdue, created) in [(due - 1, false, 0), (due, false, 0), (due + 1, true, 1)] {
        set_record_clock(&fixture, now);
        let before = facts(fixture.domain.config.store_dir());
        let checked = reviews::freshness(owner.view(), now);
        assert_eq!(facts(fixture.domain.config.store_dir()), before);
        assert!(checked.is_ok(), "valid annual review refused");
        let checked = checked.unwrap();
        assert_eq!(checked.items.len(), 1);
        assert_eq!(checked.items[0].due_at, due);
        assert_eq!(
            checked.items[0].overdue, overdue,
            "annual threshold mismatch"
        );
        let draws = fixture.draws();
        let written = reviews::open_work(&mut owner, &checked.items, now, "synthetic.operator");
        assert_eq!(fixture.draws(), draws + created);
        if created == 0 {
            assert_eq!(facts(fixture.domain.config.store_dir()), before);
        }
        assert!(written.is_ok(), "annual review write refused");
        assert_eq!(written.unwrap().created, created as u64);
    }
    assert_review_repeat(&fixture, &mut owner, due + 200, None, 1);
    let read = read_view(
        &fixture.domain.config,
        fixture.domain.clock.as_ref(),
        fixture.probe.as_ref(),
    );
    assert!(read.is_ok(), "persisted annual work refused");
    assert_eq!(read.unwrap().records().len(), 2);
}

fn assert_review_repeat(
    fixture: &RecordsFixture,
    owner: &mut RecordStore,
    now: i64,
    trigger: Option<stract::compliance::record_types::TriggerKind>,
    expected: u64,
) {
    use stract::compliance::reviews;
    set_record_clock(fixture, now);
    let items = if let Some(trigger) = trigger {
        reviews::triggered(owner.view(), trigger, "synthetic-change", now).unwrap()
    } else {
        reviews::freshness(owner.view(), now).unwrap().items
    };
    let before = facts(fixture.domain.config.store_dir());
    let writes = fixture.probe.writes.load(SeqCst);
    let draws = fixture.draws();
    let result = reviews::open_work(owner, &items, now, "synthetic.operator");
    assert_eq!(fixture.draws(), draws, "repeated review consumed entropy");
    assert_eq!(
        fixture.probe.writes.load(SeqCst),
        writes,
        "repeated review wrote index"
    );
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert!(result.is_ok(), "existing review refused");
    let result = result.unwrap();
    assert_eq!(result.created, 0);
    assert_eq!(result.existing, expected);
    assert_eq!(result.record_refs.len() as u64, expected);
}

fn trigger_reviews_case(trigger: &str, expected: &[&str]) {
    use stract::compliance::reviews;
    let fixture = RecordsFixture::new();
    let mut owner = fixture.owner();
    for kind in ["measures", "icra", "caa", "cra"] {
        add_record(&mut owner, record_input(kind));
    }
    let trigger = serde_json::from_value(json!(trigger)).unwrap();
    let before = facts(fixture.domain.config.store_dir());
    let items = reviews::triggered(owner.view(), trigger, "synthetic-change", RECORD_TIME);
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert!(items.is_ok(), "valid explicit trigger refused");
    let items = items.unwrap();
    let mut actual = items
        .iter()
        .map(|item| item.assessment.id.clone())
        .collect::<Vec<_>>();
    actual.sort();
    let mut expected = expected
        .iter()
        .map(|kind| format!("assessment.{kind}"))
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(actual, expected, "trigger scope mapping mismatch");
    assert!(items
        .iter()
        .all(|item| item.due_at == RECORD_TIME && item.overdue));
    let written = reviews::open_work(&mut owner, &items, RECORD_TIME, "synthetic.operator");
    assert!(written.is_ok(), "trigger work write refused");
    assert_eq!(written.unwrap().created, expected.len() as u64);
    assert_review_repeat(
        &fixture,
        &mut owner,
        RECORD_TIME + 50,
        Some(trigger),
        expected.len() as u64,
    );
}

/// Pins annual access reviews, calendar deadlines and preserved late-completion facts.
pub fn child_reviews_contract() {
    use stract::compliance::clock;
    cli_review_boundaries("caa", "2027-09-19T12:00:00Z", "2028-09-18T12:00:00Z", false);
    annual_review_case("caa", "2027-09-19T12:00:00Z", "2028-09-18T12:00:00Z");
    for (concluded, due) in [
        ("2026-11-30T12:00:00Z", "2027-02-28T12:00:00Z"),
        ("2023-11-30T12:00:00Z", "2024-02-29T12:00:00Z"),
        ("2024-01-31T12:00:00Z", "2024-04-30T12:00:00Z"),
    ] {
        cli_review_boundaries("caa", concluded, due, true);
        child_deadline_case(concluded, due);
    }
    trigger_reviews_case("evidence_of_child_use", &["caa"]);
    trigger_reviews_case("significant_change", &["measures", "icra", "caa", "cra"]);
    cli_trigger_repeat("evidence-of-child-use", 1);
    cli_trigger_repeat("significant-change", 4);
    hosted_deadline_cases();
    child_completion_case(false, false);
    child_completion_case(true, false);
    child_completion_case(true, true);
    assert_eq!(clock::CHILD_RISK_MONTHS, 3);
}

fn cli_trigger_repeat(kind: &str, expected: usize) {
    let fixture = RecordsFixture::new();
    let mut owner = fixture.owner();
    for kind in ["icra", "cra", "caa", "measures"] {
        add_record(&mut owner, record_input(kind));
    }
    drop(owner);
    let config = cli_config(&fixture);
    let words = [
        "review",
        "trigger",
        "--kind",
        kind,
        "--reference",
        "synthetic-change",
        "--actor",
        "synthetic.operator",
    ];
    let draws = fixture.draws();
    let written = injected_cli(&fixture, &config, &words, &[]);
    assert_eq!(fixture.draws(), draws + expected);
    let written = injected_success(written);
    assert_eq!(written["created"], expected);
    let references = written["record_refs"].as_array();
    assert!(references.is_some(), "review writer references shape");
    let reference = stract::compliance::record_types::RecordRef::parse(
        references.unwrap()[0].as_str().unwrap(),
    )
    .unwrap();
    set_record_clock(&fixture, RECORD_TIME + 20);
    let mut owner = fixture.owner();
    let mut completed = serde_json::to_value(owner.view().get(&reference).unwrap()).unwrap();
    completed["version"] = json!(2);
    completed["supersedes"] = json!(reference.to_string());
    completed["body"]["status"] = json!("completed");
    completed["body"]["completed_at"] = json!(RECORD_TIME + 20);
    add_record(&mut owner, completed);
    drop(owner);
    set_record_clock(&fixture, RECORD_TIME + 50);
    let before = facts(fixture.domain.config.store_dir());
    let draws = fixture.draws();
    let repeated = injected_cli(&fixture, &config, &words, &[]);
    assert_eq!(fixture.draws(), draws, "repeated trigger consumed entropy");
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    let repeated = injected_success(repeated);
    assert_eq!(repeated["created"], 0);
    assert_eq!(repeated["existing"], expected);
    let references = repeated["record_refs"].as_array();
    assert!(references.is_some(), "repeated references shape");
    assert!(references
        .unwrap()
        .contains(&json!(format!("{}:2", reference.id))));
}

fn child_deadline_case(concluded: &str, due: &str) {
    use stract::compliance::{clock, reviews};
    let concluded = support::utc(concluded).timestamp();
    let due = support::utc(due).timestamp();
    let fixture = RecordsFixture::new();
    set_record_clock(&fixture, concluded);
    let mut owner = fixture.owner();
    let mut record = dated(record_input("caa"), concluded);
    record["body"]["access"]["conclusion"] = json!("likely");
    add_record(&mut owner, record);
    assert_eq!(clock::child_risk_due(concluded).unwrap(), due);
    for (now, overdue) in [(due - 1, false), (due, false), (due + 1, true)] {
        set_record_clock(&fixture, now);
        let result = reviews::freshness(owner.view(), now);
        assert!(result.is_ok(), "valid child-risk deadline refused");
        let result = result.unwrap();
        assert_eq!(result.items.len(), 1);
        assert_eq!(result.items[0].due_at, due);
        assert_eq!(
            result.items[0].overdue, overdue,
            "child-risk threshold mismatch"
        );
        let before = facts(fixture.domain.config.store_dir());
        let draws = fixture.draws();
        let written = reviews::open_work(&mut owner, &result.items, now, "synthetic.operator");
        assert_eq!(fixture.draws(), draws + usize::from(overdue));
        if !overdue {
            assert_eq!(facts(fixture.domain.config.store_dir()), before);
        }
        assert!(written.is_ok(), "child-risk work refused");
        assert_eq!(written.unwrap().created, u64::from(overdue));
    }
    assert_review_repeat(&fixture, &mut owner, due + 10, None, 1);
}

fn child_completion_case(approved: bool, wrong_service: bool) {
    use stract::compliance::reviews;
    let concluded = support::utc("2024-01-31T12:00:00Z").timestamp();
    let due = support::utc("2024-04-30T12:00:00Z").timestamp();
    let mut fixture = RecordsFixture::new();
    approved_config(&mut fixture.domain);
    set_record_clock(&fixture, concluded);
    let mut owner = fixture.owner();
    let mut record = dated(record_input("caa"), concluded);
    record["body"]["access"]["conclusion"] = json!("likely");
    add_record(&mut owner, record);
    set_record_clock(&fixture, due + 1);
    let mut cra = dated(
        if approved {
            approved_record("cra")
        } else {
            record_input("cra")
        },
        due + 1,
    );
    if wrong_service {
        cra["body"]["service"] = json!("Different synthetic service");
    }
    add_record(&mut owner, cra);
    let before = facts(fixture.domain.config.store_dir());
    let result = reviews::freshness(owner.view(), due + 1);
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert!(result.is_ok(), "completed child-risk review refused");
    let result = result.unwrap();
    let resolved = approved && !wrong_service;
    assert_eq!(result.items.len(), if resolved { 1 } else { 2 });
    assert_eq!(result.late_completions.len(), usize::from(resolved));
    if resolved {
        assert_eq!(result.late_completions[0].due_at, due);
        assert_eq!(result.late_completions[0].completed_at, due + 1);
    }
    drop(owner);
    let config = cli_config(&fixture);
    let before = facts(fixture.domain.config.store_dir());
    let draws = fixture.draws();
    let written = injected_cli(&fixture, &config, &["review", "check"], &[]);
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert_eq!(fixture.draws(), draws);
    assert_eq!(
        written.1.last(),
        Some(&b'\n'),
        "review check JSON terminator"
    );
    let written = injected_success(written);
    assert_eq!(
        written
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["items", "late_completions"],
        "review check omitted retained lateness"
    );
    assert_eq!(
        written["late_completions"],
        if resolved {
            json!([{"access":"assessment.caa:1","assessment":"assessment.cra:1",
            "due_at":due,"completed_at":due + 1}])
        } else {
            json!([])
        }
    );
}

fn assessment_input(kind: &str) -> Value {
    let risks = (1..=17)
        .map(|slot| {
            json!({
                "kind":format!("P{slot:02}"),"level":"low","explanation":"Synthetic assessment",
                "evidence_ids":["evidence.one"]
            })
        })
        .collect::<Vec<_>>();
    let classes = ["primary_priority", "priority", "non_designated"].map(|class| {
        json!({
            "class":class,"level":"low","explanation":"Synthetic child assessment",
            "evidence_ids":["evidence.one"]
        })
    });
    let mut body = json!({
        "service":"Synthetic service","date_completed":RECORD_TIME,
        "review_update_dates":[RECORD_TIME],"author":"Synthetic author",
        "responsible_person":"Synthetic individual","approver":"Synthetic approver",
        "approval_status":"draft","approved_at":null,"risk_profiles_consulted":"no",
        "questionnaire_outcomes":[{"id":"question.one","answer":"Synthetic answer"}],
        "risk_factors":["Synthetic risk"],"additional_characteristics":[],
        "existing_controls":[{"description":"Synthetic control","effect":"Synthetic effect"}],
        "priority_risks":risks,"other_illegal_risks":[{"name":"Synthetic other risk",
            "level":"low","explanation":"Synthetic additional assessment",
            "evidence_ids":["evidence.one"]}],
        "other_illegal_reasoning":"No additional synthetic risk",
        "evidence":[{"id":"evidence.one","description":"Synthetic evidence",
            "source":"Synthetic reference"}],
        "reasoning":"Synthetic reasoning","governance_reporting":"no",
        "governance_reference":"synthetic.governance",
        "keep_up_to_date_policy":"Review synthetic changes","last_reviewed_at":RECORD_TIME,
        "review_triggers":[],"priority_catalog_version":"pending","access":null,"children":null
    });
    if kind == "caa" {
        body["access"] = json!({"conclusion":"not_likely","concluded_at":RECORD_TIME,
            "steps":"Synthetic access steps","evidence_ids":["evidence.one"]});
    }
    if kind == "cra" {
        body["children"] = json!({"classes":classes});
    }
    body
}

fn measure_codes() -> [&'static str; 28] {
    [
        "ICS A2", "ICS C1.2", "ICS C1.4", "ICS C3", "ICS C7.6", "ICS D1", "ICS D2", "ICS D3",
        "ICS D4", "ICS D5", "ICS D8", "ICS D9", "ICS D12", "ICS G1", "ICS G3", "PCS A2", "PCS C1",
        "PCS D1", "PCS D2", "PCS D4", "PCS D5", "PCS D6", "PCS D7", "PCS D9", "PCS D10", "PCS D14",
        "PCS G1", "PCS G3",
    ]
}

fn measures_input() -> Value {
    let voluntary = [
        "ICS C3", "ICS D3", "ICS D4", "ICS D5", "PCS D4", "PCS D5", "PCS D6",
    ];
    let rows = measure_codes().map(|code| {
        json!({"code":code,
            "description":"Synthetic measure","date_effective":RECORD_TIME,"disposition":"taken",
            "alternative":null,"adoption":if voluntary.contains(&code) {
                "voluntary_pending_legal_review"
            } else { "required" }
        })
    });
    json!({"service":"Synthetic service","date_effective":RECORD_TIME,
        "approval_status":"draft","approver":"Synthetic approver","rows":rows,
        "last_reviewed_at":RECORD_TIME})
}

fn metrics_input() -> Value {
    let counts = [
        "illegal_content",
        "harmful_to_children",
        "intimate_images",
        "site_complaint",
        "rights_removal",
        "data_rights",
        "data_protection_complaint",
        "online_safety_complaint",
    ]
    .map(|route| json!({"route":route,"count":0}));
    let durations = json!({"n":0,"median":null,"p95":null});
    json!({"month":"2026-09","as_of_sequence":0,"generated_at":RECORD_TIME,
        "counts_by_route":counts,"ack_seconds":durations,"decision_seconds":durations,
        "action_seconds":durations,"actions_by_type":[{"kind":"global_deindex","count":0},
            {"kind":"name_delisting","count":0}],"reversals":0,
        "intimate":{"due":0,"met":0,"missed":0,"pending":0,"exempt":0},
        "unfounded_by_clause":[]})
}

fn record_input(kind: &str) -> Value {
    let body = match kind {
        "icra" | "caa" | "cra" => assessment_input(kind),
        "measures" => measures_input(),
        "metrics" => metrics_input(),
        "manifest" => json!({"service":"Synthetic service",
            "accountable_person":"Synthetic individual","governance_body":"Synthetic board",
            "icra":"assessment.icra:1","caa":"assessment.caa:1","cra":null,
            "measures":"assessment.measures:1","statement_version":"619.1",
            "approval_status":"draft","approver":"Synthetic approver","approved_at":null}),
        "review" => json!({"scope":"risk","trigger":{"kind":"annual","at":RECORD_TIME,
            "reference":"synthetic.review"},"assessment":"assessment.icra:1",
            "opened_at":RECORD_TIME,"due_at":RECORD_TIME,"status":"open","completed_at":null,
            "reasons":"Synthetic review work"}),
        _ => panic!("unknown independent record kind"),
    };
    json!({"format_version":1,"id":format!("assessment.{kind}"),"version":1,
        "kind":kind,"completed_at":RECORD_TIME,"supersedes":null,"body":body})
}

fn schema_result(value: Value, fixture: &DomainFixture) -> Result<RecordEnvelope> {
    let before = facts(fixture.config.store_dir());
    let result = serde_json::from_value::<RecordEnvelope>(value)
        .map_err(|_| Error::InvalidInput)
        .and_then(|record| record.validate(RECORD_TIME).map(|()| record));
    assert_eq!(
        facts(fixture.config.store_dir()),
        before,
        "schema validation wrote files"
    );
    result
}

fn schema_refused(value: Value, fixture: &DomainFixture) {
    assert!(
        matches!(schema_result(value, fixture), Err(Error::InvalidInput)),
        "invalid record schema accepted"
    );
}

fn schema_accepted(value: Value, fixture: &DomainFixture) -> RecordEnvelope {
    let result = schema_result(value, fixture);
    assert!(result.is_ok(), "valid record schema refused");
    result.unwrap()
}

fn object_paths(value: &Value, path: String, paths: &mut Vec<String>) {
    if let Some(object) = value.as_object() {
        paths.push(path.clone());
        for (key, child) in object {
            object_paths(child, format!("{path}/{key}"), paths);
        }
    } else if let Some(array) = value.as_array() {
        for (at, child) in array.iter().enumerate() {
            object_paths(child, format!("{path}/{at}"), paths);
        }
    }
}

fn object_shape_cases(value: &Value, fixture: &DomainFixture) {
    let mut paths = Vec::new();
    object_paths(value, String::new(), &mut paths);
    for path in paths {
        let object = value.pointer(&path).unwrap().as_object().unwrap();
        let mut unknown = value.clone();
        unknown.pointer_mut(&path).unwrap()["unknown_field"] = json!("unknown");
        schema_refused(unknown, fixture);
        for key in object.keys() {
            let mut missing = value.clone();
            missing
                .pointer_mut(&path)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            schema_refused(missing, fixture);
            for bad in [json!(false), json!(1.5)] {
                let mut changed = value.clone();
                changed.pointer_mut(&path).unwrap()[key] = bad;
                schema_refused(changed, fixture);
            }
            if object[key].is_string() {
                let mut blank = value.clone();
                blank.pointer_mut(&path).unwrap()[key] = json!(" ");
                schema_refused(blank, fixture);
            }
        }
    }
}

/// Exercises independent complete body shapes, scalar bounds and assessment invariants.
pub fn schema_contract() {
    let fixture = DomainFixture::new();
    for kind in [
        "icra", "caa", "cra", "measures", "manifest", "metrics", "review",
    ] {
        let value = record_input(kind);
        schema_accepted(value.clone(), &fixture);
        object_shape_cases(&value, &fixture);
    }
    schema_text_bounds(&fixture);
    schema_dates_and_identity(&fixture);
    schema_vector_bounds(&fixture);
    schema_approved_control();
    let mut draft = record_input("manifest");
    draft["body"]["approved_at"] = json!(RECORD_TIME - 1);
    schema_accepted(draft, &fixture);
    record_config_caps(&fixture);
    record_capacity_equality();
    record_path_overlaps();
    manifest_identity_admission();
    schema_store_references();
}

#[derive(Default)]
struct RecordProbe {
    counts: FileCounts,
    writes: std::sync::atomic::AtomicUsize,
    fail: Mutex<Option<(ComplianceStage, usize)>>,
    quarantines: support::QuarantineProbe,
}
impl ComplianceHooks for RecordProbe {
    fn at(&self, stage: ComplianceStage) -> io::Result<()> {
        self.quarantines.at(stage)?;
        self.counts.at(stage)?;
        if matches!(
            stage,
            ComplianceStage::AfterRecordStageSync
                | ComplianceStage::DuringRecordWrite
                | ComplianceStage::AfterJournalSync
        ) {
            self.writes.fetch_add(1, SeqCst);
        }
        let mut armed = self.fail.lock().unwrap();
        if let Some((target, remaining)) = armed.as_mut() {
            if stage == *target {
                *remaining -= 1;
                if *remaining == 0 {
                    *armed = None;
                    return Err(io::Error::other("synthetic record stage interruption"));
                }
            }
        }
        Ok(())
    }
    fn unclaimed_quarantines(&self, store: stract::compliance::disk::QuarantineStore, count: u64) {
        self.quarantines.unclaimed_quarantines(store, count);
    }
}

struct RecordsFixture {
    domain: DomainFixture,
    probe: Arc<RecordProbe>,
    entropy: Arc<support::CountingEntropy>,
}
impl RecordsFixture {
    fn new() -> Self {
        Self {
            domain: DomainFixture::new(),
            probe: Arc::new(RecordProbe::default()),
            entropy: Arc::new(support::CountingEntropy::default()),
        }
    }
    fn open(&self) -> Result<RecordStore> {
        RecordStore::open(
            &self.domain.config,
            self.domain.clock.clone(),
            self.entropy.clone(),
            self.probe.clone(),
        )
    }
    fn owner(&self) -> RecordStore {
        let result = self.open();
        assert!(result.is_ok(), "valid record owner refused");
        result.unwrap()
    }
    fn path(&self, relative: &str) -> PathBuf {
        self.domain.config.records_dir().join(relative)
    }
    fn draws(&self) -> usize {
        self.entropy.widths.lock().unwrap().len()
    }
}

fn typed(value: Value) -> RecordEnvelope {
    serde_json::from_value(value).unwrap()
}

fn add_record(store: &mut RecordStore, value: Value) {
    let result = store.add(typed(value), "synthetic.operator");
    assert!(result.is_ok(), "valid record addition refused");
}

fn assert_addition_refused(
    fixture: &RecordsFixture,
    store: &mut RecordStore,
    value: Value,
    expected: Error,
    case: &str,
) {
    let before = facts(fixture.domain.config.store_dir());
    let draws = fixture.draws();
    let writes = fixture.probe.writes.load(SeqCst);
    let result = store.add(typed(value), "synthetic.operator");
    assert_eq!(
        fixture.draws(),
        draws,
        "{case}: refused record consumed entropy"
    );
    assert_eq!(
        fixture.probe.writes.load(SeqCst),
        writes,
        "{case}: refused record reached a write"
    );
    assert_eq!(
        facts(fixture.domain.config.store_dir()),
        before,
        "{case}: refused record changed files"
    );
    let actual = result.map(|_| ());
    assert_eq!(
        actual,
        Err(expected),
        "{case}: invalid record addition accepted; expected {expected:?}, actual {actual:?}"
    );
}

fn schema_store_references() {
    let fixture = RecordsFixture::new();
    let mut owner = fixture.owner();
    for kind in [
        "icra", "caa", "cra", "measures", "metrics", "review", "manifest",
    ] {
        add_record(&mut owner, record_input(kind));
    }
    for (field, bad) in [
        ("icra", json!("assessment.caa:1")),
        ("icra", json!("assessment.icra:2")),
        ("caa", json!("assessment.cra:1")),
        ("measures", json!("assessment.icra:1")),
        ("service", json!("Another synthetic service")),
        ("accountable_person", json!("Another synthetic individual")),
    ] {
        let mut value = next_version(record_input("manifest"), 2);
        let case = format!("manifest reference {field}={bad}");
        value["body"][field] = bad;
        assert_addition_refused(&fixture, &mut owner, value, Error::InvalidInput, &case);
    }
    let before = facts(fixture.domain.config.store_dir());
    let draws = fixture.draws();
    let view = read_view(
        &fixture.domain.config,
        fixture.domain.clock.as_ref(),
        fixture.probe.as_ref(),
    );
    assert_eq!(fixture.draws(), draws);
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert!(view.is_ok(), "valid seven-kind snapshot refused");
    assert_eq!(view.unwrap().records().len(), 7);
}

fn index_rows(fixture: &RecordsFixture) -> Vec<Value> {
    fs::read_to_string(fixture.path("index.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn addition_counts(fixture: &RecordsFixture) -> (usize, usize, usize) {
    let rows = index_rows(fixture);
    let intents = rows
        .iter()
        .filter(|row| row["event"] == "record_intent")
        .count();
    let completed = rows
        .iter()
        .filter(|row| row["event"] == "record_added")
        .count();
    let pending = fs::read_dir(fixture.path(".pending")).map_or(0, |entries| entries.count());
    (intents, completed, pending)
}

/// Exercises immutable versions, full-stage crash recovery and reservation ordering through owners.
pub fn versions_contract() {
    historical_guard_cases();
    persist_final_binding();
    record_quarantine_claims();
    immutable_versions();
    record_owner_hardening();
    for (stage, occurrence, published) in [
        (ComplianceStage::AfterRecordStageSync, 1, false),
        (ComplianceStage::AfterJournalSync, 1, true),
        (ComplianceStage::AfterHeadRename, 1, true),
        (ComplianceStage::AfterHeadSync, 1, true),
        (ComplianceStage::AfterIntentSync, 1, true),
        (ComplianceStage::DuringRecordWrite, 1, true),
        (ComplianceStage::AfterRecordSync, 1, true),
        (ComplianceStage::BeforeCompletionRow, 1, true),
        (ComplianceStage::AfterJournalSync, 2, true),
        (ComplianceStage::AfterHeadRename, 2, true),
        (ComplianceStage::AfterHeadSync, 2, true),
    ] {
        interrupted_addition(stage, occurrence, published);
    }
    recover_final_cases();
    record_capacity_cases();
    record_byte_caps();
    published_record_hardening();
    recovered_equal_final_is_synced_before_completion();
    lower_base_quarantine_stays_unclaimed();
}

fn refused_record_view(fixture: &RecordsFixture, case: &str) {
    let before = safe_tree(fixture.domain.config.store_dir());
    let writes = fixture.probe.writes.load(SeqCst);
    let draws = fixture.draws();
    let result = read_view(
        &fixture.domain.config,
        fixture.domain.clock.as_ref(),
        fixture.probe.as_ref(),
    );
    assert_eq!(
        safe_tree(fixture.domain.config.store_dir()),
        before,
        "{case}: tree"
    );
    assert_eq!(fixture.probe.writes.load(SeqCst), writes, "{case}: writes");
    assert_eq!(fixture.draws(), draws, "{case}: entropy");
    assert_eq!(
        result.as_ref().map(|_| ()).map_err(|error| *error),
        Err(Error::Unavailable),
        "{case}"
    );
}

fn historical_guard_cases() {
    for fault in [
        "resalt",
        "reference",
        "kind",
        "whitespace",
        "key-order",
        "missing-lf",
        "format",
    ] {
        let fixture = RecordsFixture::new();
        let mut owner = fixture.owner();
        add_record(&mut owner, record_input("icra"));
        drop(owner);
        let path = fixture.path("assessment.icra/0000000001.json");
        let original = fs::read(&path).unwrap();
        let mut stored: Value = serde_json::from_slice(&original).unwrap();
        match fault {
            "resalt" => stored["salt"] = json!("51".repeat(32)),
            "reference" => stored["record"]["id"] = json!("other.assessment"),
            "kind" => {
                stored["record"] = record_input("caa");
                stored["record"]["id"] = json!("assessment.icra");
            }
            "format" => stored["format_version"] = json!(2),
            _ => {}
        }
        let canonical = refresh_wrapper(&mut stored);
        let bytes = match fault {
            "whitespace" => serde_json::to_vec_pretty(&stored).unwrap(),
            "key-order" => {
                let fields = stored
                    .as_object()
                    .unwrap()
                    .iter()
                    .rev()
                    .map(|(k, v)| format!("\"{k}\":{v}"))
                    .collect::<Vec<_>>();
                format!("{{{}}}\n", fields.join(",")).into_bytes()
            }
            "missing-lf" => canonical[..canonical.len() - 1].to_vec(),
            _ => canonical,
        };
        fs::write(&path, bytes).unwrap();
        refused_record_view(
            &fixture,
            if matches!(fault, "resalt" | "reference" | "kind") {
                "wrapper not bound to published index"
            } else {
                "noncanonical record wrapper accepted"
            },
        );
        fs::write(path, original).unwrap();
        assert_eq!(checked_record_view(&fixture).records().len(), 1);
    }
    historical_predecessors();
    for reference in ["assessment.caa:1", "absent.assessment:1"] {
        let fixture = approved_store(false, false, false);
        assert_eq!(checked_record_view(&fixture).records().len(), 4);
        rewrite_record(&fixture, "manifest", |record| {
            record["body"]["icra"] = json!(reference)
        });
        refused_record_view(&fixture, "historical reference mismatch accepted");
    }
}

fn historical_predecessors() {
    for fault in ["gap", "supersedes", "kind"] {
        let fixture = RecordsFixture::new();
        let mut owner = fixture.owner();
        add_record(&mut owner, record_input("icra"));
        let original = next_version(record_input("icra"), 2);
        add_record(&mut owner, original.clone());
        drop(owner);
        assert_eq!(checked_record_view(&fixture).records().len(), 2);
        let mut record = original;
        match fault {
            "gap" => record["version"] = json!(3),
            "supersedes" => record["supersedes"] = json!("assessment.icra:2"),
            "kind" => {
                record["kind"] = json!("caa");
                record["body"] = record_input("caa")["body"].clone();
            }
            _ => unreachable!(),
        }
        replace_historical_version(&fixture, "assessment.icra:2", record);
        refused_record_view(&fixture, "historical predecessor gap accepted");
    }
}

struct FinalReadProbe {
    stages: Mutex<Vec<ComplianceStage>>,
    armed: AtomicBool,
    fired: AtomicBool,
    path: PathBuf,
    change: bool,
}
impl ComplianceHooks for FinalReadProbe {
    fn at(&self, stage: ComplianceStage) -> io::Result<()> {
        self.stages.lock().unwrap().push(stage);
        if stage == ComplianceStage::DuringRecordWrite {
            self.armed.store(true, SeqCst);
        }
        if stage == ComplianceStage::BeforeOpen && self.armed.swap(false, SeqCst) {
            self.fired.store(true, SeqCst);
            if self.change {
                let mut stored = support::read_json(&self.path);
                stored["record"]["body"]["reasoning"] = json!("Changed before final read");
                fs::write(&self.path, refresh_wrapper(&mut stored)).unwrap();
            }
        }
        Ok(())
    }
}

fn persist_final_binding() {
    for change in [false, true] {
        let fixture = RecordsFixture::new();
        let hooks = Arc::new(FinalReadProbe {
            stages: Mutex::new(Vec::new()),
            armed: AtomicBool::new(false),
            fired: AtomicBool::new(false),
            path: fixture.path("assessment.icra/0000000001.json"),
            change,
        });
        let mut owner = RecordStore::open(
            &fixture.domain.config,
            fixture.domain.clock.clone(),
            fixture.entropy.clone(),
            hooks.clone(),
        )
        .unwrap();
        let result = owner.add(typed(record_input("icra")), "synthetic.operator");
        assert_eq!(fixture.draws(), 1);
        assert!(hooks.fired.load(SeqCst), "final-read hook did not fire");
        assert_eq!(
            addition_counts(&fixture),
            (1, usize::from(!change), usize::from(change)),
            "persist published a mismatched final"
        );
        assert_eq!(
            hooks
                .stages
                .lock()
                .unwrap()
                .contains(&ComplianceStage::AfterRecordSync),
            !change,
            "mismatched final reached acknowledged boundary"
        );
        if change {
            let pending =
                support::read_json(&fixture.path(".pending/assessment.icra-0000000001.json"));
            assert_eq!(pending["record"], record_input("icra"));
        }
        assert_eq!(
            result.map(|_| ()),
            if change {
                Err(Error::Unavailable)
            } else {
                Ok(())
            }
        );
    }
}

fn record_quarantine_claims() {
    record_observed_tail_cases();
    for populated in [false, true] {
        for shape in [
            "private",
            "malformed",
            "symlink",
            "public-mode",
            "directory",
            "fifo",
            "oversized",
        ] {
            record_unclaimed_case(populated, shape);
        }
    }
}

fn record_unclaimed_case(populated: bool, shape: &str) {
    use stract::compliance::disk::QuarantineStore;
    let fixture = RecordsFixture::new();
    let mut owner = fixture.owner();
    if populated {
        add_record(&mut owner, record_input("icra"));
    }
    let sequence = owner.view().sequence;
    drop(owner);
    let bytes = b"synthetic unobserved record tail";
    let opens = fixture.probe.counts.opens.load(SeqCst);
    drop(fixture.owner());
    let expected_opens = fixture.probe.counts.opens.load(SeqCst) - opens;
    support::plant_quarantine(
        fixture.domain.config.records_dir(),
        &format!("quarantine-{sequence}-{}.bin", support::digest(bytes)),
        shape,
        bytes,
    );
    let before = safe_tree(fixture.domain.config.records_dir());
    let draws = fixture.draws();
    for _ in 0..2 {
        fixture.probe.quarantines.stages.lock().unwrap().clear();
        fixture.probe.quarantines.reports.lock().unwrap().clear();
        let opens = fixture.probe.counts.opens.load(SeqCst);
        let result = fixture.open();
        assert_eq!(
            safe_tree(fixture.domain.config.records_dir()),
            before,
            "unclaimed record quarantine acquired recovery authority"
        );
        assert_eq!(fixture.draws(), draws);
        assert_eq!(
            fixture.probe.counts.opens.load(SeqCst) - opens,
            expected_opens,
            "{shape}: unclaimed record artefact opened"
        );
        assert!(!fixture
            .probe
            .quarantines
            .stages
            .lock()
            .unwrap()
            .contains(&ComplianceStage::AfterJournalSync));
        assert_eq!(
            *fixture.probe.quarantines.reports.lock().unwrap(),
            vec![(QuarantineStore::Records, 1)]
        );
        assert_eq!(
            result.as_ref().map(|_| ()).map_err(|error| *error),
            Ok(()),
            "{shape}"
        );
        drop(result);
    }
}

fn record_observed_tail_cases() {
    use stract::compliance::disk::QuarantineStore;
    for (interrupt, suffix) in [
        (None, false),
        (Some(ComplianceStage::AfterTailTruncate), false),
        (Some(ComplianceStage::AfterTailTruncate), true),
        (Some(ComplianceStage::AfterJournalSync), false),
    ] {
        let fixture = RecordsFixture::new();
        let mut owner = fixture.owner();
        add_record(&mut owner, record_input("icra"));
        let head = fs::read(fixture.path("head.json")).unwrap();
        if suffix {
            add_record(&mut owner, record_input("caa"));
        }
        let base = owner.view().sequence;
        drop(owner);
        if suffix {
            fs::write(fixture.path("head.json"), &head).unwrap();
        }
        let prefix = fs::read(fixture.path("index.jsonl")).unwrap();
        let tail = b"{synthetic observed torn record";
        fs::write(
            fixture.path("index.jsonl"),
            [&prefix[..], &tail[..]].concat(),
        )
        .unwrap();
        let path = fixture.path(&format!("quarantine-{base}-{}.bin", support::digest(tail)));
        *fixture.probe.quarantines.fail.lock().unwrap() = interrupt;
        fixture.probe.quarantines.reports.lock().unwrap().clear();
        let draws = fixture.draws();
        let first = fixture.open();
        assert_eq!(fixture.draws(), draws);
        let quarantined = fs::read(&path);
        assert!(
            quarantined.is_ok(),
            "observed record tail was not quarantined"
        );
        assert_eq!(quarantined.unwrap(), tail);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert!(fs::read(fixture.path("index.jsonl"))
            .unwrap()
            .starts_with(&prefix));
        assert_eq!(
            first.as_ref().map(|_| ()).map_err(|error| *error),
            if interrupt.is_some() {
                Err(Error::Unavailable)
            } else {
                Ok(())
            }
        );
        drop(first);
        fixture.probe.quarantines.reports.lock().unwrap().clear();
        let reopened = fixture.open();
        let rows = record_rows(&fixture);
        let recovered = rows
            .iter()
            .filter(|row| row["event"] == "tail_recovered")
            .collect::<Vec<_>>();
        let gap = interrupt == Some(ComplianceStage::AfterTailTruncate);
        assert_eq!(
            recovered.len(),
            usize::from(!gap),
            "observed record tail lacks exactly one recovery row"
        );
        if gap && !suffix {
            assert_eq!(fs::read(fixture.path("head.json")).unwrap(), head);
        }
        if let Some(row) = recovered.first() {
            assert_eq!(row["quarantined_bytes"], tail.len());
            assert_eq!(row["quarantine_hash"], support::digest(tail));
        }
        assert_eq!(
            *fixture.probe.quarantines.reports.lock().unwrap(),
            vec![(QuarantineStore::Records, u64::from(gap))]
        );
        assert_eq!(
            reopened.as_ref().map(|_| ()).map_err(|error| *error),
            Ok(())
        );
        drop(reopened);
        let before = safe_tree(fixture.domain.config.records_dir());
        drop(fixture.owner());
        assert_eq!(safe_tree(fixture.domain.config.records_dir()), before);
    }
}

fn record_rows(fixture: &RecordsFixture) -> Vec<Value> {
    fs::read(fixture.path("index.jsonl"))
        .unwrap()
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}

fn lower_base_quarantine_stays_unclaimed() {
    use stract::compliance::disk::QuarantineStore;
    let fixture = RecordsFixture::new();
    let mut owner = fixture.owner();
    add_record(&mut owner, record_input("icra"));
    drop(owner);
    let tail = b"{synthetic exact next sequence tail";
    let prefix = fs::read(fixture.path("index.jsonl")).unwrap();
    fs::write(
        fixture.path("index.jsonl"),
        [&prefix[..], &tail[..]].concat(),
    )
    .unwrap();
    let recovered = fixture.open();
    assert!(
        recovered.is_ok(),
        "valid exact next sequence recovery refused"
    );
    drop(recovered);
    let rows = record_rows(&fixture);
    let row = rows.iter().find(|row| row["event"] == "tail_recovered");
    assert!(
        row.is_some(),
        "observed record tail lacks exactly one recovery row"
    );
    let row = row.unwrap();
    let sequence = row["sequence"].as_u64().unwrap();
    assert!(sequence >= 3);
    let hash = row["quarantine_hash"].as_str().unwrap();
    assert_eq!(hash, support::digest(tail));
    let genuine = fixture.path(&format!("quarantine-{}-{hash}.bin", sequence - 1));
    assert_eq!(fs::read(&genuine).unwrap(), tail);
    fixture.probe.quarantines.reports.lock().unwrap().clear();
    let opens = fixture.probe.counts.opens.load(SeqCst);
    let control = fixture.open();
    let expected_opens = fixture.probe.counts.opens.load(SeqCst) - opens;
    assert_eq!(
        *fixture.probe.quarantines.reports.lock().unwrap(),
        vec![(QuarantineStore::Records, 0)]
    );
    assert!(control.is_ok(), "genuine recovery artefact refused");
    drop(control);
    let planted = fixture.path(&format!("quarantine-{}-{hash}.bin", sequence - 2));
    private_record_file(&planted, b"different synthetic unclaimed bytes");
    let before = facts(fixture.domain.config.records_dir());
    let draws = fixture.draws();
    for _ in 0..2 {
        fixture.probe.quarantines.stages.lock().unwrap().clear();
        fixture.probe.quarantines.reports.lock().unwrap().clear();
        let opens = fixture.probe.counts.opens.load(SeqCst);
        let result = fixture.open();
        assert_eq!(facts(fixture.domain.config.records_dir()), before);
        assert_eq!(fixture.draws(), draws);
        assert!(!fixture
            .probe
            .quarantines
            .stages
            .lock()
            .unwrap()
            .contains(&ComplianceStage::AfterJournalSync));
        assert_eq!(
            *fixture.probe.quarantines.reports.lock().unwrap(),
            vec![(QuarantineStore::Records, 1)],
            "lower-base artefact acquired recovery authority"
        );
        assert_eq!(
            fixture.probe.counts.opens.load(SeqCst) - opens,
            expected_opens,
            "lower-base artefact acquired recovery authority: opened planted file"
        );
        assert!(
            result.is_ok(),
            "lower-base artefact acquired recovery authority"
        );
        drop(result);
    }
    fs::write(&genuine, b"corrupted accounted tail").unwrap();
    let before = facts(fixture.domain.config.records_dir());
    let writes = fixture.probe.writes.load(SeqCst);
    let corrupt = fixture.open();
    assert_eq!(facts(fixture.domain.config.records_dir()), before);
    assert_eq!(fixture.draws(), draws);
    assert_eq!(fixture.probe.writes.load(SeqCst), writes);
    assert_eq!(
        corrupt.as_ref().map(|_| ()).map_err(|error| *error),
        Err(Error::Unavailable),
        "corrupt genuine recovery artefact accepted"
    );
}

fn immutable_versions() {
    let fixture = RecordsFixture::new();
    let journal = fixture.domain.journal();
    let ticket_before = facts(fixture.domain.config.journal_dir());
    let mut owner = fixture.owner();
    add_record(&mut owner, record_input("icra"));
    let original = fs::read(fixture.path("assessment.icra/0000000001.json")).unwrap();
    let mut second = record_input("icra");
    second["version"] = json!(2);
    second["supersedes"] = json!("assessment.icra:1");
    second["body"]["reasoning"] = json!("Second synthetic version");
    add_record(&mut owner, second.clone());
    assert_eq!(facts(fixture.domain.config.journal_dir()), ticket_before);
    assert_eq!(
        fs::read(fixture.path("assessment.icra/0000000001.json")).unwrap(),
        original
    );
    assert_eq!(addition_counts(&fixture), (2, 2, 0));
    let rows = index_rows(&fixture);
    assert_eq!(rows[0]["sequence"], 1);
    assert_eq!(rows[1]["intent_sequence"], 1);
    assert_eq!(rows[3]["intent_sequence"], 3);
    let wrapper: Value =
        serde_json::from_slice(&fs::read(fixture.path("assessment.icra/0000000002.json")).unwrap())
            .unwrap();
    assert_eq!(wrapper["record"], second);
    for (version, supersedes, kind) in [
        (2, "assessment.icra:1", "icra"),
        (4, "assessment.icra:2", "icra"),
        (3, "assessment.icra:3", "icra"),
        (3, "assessment.icra:2", "caa"),
    ] {
        let mut value = record_input(kind);
        value["id"] = json!("assessment.icra");
        value["version"] = json!(version);
        value["supersedes"] = json!(supersedes);
        assert_addition_refused(
            &fixture,
            &mut owner,
            value,
            Error::InvalidInput,
            &format!("predecessor version={version} supersedes={supersedes} kind={kind}"),
        );
    }
    drop(owner);
    let reopened = fixture.owner();
    assert_eq!(reopened.view().records().len(), 2);
    assert_eq!(facts(fixture.domain.config.journal_dir()), ticket_before);
    drop(journal);
}

fn interrupted_addition(stage: ComplianceStage, occurrence: usize, published: bool) {
    let fixture = RecordsFixture::new();
    let mut owner = fixture.owner();
    *fixture.probe.fail.lock().unwrap() = Some((stage, occurrence));
    let result = owner.add(typed(record_input("icra")), "synthetic.operator");
    assert_eq!(fixture.draws(), 1);
    assert!(
        fixture.probe.fail.lock().unwrap().is_none(),
        "crash stage was not reached"
    );
    assert!(
        matches!(result, Err(Error::Unavailable)),
        "failed record stage acknowledged"
    );
    let staged = if stage == ComplianceStage::DuringRecordWrite {
        let bytes = fs::read(fixture.path(".pending/assessment.icra-0000000001.json")).unwrap();
        assert_eq!(
            fs::metadata(fixture.path("assessment.icra/0000000001.json"))
                .unwrap()
                .len(),
            0,
            "final write hook did not precede the complete write"
        );
        assert_eq!(addition_counts(&fixture), (1, 0, 1));
        let wrapper: StoredRecord = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            serde_json::to_value(wrapper.record).unwrap(),
            record_input("icra")
        );
        Some(bytes)
    } else {
        None
    };
    drop(owner);
    let reopened = fixture.open();
    let expected = usize::from(published);
    assert_eq!(
        addition_counts(&fixture),
        (expected, expected, 0),
        "record recovery completion count: stage={stage:?} occurrence={occurrence} \
         result={:?} draws={} root={}",
        reopened.as_ref().map(|_| ()),
        fixture.draws(),
        fixture.domain.config.records_dir().display()
    );
    assert_eq!(
        fixture.path("assessment.icra/0000000001.json").exists(),
        published
    );
    assert!(reopened.is_ok(), "recoverable record addition refused");
    let reopened = reopened.unwrap();
    if let Some(bytes) = staged {
        assert_eq!(
            fs::read(fixture.path("assessment.icra/0000000001.json")).unwrap(),
            bytes
        );
    }
    assert_eq!(reopened.view().records().len(), expected);
    let after = facts(fixture.domain.config.store_dir());
    let draws = fixture.draws();
    drop(reopened);
    let again = fixture.open();
    assert_eq!(fixture.draws(), draws);
    assert_eq!(
        facts(fixture.domain.config.store_dir()),
        after,
        "second recovery changed files"
    );
    assert!(again.is_ok(), "second record owner refused");
}

fn private_record_file(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn recover_final_cases() {
    for fault in [
        "torn",
        "mismatch",
        "foreign",
        "both-missing",
        "completed-corrupt",
    ] {
        let fixture = RecordsFixture::new();
        let mut owner = fixture.owner();
        *fixture.probe.fail.lock().unwrap() = Some((ComplianceStage::AfterIntentSync, 1));
        let result = owner.add(typed(record_input("icra")), "synthetic.operator");
        assert!(matches!(result, Err(Error::Unavailable)));
        drop(owner);
        final_fault(&fixture, fault);
        let before = facts(fixture.domain.config.store_dir());
        let result = fixture.open();
        if matches!(fault, "torn" | "mismatch") {
            assert_eq!(
                addition_counts(&fixture),
                (1, 1, 0),
                "torn final was not recovered"
            );
            assert!(result.is_ok(), "recoverable final refused");
        } else {
            assert_eq!(
                facts(fixture.domain.config.store_dir()),
                before,
                "foreign or published final changed"
            );
            assert!(
                matches!(result, Err(Error::Unavailable)),
                "invalid final accepted"
            );
        }
    }
}

fn equal_pending_final(fixture: &RecordsFixture) -> (PathBuf, Vec<u8>, u64) {
    let mut owner = fixture.owner();
    *fixture.probe.fail.lock().unwrap() = Some((ComplianceStage::DuringRecordWrite, 1));
    let result = owner.add(typed(record_input("icra")), "synthetic.operator");
    let path = fixture.path("assessment.icra/0000000001.json");
    assert_eq!(
        fs::metadata(&path).unwrap().len(),
        0,
        "pending final was not empty"
    );
    assert_eq!(addition_counts(fixture), (1, 0, 1));
    assert!(
        matches!(result, Err(Error::Unavailable)),
        "pending seed was acknowledged"
    );
    drop(owner);
    let bytes = fs::read(fixture.path(".pending/assessment.icra-0000000001.json")).unwrap();
    fs::write(&path, &bytes).unwrap();
    let inode = fs::metadata(&path).unwrap().ino();
    fixture.probe.quarantines.stages.lock().unwrap().clear();
    (path, bytes, inode)
}

fn recovered_equal_final_is_synced_before_completion() {
    use ComplianceStage::{
        AfterRecoveredRecordFileSync as File, AfterRecoveredRecordParentSync as Parent,
    };
    for fail in [None, Some(File), Some(Parent)] {
        let fixture = RecordsFixture::new();
        let (path, bytes, inode) = equal_pending_final(&fixture);
        let draws = fixture.draws();
        *fixture.probe.fail.lock().unwrap() = fail.map(|stage| (stage, 1));
        let result = fixture.open();
        assert_eq!(fixture.draws(), draws, "equal recovery consumed a new salt");
        assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_equal_recovery_stages(&fixture, fail);
        assert_eq!(
            addition_counts(&fixture),
            if fail.is_none() { (1, 1, 0) } else { (1, 0, 1) }
        );
        assert_eq!(
            result.as_ref().map(|_| ()).map_err(|error| *error),
            if fail.is_none() {
                Ok(())
            } else {
                Err(Error::Unavailable)
            },
            "equal final recovery: {fail:?}"
        );
        drop(result);
        if fail.is_some() {
            fixture.probe.quarantines.stages.lock().unwrap().clear();
            let retry = fixture.open();
            assert_eq!(fixture.draws(), draws);
            assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert_equal_recovery_stages(&fixture, None);
            assert_eq!(addition_counts(&fixture), (1, 1, 0));
            assert!(retry.is_ok(), "equal final retry failed: {fail:?}");
            drop(retry);
        }
        let before = facts(fixture.domain.config.records_dir());
        fixture.probe.quarantines.stages.lock().unwrap().clear();
        let again = fixture.open();
        assert_eq!(fixture.draws(), draws);
        assert_eq!(facts(fixture.domain.config.records_dir()), before);
        let stages = fixture.probe.quarantines.stages.lock().unwrap();
        assert!(!stages.contains(&File) && !stages.contains(&Parent));
        assert!(!stages.contains(&ComplianceStage::AfterJournalSync));
        assert_eq!(addition_counts(&fixture), (1, 1, 0));
        assert!(again.is_ok(), "completed equal final recovery repeated");
    }
}

fn assert_equal_recovery_stages(fixture: &RecordsFixture, fail: Option<ComplianceStage>) {
    use ComplianceStage::{
        AfterRecoveredRecordFileSync as File, AfterRecoveredRecordParentSync as Parent,
    };
    let stages = fixture.probe.quarantines.stages.lock().unwrap();
    let count = |stage| stages.iter().filter(|value| **value == stage).count();
    assert_eq!(
        count(File),
        1,
        "equal recovered final skipped file/parent sync"
    );
    assert_eq!(
        count(Parent),
        usize::from(fail != Some(File)),
        "equal recovered final skipped file/parent sync"
    );
    if fail.is_none() {
        let order = [
            File,
            Parent,
            ComplianceStage::AfterRecordSync,
            ComplianceStage::BeforeCompletionRow,
        ]
        .map(|stage| stages.iter().position(|value| *value == stage));
        assert!(
            order.iter().all(Option::is_some),
            "equal recovery skipped a completion boundary"
        );
        assert!(
            order.windows(2).all(|pair| pair[0] < pair[1]),
            "equal recovery sync order"
        );
    } else {
        assert!(
            !stages.contains(&ComplianceStage::BeforeCompletionRow),
            "equal recovery completed after failed sync"
        );
    }
}

fn final_fault(fixture: &RecordsFixture, fault: &str) {
    let pending_path = fixture.path(".pending/assessment.icra-0000000001.json");
    let path = fixture.path("assessment.icra/0000000001.json");
    let pending = fs::read(&pending_path).unwrap();
    match fault {
        "torn" => private_record_file(&path, &pending[..pending.len() / 2]),
        "mismatch" => private_record_file(&path, b"incomplete synthetic final"),
        "foreign" => {
            let mut stored: StoredRecord = serde_json::from_slice(&pending).unwrap();
            stored.record.id = "foreign.record".into();
            stored.commitment =
                stract::compliance::records::record_commitment(&stored.salt, &stored.record)
                    .unwrap();
            let mut bytes = stract::compliance::records::canonical(&stored).unwrap();
            bytes.push(b'\n');
            private_record_file(&path, &bytes);
        }
        "both-missing" => fs::remove_file(pending_path).unwrap(),
        "completed-corrupt" => {
            let owner = fixture.owner();
            drop(owner);
            fs::write(path, b"corrupt published final").unwrap();
        }
        _ => panic!("unknown final fault"),
    }
}

fn record_capacity_cases() {
    let mut fixture = RecordsFixture::new();
    let mut settings = fixture.domain.config.settings().clone();
    settings.max_records = 1;
    fixture.domain.config = settings
        .validate(
            &fixture
                .domain
                .config
                .store_dir()
                .parent()
                .unwrap()
                .join("suppression.json"),
        )
        .unwrap();
    let mut owner = fixture.owner();
    add_record(&mut owner, record_input("icra"));
    assert_addition_refused(
        &fixture,
        &mut owner,
        record_input("caa"),
        Error::Capacity,
        "record count full",
    );
    let before = facts(fixture.domain.config.store_dir());
    let view = read_view(
        &fixture.domain.config,
        fixture.domain.clock.as_ref(),
        fixture.probe.as_ref(),
    );
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert!(
        view.is_ok(),
        "full record store stopped read-only inspection"
    );
}

fn configured_record_caps(fixture: &mut RecordsFixture, per_record: u64, total: u64) {
    let mut settings = fixture.domain.config.settings().clone();
    settings.max_record_bytes = per_record;
    settings.max_records_bytes = total;
    fixture.domain.config = settings
        .validate(
            &fixture
                .domain
                .config
                .store_dir()
                .parent()
                .unwrap()
                .join("suppression.json"),
        )
        .unwrap();
}

fn wrapper_size(input: Value) -> u64 {
    let marker = stract::compliance::model::Hex64::parse(&"42".repeat(32)).unwrap();
    let wrapper = StoredRecord {
        format_version: 1,
        salt: marker.clone(),
        commitment: marker,
        record: typed(input),
    };
    stract::compliance::records::canonical(&wrapper)
        .unwrap()
        .len() as u64
        + 1
}

fn record_byte_caps() {
    let mut input = record_input("icra");
    input["body"]["reasoning"] = json!("x".repeat(4096));
    let size = wrapper_size(input.clone());
    assert!(
        size > 4096 && size < 32768,
        "literal cap fixture size range"
    );
    for delta in [-1, 0, 1] {
        let mut fixture = RecordsFixture::new();
        configured_record_caps(
            &mut fixture,
            size.checked_add_signed(delta).unwrap(),
            1048576,
        );
        let mut owner = fixture.owner();
        if delta < 0 {
            assert_addition_refused(
                &fixture,
                &mut owner,
                input.clone(),
                Error::Capacity,
                &format!("wrapper cap delta={delta}"),
            );
        } else {
            add_record(&mut owner, input.clone());
            assert_eq!(addition_counts(&fixture), (1, 1, 0));
        }
    }
    for remaining in [-1, 0, 1] {
        record_aggregate_cap(input.clone(), size, remaining);
    }
}

fn record_aggregate_cap(input: Value, size: u64, remaining: i64) {
    let mut fixture = RecordsFixture::new();
    configured_record_caps(&mut fixture, 32768, 1048576);
    let mut owner = fixture.owner();
    let used = facts(fixture.domain.config.records_dir())
        .values()
        .map(|entry| entry.bytes.len() as u64)
        .sum::<u64>();
    let reserve = 2 * size + 3 * 8192 + 65536;
    let filler = (1048576 - used - reserve)
        .checked_add_signed(-remaining)
        .unwrap();
    private_record_file(
        &fixture.path("private-sentinel"),
        &vec![b' '; filler as usize],
    );
    if remaining < 0 {
        assert_addition_refused(
            &fixture,
            &mut owner,
            input,
            Error::Capacity,
            &format!("aggregate reserve remaining={remaining}"),
        );
        return;
    }
    *fixture.probe.fail.lock().unwrap() = Some((ComplianceStage::DuringRecordWrite, 1));
    let result = owner.add(typed(input), "synthetic.operator");
    assert_eq!(fixture.draws(), 1, "exact reserve refused before entropy");
    assert!(
        matches!(result, Err(Error::Unavailable)),
        "crash did not interrupt write"
    );
    drop(owner);
    let restored = fixture.open();
    assert_eq!(
        addition_counts(&fixture),
        (1, 1, 0),
        "reserved recovery did not complete"
    );
    assert!(restored.is_ok(), "exact-cap recovery refused");
    let total = facts(fixture.domain.config.records_dir())
        .values()
        .map(|entry| entry.bytes.len() as u64)
        .sum::<u64>();
    assert!(total <= 1048576, "recovery exceeded aggregate cap");
}

fn published_record_hardening() {
    use std::os::unix::fs::PermissionsExt;
    for fault in [
        "file-mode",
        "parent-mode",
        "symlink",
        "hardlink",
        "parent-link",
    ] {
        let fixture = RecordsFixture::new();
        let mut owner = fixture.owner();
        add_record(&mut owner, record_input("icra"));
        drop(owner);
        let path = fixture.path("assessment.icra/0000000001.json");
        let sentinel = fixture.path("private-sentinel");
        private_record_file(&sentinel, b"private sentinel");
        match fault {
            "file-mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            "parent-mode" => {
                fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o755))
                    .unwrap();
            }
            "symlink" | "hardlink" => {
                fs::remove_file(&path).unwrap();
                if fault == "symlink" {
                    std::os::unix::fs::symlink(&sentinel, &path).unwrap();
                } else {
                    fs::hard_link(&sentinel, &path).unwrap();
                }
            }
            "parent-link" => {
                let moved = fixture.path("private-record-parent");
                fs::rename(path.parent().unwrap(), &moved).unwrap();
                std::os::unix::fs::symlink(moved, path.parent().unwrap()).unwrap();
            }
            _ => unreachable!(),
        }
        let before = safe_tree(fixture.domain.config.store_dir());
        let opens = fixture.probe.counts.opens.load(SeqCst);
        *fixture.probe.fail.lock().unwrap() = Some((ComplianceStage::BeforeOpen, 3));
        let result = read_view(
            &fixture.domain.config,
            fixture.domain.clock.as_ref(),
            fixture.probe.as_ref(),
        );
        assert_eq!(
            fixture.probe.counts.opens.load(SeqCst),
            opens + 2,
            "unsafe published wrapper reached open"
        );
        assert_eq!(safe_tree(fixture.domain.config.store_dir()), before);
        assert!(
            matches!(result, Err(Error::Unavailable)),
            "unsafe published record accepted"
        );
    }
}

fn record_owner_hardening() {
    use std::os::unix::fs::PermissionsExt;
    for fault in ["mode", "hardlink", "symlink", "directory", "fifo"] {
        let fixture = RecordsFixture::new();
        drop(fixture.owner());
        let lock = fixture.domain.config.records_lock();
        fs::remove_file(&lock).unwrap();
        let sentinel = fixture.domain.config.store_dir().join("lock-sentinel");
        private_record_file(&sentinel, b"private synthetic sentinel");
        match fault {
            "mode" => {
                private_record_file(&lock, b"");
                fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
            }
            "hardlink" => fs::hard_link(&sentinel, &lock).unwrap(),
            "symlink" => std::os::unix::fs::symlink(&sentinel, &lock).unwrap(),
            "directory" => fs::create_dir(&lock).unwrap(),
            "fifo" => {
                use std::os::unix::ffi::OsStrExt;
                let name = std::ffi::CString::new(lock.as_os_str().as_bytes()).unwrap();
                // # Safety
                // The CString is NUL-terminated and live throughout this pointer-only system call.
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
            _ => panic!("unknown record owner fault"),
        }
        let before = safe_inode_facts(&lock);
        let opens = fixture.probe.counts.opens.load(SeqCst);
        *fixture.probe.fail.lock().unwrap() = Some((ComplianceStage::BeforeOpen, 1));
        let result = fixture.open();
        assert_eq!(
            fixture.probe.counts.opens.load(SeqCst),
            opens,
            "unsafe record opened"
        );
        assert_eq!(safe_inode_facts(&lock), before);
        assert!(
            matches!(result, Err(Error::Unavailable)),
            "unsafe record owner accepted"
        );
    }
    let fixture = RecordsFixture::new();
    let owner = fixture.owner();
    let before = facts(fixture.domain.config.store_dir());
    let second = fixture.open();
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert!(
        matches!(second, Err(Error::Unavailable)),
        "second record owner accepted"
    );
    drop(owner);
    drop(fixture.owner());
}

fn safe_inode_facts(path: &Path) -> (u64, u64, u32, Option<PathBuf>, Vec<u8>) {
    let metadata = fs::symlink_metadata(path).unwrap();
    let link = metadata
        .file_type()
        .is_symlink()
        .then(|| fs::read_link(path).unwrap());
    let bytes = if metadata.is_file() {
        fs::read(path).unwrap()
    } else {
        Vec::new()
    };
    (
        metadata.ino(),
        metadata.nlink(),
        metadata.mode(),
        link,
        bytes,
    )
}

type InodeFacts = (u64, u64, u32, Option<PathBuf>, Vec<u8>);

fn safe_tree(root: &Path) -> BTreeMap<PathBuf, InodeFacts> {
    let mut result = BTreeMap::new();
    let Ok(metadata) = fs::symlink_metadata(root) else {
        return result;
    };
    result.insert(root.to_owned(), safe_inode_facts(root));
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        for entry in fs::read_dir(root).unwrap() {
            result.extend(safe_tree(&entry.unwrap().path()));
        }
    }
    result
}

fn encoded_index(row: &Value, signed: bool) -> Vec<u8> {
    let fields = [
        "format_version",
        "sequence",
        "previous_hash",
        "at",
        "event",
        "actor",
        "record_ref",
        "record_kind",
        "commitment",
        "intent_sequence",
        "quarantined_bytes",
        "quarantine_hash",
        "hash",
    ];
    let count = if signed { 13 } else { 12 };
    let entries = fields[..count]
        .iter()
        .map(|field| {
            format!(
                "\"{field}\":{}",
                serde_json::to_string(&row[field]).unwrap()
            )
        })
        .collect::<Vec<_>>();
    format!(
        "{{{}}}{}",
        entries.join(","),
        if signed { "\n" } else { "" }
    )
    .into_bytes()
}

fn rehash_index(row: &mut Value) {
    let mut bytes = b"AVA619-RECORD-INDEX-v1\0".to_vec();
    bytes.extend(encoded_index(row, false));
    row["hash"] = json!(support::digest(&bytes));
}

fn independent_index_vector() {
    use stract::compliance::record_index::RecordIndexRow;
    let mut value = json!({"format_version":1,"sequence":1,"previous_hash":"0".repeat(64),
        "at":1789732800i64,"event":"record_intent","actor":"synthetic.operator",
        "record_ref":"assessment.icra:1","record_kind":"icra","commitment":"42".repeat(32),
        "intent_sequence":0,"quarantined_bytes":0,"quarantine_hash":"","hash":""});
    rehash_index(&mut value);
    let expected = [
        "69062039", "869f1d9c", "80ee208a", "c886a36d", "f9e937aa", "d448cc35", "78d30901",
        "c94cdcae",
    ]
    .concat();
    assert_eq!(value["hash"], expected, "independent index vector mismatch");
    let row: RecordIndexRow = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(
        row.computed_hash().unwrap(),
        expected,
        "ordered index hash vector mismatch"
    );
    assert_eq!(row.bytes().unwrap(), encoded_index(&value, true));
}

fn verify_salted_wrapper(fixture: &RecordsFixture, name: &str) {
    let bytes = fs::read(fixture.path(name)).unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let salt = value["salt"]
        .as_str()
        .unwrap()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(salt.len(), 32);
    let canonical = serde_json::to_vec(&value["record"]).unwrap();
    let mut input = b"AVA619-RECORD-v1\0".to_vec();
    input.extend(salt);
    input.extend((canonical.len() as u64).to_be_bytes());
    input.extend(canonical);
    assert_eq!(
        value["commitment"],
        support::digest(&input),
        "salted record vector mismatch"
    );
    let mut complete = serde_json::to_vec(&value).unwrap();
    complete.push(b'\n');
    assert_eq!(complete, bytes, "wrapper canonical byte vector mismatch");
}

fn populated_records() -> RecordsFixture {
    let fixture = RecordsFixture::new();
    let mut owner = fixture.owner();
    add_record(&mut owner, record_input("icra"));
    add_record(&mut owner, record_input("caa"));
    drop(owner);
    fixture
}

fn independent_salts() {
    let first = RecordsFixture::new();
    let second = RecordsFixture::new();
    let name = "assessment.icra/0000000001.json";
    for fixture in [&first, &second] {
        add_record(&mut fixture.owner(), record_input("icra"));
        assert_eq!(fixture.draws(), 1);
        verify_salted_wrapper(fixture, name);
    }
    let left: Value = serde_json::from_slice(&fs::read(first.path(name)).unwrap()).unwrap();
    let right: Value = serde_json::from_slice(&fs::read(second.path(name)).unwrap()).unwrap();
    assert_eq!(left["record"], right["record"]);
    assert!(
        left["salt"] != right["salt"],
        "independent record salts were equal"
    );
    assert!(
        left["commitment"] != right["commitment"],
        "equal records with different salts had equal commitments"
    );
}

/// Verifies independent index/wrapper vectors, committed corruption and recoverable suffixes.
pub fn index_contract() {
    independent_index_vector();
    let fixture = populated_records();
    verify_salted_wrapper(&fixture, "assessment.icra/0000000001.json");
    verify_salted_wrapper(&fixture, "assessment.caa/0000000001.json");
    independent_salts();
    for fault in [
        "previous",
        "own",
        "sequence",
        "checkpoint",
        "whitespace",
        "future",
        "backwards",
        "pair",
        "metadata",
        "unknown",
        "float",
        "short",
        "missing",
        "committed-torn",
        "changed-record",
        "changed-salt",
    ] {
        corrupt_record_index(fault);
    }
    for interrupted in [false, true] {
        recover_index_tail(interrupted);
    }
    adopt_complete_suffix();
    record_temp_families();
    unsafe_record_temps();
}

fn unsafe_record_temps() {
    use std::os::unix::fs::PermissionsExt;
    for family in ["record-head", "record-recovery"] {
        for fault in ["symlink", "mode", "hardlink", "directory", "fifo"] {
            let fixture = populated_records();
            let path = fixture.path(&format!("{family}.1.0.tmp"));
            let sentinel = fixture.path("private-sentinel");
            private_record_file(&sentinel, b"private synthetic sentinel");
            match fault {
                "symlink" => std::os::unix::fs::symlink(&sentinel, &path).unwrap(),
                "hardlink" => fs::hard_link(&sentinel, &path).unwrap(),
                "mode" => {
                    private_record_file(&path, b"unsafe mode");
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                }
                "directory" => fs::create_dir(&path).unwrap(),
                "fifo" => {
                    use std::os::unix::ffi::OsStrExt;
                    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                    // # Safety
                    // The NUL-terminated name is live for this pointer-only system call.
                    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                }
                _ => panic!("unknown temporary-file fault"),
            }
            let before = safe_inode_facts(&path);
            let retained = safe_inode_facts(&sentinel);
            let index = fs::read(fixture.path("index.jsonl")).unwrap();
            let opens = fixture.probe.counts.opens.load(SeqCst);
            // The first open takes the owner; a second would reach the unsafe temp.
            *fixture.probe.fail.lock().unwrap() = Some((ComplianceStage::BeforeOpen, 2));
            let result = fixture.open();
            assert_eq!(fixture.probe.counts.opens.load(SeqCst), opens + 1);
            assert_eq!(safe_inode_facts(&path), before);
            assert_eq!(safe_inode_facts(&sentinel), retained);
            assert_eq!(fs::read(fixture.path("index.jsonl")).unwrap(), index);
            assert!(
                matches!(result, Err(Error::Unavailable)),
                "unsafe record temp accepted"
            );
        }
    }
}

fn corrupt_record_index(fault: &str) {
    let fixture = populated_records();
    if matches!(fault, "changed-record" | "changed-salt") {
        let path = fixture.path("assessment.icra/0000000001.json");
        let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        if fault == "changed-record" {
            value["record"]["body"]["reasoning"] = json!("Changed private synthetic reasoning");
        } else {
            value["salt"] = json!("43".repeat(32));
        }
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        fs::write(path, bytes).unwrap();
    } else {
        index_fault(&fixture, fault);
    }
    let before = facts(fixture.domain.config.store_dir());
    let draws = fixture.draws();
    let writes = fixture.probe.writes.load(SeqCst);
    let view = read_view(
        &fixture.domain.config,
        fixture.domain.clock.as_ref(),
        fixture.probe.as_ref(),
    );
    assert_eq!(fixture.draws(), draws);
    assert_eq!(fixture.probe.writes.load(SeqCst), writes);
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert!(
        matches!(view, Err(Error::Unavailable)),
        "invalid record index accepted by reader: {fault}"
    );
    let owner = fixture.open();
    assert_eq!(fixture.draws(), draws);
    assert_eq!(
        facts(fixture.domain.config.store_dir()),
        before,
        "committed corruption repaired"
    );
    assert!(
        matches!(owner, Err(Error::Unavailable)),
        "invalid record index accepted by writer: {fault}"
    );
}

fn index_fault(fixture: &RecordsFixture, fault: &str) {
    let mut rows = index_rows(fixture);
    match fault {
        "previous" => rows[0]["previous_hash"] = json!(support::digest(b"foreign predecessor")),
        "sequence" => {
            rows[0]["sequence"] = json!(10);
            rows[1]["intent_sequence"] = json!(10);
        }
        "future" => rows[3]["at"] = json!(RECORD_TIME + 1),
        "backwards" => rows[3]["at"] = json!(RECORD_TIME - 1),
        "metadata" => {
            rows[0]["actor"] = json!("");
            rows[1]["actor"] = json!("");
        }
        "pair" => {
            rows.swap(1, 2);
            for (at, row) in rows.iter_mut().enumerate() {
                row["sequence"] = json!(at + 1);
            }
            rows[2]["intent_sequence"] = json!(2);
            rows[3]["intent_sequence"] = json!(1);
        }
        _ => {}
    }
    for at in 0..rows.len() {
        if at > 0 {
            rows[at]["previous_hash"] = rows[at - 1]["hash"].clone();
        }
        rehash_index(&mut rows[at]);
        if fault == "own" && at == 0 {
            rows[at]["hash"] = json!(support::digest(b"foreign digest"));
        }
    }
    let mut bytes = rows
        .iter()
        .enumerate()
        .flat_map(|(at, row)| {
            let mut line = encoded_index(row, true);
            if at == 0 {
                match fault {
                    "whitespace" => {
                        line.insert(line.len() - 1, b' ');
                    }
                    "unknown" => {
                        line.truncate(line.len() - 2);
                        line.extend(b",\"unknown\":0}\n");
                    }
                    "float" => {
                        line = String::from_utf8(line)
                            .unwrap()
                            .replacen("\"sequence\":1", "\"sequence\":1.5", 1)
                            .into_bytes()
                    }
                    _ => {}
                }
            }
            line
        })
        .collect::<Vec<_>>();
    let head = support::checkpoint(rows.last().unwrap(), bytes.len());
    fs::write(fixture.path("head.json"), &head).unwrap();
    if fault == "checkpoint" {
        let mut last = rows.last().unwrap().clone();
        last["hash"] = json!(support::digest(b"foreign head"));
        fs::write(
            fixture.path("head.json"),
            support::checkpoint(&last, bytes.len()),
        )
        .unwrap();
    }
    if matches!(fault, "short" | "committed-torn") {
        bytes.truncate(bytes.len() - 9);
    }
    fs::write(fixture.path("index.jsonl"), bytes).unwrap();
    if fault == "missing" {
        fs::remove_file(fixture.path("index.jsonl")).unwrap();
    }
}

fn recover_index_tail(interrupted: bool) {
    use std::io::Write;
    let fixture = populated_records();
    let committed = fs::read(fixture.path("index.jsonl")).unwrap();
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(fixture.path("index.jsonl"))
        .unwrap();
    file.write_all(b"{torn synthetic row").unwrap();
    drop(file);
    let before = facts(fixture.domain.config.store_dir());
    let view = read_view(
        &fixture.domain.config,
        fixture.domain.clock.as_ref(),
        fixture.probe.as_ref(),
    );
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert!(
        view.is_ok(),
        "committed record prefix refused a torn suffix"
    );
    if interrupted {
        *fixture.probe.fail.lock().unwrap() = Some((ComplianceStage::AfterJournalSync, 1));
        let result = fixture.open();
        assert!(fixture.probe.fail.lock().unwrap().is_none());
        assert!(
            matches!(result, Err(Error::Unavailable)),
            "failed recovery sync acknowledged"
        );
    }
    let recovered = fixture.open();
    let raw = fs::read_to_string(fixture.path("index.jsonl")).unwrap();
    let count = raw.matches("\"event\":\"tail_recovered\"").count();
    assert!(count <= 1, "duplicate tail recovery rows");
    assert!(fs::read(fixture.path("index.jsonl"))
        .unwrap()
        .starts_with(&committed));
    assert!(
        recovered.is_ok(),
        "valid uncommitted record tail recovery refused"
    );
    let rows = index_rows(&fixture);
    assert_eq!(count, 1);
    assert_eq!(rows[4]["quarantined_bytes"], 19);
    assert_eq!(
        rows[4]["quarantine_hash"],
        support::digest(b"{torn synthetic row")
    );
    drop(recovered);
    let after = facts(fixture.domain.config.store_dir());
    let again = fixture.open();
    assert_eq!(facts(fixture.domain.config.store_dir()), after);
    assert!(again.is_ok(), "repeated tail recovery refused");
}

fn adopt_complete_suffix() {
    let fixture = RecordsFixture::new();
    let mut owner = fixture.owner();
    add_record(&mut owner, record_input("icra"));
    let head = fs::read(fixture.path("head.json")).unwrap();
    add_record(&mut owner, record_input("caa"));
    drop(owner);
    fs::write(fixture.path("head.json"), head).unwrap();
    let before = facts(fixture.domain.config.store_dir());
    let view = read_view(
        &fixture.domain.config,
        fixture.domain.clock.as_ref(),
        fixture.probe.as_ref(),
    );
    assert_eq!(facts(fixture.domain.config.store_dir()), before);
    assert!(
        view.is_ok(),
        "published prefix with complete suffix refused"
    );
    assert_eq!(view.unwrap().records().len(), 1);
    let recovered = fixture.open();
    assert_eq!(addition_counts(&fixture), (2, 2, 0));
    assert!(recovered.is_ok(), "valid complete record suffix refused");
    assert_eq!(recovered.unwrap().view().records().len(), 2);
}

fn record_temp_families() {
    for family in ["record-head", "record-recovery"] {
        let fixture = populated_records();
        let candidates = (0..256)
            .map(|counter| fixture.path(&format!("{family}.{}.{counter}.tmp", std::process::id())))
            .collect::<Vec<_>>();
        for path in &candidates {
            private_record_file(path, b"synthetic staging bytes");
        }
        let other = fixture.path(&format!("{family}.4294967295.0.tmp"));
        private_record_file(&other, b"other excluded writer");
        let sentinels = [
            format!("{family}.0.0.tmp"),
            format!("{family}.01.0.tmp"),
            format!("{family}.1.00.tmp"),
            "keep.tmp".into(),
        ];
        for name in &sentinels {
            private_record_file(&fixture.path(name), b"private sentinel");
        }
        let result = fixture.open();
        assert!(
            candidates.iter().all(|path| !path.exists()),
            "owned record temp survived open"
        );
        assert!(!other.exists());
        for name in &sentinels {
            assert_eq!(fs::read(fixture.path(name)).unwrap(), b"private sentinel");
        }
        assert!(result.is_ok(), "safe record temp sweep refused");
        let mut owner = result.unwrap();
        let persisted = owner.add(typed(record_input("cra")), "synthetic.operator");
        assert!(persisted.is_ok(), "record persistence after sweep refused");
    }
}

fn schema_text_bounds(fixture: &DomainFixture) {
    for (path, maximum) in [
        ("/id", 64),
        ("/body/service", 128),
        ("/body/author", 128),
        ("/body/responsible_person", 128),
        ("/body/approver", 128),
        ("/body/governance_reference", 128),
        ("/body/priority_catalog_version", 64),
        ("/body/questionnaire_outcomes/0/id", 64),
        ("/body/questionnaire_outcomes/0/answer", 2048),
        ("/body/risk_factors/0", 2048),
        ("/body/existing_controls/0/description", 2048),
        ("/body/existing_controls/0/effect", 2048),
        ("/body/priority_risks/0/explanation", 2048),
        ("/body/evidence/0/description", 2048),
        ("/body/evidence/0/source", 2048),
        ("/body/reasoning", 4096),
        ("/body/other_illegal_reasoning", 4096),
        ("/body/keep_up_to_date_policy", 4096),
    ] {
        for (length, valid) in [(0, false), (1, true), (maximum, true), (maximum + 1, false)] {
            let mut value = record_input("icra");
            *value.pointer_mut(path).unwrap() = json!("x".repeat(length));
            if valid {
                schema_accepted(value, fixture);
            } else {
                schema_refused(value, fixture);
            }
        }
    }
    for (value, valid) in [("é".repeat(64), true), ("é".repeat(65), false)] {
        let mut record = record_input("icra");
        record["body"]["author"] = json!(value);
        if valid {
            schema_accepted(record, fixture);
        } else {
            schema_refused(record, fixture);
        }
    }
    for (path, text, valid) in [
        ("/body/author", "bad\nlabel", false),
        ("/body/reasoning", "line\n\tline", true),
        ("/body/reasoning", "bad\rtext", false),
        ("/id", "Upper", false),
        ("/id", ".leading", false),
    ] {
        let mut value = record_input("icra");
        *value.pointer_mut(path).unwrap() = json!(text);
        if valid {
            schema_accepted(value, fixture);
        } else {
            schema_refused(value, fixture);
        }
    }
}

fn schema_dates_and_identity(fixture: &DomainFixture) {
    for id in [
        "index",
        "index.jsonl",
        "head",
        "head.json",
        "record-owned",
        "quarantine-owned",
        "record-probe",
        "quarantine-probe",
    ] {
        let mut value = record_input("icra");
        value["id"] = json!(id);
        assert_eq!(
            schema_result(value, fixture).map(|_| ()),
            Err(Error::InvalidInput),
            "reserved record id accepted: {id}"
        );
    }
    for (path, bad) in [
        ("/version", json!(0)),
        ("/format_version", json!(2)),
        ("/completed_at", json!(RECORD_TIME + 1)),
        ("/body/date_completed", json!(i64::MAX)),
        ("/body/last_reviewed_at", json!(RECORD_TIME - 1)),
        (
            "/body/review_update_dates",
            json!([RECORD_TIME, RECORD_TIME]),
        ),
        ("/body/priority_risks/1/kind", json!("P01")),
        ("/body/priority_risks/0/evidence_ids", json!(["missing"])),
        ("/kind", json!("caa")),
        ("/body/access", json!({})),
        ("/supersedes", json!("assessment.icra:01")),
        ("/supersedes", json!("assessment.icra:0")),
    ] {
        let mut value = record_input("icra");
        *value.pointer_mut(path).unwrap() = bad;
        schema_refused(value, fixture);
    }
    let mut value = record_input("cra");
    value["body"]["children"]["classes"][1]["class"] = json!("primary_priority");
    schema_refused(value, fixture);
    let mut value = record_input("caa");
    value["body"]["access"]["concluded_at"] = json!(RECORD_TIME + 1);
    schema_refused(value, fixture);
}

fn schema_vector_bounds(fixture: &DomainFixture) {
    for (path, optional) in [
        ("risk_factors", false),
        ("additional_characteristics", true),
        ("questionnaire_outcomes", false),
        ("existing_controls", false),
        ("evidence", false),
    ] {
        for (length, valid) in [(0, optional), (1, true), (64, true), (65, false)] {
            let mut value = record_input("icra");
            let prototype = if path == "additional_characteristics" {
                json!("Synthetic extra")
            } else {
                value["body"][path][0].clone()
            };
            let values = (0..length)
                .map(|at| {
                    let mut item = prototype.clone();
                    if at != 0 {
                        if item.is_string() {
                            item = json!(format!("item.{at}"));
                        } else if path == "existing_controls" {
                            item["description"] = json!(format!("Control {at}"));
                        } else {
                            item["id"] = json!(format!("item.{at}"));
                        }
                    }
                    item
                })
                .collect::<Vec<_>>();
            value["body"][path] = json!(values);
            if valid {
                schema_accepted(value, fixture);
            } else {
                schema_refused(value, fixture);
            }
        }
    }
    for (length, valid) in [(0, false), (1, true), (32, true), (33, false)] {
        let mut value = record_input("icra");
        let start = RECORD_TIME - i64::from(length.max(1)) + 1;
        value["completed_at"] = json!(start);
        value["body"]["date_completed"] = json!(start);
        value["body"]["review_update_dates"] = json!((0..length)
            .map(|at| start + i64::from(at))
            .collect::<Vec<_>>());
        if valid {
            schema_accepted(value, fixture);
        } else {
            schema_refused(value, fixture);
        }
    }
}

fn schema_approved_control() {
    let mut fixture = DomainFixture::new();
    let mut settings = fixture.config.settings().clone();
    settings.priority_catalog_version = Some("catalog.synthetic".into());
    settings.priority_catalog_source = Some("Synthetic catalog source".into());
    settings.priority_kind_labels = std::array::from_fn(|at| Some(format!("Synthetic kind {at}")));
    fixture.config = settings
        .validate(
            &fixture
                .config
                .store_dir()
                .parent()
                .unwrap()
                .join("suppression.json"),
        )
        .unwrap();
    for kind in ["icra", "caa", "cra"] {
        let mut value = record_input(kind);
        value["body"]["approval_status"] = json!("approved");
        value["body"]["approved_at"] = json!(RECORD_TIME);
        value["body"]["risk_profiles_consulted"] = json!("yes");
        value["body"]["governance_reporting"] = json!("yes");
        value["body"]["priority_catalog_version"] = json!("catalog.synthetic");
        schema_accepted(value.clone(), &fixture);
        for (field, bad) in [
            ("approved_at", Value::Null),
            ("risk_profiles_consulted", json!("no")),
            ("governance_reporting", json!("no")),
            ("author", json!("[FOUNDER REQUIRED: named author]")),
        ] {
            let mut changed = value.clone();
            changed["body"][field] = bad;
            schema_refused(changed, &fixture);
        }
        let mut stale = value.clone();
        stale["body"]["priority_catalog_version"] = json!("pending");
        schema_accepted(stale.clone(), &fixture);
        let before = facts(fixture.config.store_dir());
        let result = stract::compliance::records::validate_candidate(
            &fixture.config,
            &Default::default(),
            &typed(stale),
            RECORD_TIME,
        );
        assert_eq!(facts(fixture.config.store_dir()), before);
        assert_eq!(
            result,
            Err(Error::InvalidInput),
            "stale approved catalog admitted"
        );
    }
}

fn record_config_caps(fixture: &DomainFixture) {
    for (file, total, valid) in [
        (4095, 1048576, false),
        (4096, 1048576, true),
        (1048576, 2187388, true),
        (1048577, 2187390, false),
        (1048576, 2187387, false),
        (4096, 1048575, false),
        (4096, 2684354560, true),
        (4096, 2684354561, false),
    ] {
        let mut settings = fixture.config.settings().clone();
        settings.max_record_bytes = file;
        settings.max_records_bytes = total;
        let before = facts(fixture.config.store_dir());
        let result = settings.validate(
            &fixture
                .config
                .store_dir()
                .parent()
                .unwrap()
                .join("suppression.json"),
        );
        assert_eq!(facts(fixture.config.store_dir()), before);
        if valid {
            assert!(result.is_ok(), "valid record capacity refused");
        } else {
            assert!(
                matches!(result, Err(Error::InvalidInput)),
                "invalid record cap accepted"
            );
        }
    }
}

fn record_capacity_equality() {
    use stract::compliance::{bounds::BoundKey, record_index, records};
    assert_eq!(record_index::initial_record_bytes().unwrap(), 124);
    assert_eq!(3 * BoundKey::JournalRow.spec().max, 24576);
    assert_eq!(BoundKey::ReservedJournalBytes.spec().min, 65536);
    assert_eq!(records::record_reservation_bytes(124, 1048576), Ok(2187388));
    assert_eq!(
        records::record_reservation_bytes(u64::MAX, 1),
        Err(Error::Capacity)
    );
    assert_eq!(
        records::record_reservation_bytes(0, u64::MAX),
        Err(Error::Capacity)
    );
    for size in [524288, 524289] {
        let mut fixture = RecordsFixture::new();
        configured_record_caps(&mut fixture, 524288, 1138812);
        let input = sized_record(size);
        let mut owner = fixture.owner();
        if size == 524289 {
            assert_addition_refused(
                &fixture,
                &mut owner,
                input,
                Error::Capacity,
                &format!("configured equality wrapper bytes={size}"),
            );
        } else {
            add_record(&mut owner, input);
            assert_eq!(
                fs::metadata(fixture.path("assessment.icra/0000000001.json"))
                    .unwrap()
                    .len(),
                size,
                "exact reservation failed to admit its promised wrapper"
            );
        }
    }
}

fn record_path_overlaps() {
    let fixture = DomainFixture::new();
    let suppression = fixture
        .config
        .store_dir()
        .parent()
        .unwrap()
        .join("suppression.json");
    for (path, expected) in [
        (
            fixture.config.journal_dir().join("nested-records"),
            Err(Error::InvalidInput),
        ),
        (
            fixture.config.rules_dir().join("nested-records"),
            Err(Error::InvalidInput),
        ),
        (
            fixture.config.store_dir().join("journal.lock"),
            Err(Error::InvalidInput),
        ),
        (fixture.config.store_dir().join("sibling-records"), Ok(())),
    ] {
        let mut settings = fixture.config.settings().clone();
        settings.records_dir = Some(path);
        let before = safe_tree(fixture.config.store_dir().parent().unwrap());
        let result = settings.validate(&suppression);
        assert_eq!(
            safe_tree(fixture.config.store_dir().parent().unwrap()),
            before
        );
        assert_eq!(
            result.map(|_| ()),
            expected,
            "overlapping record path accepted"
        );
    }
}

fn manifest_identity_admission() {
    let fixture = approved_store(false, false, false);
    let mut owner = fixture.owner();
    let mut other = approved_record("manifest");
    other["id"] = json!("manifest.other");
    assert_addition_refused(
        &fixture,
        &mut owner,
        other,
        Error::InvalidInput,
        "second manifest identity",
    );
    add_record(&mut owner, next_version(approved_record("manifest"), 2));
    drop(owner);
    startup_result(
        &fixture,
        &api_config(&fixture, true),
        Ok(()),
        "same identity next version",
    );
}

/// Pins the exact vocabulary and each alternative's complete reasons independently.
pub fn measures_contract() {
    let fixture = DomainFixture::new();
    let value = record_input("measures");
    let accepted = schema_accepted(value.clone(), &fixture);
    let encoded = serde_json::to_value(accepted).unwrap();
    assert!(encoded["body"]["rows"].is_array());
    assert_eq!(encoded["body"]["rows"].as_array().unwrap().len(), 28);
    let voluntary = [
        "ICS C3", "ICS D3", "ICS D4", "ICS D5", "PCS D4", "PCS D5", "PCS D6",
    ];
    for (at, code) in measure_codes().iter().enumerate() {
        assert_eq!(encoded["body"]["rows"][at]["code"], *code);
        assert_eq!(
            encoded["body"]["rows"][at]["adoption"],
            if voluntary.contains(code) {
                "voluntary_pending_legal_review"
            } else {
                "required"
            },
            "{code}: final adoption wire value"
        );
        let mut removed = value.clone();
        removed["body"]["rows"].as_array_mut().unwrap().remove(at);
        schema_refused(removed, &fixture);
        let mut duplicate = value.clone();
        duplicate["body"]["rows"][at] = value["body"]["rows"][(at + 1) % 28].clone();
        schema_refused(duplicate, &fixture);
        let mut adoption = value.clone();
        adoption["body"]["rows"][at]["adoption"] =
            if value["body"]["rows"][at]["adoption"] == "required" {
                json!("voluntary_pending_legal_review")
            } else {
                json!("required")
            };
        schema_refused(adoption, &fixture);
    }
    alternative_cases(&value, &fixture);
}

fn alternative_cases(original: &Value, fixture: &DomainFixture) {
    let mut value = original.clone();
    value["body"]["rows"][0]["disposition"] = json!("alternative");
    value["body"]["rows"][0]["alternative"] = json!({"not_taken":["ICS A2"],
        "measure":"Synthetic alternative","compliance_reasoning":"Synthetic compliance",
        "freedom_of_expression_and_privacy":"Synthetic rights assessment"});
    schema_accepted(value.clone(), fixture);
    let mut taken = value.clone();
    taken["body"]["rows"][0]["disposition"] = json!("taken");
    schema_refused(taken, fixture);
    for (field, bad) in [
        ("not_taken", json!(["PCS A2"])),
        ("not_taken", json!(["ICS A2", "ICS A2"])),
        ("measure", json!("")),
        ("compliance_reasoning", json!("")),
        ("freedom_of_expression_and_privacy", json!("")),
    ] {
        let mut changed = value.clone();
        changed["body"]["rows"][0]["alternative"][field] = bad;
        schema_refused(changed, fixture);
    }
    let mut unknown = original.clone();
    unknown["body"]["rows"][0]["code"] = json!("ICS unknown");
    schema_refused(unknown, fixture);
    object_shape_cases(&value, fixture);
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct Facts {
    inode: u64,
    links: u64,
    mode: u32,
    bytes: Vec<u8>,
}

fn facts(root: &Path) -> BTreeMap<PathBuf, Facts> {
    let mut result = BTreeMap::new();
    let Ok(metadata) = fs::symlink_metadata(root) else {
        return result;
    };
    assert!(!metadata.file_type().is_symlink());
    let bytes = if metadata.is_file() {
        fs::read(root).unwrap()
    } else {
        Vec::new()
    };
    result.insert(
        root.to_owned(),
        Facts {
            inode: metadata.ino(),
            links: metadata.nlink(),
            mode: metadata.mode(),
            bytes,
        },
    );
    if metadata.is_dir() {
        for entry in fs::read_dir(root).unwrap() {
            result.extend(facts(&entry.unwrap().path()));
        }
    }
    result
}

fn observed(fixture: &DomainFixture) -> (Result<CommittedJournal>, Arc<FileCounts>) {
    let counts = Arc::new(FileCounts::default());
    let before = facts(fixture.config.store_dir());
    let result = read_committed(&fixture.config, fixture.clock.as_ref(), counts.as_ref());
    assert_eq!(counts.writes.load(SeqCst), 0, "snapshot performed a write");
    assert_eq!(
        facts(fixture.config.store_dir()),
        before,
        "snapshot changed filesystem facts"
    );
    (result, counts)
}

fn accepted(result: Result<CommittedJournal>) -> CommittedJournal {
    assert!(result.is_ok(), "valid committed snapshot refused");
    result.unwrap()
}

fn refused(fixture: &DomainFixture) {
    let (result, _) = observed(fixture);
    assert!(
        matches!(result, Err(Error::Unavailable)),
        "invalid committed snapshot accepted"
    );
}

/// Exercises origin, corruption, live append, monotonic checkpoints and purged metadata.
pub fn snapshot_contract() {
    metadata_valid_illegal_close();
    origin_and_missing();
    static_suffixes();
    for fault in [
        "missing-head",
        "missing-events",
        "short",
        "byte",
        "head-hash",
        "head-sequence",
        "head-length",
        "head-unknown",
        "head-version",
        "head-cap",
        "sequence",
        "previous",
        "own-hash",
        "future",
        "backwards",
        "metadata",
        "whitespace",
        "row-unknown",
        "float",
    ] {
        corrupted_prefix(fault);
    }
    for change in [
        "advance-once",
        "advance-twice",
        "regress",
        "foreign",
        "unparseable",
    ] {
        moving_heads(change);
    }
    live_append(ComplianceStage::AfterJournalSync, 0);
    live_append(ComplianceStage::AfterIntentSync, 2);
    purged_projection();
    invalid_lifecycle();
}

fn metadata_valid_illegal_close() {
    let fixture = DomainFixture::new();
    drop(fixture.journal());
    let mut ticket = MetricTicket::new(401, "illegal_content", RECORD_TIME);
    ticket.row("closed", "closed", 0);
    let mut previous = "0".repeat(64);
    let mut bytes = Vec::new();
    for (at, row) in ticket.rows.iter_mut().enumerate() {
        row["sequence"] = json!(at + 1);
        row["previous_hash"] = json!(previous);
        support::rehash(row);
        previous = row["hash"].as_str().unwrap().into();
        bytes.extend(support::encoded_row(row, true));
    }
    fs::write(fixture.path("events.jsonl"), &bytes).unwrap();
    fs::write(
        fixture.path("head.json"),
        support::checkpoint(ticket.rows.last().unwrap(), bytes.len()),
    )
    .unwrap();
    let metadata = fixture.journal();
    assert_eq!(
        metadata.rows().len(),
        2,
        "illegal-close fixture metadata and chain"
    );
    drop(metadata);
    let (result, counts) = observed(&fixture);
    assert_eq!(counts.writes.load(SeqCst), 0);
    assert_eq!(
        result.as_ref().map(|_| ()).map_err(|error| *error),
        Err(Error::Unavailable),
        "illegal lifecycle accepted by read-only snapshot"
    );
    genuine_closed_complaint();
}

fn genuine_closed_complaint() {
    let fixture = DomainFixture::new();
    let store = fixture.store();
    let runtime = support::runtime();
    let admitted = runtime
        .block_on(store.admit(
            support::intake(IntakeKind::DataProtectionComplaint),
            Arc::new(()),
        ))
        .unwrap();
    let id = admitted.ticket.id;
    runtime
        .block_on(store.administer(
            id.clone(),
            "reviewer".into(),
            AdministrationEvent::Decision {
                decision: Decision::Refused {
                    reasons: "Synthetic complaint decision".into(),
                    delivery: support::delivery(),
                },
            },
            Arc::new(()),
        ))
        .unwrap();
    runtime
        .block_on(store.administer(
            id.clone(),
            "reviewer".into(),
            AdministrationEvent::Closure {
                reasons: "Synthetic complaint closure".into(),
            },
            Arc::new(()),
        ))
        .unwrap();
    let (result, counts) = observed(&fixture);
    assert_eq!(counts.writes.load(SeqCst), 0);
    let view = accepted(result);
    assert_eq!(view.tickets()[&id].state.as_str(), "closed");
    runtime.block_on(store.shutdown());
}

fn origin_and_missing() {
    let fixture = DomainFixture::new();
    refused(&fixture);
    let journal = fixture.journal();
    let (result, counts) = observed(&fixture);
    assert_eq!(
        counts.opens.load(SeqCst),
        3,
        "reader opened more than head/events/head"
    );
    let view = accepted(result);
    assert_eq!(view.sequence, 0);
    assert_eq!(view.byte_length, 0);
    assert_eq!(view.hash, "0".repeat(64));
    assert_eq!(view.observed_at, 1789732800);
    assert!(view.rows.is_empty());
    assert!(view.tickets().is_empty());
    drop(journal);
    let mut head = support::read_json(&fixture.path("head.json"));
    head["hash"] = json!(support::digest(b"non-origin"));
    write_head(&fixture, &head);
    refused(&fixture);
}

fn write_head(fixture: &DomainFixture, head: &Value) {
    // This is the test writer; values use the checkpoint's independent literal field order.
    let bytes = format!(
        "{{\"format_version\":{},\"sequence\":{},\"hash\":{},\"byte_length\":{}}}\n",
        head["format_version"], head["sequence"], head["hash"], head["byte_length"],
    );
    fs::write(fixture.path("head.json"), bytes).unwrap();
}

fn static_suffixes() {
    for torn in [false, true] {
        let fixture = DomainFixture::new();
        let mut journal = fixture.journal();
        fixture.list_row(&mut journal);
        let head = fs::read(fixture.path("head.json")).unwrap();
        let prefix = fs::read(fixture.path("events.jsonl")).unwrap();
        fixture.list_row(&mut journal);
        fs::write(fixture.path("head.json"), &head).unwrap();
        if torn {
            fs::write(
                fixture.path("events.jsonl"),
                [&prefix[..], b"{uncommitted"].concat(),
            )
            .unwrap();
        }
        let (result, counts) = observed(&fixture);
        assert!(
            counts.opens.load(SeqCst) <= 3,
            "static snapshot exceeded its read budget"
        );
        let view = accepted(result);
        assert_eq!(view.sequence, 1);
        assert_eq!(view.rows.len(), 1);
        assert_eq!(view.byte_length, prefix.len() as u64);
        assert_eq!(view.hash, journal.rows()[0].hash);
    }
}

fn corrupted_prefix(fault: &str) {
    let fixture = DomainFixture::new();
    let mut journal = fixture.journal();
    fixture.list_row(&mut journal);
    fixture.list_row(&mut journal);
    let mut bytes = fs::read(fixture.path("events.jsonl")).unwrap();
    let mut head = support::read_json(&fixture.path("head.json"));
    match fault {
        "missing-head" => fs::remove_file(fixture.path("head.json")).unwrap(),
        "missing-events" => fs::remove_file(fixture.path("events.jsonl")).unwrap(),
        "short" => {
            bytes.pop();
            fs::write(fixture.path("events.jsonl"), bytes).unwrap();
        }
        "byte" => {
            bytes[0] = b'[';
            fs::write(fixture.path("events.jsonl"), bytes).unwrap();
        }
        "head-hash" => {
            head["hash"] = json!(support::digest(b"foreign-head"));
            write_head(&fixture, &head);
        }
        "head-sequence" => {
            head["sequence"] = json!(3);
            write_head(&fixture, &head);
        }
        "head-length" => {
            head["byte_length"] = json!(1);
            write_head(&fixture, &head);
        }
        "head-version" => {
            head["format_version"] = json!(2);
            write_head(&fixture, &head);
        }
        "head-cap" => {
            head["byte_length"] = json!(fixture.config.settings().max_journal_bytes + 1);
            write_head(&fixture, &head);
        }
        "head-unknown" => {
            head["unknown"] = json!(1);
            support::write_json(&fixture.path("head.json"), &head);
        }
        _ => corrupt_rows(&fixture, fault),
    }
    refused(&fixture);
}

fn corrupt_rows(fixture: &DomainFixture, fault: &str) {
    let bytes = fs::read(fixture.path("events.jsonl")).unwrap();
    let mut rows = bytes
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    let row = &mut rows[1];
    match fault {
        "sequence" => row["sequence"] = json!(3),
        "previous" => row["previous_hash"] = json!(support::digest(b"wrong-link")),
        "future" => row["at"] = json!(1789732801i64),
        "backwards" => row["at"] = json!(1789732799i64),
        "metadata" => row["actor"] = json!("system.recovery"),
        "own-hash" | "whitespace" | "row-unknown" | "float" => {}
        _ => panic!("unknown row fault"),
    }
    support::rehash(row);
    if fault == "own-hash" {
        row["hash"] = json!(support::digest(b"wrong-own-hash"));
    }
    let mut second = support::encoded_row(row, true);
    match fault {
        "whitespace" => second.insert(0, b' '),
        "row-unknown" => {
            second.truncate(second.len() - 2);
            second.extend_from_slice(b",\"unknown\":1}\n");
        }
        "float" => {
            let text = String::from_utf8(second).unwrap();
            second = text
                .replace("\"url_count\":1", "\"url_count\":1.5")
                .into_bytes();
        }
        _ => {}
    }
    let bytes = [support::encoded_row(&rows[0], true), second].concat();
    fs::write(fixture.path("events.jsonl"), &bytes).unwrap();
    fs::write(
        fixture.path("head.json"),
        support::checkpoint(&rows[1], bytes.len()),
    )
    .unwrap();
}

struct HeadChanges {
    path: PathBuf,
    changes: BTreeMap<usize, Vec<u8>>,
    counts: FileCounts,
}

impl ComplianceHooks for HeadChanges {
    fn at(&self, stage: ComplianceStage) -> io::Result<()> {
        self.counts.at(stage)?;
        if stage == ComplianceStage::BeforeOpen {
            if let Some(bytes) = self.changes.get(&self.counts.opens.load(SeqCst)) {
                fs::write(&self.path, bytes)?;
            }
        }
        Ok(())
    }
}

fn moving_heads(change: &str) {
    let fixture = DomainFixture::new();
    let mut journal = fixture.journal();
    let mut heads = Vec::new();
    for _ in 0..3 {
        fixture.list_row(&mut journal);
        heads.push(fs::read(fixture.path("head.json")).unwrap());
    }
    let (initial, changes, sequence) = match change {
        "advance-once" => (&heads[0], BTreeMap::from([(3, heads[1].clone())]), Some(2)),
        "advance-twice" => (
            &heads[0],
            BTreeMap::from([(3, heads[1].clone()), (6, heads[2].clone())]),
            Some(2),
        ),
        "regress" => (&heads[1], BTreeMap::from([(3, heads[0].clone())]), None),
        "foreign" => {
            let mut head: Value = serde_json::from_slice(&heads[0]).unwrap();
            head["hash"] = json!(support::digest(b"changed-checkpoint"));
            write_head(&fixture, &head);
            let foreign = fs::read(fixture.path("head.json")).unwrap();
            (&heads[0], BTreeMap::from([(3, foreign)]), None)
        }
        "unparseable" => (&heads[0], BTreeMap::from([(3, b"{broken".to_vec())]), None),
        _ => panic!("unknown head change"),
    };
    fs::write(fixture.path("head.json"), initial).unwrap();
    let mut expected = facts(fixture.config.store_dir());
    expected.get_mut(&fixture.path("head.json")).unwrap().bytes =
        changes.last_key_value().unwrap().1.clone();
    let hooks = HeadChanges {
        path: fixture.path("head.json"),
        changes,
        counts: FileCounts::default(),
    };
    let result = read_committed(&fixture.config, fixture.clock.as_ref(), &hooks);
    assert_eq!(hooks.counts.writes.load(SeqCst), 0);
    assert_eq!(facts(fixture.config.store_dir()), expected);
    assert!(
        hooks.counts.opens.load(SeqCst) <= 6,
        "moving snapshot exceeded its read budget"
    );
    if let Some(sequence) = sequence {
        assert_eq!(hooks.counts.opens.load(SeqCst), 6);
        assert_eq!(accepted(result).sequence, sequence);
    } else {
        assert!(
            matches!(result, Err(Error::Unavailable)),
            "regressed or foreign head accepted"
        );
    }
}

struct Pause {
    stage: ComplianceStage,
    armed: AtomicBool,
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl ComplianceHooks for Pause {
    fn at(&self, stage: ComplianceStage) -> io::Result<()> {
        if stage == self.stage && self.armed.swap(false, SeqCst) {
            self.entered.send(()).map_err(io::Error::other)?;
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(30))
                .map_err(io::Error::other)?;
        }
        Ok(())
    }
}

fn live_append(stage: ComplianceStage, expected_sequence: u64) {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let pause = Arc::new(Pause {
        stage,
        armed: AtomicBool::new(false),
        entered: entered_tx,
        release: Mutex::new(release_rx),
    });
    let entropy = Arc::new(support::CountingEntropy::default());
    let fixture = HttpFixture::instrumented(
        |_| {},
        |seams| {
            seams.hooks = pause.clone();
            seams.entropy = entropy.clone();
        },
    );
    pause.armed.store(true, SeqCst);
    let store = fixture.state.compliance();
    let writer = std::thread::spawn(move || {
        support::runtime().block_on(store.admit(
            support::intake(IntakeKind::IntimateImages {
                intimate_image_content: true,
                subject_or_authorised: true,
                good_faith: true,
            }),
            Arc::new(()),
        ))
    });
    let entered = entered_rx.recv_timeout(Duration::from_secs(30));
    let before = facts(fixture.domain.config.store_dir());
    let draws = entropy.widths.lock().unwrap().len();
    let counts = FileCounts::default();
    let result = read_committed(
        &fixture.domain.config,
        fixture.domain.clock.as_ref(),
        &counts,
    );
    let after = facts(fixture.domain.config.store_dir());
    let after_draws = entropy.widths.lock().unwrap().len();
    let released = release_tx.send(());
    let joined = writer.join();
    assert_eq!(before, after);
    assert_eq!(after_draws, draws);
    assert_eq!(
        counts.opens.load(SeqCst),
        3,
        "snapshot read a payload or writer file"
    );
    assert_eq!(counts.writes.load(SeqCst), 0);
    assert!(
        entered.is_ok() && released.is_ok(),
        "writer pause did not complete"
    );
    assert!(joined.is_ok(), "owned writer thread panicked");
    assert!(joined.unwrap().is_ok(), "owned writer append failed");
    let view = accepted(result);
    assert_eq!(view.sequence, expected_sequence);
    assert_eq!(view.rows.len() as u64, expected_sequence);
    if expected_sequence == 2 {
        assert_eq!(view.tickets().len(), 1);
        assert!(view.tickets().values().next().unwrap().pending.is_some());
    }
    let (result, _) = observed(&fixture.domain);
    let completed = accepted(result);
    assert_eq!(completed.sequence, 5);
    assert_eq!(completed.tickets().len(), 1);
    assert!(completed
        .tickets()
        .values()
        .next()
        .unwrap()
        .pending
        .is_none());
    support::runtime().block_on(fixture.state.compliance().shutdown());
}

fn purged_projection() {
    let fixture = DomainFixture::new();
    fixture
        .clock
        .set_utc(support::utc("2024-02-29T12:00:00Z"))
        .unwrap();
    let store = fixture.store();
    let runtime = support::runtime();
    let admitted = runtime
        .block_on(store.admit(
            support::intake(IntakeKind::IllegalContent {
                suspected_illegality: "Synthetic evidence".into(),
            }),
            Arc::new(()),
        ))
        .unwrap();
    let id = admitted.ticket.id;
    runtime
        .block_on(store.administer(
            id.clone(),
            "reviewer".into(),
            AdministrationEvent::Decision {
                decision: Decision::Refused {
                    reasons: "Synthetic refusal".into(),
                    delivery: support::delivery(),
                },
            },
            Arc::new(()),
        ))
        .unwrap();
    runtime
        .block_on(store.administer(
            id.clone(),
            "reviewer".into(),
            AdministrationEvent::Closure {
                reasons: "Synthetic closure".into(),
            },
            Arc::new(()),
        ))
        .unwrap();
    fixture
        .clock
        .set_utc(support::utc("2027-02-28T12:00:00Z"))
        .unwrap();
    runtime
        .block_on(store.purge(id.clone(), "reviewer".into(), Arc::new(())))
        .unwrap();
    let (result, counts) = observed(&fixture);
    assert_eq!(
        counts.opens.load(SeqCst),
        3,
        "purged snapshot requested private revisions"
    );
    let view = accepted(result);
    assert_eq!(view.rows.len(), 7);
    assert_eq!(view.tickets().len(), 1);
    assert!(view.tickets()[&id].purged);
    assert_eq!(view.tickets()[&id].state.as_str(), "closed");
    runtime.block_on(store.shutdown());
}

fn invalid_lifecycle() {
    let fixture = DomainFixture::new();
    let store = fixture.store();
    let runtime = support::runtime();
    runtime
        .block_on(store.admit(
            support::intake(IntakeKind::IllegalContent {
                suspected_illegality: "Synthetic evidence".into(),
            }),
            Arc::new(()),
        ))
        .unwrap();
    let bytes = fs::read(fixture.path("events.jsonl")).unwrap();
    let mut rows = bytes
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    rows[2]["state"] = json!("closed");
    support::rehash(&mut rows[2]);
    let bytes = rows
        .iter()
        .flat_map(|row| support::encoded_row(row, true))
        .collect::<Vec<_>>();
    fs::write(fixture.path("events.jsonl"), &bytes).unwrap();
    fs::write(
        fixture.path("head.json"),
        support::checkpoint(&rows[2], bytes.len()),
    )
    .unwrap();
    refused(&fixture);
    runtime.block_on(store.shutdown());
}
