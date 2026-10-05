// SPDX-License-Identifier: AGPL-3.0-only
//! Recompute metrics and release gates from exact candidate receipts, preserving missing values.
//! A measurement, a counsel waiver and a founder release decision are different evidence kinds.

use super::*;
use std::collections::HashSet;
use stract::eval::{
    labels::Label,
    metrics::{self, Row},
    Planner, Suite,
};

/// The fixed primary control inventory must not shrink when evidence is absent.
const CONSTRAINTS: [&str; 33] = [
    "CR-01", "CR-02", "CR-04", "CR-05", "CR-06", "CR-07", "TD-01", "TD-02", "TD-04", "TD-05",
    "TD-06", "TD-09", "TD-10", "TD-11", "TD-12", "TD-13", "RT-01", "RT-03", "RT-04", "AT-01",
    "AT-03", "EX-01", "EX-02", "EX-03", "EX-04", "RK-01", "RK-02", "RK-03", "RK-06", "DP-04",
    "LIC-01", "LIC-03", "UK-01",
];
/// Required subchecks remain visible without inflating the primary count.
const SUBROWS: [&str; 6] = ["CR-03", "CR-08", "CR-09", "RK-08", "EX-05", "EX-06"];
/// Control ownership cannot be reassigned by a receipt or counsel waiver.
const FOUNDER: [&str; 17] = [
    "CR-01",
    "CR-02",
    "TD-04",
    "TD-09",
    "TD-11",
    "TD-12",
    "EX-01",
    "RK-01",
    "RK-02",
    "RK-06",
    "LIC-01",
    "LIC-03",
    "UK-01",
    "DP-01",
    "DP-02",
    "DP-03",
    "AGPL-OFFER",
];

/// Enumerate every primary gate, including the added jurisdiction row.
fn inventory() -> Vec<String> {
    CONSTRAINTS
        .iter()
        .map(|id| (*id).to_owned())
        .chain((1..=3).map(|n| format!("DP-{n:02}")))
        .chain((1..=24).map(|n| format!("Q-{n:02}")))
        .chain(["AGPL-OFFER".into()])
        .chain((1..=6).map(|n| format!("EV-{n:02}")))
        .chain(["JUR-01".into()])
        .collect()
}

/// Resolve the binding owner independently of caller-supplied gate data.
fn owner(id: &str) -> &str {
    if id.starts_with("Q-") || id == "JUR-01" {
        "counsel"
    } else if FOUNDER.contains(&id) {
        "founder"
    } else {
        "engineering"
    }
}

/// Artifact and execution-log identities must both match the candidate requirement.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    id: String,
    requirement: String,
    kind: String,
    revision: String,
    date: String,
    artifact: Asset,
    log: Asset,
}

/// Only an explicitly scoped founder waiver can disposition a counsel question.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Waiver {
    founder: String,
    scope: String,
    reason: String,
    signed: Asset,
    date: String,
    expiry: String,
}

/// Applicability, missing controls and time-critical questions have distinct meanings.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Gate {
    id: String,
    owner: String,
    timing: String,
    sources: Vec<String>,
    required: Vec<String>,
    receipt_ids: Vec<String>,
    missing_implementation: bool,
    residual: String,
    waiver: Option<Waiver>,
    checks: Vec<Requirement>,
    applicability: String,
    time_critical: bool,
}

/// Requirement types and expected identities come from the gate, never its receipt.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Requirement {
    id: String,
    kind: String,
    identities: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// Complete primary inventory and the separately counted required subrows.
pub(super) struct Gates {
    rows: Vec<Gate>,
    subrows: Vec<Gate>,
}

/// Missing or duplicated rows invalidate the gate rather than reduce its denominator.
fn validate_inventory(gates: &Gates) -> Result<()> {
    let ids: BTreeSet<_> = gates.rows.iter().map(|r| r.id.clone()).collect();
    let expected: BTreeSet<_> = inventory().into_iter().collect();
    let subrows: BTreeSet<_> = gates.subrows.iter().map(|r| r.id.as_str()).collect();
    if ids != expected
        || gates.rows.len() != expected.len()
        || subrows != SUBROWS.into_iter().collect()
        || gates.subrows.len() != 6
    {
        return Err(Error::Invalid);
    }
    for gate in gates.rows.iter().chain(&gates.subrows) {
        if gate.owner != owner(&gate.id)
            || gate.sources.is_empty()
            || gate.required.is_empty()
            || gate.timing.is_empty()
            || gate.required.iter().any(String::is_empty)
            || gate.required.iter().collect::<HashSet<_>>().len() != gate.required.len()
            || gate.checks.len() != gate.required.len()
            || gate.checks.iter().map(|c| &c.id).collect::<HashSet<_>>()
                != gate.required.iter().collect::<HashSet<_>>()
            || gate
                .checks
                .iter()
                .any(|c| c.identities.is_empty() || c.identities.iter().any(String::is_empty))
            || !["text", "images"].contains(&gate.applicability.as_str())
            || (gate.timing == "pre-images") != (gate.applicability == "images")
        {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}

/// Completion metadata must accompany substantive requirement-specific evidence.
fn receipt_valid(
    receipt: &Receipt,
    revision: &str,
    required_owner: &str,
    check: &Requirement,
) -> Result<bool> {
    if !hex(revision, 40) || receipt.revision != revision || receipt.date.is_empty() {
        return Ok(false);
    }
    let expected_kind = match required_owner {
        "founder" => "founder_record",
        "counsel" => "counsel_answer",
        _ => "execution",
    };
    if receipt.kind != expected_kind || receipt.requirement != check.id {
        return Ok(false);
    }
    let body: Value = receipt.artifact.read()?;
    receipt.log.verify()?;
    if read_private(&receipt.log.path, input::MAX_INPUT_BYTES)?.is_empty() {
        return Ok(false);
    }
    Ok(body["status"] == "COMPLETE"
        && body["revision"] == revision
        && body["requirement"] == receipt.requirement
        && body["kind"] == expected_kind
        && requirement_passed(&body, check)
        && (expected_kind != "execution" || body["exit"] == 0)
        && (expected_kind == "execution" || body["signer"].as_str().is_some_and(|s| !s.is_empty())))
}

/// Generic completion metadata cannot stand in for substantive requirement results.
fn requirement_passed(body: &Value, check: &Requirement) -> bool {
    match check.kind.as_str() {
        "test" => body["tests"].as_array().is_some_and(|tests| {
            !tests.is_empty()
                && tests.iter().all(|t| t["passed"] == true)
                && check
                    .identities
                    .iter()
                    .all(|id| tests.iter().any(|t| t["name"] == *id))
        }),
        "review" => {
            body["open_critical"] == 0
                && body["open_high"] == 0
                && body["scope"].as_array().is_some_and(|scope| {
                    check.identities.iter().all(|id| scope.contains(&json!(id)))
                })
        }
        "measurement" => {
            check.identities.len() == 1
                && hex(&check.identities[0], 64)
                && body["run_sha256"] == check.identities[0]
        }
        "founder_record" | "counsel_answer" => {
            body["kind"] == check.kind && body["signer"].as_str().is_some_and(|s| !s.is_empty())
        }
        _ => false,
    }
}

/// A dated signature cannot waive an unrelated control or survive its expiry.
fn waiver_valid(gate: &Gate, waiver: &Waiver, today: &str) -> Result<bool> {
    if !gate.id.starts_with("Q-")
        || waiver.founder.is_empty()
        || waiver.scope != gate.id
        || waiver.reason.is_empty()
        || waiver.date.is_empty()
        || waiver.date.as_str() > today
        || waiver.expiry.as_str() < today
    {
        return Ok(false);
    }
    let record: Value = waiver.signed.read()?;
    Ok(record["founder"] == waiver.founder
        && record["scope"] == waiver.scope
        && record["reason"] == waiver.reason
        && record["date"] == waiver.date
        && record["expiry"] == waiver.expiry)
}

/// Missing controls and evidence remain visible to their responsible owners.
fn colour(gate: &Gate, receipts: &[Receipt], revision: &str, today: &str) -> Result<&'static str> {
    if gate.applicability == "images" {
        return Ok("NOT APPLICABLE (text-only)");
    }
    if gate.missing_implementation {
        return Ok("RED");
    }
    if let Some(waiver) = &gate.waiver {
        if waiver_valid(gate, waiver, today)? {
            return Ok("WAIVED/AMBER");
        }
        return Err(Error::Invalid);
    }
    let mut covered = BTreeSet::new();
    for id in &gate.receipt_ids {
        let receipt = receipts
            .iter()
            .find(|r| r.id == *id)
            .ok_or(Error::Invalid)?;
        let check = gate
            .checks
            .iter()
            .find(|c| c.id == receipt.requirement)
            .ok_or(Error::Invalid)?;
        if receipt_valid(receipt, revision, &gate.owner, check)? {
            covered.insert(receipt.requirement.as_str());
        }
    }
    if gate.required.iter().all(|r| covered.contains(r.as_str())) {
        Ok("GREEN")
    } else if !gate.time_critical
        && (gate.owner == "engineering" || matches!(gate.timing.as_str(), "ongoing" | "pre-images"))
    {
        Ok("AMBER")
    } else {
        Ok("RED")
    }
}

/// Keep the first ten raw slots and reuse the frozen evaluator without backfilling.
pub(super) fn score(label: &Label, urls: Option<&[String]>, latency: f64) -> Result<Row> {
    match urls {
        Some(urls) => {
            let slots: Vec<_> = urls.iter().take(10).cloned().collect();
            Ok(Row::score(label, &slots, &HashSet::new(), latency, None)?)
        }
        None => Ok(Row::failed(label, EvalError::InvalidResponse, latency)?),
    }
}

/// Reuse production percentile conventions so surfaces remain comparable.
fn latency(values: &[f64]) -> (Option<f64>, Option<f64>) {
    let (p50, p95) = metrics::percentiles(values);
    (p50, p95)
}

/// Normalization uses actual successful documents and unscaled process RSS.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cost {
    successful: bool,
    documents: u64,
    parsed_candidates: u64,
    wall_seconds: f64,
    cpu_seconds: f64,
    logical_bytes: u64,
    rss_bytes: Option<u64>,
}

/// Failed or zero-document runs remain absent measurements, never zero estimates.
fn cost(value: &Cost) -> Value {
    let count = value.documents;
    let valid = value.successful
        && count != 0
        && value.wall_seconds.is_finite()
        && value.cpu_seconds.is_finite()
        && value.wall_seconds >= 0.0
        && value.cpu_seconds >= 0.0;
    let factor = 1_000_000.0 / count.max(1) as f64;
    json!({"wall_h_per_million": valid.then(|| value.wall_seconds * factor / 3600.0),
        "cpu_h_per_million": valid.then(|| value.cpu_seconds * factor / 3600.0),
        "index_gib_per_million": valid.then(|| value.logical_bytes as f64 * factor / 1073741824.0),
        "rss_bytes": value.rss_bytes, "currency_per_million": null})
}

/// Make table text inert while preserving readable inline backticks.
fn escaped(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('|', "&#124;")
        .replace(['\n', '\r'], " ")
        .replace('[', "&#91;")
        .replace(']', "&#93;")
}

/// The full gate remains visible independently of measurement availability.
fn render(
    gates: &Gates,
    receipts: &[Receipt],
    revision: &str,
    today: &str,
) -> Result<(Value, String)> {
    validate_inventory(gates)?;
    let mut rows = Vec::new();
    let mut markdown = String::from(
        "| ID | Owner | Status | Required / residual |\n\
        |---|---|---|---|\n",
    );
    for id in inventory().iter().chain(
        SUBROWS
            .iter()
            .copied()
            .map(String::from)
            .collect::<Vec<_>>()
            .iter(),
    ) {
        let gate = gates
            .rows
            .iter()
            .chain(&gates.subrows)
            .find(|r| r.id == *id)
            .ok_or(Error::Invalid)?;
        let status = colour(gate, receipts, revision, today)?;
        markdown.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            gate.id,
            gate.owner,
            status,
            escaped(&format!("{}; {}", gate.required.join("; "), gate.residual))
        ));
        rows.push(json!({"id": gate.id, "owner": gate.owner, "status": status,
            "applicability":gate.applicability,"required":gate.required,
            "residual":gate.residual,"time_critical":gate.time_critical,
            "subrow": SUBROWS.contains(&gate.id.as_str()), "receipt_ids": gate.receipt_ids}));
    }
    let primary: Vec<_> = rows.iter().filter(|r| r["subrow"] == false).collect();
    let green = primary.iter().filter(|r| r["status"] == "GREEN").count();
    let red = primary.iter().filter(|r| r["status"] == "RED").count();
    let not_applicable = primary
        .iter()
        .filter(|r| r["status"] == "NOT APPLICABLE (text-only)")
        .count();
    let all_green = rows
        .iter()
        .all(|r| r["status"] == "GREEN" || r["status"] == "NOT APPLICABLE (text-only)");
    let recommendation = if all_green {
        "READY FOR FOUNDER DECISION"
    } else {
        "NO-GO"
    };
    Ok((
        json!({"rows": rows, "primary_count": 68, "subrow_count": 6,
        "green": green, "red": red, "amber": 68 - green - red - not_applicable,
        "not_applicable":not_applicable,
        "release_recommendation": recommendation, "founder_decision": "PENDING",
        "measurement_status": "NOT RUN"}),
        markdown,
    ))
}

/// Receipt, measurement and security evidence have separate validation paths.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceIndex {
    receipts: Vec<Receipt>,
    measurements: Vec<Measurement>,
    costs: Vec<Asset>,
    #[serde(default)]
    security_reviews: Vec<Asset>,
}

/// Recompute costs from hash-verified raw measure-index rows.
fn raw_costs(asset: &Asset) -> Result<Value> {
    let report: Value = asset.read()?;
    if report["schema_version"] != 1 {
        return Err(Error::Invalid);
    }
    let rows = report["rows"].as_array().ok_or(Error::Invalid)?;
    if rows.len() > 12 {
        return Err(Error::Invalid);
    }
    let mut seen = HashSet::new();
    let mut measured = Vec::new();
    for row in rows {
        let warc = row["warc_sha256"].as_str().ok_or(Error::Invalid)?;
        let batch = row["batch_size"].as_u64().ok_or(Error::Invalid)?;
        let run = row["run"].as_u64().ok_or(Error::Invalid)?;
        if !hex(warc, 64)
            || ![128, 512, 2048].contains(&batch)
            || ![1, 2].contains(&run)
            || !seen.insert((warc, batch, run))
        {
            return Err(Error::Invalid);
        }
        let valid = row["failed"] == false
            && row["reap_certain"] == true
            && row["timed_out"] == false
            && row["descendants_remained"] == false
            && row["exit_code"] == 0
            && row["parse_errors"] == 0;
        let cpu = row["user_cpu_seconds"]
            .as_f64()
            .zip(row["system_cpu_seconds"].as_f64())
            .map(|(user, system)| user + system);
        let input = Cost {
            successful: valid
                && cpu.is_some()
                && row["wall_seconds"].is_number()
                && row["final_disk_bytes"].is_u64(),
            documents: row["documents"].as_u64().unwrap_or(0),
            parsed_candidates: row["index_candidates"].as_u64().unwrap_or(0),
            wall_seconds: row["wall_seconds"].as_f64().unwrap_or(0.0),
            cpu_seconds: cpu.unwrap_or(0.0),
            logical_bytes: row["final_disk_bytes"].as_u64().unwrap_or(0),
            rss_bytes: row["peak_rss_bytes"].as_u64(),
        };
        measured.push(json!({"warc_sha256":warc,"batch_size":batch,"run":run,
            "raw":row,"normalized":cost(&input)}));
    }
    let segments = seen.iter().map(|(warc, _, _)| warc).collect::<HashSet<_>>();
    Ok(
        json!({"source":asset,"rows":measured,"rows_present":rows.len(),"expected_rows":12,
        "complete_matrix":rows.len()==12 && segments.len()==2}),
    )
}

/// A cell label is accepted only with its producing run identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Measurement {
    suite: String,
    planner: String,
    surface: String,
    revision: String,
    historical: bool,
    raw: Asset,
    run: Asset,
}

/// Capture companions bind the producing executable and cell to exact raw and config bytes.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RunIdentity {
    revision: String,
    executable_sha256: String,
    binary_sha256: String,
    suite: String,
    surface: String,
    planner: String,
    raw: Asset,
    configs: Vec<Asset>,
    responses: Vec<Asset>,
}

/// Seal the producing run at the capture call site, before reporting can relabel it.
pub(super) fn seal_run(
    plan: &Plan,
    out: &Out,
    cell: (&str, &str, &str),
    raw: Asset,
    configs: Vec<Asset>,
    responses: Vec<Asset>,
) -> Result<()> {
    plan.capture_ready()?;
    let run = RunIdentity {
        revision: plan.candidate_revision.clone().ok_or(Error::Blocked)?,
        executable_sha256: if cell.1 == "beta" {
            plan.binary.sha256.clone()
        } else {
            plan.example_sha256.clone()
        },
        binary_sha256: plan.binary.sha256.clone(),
        suite: cell.0.into(),
        surface: cell.1.into(),
        planner: cell.2.into(),
        raw,
        configs,
        responses,
    };
    out.json(&format!("{}-{}-{}.run.json", cell.0, cell.1, cell.2), &run)?;
    Ok(())
}

/// Check all plan fields needed by the run sealer before polling side-effecting work.
pub(super) async fn before_run(
    plan: &Plan,
    work: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    plan.capture_ready()?;
    work.await
}

/// Require the producing run to match the sealed run inventory and all of its physical inputs.
fn provenance(item: &Measurement, plan: &Plan) -> Result<()> {
    let run: RunIdentity = item.run.read()?;
    let sealed: Vec<Asset> = plan.asset("measurement-runs")?.read()?;
    let expected = if item.surface == "beta" {
        &plan.binary.sha256
    } else {
        &plan.example_sha256
    };
    if !sealed
        .iter()
        .any(|a| a.path == item.run.path && a.sha256 == item.run.sha256)
        || run.revision != item.revision
        || run.suite != item.suite
        || run.surface != item.surface
        || run.planner != item.planner
        || run.executable_sha256 != *expected
        || run.binary_sha256 != plan.binary.sha256
        || run.raw.path != item.raw.path
        || run.raw.sha256 != item.raw.sha256
    {
        return Err(Error::Invalid);
    }
    if run.configs.is_empty() || run.responses.is_empty() {
        return Err(Error::Invalid);
    }
    for asset in run.configs.iter().chain(&run.responses).chain([&run.raw]) {
        asset.verify()?;
    }
    Ok(())
}

/// Preserve response order within the explicitly selected set.
fn captured_rows(item: &Measurement) -> Result<Vec<Value>> {
    let value: Value = item.raw.read()?;
    let rows = if value.is_array() {
        &value
    } else {
        &value["rows"]
    };
    let rows = rows.as_array().ok_or(Error::Invalid)?;
    Ok(rows
        .iter()
        .filter(|r| r.get("set").is_none_or(|s| s == &item.suite))
        .cloned()
        .collect())
}

/// Failed captures cannot acquire invented empty successful result lists.
fn captured_urls(row: &Value) -> Result<Option<Vec<String>>> {
    if row["success"] != true {
        return Ok(None);
    }
    let value = row
        .get("top10_urls")
        .or_else(|| row.get("urls"))
        .ok_or(Error::Invalid)?;
    serde_json::from_value(value.clone()).map_err(|_| Error::Invalid)
}

/// Rescore exact raw slots against original and independent label views.
fn measured(item: &Measurement, plan: &Plan) -> Result<Value> {
    if item.historical
        || Some(&item.revision) != plan.candidate_revision.as_ref()
        || !["beta", "v1", "firecrawl"].contains(&item.surface.as_str())
    {
        return Err(Error::Invalid);
    }
    provenance(item, plan)?;
    let labels = agreement::labels(plan, &item.suite)?;
    let raw = captured_rows(item)?;
    if raw.len() != labels.len() {
        return Err(Error::Invalid);
    }
    let mut scored = Vec::new();
    let overlay = match plan.asset(&format!("sol-{}", item.suite)) {
        Ok(_) => Some(agreement::sol_view(plan, &item.suite, &labels)?),
        Err(Error::Blocked) => None,
        Err(error) => return Err(error),
    };
    let mut sol_rows = Vec::new();
    for (row, label) in raw.iter().zip(&labels) {
        if row["id"] != label.id || row["query"] != label.query || row["category"] != label.category
        {
            return Err(Error::Invalid);
        }
        let urls = captured_urls(row)?;
        let elapsed = match row["latency_ms"].as_f64() {
            Some(ms) if ms.is_finite() && ms >= 0.0 => ms,
            _ if urls.is_none() => 0.0,
            _ => return Err(Error::Invalid),
        };
        scored.push(score(label, urls.as_deref(), elapsed)?);
        if let Some(Some(sol)) = overlay.as_ref().and_then(|rows| rows.get(scored.len() - 1)) {
            sol_rows.push(score(sol, urls.as_deref(), elapsed)?);
        }
    }
    let suite = if item.suite == "frozen" {
        Suite::Frozen
    } else {
        Suite::HeldOut
    };
    let planner = match item.planner.as_str() {
        "on" => Planner::On,
        "off" => Planner::Off,
        _ => return Err(Error::Invalid),
    };
    let values: Vec<_> = scored.iter().filter_map(|r| r.latency_ms).collect();
    Ok(
        json!({"surface": item.surface, "suite": item.suite, "planner": item.planner,
        "summary": metrics::summary(&scored),
        "raw": item.raw,
        "paired_rows": scored,
        "acceptance": metrics::acceptance(&scored, suite, planner),
        "latency": latency(&values), "rows": report_rows(&scored),
        "sol": {"summary": metrics::summary(&sol_rows), "scorable": sol_rows.len(),
            "fixed_recall_at_10": overlay.as_ref().map(|_| sol_rows.iter()
                .filter_map(|r| r.recall_at_10).sum::<f64>() / labels.len() as f64),
            "acceptance": metrics::acceptance(&sol_rows, suite, planner),
            "fixed_query_count": labels.len(), "rows": report_rows(&sol_rows),
            "status": if overlay.is_some() { "SCORED" } else { "NOT RUN" }}}),
    )
}

/// Unknown adapter fields remain null instead of implying unperformed measurements.
fn report_rows(rows: &[Row]) -> Vec<Value> {
    rows.iter()
        .map(|row| {
            let mut value = json!(row);
            // The scoring adapter has no corpus or failed-attempt clock; raw receipts retain those.
            value["top10_urls_in_sample"] = Value::Null;
            value["failed_attempt_ms"] = Value::Null;
            value
        })
        .collect()
}

/// Readiness requires every cell and the paired protected-match verdict.
fn measured_ready(rows: &[Value]) -> bool {
    let cells = ["frozen", "held-out"].iter().all(|set| {
        [("beta", "off"), ("beta", "on"), ("v1", "on")]
            .iter()
            .all(|(surface, planner)| {
                rows.iter().any(|row| {
                    row["suite"] == *set
                        && row["surface"] == *surface
                        && row["planner"] == *planner
                        && row["acceptance"]["passed"] == true
                        && row["sol"]["scorable"] == 50
                        && (*planner == "off" || row["sol"]["acceptance"]["passed"] == true)
                })
            })
    });
    cells && paired_ready(rows)
}

/// Recompute paired retention with the production diff, never a copied verdict.
fn paired_ready(rows: &[Value]) -> bool {
    ["frozen", "held-out"].iter().all(|set| {
        let cell = |surface, planner| {
            rows.iter()
                .find(|r| r["suite"] == *set && r["surface"] == surface && r["planner"] == planner)
        };
        let compare = |before: &Value, after: &Value| -> Result<bool> {
            let old: Vec<Row> = serde_json::from_value(before["paired_rows"].clone())
                .map_err(|_| Error::Invalid)?;
            let new: Vec<Row> =
                serde_json::from_value(after["paired_rows"].clone()).map_err(|_| Error::Invalid)?;
            let diff = stract::eval::diff::compare(&old, &new)?;
            let before = json!({"suite":set,"planner_expectation":"off",
                "acceptance":before["acceptance"]});
            let after = json!({"suite":set,"planner_expectation":"on",
                "acceptance":after["acceptance"]});
            let verdict = stract::eval::diff::paired_acceptance(&before, &after, &diff)?;
            Ok(verdict["passed"] == true)
        };
        cell("beta", "off")
            .zip(cell("beta", "on"))
            .zip(cell("v1", "on"))
            .is_some_and(|((off, on), v1)| {
                compare(off, on).unwrap_or(false) && compare(on, v1).unwrap_or(false)
            })
    })
}

/// Render numeric evidence and missing values through one deterministic path.
fn results_markdown(value: &Value) -> String {
    let mut text = String::from(
        "# Stage 1 measurements\n\n\
        Missing values are NOT RUN. Each row retains its source hash.\n\n",
    );
    text.push_str(&matrix_markdown(value));
    for row in value["measurements"].as_array().into_iter().flatten() {
        text.push_str(&format!(
            "## {} / {} / {}\n\nSource SHA-256: `{}`\n\n",
            escaped(row["suite"].as_str().unwrap_or("")),
            escaped(row["surface"].as_str().unwrap_or("")),
            escaped(row["planner"].as_str().unwrap_or("")),
            escaped(row["raw"]["sha256"].as_str().unwrap_or("")),
        ));
        for (label, view) in [("Original", row), ("Sol", &row["sol"])] {
            text.push_str(&format!("### {label}\n\n"));
            if label == "Sol" {
                text.push_str(&format!(
                    "Scorable: {}/50; fixed-denominator recall: {}.\n\n",
                    number(&view["scorable"]),
                    number(&view["fixed_recall_at_10"])
                ));
            }
            text.push_str("| Scope | Successful | Recall@10 | p50 ms | p95 ms |\n");
            text.push_str("|---|---|---|---|---|\n");
            let summary = &view["summary"];
            let scopes = std::iter::once(("all", summary)).chain(
                summary["categories"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|category| (category["category"].as_str().unwrap_or(""), category)),
            );
            for (scope, summary) in scopes {
                text.push_str(&format!(
                    "| {} | {} | {} | {} | {} |\n",
                    escaped(scope),
                    number(&summary["successful"]),
                    number(&summary["recall_at_10"]),
                    number(&summary["p50_ms"]),
                    number(&summary["p95_ms"])
                ));
            }
            text.push_str("\n| Query ID | Success | Recall@10 | Latency ms |\n");
            text.push_str("|---|---|---|---|\n");
            for query in view["rows"].as_array().into_iter().flatten() {
                text.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    escaped(query["id"].as_str().unwrap_or("")),
                    query["success"],
                    number(&query["recall_at_10"]),
                    number(&query["latency_ms"])
                ));
            }
            text.push('\n');
        }
    }
    text.push_str(
        "## Cost matrix\n\n| WARC SHA-256 | Batch | Run | Wall h/M | CPU h/M | GiB/M |\n",
    );
    text.push_str("|---|---|---|---|---|---|\n");
    for matrix in value["costs"].as_array().into_iter().flatten() {
        for row in matrix["rows"].as_array().into_iter().flatten() {
            let normalized = &row["normalized"];
            text.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                row["warc_sha256"].as_str().unwrap_or(""),
                row["batch_size"],
                row["run"],
                number(&normalized["wall_h_per_million"]),
                number(&normalized["cpu_h_per_million"]),
                number(&normalized["index_gib_per_million"])
            ));
        }
    }
    text.push_str("\nN is actual successful indexed documents. b512 is closest to #573.\n");
    text.push_str(
        "RSS is unscaled; currency is NOT RUN without tariffs. See results.json for coverage.\n",
    );
    text
}

/// Render every prescribed cell, even when no producing dispatch is available.
fn matrix_markdown(value: &Value) -> String {
    let mut text = String::from("| Set | Surface | Planner | Status |\n|---|---|---|---|\n");
    for set in ["frozen", "held-out"] {
        for (surface, planner) in [
            ("beta", "off"),
            ("beta", "on"),
            ("v1", "on"),
            ("firecrawl", "on"),
        ] {
            let present = value["measurements"].as_array().is_some_and(|rows| {
                rows.iter().any(|r| {
                    r["suite"] == set && r["surface"] == surface && r["planner"] == planner
                })
            });
            let status = if present { "MEASURED" } else { "NOT RUN" };
            text.push_str(&format!("| {set} | {surface} | {planner} | {status} |\n"));
        }
    }
    text.push_str("\n| Segment | Batch | Repeat | Status |\n|---|---|---|---|\n");
    for segment in ["original", "selected"] {
        for batch in [128, 512, 2048] {
            for repeat in [1, 2] {
                let present = value["costs"].as_array().is_some_and(|matrices| {
                    matrices.iter().any(|m| {
                        m["rows"].as_array().is_some_and(|rows| {
                            rows.iter().any(|r| {
                                r["segment_role"] == segment
                                    && r["batch_size"] == batch
                                    && r["run"] == repeat
                            })
                        })
                    })
                });
                let status = if present { "MEASURED" } else { "NOT RUN" };
                text.push_str(&format!("| {segment} | {batch} | {repeat} | {status} |\n"));
            }
        }
    }
    text.push('\n');
    text
}

/// Keep cost rows tied to the original segment and the sealed distinct manifest selection.
fn checked_costs(asset: &Asset, plan: &Plan) -> Result<Value> {
    let binding: Value = plan.asset("cost-segments")?.read()?;
    let original: Asset =
        serde_json::from_value(binding["original"]["warc"].clone()).map_err(|_| Error::Invalid)?;
    let selected: Asset =
        serde_json::from_value(binding["selected"]["warc"].clone()).map_err(|_| Error::Invalid)?;
    original.verify()?;
    selected.verify()?;
    let selection: Asset =
        serde_json::from_value(binding["selection"].clone()).map_err(|_| Error::Invalid)?;
    let receipt: Value = selection.read()?;
    selected_download(&selected, &receipt, plan)?;
    if binding["original"]["segment"] != "1786091384908.68"
        || binding["selected"]["segment"] == binding["original"]["segment"]
        || binding["selected"]["segment"] != receipt["segment"]
        || !receipt["segment"].is_string()
        || original.sha256 == selected.sha256
    {
        return Err(Error::Invalid);
    }
    let mut matrix = raw_costs(asset)?;
    for row in matrix["rows"].as_array_mut().ok_or(Error::Invalid)? {
        row["segment_role"] = json!(if row["warc_sha256"] == original.sha256 {
            "original"
        } else if row["warc_sha256"] == selected.sha256 {
            "selected"
        } else {
            return Err(Error::Invalid);
        });
    }
    Ok(matrix)
}

/// Bind the selected cost input to a successful, hash-pinned Common Crawl transfer.
fn selected_download(selected: &Asset, selection: &Value, plan: &Plan) -> Result<()> {
    let download: Value = plan.asset("cc-download")?.read()?;
    let downloaded: Asset =
        serde_json::from_value(download["warc"].clone()).map_err(|_| Error::Invalid)?;
    downloaded.verify()?;
    let expected: Asset =
        serde_json::from_value(download["receipt"].clone()).map_err(|_| Error::Invalid)?;
    let asset = plan.asset("cc-download-receipt")?;
    if expected.path != asset.path || expected.sha256 != asset.sha256 {
        return Err(Error::Invalid);
    }
    let receipt: Value = asset.read()?;
    if receipt["complete"] != true
        || receipt["http_status"] != 200
        || receipt["url"] != selection["url"]
        || !receipt["url"].is_string()
        || receipt["sha256"] != downloaded.sha256
        || receipt["bytes"]
            != fs::metadata(&downloaded.path)
                .map_err(|_| Error::Invalid)?
                .len()
    {
        return Err(Error::Invalid);
    }
    if selected.sha256 != downloaded.sha256 {
        return Err(Error::Invalid);
    }
    Ok(())
}

/// Preserve independent open findings as additional engineering blockers, never waivers.
fn security_rows(value: &mut Value, assets: &[Asset]) -> Result<()> {
    let mut ids = HashSet::new();
    for asset in assets {
        let review: Value = asset.read()?;
        if review["reviewer"].as_str().is_none_or(str::is_empty)
            || review["scope"].as_array().is_none_or(Vec::is_empty)
        {
            return Err(Error::Invalid);
        }
        for finding in review["findings"].as_array().ok_or(Error::Invalid)? {
            let id = finding["id"].as_str().ok_or(Error::Invalid)?;
            if !id.starts_with("SB-")
                || !ids.insert(id.to_owned())
                || finding["owner"] != "engineering"
                || finding["file_line"]
                    .as_str()
                    .is_none_or(|s| !s.contains(':'))
                || !["High", "Critical"]
                    .iter()
                    .any(|s| finding["severity"] == *s)
            {
                return Err(Error::Invalid);
            }
            let mut row = finding.clone();
            row["status"] = json!("RED");
            row["applicability"] = json!("text");
            row["receipt"] = json!(asset);
            value["rows"]
                .as_array_mut()
                .ok_or(Error::Invalid)?
                .push(row);
            value["release_recommendation"] = json!("NO-GO");
        }
    }
    Ok(())
}

/// Emit the binding jurisdiction, quality caveat and deduplicated owner columns from gate data.
fn memo(value: &Value) -> Value {
    let mut columns = serde_json::Map::new();
    for owner in ["engineering", "founder", "counsel"] {
        let mut ids = BTreeSet::new();
        for row in value["rows"].as_array().into_iter().flatten() {
            if row["owner"] != owner
                || matches!(
                    row["status"].as_str(),
                    Some("GREEN" | "NOT APPLICABLE (text-only)")
                )
            {
                continue;
            }
            let id = row["id"].as_str().unwrap_or("");
            ids.insert(if ["AGPL-OFFER", "LIC-01", "LIC-03"].contains(&id) {
                "AGPL-OFFER/LIC-01/LIC-03"
            } else {
                id
            });
        }
        columns.insert(owner.into(), json!({"count":ids.len(),"ids":ids}));
    }
    json!({"columns":columns,
        "jurisdiction":concat!("Operator: US entity TBD; no UK-based operation; ",
            "UK/EU/EEA/CH users served; this checklist enumerates the #574 UK baseline only."),
        "quality":concat!("The original held-out labels are saturated (planner-on 50/50 in #618) ",
            "and their queries were written from the labelled pages. A held-out PASS on ",
            "original labels is not generalisation evidence. ",
            "The Sol-label held-out score is the primary quality reading.")})
}

/// Every generated evidence link targets a checked file in the same output directory.
fn gate_links(value: &Value, out: &Out, markdown: &mut String) -> Result<()> {
    markdown.push_str("\n| ID | Evidence |\n|---|---|\n");
    for row in value["rows"].as_array().ok_or(Error::Invalid)? {
        let id = row["id"].as_str().ok_or(Error::Invalid)?;
        if !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(Error::Invalid);
        }
        let name = format!("gate-{id}.json");
        let asset = out.json(
            &name,
            &json!({"row":row,
            "reason":"See status and receipt identities; missing evidence remains blocked"}),
        )?;
        asset.verify()?;
        markdown.push_str(&format!("| {id} | [receipt]({name}) |\n"));
    }
    Ok(())
}

/// Missing values stay visibly distinct from a measured numeric zero.
fn number(value: &Value) -> String {
    if value.is_number() {
        value.to_string()
    } else {
        "NOT RUN".into()
    }
}

/// Validate the exact serialized destinations rather than assuming link formatting is correct.
fn validate_links(markdown: &str, out: &Out) -> Result<()> {
    for suffix in markdown.split("](").skip(1) {
        let name = suffix.split_once(')').ok_or(Error::Invalid)?.0;
        if name.contains('/') || !name.starts_with("gate-") || !name.ends_with(".json") {
            return Err(Error::Invalid);
        }
        read_private(&out.0.join(name), input::MAX_INPUT_BYTES)?;
    }
    Ok(())
}

/// The three owner columns include every applicable RED and AMBER blocker.
fn memo_markdown(value: &Value) -> String {
    let memo = memo(value);
    let mut text = format!(
        "{}\n\n{}\n\n",
        memo["jurisdiction"].as_str().unwrap_or(""),
        memo["quality"].as_str().unwrap_or("")
    );
    text.push_str("| Engineering not ready | Founder-owned | Counsel-owned |\n|---|---|---|\n");
    let mut blocking = Vec::new();
    for owner in ["engineering", "founder", "counsel"] {
        let column = &memo["columns"][owner];
        let ids = column["ids"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        text.push_str(&format!("| {}: {} ", column["count"], ids));
        if column["count"].as_u64().is_some_and(|n| n > 0) {
            blocking.push(owner);
        }
    }
    text.push_str("|\n\n");
    if !blocking.is_empty() {
        text.push_str(&format!(
            "Each of these columns independently forces NO-GO: {}.\n",
            blocking.join(", ")
        ));
    }
    text
}

/// Produce deterministic offline tables; a red gate is a successful reporting operation.
pub(super) fn report(plan: &Plan, out: &Out, gates: &Path, receipts: &Path) -> Result<()> {
    let gates_asset = Asset {
        path: gates.to_owned(),
        sha256: input::hash_file(gates)?,
    };
    let receipts_asset = Asset {
        path: receipts.to_owned(),
        sha256: input::hash_file(receipts)?,
    };
    let gates: Gates = gates_asset.read()?;
    let index: EvidenceIndex = receipts_asset.read()?;
    let mut ids = HashSet::new();
    if index.receipts.iter().any(|r| !ids.insert(&r.id)) {
        return Err(Error::Invalid);
    }
    let mut cells = HashSet::new();
    if index
        .measurements
        .iter()
        .any(|row| !cells.insert((&row.suite, &row.surface, &row.planner)))
    {
        return Err(Error::Invalid);
    }
    let revision = plan.candidate_revision.as_deref().unwrap_or("unknown");
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let (mut value, mut markdown) = render(&gates, &index.receipts, revision, &today)?;
    security_rows(&mut value, &index.security_reviews)?;
    for row in value["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["id"].as_str().is_some_and(|s| s.starts_with("SB-")))
    {
        markdown.push_str(&format!(
            "| {} | engineering | RED | {}: {} |\n",
            escaped(row["id"].as_str().unwrap_or("")),
            escaped(row["severity"].as_str().unwrap_or("")),
            escaped(row["file_line"].as_str().unwrap_or(""))
        ));
    }
    let rows: Vec<_> = index
        .measurements
        .iter()
        .map(|m| measured(m, plan))
        .collect::<Result<_>>()?;
    let ready = measured_ready(&rows);
    value["measurement_status"] = json!(if rows.is_empty() {
        "NOT RUN"
    } else {
        "MEASURED"
    });
    value["measurements"] = json!(rows);
    value["costs"] = json!(index
        .costs
        .iter()
        .map(|asset| checked_costs(asset, plan))
        .collect::<Result<Vec<_>>>()?);
    value["inputs"] = json!({"gates":gates_asset,"receipts":receipts_asset});
    if !ready
        || value["costs"]
            .as_array()
            .is_none_or(|costs| !costs.iter().any(costs_ready))
    {
        value["release_recommendation"] = json!("NO-GO");
    }
    out.json("release-gates.json", &value)?;
    gate_links(&value, out, &mut markdown)?;
    validate_links(&markdown, out)?;
    out.json("memo.json", &memo(&value))?;
    out.bytes("MEMO.md", memo_markdown(&value).as_bytes())?;
    out.bytes("RELEASE-GATES.md", markdown.as_bytes())?;
    out.bytes("RESULTS.md", results_markdown(&value).as_bytes())?;
    out.json("results.json", &value)?;
    Ok(())
}

/// An incomplete or failed cost matrix cannot support release readiness.
fn costs_ready(matrix: &Value) -> bool {
    matrix["complete_matrix"] == true
        && matrix["rows"].as_array().is_some_and(|rows| {
            rows.iter()
                .all(|row| row["normalized"]["wall_h_per_million"].is_number())
        })
}

#[cfg(test)]
/// Synthetic complete inventory shared with the actual in-process CLI witness.
pub(super) fn test_gates() -> Gates {
    let gate = |id: String| Gate {
        owner: owner(&id).into(),
        id,
        timing: "pre-beta".into(),
        sources: vec!["synthetic source".into()],
        required: vec!["synthetic requirement".into()],
        receipt_ids: vec![],
        missing_implementation: false,
        residual: "NOT RUN <script>synthetic</script>".into(),
        waiver: None,
        checks: vec![Requirement {
            id: "synthetic requirement".into(),
            kind: "test".into(),
            identities: vec!["synthetic_test".into()],
        }],
        applicability: "text".into(),
        time_critical: false,
    };
    Gates {
        rows: inventory().into_iter().map(gate).collect(),
        subrows: SUBROWS.iter().map(|id| gate((*id).into())).collect(),
    }
}

/// Offline witnesses exercise production call sites with content-free assertions.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{label, Temp};

    /// Pin the expected test identity independently of the receipt under review.
    fn check() -> Requirement {
        Requirement {
            id: "synthetic requirement".into(),
            kind: "test".into(),
            identities: vec!["synthetic_test".into()],
        }
    }

    #[test]
    fn raw_slots_and_normalization() {
        let label = label(0);
        let mut urls = vec!["https://example.test/other".to_string(); 10];
        urls.push(label.acceptable_urls[0].clone());
        let scored = score(&label, Some(&urls), 1.0).unwrap();
        assert!(
            scored.recall_at_10 == Some(0.0)
                && scored.top10_urls == urls[..10]
                && scored.matched_urls.is_empty(),
            "W04_RAW_SLOTS"
        );
        let normalize = stract::eval::normalize::normalize;
        assert!(
            normalize("https://WWW.example.test/Path/?utm_x=x&b=2&a=1#x").unwrap()
                == "example.test/Path?a=1&b=2",
            "W04_NORMALIZE"
        );
        assert!(
            normalize("https://example.test/path?a=1&b=2").unwrap() != "example.test/Path?a=1&b=2",
            "W04_CASE"
        );
    }

    #[test]
    fn missing_is_not_zero() {
        let label = label(0);
        let empty = score(&label, Some(&[]), 1.0).unwrap();
        assert!(
            empty.success && empty.zero_results && empty.recall_at_10 == Some(0.0),
            "W05_EMPTY"
        );
        let failed = score(&label, None, 1.0).unwrap();
        assert!(
            !failed.success
                && failed.recall_at_10.is_none()
                && failed.latency_ms.is_none()
                && !failed.zero_results,
            "W05_NULL"
        );
        let acceptance = metrics::acceptance(&[empty, failed], Suite::Frozen, Planner::On);
        assert!(acceptance["passed"] == false, "W05_INCOMPLETE");
    }

    #[test]
    fn percentiles_and_cost() {
        assert!(
            latency(&[1.0, 2.0, 3.0, 4.0]) == (Some(2.5), Some(4.0)),
            "W06_PERCENTILES"
        );
        let values: Vec<_> = (1..=21).map(f64::from).collect();
        assert!(
            latency(&values) == (Some(11.0), Some(20.0)),
            "W06_CEIL_RANK"
        );
        let mut value = Cost {
            successful: true,
            documents: 1000,
            parsed_candidates: 2000,
            wall_seconds: 36.0,
            cpu_seconds: 72.0,
            logical_bytes: 1073741824,
            rss_bytes: Some(4096),
        };
        assert!(
            cost(&value)
                == json!({"wall_h_per_million":10.0,"cpu_h_per_million":20.0,
            "index_gib_per_million":1000.0,"rss_bytes":4096,"currency_per_million":null}),
            "W06_DOCUMENT_DENOMINATOR"
        );
        value.documents = 0;
        assert!(
            cost(&value)["wall_h_per_million"].is_null(),
            "W06_ZERO_DOCUMENTS"
        );
        value.documents = 1000;
        value.successful = false;
        assert!(cost(&value)["cpu_h_per_million"].is_null(), "W06_FAILURE");
        raw_cost_receipt();
    }

    fn raw_cost_receipt() {
        let temp = Temp::new();
        let raw = json!({"schema_version":1,"rows":[{
            "warc_sha256":"a".repeat(64),"batch_size":512,"run":1,
            "documents":1000,"index_candidates":2000,"parse_errors":0,
            "wall_seconds":36.0,"user_cpu_seconds":50.0,"system_cpu_seconds":22.0,
            "final_disk_bytes":1073741824_u64,"peak_rss_bytes":4096,
            "failed":false,"reap_certain":true,"timed_out":false,
            "descendants_remained":false,"exit_code":0
        }]});
        let asset = temp.asset("measure.json", &serde_json::to_vec(&raw).unwrap());
        let actual = raw_costs(&asset).unwrap();
        assert!(
            actual
                == json!({"source":asset,"rows_present":1,"expected_rows":12,
                "complete_matrix":false,"rows":[{"warc_sha256":"a".repeat(64),
                    "batch_size":512,"run":1,"raw":raw["rows"][0],
                    "normalized":{"wall_h_per_million":10.0,"cpu_h_per_million":20.0,
                        "index_gib_per_million":1000.0,"rss_bytes":4096,
                        "currency_per_million":null}}]}),
            "W06_RAW_COST_RECEIPT"
        );
    }

    #[test]
    fn gate_inventory() {
        let gates = test_gates();
        assert!(
            gates.rows.len() == 68
                && gates.subrows.len() == 6
                && validate_inventory(&gates).is_ok(),
            "W19_COUNTS"
        );
        for id in inventory() {
            let mut missing = test_gates();
            missing.rows.retain(|r| r.id != id);
            assert!(validate_inventory(&missing).is_err(), "W19_OMISSION");
        }
        let mut wrong = test_gates();
        wrong.rows[0].owner = "counsel".into();
        assert!(validate_inventory(&wrong).is_err(), "W19_OWNER");
        wrong = test_gates();
        wrong.rows[1] = wrong.rows[0].clone();
        assert!(validate_inventory(&wrong).is_err(), "W19_DUPLICATE");
        wrong = test_gates();
        wrong.rows[0].id = "OTHER".into();
        assert!(validate_inventory(&wrong).is_err(), "W19_UNKNOWN");
    }

    fn receipt(temp: &Temp) -> Receipt {
        let body = json!({"status":"COMPLETE","revision":"a".repeat(40),
            "requirement":"synthetic requirement","kind":"execution","exit":0,
            "tests":[{"name":"synthetic_test","passed":true}]});
        Receipt {
            id: "receipt".into(),
            requirement: "synthetic requirement".into(),
            kind: "execution".into(),
            revision: "a".repeat(40),
            date: "2026-10-04".into(),
            artifact: temp.asset("receipt.json", &serde_json::to_vec(&body).unwrap()),
            log: temp.asset("log", b"synthetic execution log"),
        }
    }

    #[test]
    fn gate_receipts_required() {
        review_with_high();
        let temp = Temp::new();
        let receipt = receipt(&temp);
        assert!(
            receipt_valid(&receipt, &"a".repeat(40), "engineering", &check()).unwrap(),
            "W20_CURRENT"
        );
        assert!(
            !receipt_valid(
                &Receipt {
                    revision: "b".repeat(40),
                    ..receipt.clone()
                },
                &"a".repeat(40),
                "engineering",
                &check()
            )
            .unwrap(),
            "W20_STALE"
        );
        assert!(
            !receipt_valid(&receipt, &"a".repeat(40), "founder", &check()).unwrap(),
            "W20_OWNER"
        );
        let mut corrupt = receipt.clone();
        corrupt.log.sha256 = "c".repeat(64);
        assert!(
            receipt_valid(&corrupt, &"a".repeat(40), "engineering", &check()).is_err(),
            "W20_HASH"
        );
        corrupt.log.path = temp.0.join("absent");
        assert!(
            receipt_valid(&corrupt, &"a".repeat(40), "engineering", &check()).is_err(),
            "W20_LOG"
        );
        let gates = test_gates();
        let gate = gates.rows.iter().find(|r| r.id == "CR-04").unwrap();
        assert!(
            colour(gate, &[], &"a".repeat(40), "2026-10-04").unwrap() != "GREEN",
            "W20_NAME"
        );
    }

    /// A successfully completed independent review can still fail the release requirement.
    fn review_with_high() {
        let temp = Temp::new();
        let mut receipt = receipt(&temp);
        let body = json!({"status":"COMPLETE","revision":"a".repeat(40),
            "requirement":"synthetic requirement","kind":"execution","exit":0,
            "scope":["whole-stage1"],"open_critical":0,"open_high":1});
        receipt.artifact = temp.asset("review.json", &serde_json::to_vec(&body).unwrap());
        let check = Requirement {
            id: receipt.requirement.clone(),
            kind: "review".into(),
            identities: vec!["whole-stage1".into()],
        };
        assert!(
            !receipt_valid(&receipt, &"a".repeat(40), "engineering", &check).unwrap(),
            "W20_OPEN_HIGH"
        );
    }

    #[test]
    fn waiver_is_not_control() {
        let temp = Temp::new();
        let record = json!({"founder":"synthetic founder","scope":"Q-09","reason":"synthetic",
            "date":"2026-10-04","expiry":"2026-10-05"});
        let waiver = Waiver {
            founder: "synthetic founder".into(),
            scope: "Q-09".into(),
            reason: "synthetic".into(),
            date: "2026-10-04".into(),
            expiry: "2026-10-05".into(),
            signed: temp.asset("signed.json", &serde_json::to_vec(&record).unwrap()),
        };
        let gates = test_gates();
        let mut question = gates.rows.iter().find(|r| r.id == "Q-09").unwrap().clone();
        question.waiver = Some(waiver.clone());
        assert!(
            colour(&question, &[], "unknown", "2026-10-04").unwrap() == "WAIVED/AMBER",
            "W21_SCOPED"
        );
        let mut control = gates.rows.iter().find(|r| r.id == "DP-01").unwrap().clone();
        control.missing_implementation = true;
        control.waiver = Some(waiver);
        assert!(
            colour(&control, &[], "unknown", "2026-10-04").unwrap() == "RED",
            "W21_CONTROL"
        );
        question.waiver.as_mut().unwrap().founder.clear();
        assert!(
            colour(&question, &[], "unknown", "2026-10-04").is_err(),
            "W21_SIGNATURE"
        );
    }

    #[test]
    fn report_no_fabrication() {
        report_security_paths();
        report_rendered_values();
        paired_and_provenance();
        let mut images = test_gates();
        let row = &mut images.rows[0];
        row.applicability = "images".into();
        row.timing = "pre-images".into();
        row.missing_implementation = true;
        assert!(
            colour(row, &[], "unknown", "2026-10-04").unwrap() == "NOT APPLICABLE (text-only)",
            "W22_IMAGE_APPLICABILITY"
        );
        let gates = test_gates();
        let (value, markdown) = render(&gates, &[], "unknown", "2026-10-04").unwrap();
        assert!(value["recall_at_10"].is_null(), "W22_MISSING_NULL");
        assert!(
            value["release_recommendation"] == "NO-GO"
                && value["measurement_status"] == "NOT RUN"
                && value["green"] == 0
                && value["founder_decision"] == "PENDING",
            "W22_NO_GO"
        );
        assert!(
            !markdown.contains("<script>") && markdown.contains("&lt;script&gt;"),
            "W22_INERT"
        );
        let rows = [
            score(&label(0), Some(&[]), 1.0).unwrap(),
            score(&label(1), None, 1.0).unwrap(),
        ];
        let summary = metrics::summary(&rows);
        assert!(
            summary["successful"] == 1 && summary["attempted"] == 2,
            "W22_PARTIAL"
        );
        let reported = report_rows(&rows);
        assert!(
            reported
                .iter()
                .all(|row| row["top10_urls_in_sample"].is_null()
                    && row["failed_attempt_ms"].is_null()),
            "W22_UNMEASURED_FIELDS"
        );
        let item = Measurement {
            suite: "frozen".into(),
            planner: "on".into(),
            surface: "beta".into(),
            revision: "a".repeat(40),
            historical: true,
            run: Asset {
                path: PathBuf::new(),
                sha256: String::new(),
            },
            raw: Asset {
                path: PathBuf::new(),
                sha256: String::new(),
            },
        };
        assert!(
            measured(&item, &crate::fixtures::plan()).is_err(),
            "W22_HISTORICAL"
        );
        assert!(!measured_ready(&[]), "W22_ABSENT_CELLS");
        assert!(
            !costs_ready(&json!({"complete_matrix":true,"rows":[{
                "normalized":{"wall_h_per_million":null}}]})),
            "W22_FAILED_COST"
        );
        assert!(
            results_markdown(&json!({"measurements":[],"costs":[]}))
                .contains("Missing values are NOT RUN"),
            "W22_TABLE_MISSING"
        );
    }

    /// Recompute protected matches and reject a stale run that merely changes its cell label.
    fn paired_and_provenance() {
        let rows: Vec<_> = (0..50)
            .map(|n| {
                let label = label(n);
                score(&label, Some(&label.acceptable_urls), 1.0).unwrap()
            })
            .collect();
        let mut cells = Vec::new();
        for set in ["frozen", "held-out"] {
            for (surface, planner) in [("beta", "off"), ("beta", "on"), ("v1", "on")] {
                cells.push(json!({"suite":set,"surface":surface,"planner":planner,
                    "acceptance":{"passed":true},"paired_rows":rows,
                    "sol":{"scorable":50,"acceptance":{"passed":true}}}));
            }
        }
        assert!(measured_ready(&cells), "W22_PAIRED_VALID");
        cells[1]["paired_rows"][0] = json!(score(&label(0), Some(&[]), 1.0).unwrap());
        assert!(!measured_ready(&cells), "W22_PROTECTED_MATCH");
        let temp = Temp::new();
        let mut plan = crate::fixtures::plan();
        let raw = temp.asset("raw.json", b"[]");
        let config = temp.asset("config", b"synthetic");
        let out = Out(temp.0.clone());
        plan.candidate_revision = Some("a".repeat(40));
        seal_run(
            &plan,
            &out,
            ("frozen", "v1", "on"),
            raw.clone(),
            vec![config.clone()],
            vec![raw.clone()],
        )
        .unwrap();
        let path = temp.0.join("frozen-v1-on.run.json");
        let run = Asset {
            sha256: input::hash_file(&path).unwrap(),
            path,
        };
        plan.inputs.push(NamedAsset {
            name: "measurement-runs".into(),
            asset: temp.asset("runs.json", &serde_json::to_vec(&vec![&run]).unwrap()),
        });
        let mut item = Measurement {
            suite: "frozen".into(),
            surface: "v1".into(),
            planner: "on".into(),
            revision: "a".repeat(40),
            historical: false,
            raw,
            run,
        };
        assert!(provenance(&item, &plan).is_ok(), "W22_PROVENANCE_VALID");
        item.planner = "off".into();
        assert!(provenance(&item, &plan).is_err(), "W22_STALE_RUN");
    }

    /// Drive the actual report with numeric and missing raw cost measurements.
    fn report_rendered_values() {
        let temp = Temp::new();
        let mut plan = crate::fixtures::plan();
        let original = temp.asset("original", b"synthetic original");
        let selected = temp.asset("selected", b"synthetic selected");
        let selection_value = json!({"segment":"123.4", "url":"https://example.test/warc"});
        let selection = temp.asset(
            "selection.json",
            &serde_json::to_vec(&selection_value).unwrap(),
        );
        downloaded_fixture(&temp, &mut plan, &selected, &selection_value);
        let binding = json!({"original":{"segment":"1786091384908.68","warc":original},
            "selected":{"segment":"123.4","warc":selected},"selection":selection});
        plan.inputs.push(NamedAsset {
            name: "cost-segments".into(),
            asset: temp.asset("segments.json", &serde_json::to_vec(&binding).unwrap()),
        });
        let cost_row = |hash: &str, failed| {
            json!({"warc_sha256":hash,"batch_size":512,
            "run":1,"documents":1000,"index_candidates":1000,"parse_errors":0,
            "wall_seconds":0.0,"user_cpu_seconds":0.0,"system_cpu_seconds":0.0,
            "final_disk_bytes":0,"peak_rss_bytes":4096,"failed":failed,
            "reap_certain":true,"timed_out":false,"descendants_remained":false,"exit_code":0})
        };
        let cost = temp.asset(
            "cost.json",
            &serde_json::to_vec(&json!({"schema_version":1,
            "rows":[cost_row(&original.sha256, false), cost_row(&selected.sha256, true)]}))
            .unwrap(),
        );
        let index = temp.asset(
            "index.json",
            &serde_json::to_vec(&json!({"receipts":[],
            "measurements":[],"costs":[cost]}))
            .unwrap(),
        );
        let gates = temp.asset("gates.json", &serde_json::to_vec(&test_gates()).unwrap());
        let out = Out::new(&temp.0.join("report"), &plan).unwrap();
        assert!(
            report(&plan, &out, &gates.path, &index.path).is_ok(),
            "W22_REPORT_VALUES"
        );
        let text = fs::read_to_string(out.0.join("RESULTS.md")).unwrap();
        let expected = format!(
            "| {} | 512 | 1 | NOT RUN | NOT RUN | NOT RUN |",
            selected.sha256
        );
        assert!(
            text.lines().any(|line| line == expected),
            "W22_RENDER_NOT_RUN"
        );
        let expected = format!("| {} | 512 | 1 | 0.0 | 0.0 | 0.0 |", original.sha256);
        assert!(text.lines().any(|line| line == expected), "W22_RENDER_SOME");
        assert!(
            text.contains("| held-out | v1 | on | NOT RUN |"),
            "W22_FULL_MATRIX"
        );
        let memo: Value =
            serde_json::from_slice(&fs::read(out.0.join("memo.json")).unwrap()).unwrap();
        assert!(
            memo["columns"]["engineering"]["count"].as_u64().unwrap() > 0,
            "W22_MEMO_AMBER"
        );
        selected_report_case(&temp, &mut plan, &binding, &cost, &gates);
    }

    /// Resealing both the binding and cost rows leaves the download hash as the sole mismatch.
    fn selected_report_case(
        temp: &Temp,
        plan: &mut Plan,
        binding: &Value,
        cost: &Asset,
        gates: &Asset,
    ) {
        let other = temp.asset("different-warc", b"different synthetic WARC");
        let mut binding = binding.clone();
        let old = binding["selected"]["warc"]["sha256"].clone();
        binding["selected"]["warc"] = json!(other);
        let mut costs: Value = cost.read().unwrap();
        for row in costs["rows"].as_array_mut().unwrap() {
            if row["warc_sha256"] == old {
                row["warc_sha256"] = json!(other.sha256);
            }
        }
        let cost = temp.asset("changed-cost", &serde_json::to_vec(&costs).unwrap());
        let index = temp.asset(
            "changed-index",
            &serde_json::to_vec(&json!({
            "receipts":[],"measurements":[],"costs":[cost]}))
            .unwrap(),
        );
        plan.inputs.retain(|entry| entry.name != "cost-segments");
        plan.inputs.push(NamedAsset {
            name: "cost-segments".into(),
            asset: temp.asset("changed-segments", &serde_json::to_vec(&binding).unwrap()),
        });
        let out = Out::new(&temp.0.join("changed-report"), plan).unwrap();
        assert!(
            report(plan, &out, &gates.path, &index.path) == Err(Error::Invalid),
            "W22_SELECTED_WARC"
        );
    }

    /// Use the actual transfer and download schemas to bind synthetic cost inputs.
    fn downloaded_fixture(temp: &Temp, plan: &mut Plan, warc: &Asset, selection: &Value) {
        let receipt = temp.asset(
            "transfer.json",
            &serde_json::to_vec(&json!({
            "complete":true,"http_status":200,"url":selection["url"],
            "sha256":warc.sha256,"bytes":fs::metadata(&warc.path).unwrap().len()}))
            .unwrap(),
        );
        let download = temp.asset(
            "download.json",
            &serde_json::to_vec(&json!({
            "warc":warc,"receipt":receipt}))
            .unwrap(),
        );
        plan.inputs.extend([
            NamedAsset {
                name: "cc-download".into(),
                asset: download,
            },
            NamedAsset {
                name: "cc-download-receipt".into(),
                asset: receipt,
            },
        ]);
        assert!(
            selected_download(warc, selection, plan).is_ok(),
            "W22_DOWNLOAD_VALID"
        );
    }

    /// Drive security findings, time-critical rows and memo/link checks through report itself.
    fn report_security_paths() {
        let temp = Temp::new();
        let plan = crate::fixtures::plan();
        let review = json!({"reviewer":"synthetic","scope":["synthetic scope"],
            "findings":[{"id":"SB-01","severity":"High","file_line":"synthetic.rs:1",
                "owner":"engineering"}]});
        let asset = temp.asset("review.json", &serde_json::to_vec(&review).unwrap());
        let index = temp.asset(
            "index.json",
            &serde_json::to_vec(&json!({"receipts":[],
            "measurements":[],"costs":[],"security_reviews":[asset]}))
            .unwrap(),
        );
        let mut gates = test_gates();
        let question = gates.rows.iter_mut().find(|r| r.id == "Q-08").unwrap();
        question.timing = "ongoing".into();
        question.time_critical = false;
        let ordinary = temp.asset("ordinary-gates", &serde_json::to_vec(&gates).unwrap());
        let ordinary_out = Out::new(&temp.0.join("ordinary-report"), &plan).unwrap();
        report(&plan, &ordinary_out, &ordinary.path, &index.path).unwrap();
        let value: Value =
            serde_json::from_slice(&fs::read(ordinary_out.0.join("results.json")).unwrap())
                .unwrap();
        assert!(
            value["rows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["id"] == "Q-08" && row["status"] == "AMBER"),
            "W22_TIME_ORDINARY"
        );
        gates
            .rows
            .iter_mut()
            .find(|r| r.id == "Q-08")
            .unwrap()
            .time_critical = true;
        let gates = temp.asset("gates.json", &serde_json::to_vec(&gates).unwrap());
        let out = Out::new(&temp.0.join("report"), &plan).unwrap();
        report(&plan, &out, &gates.path, &index.path).unwrap();
        let value: Value =
            serde_json::from_slice(&fs::read(out.0.join("results.json")).unwrap()).unwrap();
        assert!(
            value["rows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["id"] == "Q-08" && row["status"] == "RED"),
            "W22_TIME_CRITICAL"
        );
        assert!(
            value["release_recommendation"] == "NO-GO"
                && ["SB-01"].iter().all(|id| value["rows"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["id"] == *id && row["status"] == "RED")),
            "W22_SECURITY_RED"
        );
        let agpl: Vec<_> = value["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| {
                ["AGPL-OFFER", "LIC-01", "LIC-03"]
                    .iter()
                    .any(|id| row["id"] == *id)
            })
            .cloned()
            .collect();
        assert!(
            agpl.len() == 3 && memo(&json!({"rows":agpl}))["columns"]["founder"]["count"] == 1,
            "W22_AGPL_ONCE"
        );
        memo_lines_case(&out);
        let markdown = fs::read_to_string(out.0.join("RELEASE-GATES.md")).unwrap();
        assert!(validate_links(&markdown, &out).is_ok(), "W22_LINKS_VALID");
        fs::remove_file(out.0.join("gate-SB-01.json")).unwrap();
        assert!(validate_links(&markdown, &out).is_err(), "W22_LINK_MISSING");
        for (field, invalid) in [("severity", "Info"), ("owner", "founder")] {
            let mut wrong = review.clone();
            wrong["findings"][0][field] = json!(invalid);
            let asset = temp.asset(
                &format!("invalid-{field}.json"),
                &serde_json::to_vec(&wrong).unwrap(),
            );
            assert!(
                security_rows(&mut json!({"rows":[]}), &[asset]).is_err(),
                "W22_BAD_FINDING"
            );
        }
    }

    /// Required policy caveats remain exact independently of the memo implementation.
    fn memo_lines_case(out: &Out) {
        let text = fs::read_to_string(out.0.join("MEMO.md")).unwrap();
        assert!(
            text.contains(concat!(
                "Operator: US entity TBD; no UK-based operation; ",
                "UK/EU/EEA/CH users served; this checklist enumerates the #574 UK baseline only."
            )),
            "W22_JURISDICTION"
        );
        assert!(
            text.contains(concat!("The original held-out labels are saturated ",
            "(planner-on 50/50 in #618) and their queries were written from the labelled pages. ",
            "A held-out PASS on original labels is not generalisation evidence. ",
            "The Sol-label held-out score is the primary quality reading.")),
            "W22_SATURATION"
        );
    }
}
