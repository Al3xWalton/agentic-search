// SPDX-License-Identifier: AGPL-3.0-only
//! Compare complete run identities by label id, including the read-only spike573 format.
//! Semantic label changes fail closed; imported rows retain absent provenance explicitly.
//! A diff does not rerun queries, infer omitted results, or treat summary medians as paired data.

use super::{
    input,
    labels::Labels,
    metrics::{self, Row},
    normalize::normalize,
    output::{self, Output},
    EvalError,
};
use clap::{Args, ValueEnum};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

/// Explicit input schema, never inferred from filename or query ids.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum Format {
    /// Native schema-version-one evaluator envelope.
    Native,
    /// Frozen spike rows with only their stract measurements imported.
    Spike573,
}

/// Paired diff inputs and private output.
#[derive(Debug, Args)]
pub struct Arguments {
    /// Earlier run or frozen spike metrics.
    #[arg(long)]
    pub before: PathBuf,
    /// Later native run.
    #[arg(long)]
    pub after: PathBuf,
    /// Explicit earlier format.
    #[arg(long, value_enum, default_value = "native")]
    pub before_format: Format,
    /// Required frozen labels for the spike adapter.
    #[arg(long)]
    pub labels: Option<PathBuf>,
    /// Absolute create-new output report.
    #[arg(long)]
    pub out: PathBuf,
}

fn native(value: &Value) -> Result<Vec<Row>, EvalError> {
    if value["schema_version"] != 1 || value["metric_version"] != "spike573-v1" {
        return Err(EvalError::IdentityMismatch);
    }
    let _: super::Suite =
        serde_json::from_value(value["suite"].clone()).map_err(|_| EvalError::IdentityMismatch)?;
    let _: super::Planner = serde_json::from_value(value["planner_expectation"].clone())
        .map_err(|_| EvalError::IdentityMismatch)?;
    let array = value["rows"].as_array().ok_or(EvalError::InvalidInput)?;
    if array.len() > input::MAX_LABELS {
        return Err(EvalError::LabelLimit);
    }
    let rows: Vec<Row> =
        serde_json::from_value(value["rows"].clone()).map_err(|_| EvalError::InvalidInput)?;
    for row in &rows {
        if row.acceptable_urls.len() > input::MAX_ANSWERS
            || row.acceptable_urls.is_empty()
            || row.top10_urls.len() > 10
        {
            return Err(EvalError::InvalidInput);
        }
        for url in row
            .top10_urls
            .iter()
            .chain(&row.matched_urls)
            .chain(&row.acceptable_urls)
        {
            normalize(url)?;
        }
        if row.success != row.recall_at_10.is_some()
            || (row.success && row.latency_ms.is_none())
            || (!row.success
                && (row.latency_ms.is_some()
                    || row.server_duration_ms.is_some()
                    || !row.top10_urls.is_empty()
                    || row.zero_results))
        {
            return Err(EvalError::InvalidInput);
        }
    }
    Ok(rows)
}

/// Import frozen measurements without changing numbers or inventing legacy stage attribution.
pub fn spike(value: &Value, labels: &Labels) -> Result<Vec<Row>, EvalError> {
    if value["answer_set_sha256"] != labels.document.sha256 {
        return Err(EvalError::IdentityMismatch);
    }
    let source = value["rows"]
        .as_array()
        .ok_or(EvalError::IdentityMismatch)?;
    if source.len() != labels.rows.len() {
        return Err(EvalError::IdentityMismatch);
    }
    let mut rows = Vec::new();
    let mut ids = BTreeSet::new();
    for outer in source {
        let id = outer["id"].as_str().ok_or(EvalError::IdentityMismatch)?;
        if !ids.insert(id) {
            return Err(EvalError::IdentityMismatch);
        }
        let label = labels
            .rows
            .iter()
            .find(|r| r.id == id)
            .ok_or(EvalError::IdentityMismatch)?;
        let answers: Vec<String> = serde_json::from_value(outer["answers"].clone())
            .map_err(|_| EvalError::IdentityMismatch)?;
        let normalized: BTreeSet<_> = answers
            .iter()
            .map(|u| normalize(u))
            .collect::<Result<_, _>>()
            .map_err(|_| EvalError::IdentityMismatch)?;
        if outer["query"] != label.query
            || outer["category"] != label.category
            || normalized != label.answers()?
        {
            return Err(EvalError::IdentityMismatch);
        }
        let old = &outer["stract"];
        let mut row = Row::failed(
            label,
            EvalError::Network,
            old["failed_attempt_ms"].as_f64().unwrap_or(0.0),
        )?;
        if old["success"]
            .as_bool()
            .ok_or(EvalError::IdentityMismatch)?
        {
            row.success = true;
            row.error = None;
            row.failed_attempt_ms = None;
            row.recall_at_10 = Some(
                old["recall_at_10"]
                    .as_f64()
                    .ok_or(EvalError::IdentityMismatch)?,
            );
            row.latency_ms = Some(
                old["latency_ms"]
                    .as_f64()
                    .ok_or(EvalError::IdentityMismatch)?,
            );
            row.server_duration_ms = old["server_duration_ms"].as_f64();
            row.top10_urls = serde_json::from_value(old["top10_urls"].clone())
                .map_err(|_| EvalError::IdentityMismatch)?;
            row.matched_urls = serde_json::from_value(old["matched_urls"].clone())
                .map_err(|_| EvalError::IdentityMismatch)?;
            row.top10_urls_in_sample = old["top10_urls_in_sample"]
                .as_u64()
                .ok_or(EvalError::IdentityMismatch)?
                .try_into()
                .map_err(|_| EvalError::IdentityMismatch)?;
            let answers = label.answers()?;
            let top10: BTreeSet<_> = row
                .top10_urls
                .iter()
                .map(|url| normalize(url))
                .collect::<Result<_, _>>()
                .map_err(|_| EvalError::IdentityMismatch)?;
            let matched: BTreeSet<_> = top10.intersection(&answers).cloned().collect();
            let recall = matched.len() as f64 / answers.len() as f64;
            if row.recall_at_10 != Some(recall)
                || normalized_matches(&row).map_err(|_| EvalError::IdentityMismatch)? != matched
                || row.top10_urls.len() > 10
                || row.top10_urls_in_sample > row.top10_urls.len()
                || row
                    .latency_ms
                    .is_none_or(|value| !value.is_finite() || value < 0.0)
            {
                return Err(EvalError::IdentityMismatch);
            }
            row.zero_results = row.top10_urls.is_empty();
        } else if !["recall_at_10", "latency_ms", "server_duration_ms"]
            .into_iter()
            .all(|key| old.get(key).is_none_or(Value::is_null))
            || !["top10_urls", "matched_urls"].into_iter().all(|key| {
                old.get(key)
                    .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty))
            })
            || old
                .get("top10_urls_in_sample")
                .is_some_and(|value| value.as_u64() != Some(0))
            || old
                .get("zero_results")
                .is_some_and(|value| value.as_bool() != Some(false))
            || old["failed_attempt_ms"]
                .as_f64()
                .is_none_or(|value| !value.is_finite() || value < 0.0)
            || old["error"].as_str().is_none_or(str::is_empty)
        {
            return Err(EvalError::IdentityMismatch);
        }
        rows.push(row);
    }
    Ok(rows)
}

fn normalized_matches(row: &Row) -> Result<BTreeSet<String>, EvalError> {
    row.matched_urls.iter().map(|u| normalize(u)).collect()
}
fn first_stage(row: &Row) -> Option<&str> {
    row.stages
        .as_ref()?
        .as_array()?
        .iter()
        .find(|s| s["producedResults"] == true)?["id"]
        .as_str()
}
fn delta(before: Option<f64>, after: Option<f64>) -> Option<f64> {
    before.zip(after).map(|(b, a)| a - b)
}

/// Join by id and require exact semantic labels; report paired URL gains/losses in before order.
pub fn compare(before: &[Row], after: &[Row]) -> Result<Value, EvalError> {
    let a: BTreeMap<_, _> = after.iter().map(|r| (&r.id, r)).collect();
    if a.len() != after.len()
        || before.len() != after.len()
        || before.iter().map(|r| &r.id).collect::<BTreeSet<_>>().len() != before.len()
    {
        return Err(EvalError::IdentityMismatch);
    }
    let mut rows = Vec::new();
    let mut all_retained = true;
    let mut protected_retained = true;
    for old in before {
        let new = a.get(&old.id).ok_or(EvalError::IdentityMismatch)?;
        if old.query != new.query
            || old.category != new.category
            || old.acceptable_urls != new.acceptable_urls
        {
            return Err(EvalError::IdentityMismatch);
        }
        let old_matches = normalized_matches(old)?;
        let new_matches = normalized_matches(new)?;
        let gained: Vec<_> = new_matches.difference(&old_matches).cloned().collect();
        let lost: Vec<_> = old_matches.difference(&new_matches).cloned().collect();
        all_retained &= lost.is_empty();
        if ["factual", "image_bearing"].contains(&old.category.as_str()) {
            protected_retained &= lost.is_empty();
        }
        rows.push(json!({"id": old.id, "category": old.category, "recall_delta": delta(old.recall_at_10, new.recall_at_10), "zero_results_before": old.zero_results, "zero_results_after": new.zero_results, "latency_delta_ms": delta(old.latency_ms, new.latency_ms), "gained_matches": gained, "lost_matches": lost, "first_producing_stage_before": first_stage(old), "first_producing_stage_after": first_stage(new)}));
    }
    let old = metrics::summary(before);
    let new = metrics::summary(after);
    let categories: Vec<_> = old["categories"].as_array().ok_or(EvalError::InvalidInput)?.iter().map(|b| {
        let a = new["categories"].as_array().and_then(|cats| cats.iter().find(|c| c["category"] == b["category"]));
        json!({"category": b["category"], "recall_delta": delta(b["recall_at_10"].as_f64(), a.and_then(|c| c["recall_at_10"].as_f64()))})
    }).collect();
    Ok(
        json!({"rows": rows, "before_summary": old, "after_summary": new, "recall_delta": delta(old["recall_at_10"].as_f64(), new["recall_at_10"].as_f64()), "category_deltas": categories, "previous_matches_retained": all_retained, "protected_matches_retained": protected_retained, "complete_successful_pair": before.len() == 50 && before.iter().chain(after).all(|r| r.success)}),
    )
}

/// Read both bounded inputs, compare identities, and write one create-new diff artifact.
pub fn run(args: Arguments) -> Result<(), EvalError> {
    use super::Argument;
    let mut inputs = vec![args.before.clone(), args.after.clone()];
    inputs.extend(args.labels.iter().cloned());
    output::external(&args.out, &inputs)?;
    let output = Output::reserve(&args.out, false).map_err(|e| e.argument(Argument::Out))?;
    let before_doc = input::read(&args.before).map_err(|e| e.argument(Argument::Before))?;
    let after_doc = input::read(&args.after).map_err(|e| e.argument(Argument::After))?;
    let before: Value = serde_json::from_slice(&before_doc.bytes)
        .map_err(|_| EvalError::InvalidInput.argument(Argument::Before))?;
    let after: Value = serde_json::from_slice(&after_doc.bytes)
        .map_err(|_| EvalError::InvalidInput.argument(Argument::After))?;
    let old = if args.before_format == Format::Spike573 {
        let path = args
            .labels
            .as_ref()
            .ok_or(EvalError::InvalidInput.argument(Argument::Labels))?;
        let doc = input::read(path).map_err(|e| e.argument(Argument::Labels))?;
        let labels = Labels::read(path, &doc.sha256).map_err(|e| e.argument(Argument::Labels))?;
        let rows = spike(&before, &labels)?;
        if after["labels"]["sha256"] != labels.document.sha256 {
            return Err(EvalError::IdentityMismatch);
        }
        input::verify(path, &doc.sha256)?;
        rows
    } else {
        if before["labels"]["sha256"] != after["labels"]["sha256"] {
            return Err(EvalError::IdentityMismatch);
        }
        native(&before).map_err(|e| e.argument(Argument::Before))?
    };
    let new = native(&after).map_err(|e| e.argument(Argument::After))?;
    let mut compared = compare(&old, &new)?;
    compared["schema_version"] = json!(1);
    compared["before_format"] = json!(if args.before_format == Format::Spike573 {
        "spike573"
    } else {
        "native"
    });
    compared["inputs"] = json!({"before": {"path": before_doc.path, "sha256": before_doc.sha256}, "after": {"path": after_doc.path, "sha256": after_doc.sha256}});
    compared["identity_changes"] = json!(["corpus", "configs", "indexes", "service", "executable", "cell", "planner_expectation", "endpoint"].iter().map(|key| json!({"field": key, "changed": before[*key] != after[*key], "before": before[*key], "after": after[*key]})).collect::<Vec<_>>());
    compared["acceptance"] = paired_acceptance(&before, &after, &compared)?;
    let passed = compared["acceptance"]["passed"] != false;
    input::verify(&args.before, &before_doc.sha256)?;
    input::verify(&args.after, &after_doc.sha256)?;
    output.finish(&compared)?;
    if passed {
        Ok(())
    } else {
        Err(EvalError::AcceptanceFailed)
    }
}

/// Gate a native off-to-on pair using both cell verdicts and protected-match retention.
/// Reference imports and diagnostic comparisons report metrics without claiming paired acceptance.
pub fn paired_acceptance(
    before: &Value,
    after: &Value,
    compared: &Value,
) -> Result<Value, EvalError> {
    if after["suite"] == "diagnostic" || before["suite"].is_null() {
        return Ok(json!({"claimed": false, "passed": null}));
    }
    if before["suite"] != after["suite"] {
        return Err(EvalError::IdentityMismatch);
    }
    if before["planner_expectation"] != "off" || after["planner_expectation"] != "on" {
        return Ok(json!({"claimed": false, "passed": null}));
    }
    let checks = json!({
        "complete_successful_pair": compared["complete_successful_pair"] == true,
        "off_cell_passed": before["acceptance"]["passed"] == true,
        "protected_matches_retained": compared["protected_matches_retained"] == true,
        "on_cell_passed": after["acceptance"]["passed"] == true
    });
    let passed = checks
        .as_object()
        .ok_or(EvalError::InvalidInput)?
        .values()
        .all(|v| v == true);
    Ok(
        json!({"claimed": true, "passed": passed, "checks": checks, "recall_gain_observed": compared["recall_delta"].as_f64().is_some_and(|v| v > 0.0), "review_required": compared["recall_delta"].as_f64().is_some_and(|v| v < 0.0)}),
    )
}
