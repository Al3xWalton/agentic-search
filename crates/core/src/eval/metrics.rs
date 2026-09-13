// SPDX-License-Identifier: AGPL-3.0-only
//! Frozen per-query recall, raw-slot accounting and unrounded percentile semantics.
//! Failed attempts are excluded from successful denominators but cannot pass acceptance.
//! No domain credit, URL fetch, label repair, or cross-query pooled answer fraction exists here.

use super::{labels::Label, normalize::normalize, EvalError, Planner, Suite};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashSet};

/// One attempt's complete scoring record, in label-file order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    /// Label id used to join paired runs.
    pub id: String,
    /// Validated category.
    pub category: String,
    /// Original query bytes.
    pub query: String,
    /// Normalized distinct denominator identities.
    pub acceptable_urls: BTreeSet<String>,
    /// True only after HTTP, schema, mode and scoring validation succeeds.
    pub success: bool,
    /// Mean-independent per-query recall, null on failure.
    pub recall_at_10: Option<f64>,
    /// First ten raw URLs, before any normalization or filtering.
    pub top10_urls: Vec<String>,
    /// Original matching URL slots, including duplicates, in result order.
    pub matched_urls: Vec<String>,
    /// Client wall milliseconds including raw write, without rounding.
    pub latency_ms: Option<f64>,
    /// Separate server duration, null on failure or unavailable legacy data.
    pub server_duration_ms: Option<f64>,
    /// Duration of failed attempt, excluded from latency percentiles.
    pub failed_attempt_ms: Option<f64>,
    /// Number of raw slots in the corpus, counting duplicate slots.
    pub top10_urls_in_sample: usize,
    /// True only for a successful empty raw top ten.
    pub zero_results: bool,
    /// Copied completed stage records, absent for imported spike rows.
    pub stages: Option<Value>,
    /// One producing stage per raw slot, absent for imported spike rows.
    pub plan_stages: Option<Vec<String>>,
    /// Fixed failure classification, never the offending request text.
    pub error: Option<EvalError>,
    /// HTTP status when a response was received.
    pub http_status: Option<u16>,
    /// Numeric private raw-response path.
    pub raw_path: Option<String>,
    /// SHA-256 of response bytes, including failed HTTP responses.
    pub raw_sha256: Option<String>,
}

impl Row {
    /// Build an unscored failure record; success metrics and scored arrays remain empty.
    pub fn failed(label: &Label, error: EvalError, elapsed: f64) -> Result<Self, EvalError> {
        Ok(Self {
            id: label.id.clone(),
            category: label.category.clone(),
            query: label.query.clone(),
            acceptable_urls: label.answers()?,
            success: false,
            recall_at_10: None,
            top10_urls: vec![],
            matched_urls: vec![],
            latency_ms: None,
            server_duration_ms: None,
            failed_attempt_ms: Some(elapsed),
            top10_urls_in_sample: 0,
            zero_results: false,
            stages: None,
            plan_stages: None,
            error: Some(error),
            http_status: None,
            raw_path: None,
            raw_sha256: None,
        })
    }

    /// Score only the first ten raw slots; malformed URLs fail the entire attempt.
    pub fn score(
        label: &Label,
        urls: &[String],
        corpus: &HashSet<String>,
        latency: f64,
        server: Option<f64>,
    ) -> Result<Self, EvalError> {
        let mut row = Self::failed(label, EvalError::InvalidResponse, latency)?;
        let top10: Vec<String> = urls.iter().take(10).cloned().collect();
        let normalized: Vec<String> = top10
            .iter()
            .map(|u| normalize(u))
            .collect::<Result<_, _>>()?;
        let matches: BTreeSet<_> = normalized
            .iter()
            .filter(|u| row.acceptable_urls.contains(*u))
            .collect();
        row.recall_at_10 = Some(matches.len() as f64 / row.acceptable_urls.len() as f64);
        row.matched_urls = top10
            .iter()
            .zip(&normalized)
            .filter(|(_, u)| row.acceptable_urls.contains(*u))
            .map(|(u, _)| u.clone())
            .collect();
        row.top10_urls_in_sample = normalized.iter().filter(|u| corpus.contains(*u)).count();
        row.zero_results = top10.is_empty();
        row.top10_urls = top10;
        row.latency_ms = Some(latency);
        row.server_duration_ms = server;
        row.failed_attempt_ms = None;
        row.error = None;
        row.success = true;
        Ok(row)
    }
}

/// Unrounded arithmetic mean, null for no successful measurements.
pub fn mean(values: &[f64]) -> Option<f64> {
    (!values.is_empty()).then(|| values.iter().sum::<f64>() / values.len() as f64)
}

/// Median and nearest-rank p95 in milliseconds, null for an empty successful sample.
pub fn percentiles(values: &[f64]) -> (Option<f64>, Option<f64>) {
    if values.is_empty() {
        return (None, None);
    }
    let mut values = values.to_vec();
    values.sort_by(f64::total_cmp);
    let n = values.len();
    let median = if n.is_multiple_of(2) {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    } else {
        values[n / 2]
    };
    let rank = (0.95 * n as f64).ceil() as usize - 1;
    (Some(median), Some(values[rank]))
}

fn aggregate(rows: &[&Row]) -> Value {
    let successful: Vec<_> = rows.iter().filter(|r| r.success).collect();
    let recalls: Vec<_> = successful.iter().filter_map(|r| r.recall_at_10).collect();
    let latencies: Vec<_> = successful.iter().filter_map(|r| r.latency_ms).collect();
    let (p50, p95) = percentiles(&latencies);
    let zeros = successful.iter().filter(|r| r.zero_results).count();
    json!({"attempted": rows.len(), "successful": successful.len(), "failed": rows.len() - successful.len(), "recall_at_10": mean(&recalls), "zero_results": zeros, "zero_result_rate": (!successful.is_empty()).then(|| zeros as f64 / successful.len() as f64), "p50_ms": p50, "p95_ms": p95})
}

/// Overall means and categories in first-appearance order, preserving actual row grouping.
pub fn summary(rows: &[Row]) -> Value {
    let mut value = aggregate(&rows.iter().collect::<Vec<_>>());
    let mut seen = HashSet::new();
    let categories: Vec<Value> = rows
        .iter()
        .filter(|r| seen.insert(r.category.clone()))
        .map(|r| {
            let mut category = aggregate(
                &rows
                    .iter()
                    .filter(|other| other.category == r.category)
                    .collect::<Vec<_>>(),
            );
            category["category"] = json!(r.category);
            category
        })
        .collect();
    value["categories"] = json!(categories);
    value
}

/// Apply only the explicit suite/cell's gates; paired match retention remains a diff gate.
pub fn acceptance(rows: &[Row], suite: Suite, planner: Planner) -> Value {
    if suite == Suite::Diagnostic {
        return json!({"claimed": false, "passed": null, "reason": "diagnostic"});
    }
    let summary = summary(rows);
    let complete = rows.len() == 50
        && rows.iter().all(|r| r.success)
        && rows.iter().map(|r| &r.id).collect::<HashSet<_>>().len() == 50;
    let mut checks = serde_json::Map::new();
    checks.insert("all_50_successful".into(), json!(complete));
    if planner == Planner::On {
        checks.insert(
            "p95_below_50_ms".into(),
            json!(summary["p95_ms"].as_f64().is_some_and(|v| v < 50.0)),
        );
        if suite == Suite::HeldOut {
            checks.insert(
                "recall_above_036".into(),
                json!(summary["recall_at_10"].as_f64().is_some_and(|v| v > 0.36)),
            );
            checks.insert(
                "zero_rate_below_010".into(),
                json!(summary["zero_result_rate"]
                    .as_f64()
                    .is_some_and(|v| v < 0.10)),
            );
        } else {
            for cat in ["factual", "image_bearing"] {
                let recall = summary["categories"]
                    .as_array()
                    .and_then(|cats| cats.iter().find(|c| c["category"] == cat))
                    .and_then(|c| c["recall_at_10"].as_f64());
                checks.insert(
                    format!("{cat}_at_least_070"),
                    json!(recall.is_some_and(|v| v >= 0.7)),
                );
            }
        }
    } else if suite == Suite::Frozen {
        checks.insert(
            "recall_equals_18_of_50".into(),
            json!(summary["recall_at_10"].as_f64() == Some(18.0 / 50.0)),
        );
        checks.insert(
            "zero_count_equals_19".into(),
            json!(summary["zero_results"] == 19),
        );
    }
    let passed = checks.values().all(|v| v == true);
    json!({"claimed": true, "passed": passed, "checks": checks, "paired_diff_required": planner == Planner::On})
}
