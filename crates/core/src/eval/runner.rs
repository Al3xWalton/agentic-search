// SPDX-License-Identifier: AGPL-3.0-only
//! Sequential fresh-connection HTTP measurements with the frozen runner's timing boundary.
//! All inputs and output reservations precede networking; raw writes precede scoring.
//! The runner never retries, follows redirects, resolves names, or fetches returned URLs.

use super::{
    endpoint::Endpoint,
    input,
    labels::{Corpus, Labels},
    metrics::{self, Row},
    output::{self, Output},
    EvalError, Planner, Recall, Suite,
};
use serde_json::{json, Value};
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

/// Maximum streamed HTTP body size, in bytes (8 MiB).
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
/// Whole-attempt network deadline, in seconds, including all body chunks.
pub const TIMEOUT_SECONDS: u64 = 60;
/// Maximum successful complete-attempt duration, in milliseconds, including the raw write.
pub const DEADLINE_MS: f64 = 60_000.0;

/// Exact frozen request shape; planner expectation is deliberately absent.
pub fn request(query: &str) -> Value {
    json!({"query": query, "numResults": 10, "page": 0, "flattenResponse": true, "countResultsExact": true})
}

/// One attempt's bounded raw evidence, before any parsing or scoring.
pub struct Attempt {
    /// Received body prefix up to the response cap, retained on transport failure.
    pub bytes: Vec<u8>,
    /// Received status, including redirects.
    pub status: Option<u16>,
    /// Client milliseconds through connection close and ordinary raw write.
    pub elapsed_ms: f64,
    /// Numeric response file identity.
    pub raw_path: PathBuf,
    /// Safe transport/status/limit failure, if any.
    pub error: Option<EvalError>,
}

/// Run exactly one bounded request. Test callers may inject a smaller deadline or body cap.
/// Durability sync occurs after the timer; normal raw write and connection close occur inside it.
pub async fn attempt(
    endpoint: &Endpoint,
    query: &str,
    output: &Output,
    ordinal: usize,
    timeout: Duration,
    cap: usize,
) -> Result<Attempt, EvalError> {
    let start = Instant::now();
    let (raw_path, mut raw) = output.raw(ordinal)?;
    // Keep received evidence outside the cancellable future so its deadline cannot erase it.
    let mut received_status = None;
    let mut bytes = Vec::new();
    let network = async {
        let client = endpoint.client()?;
        let body = request(query);
        let mut response = client
            .post(format!("{}/beta/api/search", endpoint.base))
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .header(reqwest::header::CONNECTION, "close")
            .json(&body)
            .send()
            .await
            .map_err(|_| EvalError::Network)?;
        let status = response.status().as_u16();
        received_status = Some(status);
        while let Some(chunk) = response.chunk().await.map_err(|_| EvalError::Network)? {
            if bytes.len().checked_add(chunk.len()).is_none_or(|n| n > cap) {
                bytes.extend_from_slice(&chunk[..cap.saturating_sub(bytes.len())]);
                return Err(EvalError::ResponseLimit);
            }
            bytes.extend_from_slice(&chunk);
        }
        drop(response);
        drop(client);
        Ok::<_, EvalError>(status)
    };
    let result = tokio::time::timeout(timeout, network)
        .await
        .unwrap_or(Err(EvalError::Timeout));
    let error = match result {
        Ok(status) => (!(200..300).contains(&status)).then_some(EvalError::HttpStatus),
        Err(error) => Some(error),
    };
    let elapsed_ms = write_timed(&mut raw, &bytes, || start.elapsed().as_secs_f64() * 1000.0)?;
    let error = finish_attempt(elapsed_ms, DEADLINE_MS, error);
    raw.sync_all().map_err(|_| EvalError::Io)?;
    Ok(Attempt {
        bytes,
        status: received_status,
        elapsed_ms,
        raw_path,
        error,
    })
}

/// Fail a previously successful attempt exceeding its total deadline, in milliseconds.
/// Equality is permitted and existing errors are preserved; callers retain the raw bytes.
pub fn finish_attempt(
    elapsed_ms: f64,
    deadline_ms: f64,
    error: Option<EvalError>,
) -> Option<EvalError> {
    error.or_else(|| (elapsed_ms > deadline_ms).then_some(EvalError::Timeout))
}

/// Finish the ordinary raw write before sampling client elapsed milliseconds.
/// The injected clock observes the same ordering in deterministic writer witnesses.
pub fn write_timed(
    writer: &mut impl Write,
    bytes: &[u8],
    elapsed: impl FnOnce() -> f64,
) -> Result<f64, EvalError> {
    writer.write_all(bytes).map_err(|_| EvalError::Io)?;
    Ok(elapsed())
}

/// Validate returned mode and completed-stage producer attribution before scoring.
pub fn response(
    value: &Value,
    expected: Planner,
) -> Result<(Vec<String>, Value, Vec<String>, f64), EvalError> {
    let plan = value.get("queryPlan").ok_or(EvalError::InvalidResponse)?;
    let expected_mode = match expected {
        Planner::Off => "strict_only",
        Planner::On => "staged",
    };
    if plan["mode"] != expected_mode || plan["version"] != 1 {
        return Err(EvalError::InvalidResponse);
    }
    let stages = plan["stages"]
        .as_array()
        .ok_or(EvalError::InvalidResponse)?;
    if stages.is_empty() || stages.len() > 4 || stages[0]["id"] != "strict" {
        return Err(EvalError::InvalidResponse);
    }
    let mut previous = None;
    for stage in stages {
        let id = stage["id"].as_str().ok_or(EvalError::InvalidResponse)?;
        let ordinal = ["strict", "content", "relaxed", "core"]
            .iter()
            .position(|s| *s == id)
            .ok_or(EvalError::InvalidResponse)?;
        if previous.is_some_and(|p| ordinal <= p)
            || stage["renderedQuery"].as_str().is_none_or(str::is_empty)
        {
            return Err(EvalError::InvalidResponse);
        }
        previous = Some(ordinal);
    }
    if expected == Planner::Off && stages.len() != 1 {
        return Err(EvalError::InvalidResponse);
    }
    let pages = value["webpages"]
        .as_array()
        .ok_or(EvalError::InvalidResponse)?;
    let mut urls = Vec::new();
    let mut producers = Vec::new();
    for page in pages.iter().take(10) {
        urls.push(
            page["url"]
                .as_str()
                .ok_or(EvalError::InvalidResponse)?
                .to_owned(),
        );
        let producer = page["planStage"]
            .as_str()
            .ok_or(EvalError::InvalidResponse)?;
        if !stages.iter().any(|s| s["id"] == producer) {
            return Err(EvalError::InvalidResponse);
        }
        producers.push(producer.to_owned());
    }
    let server = value["searchDurationMs"]
        .as_f64()
        .filter(|n| n.is_finite() && *n >= 0.0)
        .ok_or(EvalError::InvalidResponse)?;
    Ok((urls, json!(stages), producers, server))
}

fn git(args: &[&str]) -> Result<Vec<u8>, EvalError> {
    let result = Command::new("git")
        .args(args)
        .output()
        .map_err(|_| EvalError::Io)?;
    if !result.status.success() {
        return Err(EvalError::IdentityMismatch);
    }
    Ok(result.stdout)
}

fn executable() -> Result<Value, EvalError> {
    let path = std::env::current_exe().map_err(|_| EvalError::Io)?;
    let revision =
        String::from_utf8(git(&["rev-parse", "HEAD"])?).map_err(|_| EvalError::InvalidInput)?;
    let root = output::product_root()?;
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    digest.update(&git(&["diff", "--binary", "HEAD"])?);
    let files = git(&[
        "ls-files",
        "--full-name",
        "--others",
        "--exclude-standard",
        "-z",
    ])?;
    for name in files.split(|b| *b == 0).filter(|b| !b.is_empty()) {
        let name = std::str::from_utf8(name).map_err(|_| EvalError::UnsafePath)?;
        let file = input::read(&root.join(name))?;
        digest.update(&(name.len() as u64).to_le_bytes());
        digest.update(name.as_bytes());
        digest.update(&(file.bytes.len() as u64).to_le_bytes());
        digest.update(&file.bytes);
    }
    let dirty_sha256: String = digest
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(
        json!({"path": path, "sha256": input::hash_file(&path)?, "revision": revision.trim_end(), "dirty_tree_sha256": dirty_sha256, "product_root": root}),
    )
}

fn identity(path: &Path) -> Result<(input::Document, Value), EvalError> {
    let doc = input::read(path)?;
    let identity = json!({"path": doc.path, "sha256": doc.sha256});
    Ok((doc, identity))
}

/// Require service membership and each index count to match the supplied corpus export order.
/// Aggregate equality alone cannot conceal a missing or swapped shard.
pub fn validate_identities(
    corpus: &Corpus,
    service: &Value,
    indexes: &[Value],
) -> Result<(), EvalError> {
    let shards = service["shards"]
        .as_array()
        .ok_or(EvalError::IdentityMismatch)?;
    if service["verified"] != true
        || service["total_documents"].as_u64() != Some(corpus.total as u64)
        || shards.len() != corpus.files.len()
        || indexes.len() != corpus.files.len()
    {
        return Err(EvalError::IdentityMismatch);
    }
    for (ordinal, ((shard, index), export)) in
        shards.iter().zip(indexes).zip(&corpus.files).enumerate()
    {
        let count = export["records"]
            .as_u64()
            .ok_or(EvalError::IdentityMismatch)?;
        if shard["shard_id"].as_u64() != Some(ordinal as u64)
            || shard["documents"].as_u64() != Some(count)
            || index["manifest"]["documents"].as_u64() != Some(count)
        {
            return Err(EvalError::IdentityMismatch);
        }
        Endpoint::shard(
            shard["socket"]
                .as_str()
                .ok_or(EvalError::IdentityMismatch)?,
        )?;
    }
    Ok(())
}

async fn run_rows(
    endpoint: &Endpoint,
    labels: &Labels,
    corpus: &Corpus,
    output: &Output,
    planner: Planner,
) -> Result<Vec<Row>, EvalError> {
    let mut rows = Vec::new();
    for (ordinal, label) in labels.rows.iter().enumerate() {
        let attempt = attempt(
            endpoint,
            &label.query,
            output,
            ordinal,
            Duration::from_secs(TIMEOUT_SECONDS),
            MAX_RESPONSE_BYTES,
        )
        .await?;
        let result = (|| {
            if let Some(error) = attempt.error {
                return Err(error);
            }
            let value: Value =
                serde_json::from_slice(&attempt.bytes).map_err(|_| EvalError::InvalidResponse)?;
            let (urls, stages, producers, server) = response(&value, planner)?;
            let mut row = Row::score(label, &urls, &corpus.urls, attempt.elapsed_ms, Some(server))?;
            row.stages = Some(stages);
            row.plan_stages = Some(producers);
            Ok(row)
        })();
        let mut row = match result {
            Ok(row) => row,
            Err(error) => Row::failed(label, error, attempt.elapsed_ms)?,
        };
        row.http_status = attempt.status;
        row.raw_path = Some(
            attempt
                .raw_path
                .to_str()
                .ok_or(EvalError::UnsafePath)?
                .to_owned(),
        );
        row.raw_sha256 = Some(input::sha256(&attempt.bytes));
        rows.push(row);
    }
    Ok(rows)
}

/// Execute a complete cell, retain failed rows, then exit nonzero after writing failed acceptance.
pub async fn run(args: Recall) -> Result<(), EvalError> {
    use super::Argument;
    let endpoint = Endpoint::parse(&args.endpoint)?;
    let mut paths = vec![args.labels.clone(), args.service_manifest.clone()];
    paths.extend(args.corpus_jsonl.iter().cloned());
    paths.extend(args.index_manifest.iter().cloned());
    paths.extend(args.config.iter().cloned());
    output::external(&args.out, &paths)?;
    let output = Output::reserve(&args.out, true).map_err(|e| e.argument(Argument::Out))?;
    let labels = Labels::read(&args.labels, &args.labels_sha256)
        .map_err(|e| e.argument(Argument::Labels))?;
    if args.suite != Suite::Diagnostic {
        labels.protocol(args.suite == Suite::HeldOut)?;
    }
    let corpus = Corpus::read(&args.corpus_jsonl).map_err(|e| e.argument(Argument::Corpus))?;
    labels.membership(&corpus, None)?;
    let mut documents = Vec::new();
    let (served, served_identity) =
        identity(&args.service_manifest).map_err(|e| e.argument(Argument::ServiceManifest))?;
    let service: Value = serde_json::from_slice(&served.bytes)
        .map_err(|_| EvalError::InvalidInput.argument(Argument::ServiceManifest))?;
    if service["verified"] != true
        || service["total_documents"].as_u64() != Some(corpus.total as u64)
    {
        return Err(EvalError::IdentityMismatch);
    }
    documents.push(served);
    let mut indexes = Vec::new();
    let mut index_count = 0u64;
    for path in &args.index_manifest {
        let (doc, id) = identity(path).map_err(|e| e.argument(Argument::IndexManifest))?;
        let value: Value = serde_json::from_slice(&doc.bytes)
            .map_err(|_| EvalError::InvalidInput.argument(Argument::IndexManifest))?;
        index_count = index_count
            .checked_add(
                value["documents"]
                    .as_u64()
                    .ok_or(EvalError::IdentityMismatch)?,
            )
            .ok_or(EvalError::IdentityMismatch)?;
        indexes.push(json!({"identity": id, "manifest": value}));
        documents.push(doc);
    }
    if index_count != corpus.total as u64 {
        return Err(EvalError::IdentityMismatch);
    }
    validate_identities(&corpus, &service, &indexes)?;
    if args.suite != Suite::Diagnostic
        && (corpus.files.len() != 2
            || corpus.files[0]["records"] != 19285
            || corpus.files[1]["records"] != 178
            || corpus.urls.len() != 19463)
    {
        return Err(EvalError::IdentityMismatch);
    }
    let mut configs = Vec::new();
    for path in &args.config {
        let (doc, id) = identity(path).map_err(|e| e.argument(Argument::Config))?;
        let text = std::str::from_utf8(&doc.bytes)
            .map_err(|_| EvalError::InvalidInput.argument(Argument::Config))?;
        let value: toml::Value =
            toml::from_str(text).map_err(|_| EvalError::InvalidInput.argument(Argument::Config))?;
        if value.get("index_path").is_some() {
            let _: crate::config::SearchServerConfig = toml::from_str(text)
                .map_err(|_| EvalError::InvalidInput.argument(Argument::Config))?;
        } else {
            let config: crate::config::ApiConfig = toml::from_str(text)
                .map_err(|_| EvalError::InvalidInput.argument(Argument::Config))?;
            if config.agent_query_planning != (args.expect_planner == Planner::On) {
                return Err(EvalError::IdentityMismatch);
            }
        }
        configs.push(json!({"identity": id, "resolved": value}));
        documents.push(doc);
    }
    let executable = executable()?;
    let started = chrono::Utc::now().to_rfc3339();
    let rows = run_rows(&endpoint, &labels, &corpus, &output, args.expect_planner).await?;
    corpus.verify_unchanged()?;
    input::verify(&args.labels, &args.labels_sha256)?;
    for doc in &documents {
        input::verify(&doc.path, &doc.sha256)?;
    }
    let summary = metrics::summary(&rows);
    let acceptance = metrics::acceptance(&rows, args.suite, args.expect_planner);
    let passed = acceptance["passed"] != false && rows.iter().all(|r| r.success);
    output.finish(&json!({"schema_version": 1, "metric_version": "spike573-v1", "labels": {"path": labels.document.path, "sha256": args.labels_sha256, "metadata": labels.metadata}, "executable": executable, "corpus": corpus.manifest(), "service": {"identity": served_identity, "manifest": service}, "indexes": indexes, "configs": configs, "request": {"numResults": 10, "page": 0, "flattenResponse": true, "countResultsExact": true}, "endpoint": endpoint.base, "planner_expectation": args.expect_planner, "suite": args.suite, "cell": args.cell, "started_at_utc": started, "timing_policy": "monotonic; start before fresh client and JSON; stop after connection close and ordinary raw write; raw sync after timer; sequential HTTP/1; identity encoding; 60s whole attempt; no retries", "rows": rows, "summary": summary, "acceptance": acceptance}))?;
    if passed {
        Ok(())
    } else {
        Err(EvalError::AcceptanceFailed)
    }
}
