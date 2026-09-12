//! Runs the explicitly authorized frozen research sample through ordinary ingestion policy.
//! The sealed live capability admits exactly the retained 200-seed set; the separate fixture entry
//! accepts only an owned loopback descriptor. Neither capability issues a production permit or a
//! legal exemption. There is no discovery, S3, image fetch, TLS override or arbitrary live seed mode.
//! Repeated commands share the owned store's blocks; each run gets immutable metadata exports.
//! Inspection and historical reconciliation are read-only and never reconstruct unrecorded causes.

#![deny(missing_docs)]

use super::{
    host_state::{atomic_write, validate_store_root, HostRegistry},
    identity::build_user_agent,
    ledger::{FetchKind, Ledger, LedgerRow, Outcome, TargetKind},
    network::{
        parse_fetch_url, safe_url_for_record, sha256, url_key, HostKey, LoopbackEndpoint,
        OriginKey, SafeUrl,
    },
    politeness::{Clock, SystemClock},
    robot_client::RobotClient,
    DatumSink, Domain, JobExecutor, WorkerJob,
};
use crate::{
    config::{
        ingestion::{IngestionPolicy, ValidatedPolicy},
        CrawlerConfig,
    },
    entrypoint::indexer::{IndexableWebpage, IndexingWorker},
    warc::{PayloadType, WarcFile},
    webpage::url_ext::UrlExt,
};
use anyhow::{ensure, Context, Result};
use chrono::{DateTime, Utc};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::Instant,
};
use url::Url;

const FROZEN_SEEDS: &str = include_str!("../../../../.spike/data/seeds.json");
const TEMPLATE: &str = include_str!("../../../../configs/crawler/crawler.toml");
const MAX_SEEDS: usize = 200;

/// One bounded selected input; raw URL stays in memory until represented as a safe operational URL.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seed {
    /// Exact raw input, checked before normalization; invalid fixture inputs still receive an ordinal.
    pub url: String,
    /// Optional caller category, at most 128 Unicode scalar values with no controls.
    #[serde(default)]
    pub category: Option<String>,
}
/// Sealed live sample permission, constructible only by exact frozen-set equality.
pub struct SeedScope {
    urls: Vec<Url>,
}
impl SeedScope {
    /// Tests frozen exact membership without constructing a client or issuing any request.
    pub fn allows(&self, url: &Url) -> bool {
        super::network::CrawlScope::sample(self).contains_exact(url)
    }
    /// Verifies all 200 inputs, rejects duplicates and refuses any changed or additional live target.
    pub fn frozen(seeds: &[Seed]) -> Result<Self> {
        validate_inputs(seeds)?;
        let urls: Vec<_> = seeds
            .iter()
            .map(|s| normalized_url(&s.url))
            .collect::<Result<_>>()?;
        let normalized_set: BTreeSet<_> = urls.iter().map(|u| u.as_str().to_owned()).collect();
        let frozen: Vec<Seed> = serde_json::from_str(FROZEN_SEEDS)?;
        let frozen_set: BTreeSet<_> = frozen
            .iter()
            .map(|s| normalized_url(&s.url).map(|u| u.to_string()))
            .collect::<Result<_>>()?;
        ensure!(
            urls.len() == MAX_SEEDS && normalized_set.len() == MAX_SEEDS,
            "sample requires 200 unique inputs"
        );
        ensure!(
            normalized_set == frozen_set,
            "sample scope differs from frozen inputs"
        );
        Ok(Self { urls })
    }
    pub(crate) fn urls(&self) -> &[Url] {
        &self.urls
    }
}
fn validate_inputs(seeds: &[Seed]) -> Result<()> {
    ensure!(
        !seeds.is_empty() && seeds.len() <= MAX_SEEDS,
        "seed count must be in 1..=200"
    );
    let mut seen = BTreeSet::new();
    for seed in seeds {
        ensure!(seed.url.len() <= 1_048_576, "seed input exceeds file bound");
        ensure!(
            seed.category
                .as_ref()
                .is_none_or(|s| s.chars().count() <= 128 && !s.chars().any(char::is_control)),
            "seed category is invalid"
        );
        if let Ok(url) = normalized_url(&seed.url) {
            ensure!(seen.insert(url.to_string()), "duplicate normalized seed");
        }
    }
    Ok(())
}
fn normalized_url(raw: &str) -> Result<Url> {
    let original = parse_fetch_url(raw).map_err(|_| anyhow::anyhow!("invalid seed URL"))?;
    let mut normalized = original.clone().normalize();
    // Upstream removes tracking queries; operational identity under A3 retains every query byte.
    normalized.set_query(original.query());
    Ok(normalized)
}
fn read_seeds(path: &Path) -> Result<Vec<Seed>> {
    let bytes = read_bounded(path, 1_048_576)?;
    let seeds: Vec<Seed> = serde_json::from_slice(&bytes).context("decode seed JSON")?;
    validate_inputs(&seeds)?;
    Ok(seeds)
}
fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("read {}", path.display()))?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "input file exceeds bound");
    Ok(bytes)
}
fn template() -> Result<CrawlerConfig> {
    Ok(toml::from_str(TEMPLATE)?)
}
fn policy(config: Option<&Path>) -> Result<ValidatedPolicy> {
    match config {
        Some(path) => IngestionPolicy::load(path),
        None => template()?.ingestion.validate(),
    }
}
fn json_create(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().context("output has no parent")?;
    validate_store_root(parent)?;
    fs::create_dir_all(parent)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create output {}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}
fn source_state() -> Result<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let read = |args: &[&str]| -> Result<Vec<u8>> {
        let result = Command::new("git").current_dir(&root).args(args).output()?;
        ensure!(result.status.success(), "source revision command failed");
        Ok(result.stdout)
    };
    let revision = String::from_utf8(read(&["rev-parse", "HEAD"])?)?
        .trim()
        .to_owned();
    let mut diff = read(&["diff", "--binary", "HEAD"])?;
    for name in read(&["ls-files", "--others", "--exclude-standard", "-z"])?
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
    {
        let name = std::str::from_utf8(name)?;
        diff.extend_from_slice(name.as_bytes());
        diff.push(0);
        diff.extend(fs::read(root.join(name))?);
        diff.push(0);
    }
    Ok((revision, sha256(&diff)))
}
/// Measured per-run sample summary; completion requires durable rows and a clean retention scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SampleSummary {
    /// Stable schema version, currently 1.
    pub schema_version: u16,
    /// Current opaque ledger run ID.
    pub run_id: String,
    /// Owning persistent local store ID.
    pub store_id: String,
    /// True only after every target, terminal projection and retention check succeeds.
    pub complete: bool,
    /// Fixed failure code when completion cannot be established.
    pub failure: Option<String>,
    /// Selected input count, never a count of HTTP requests.
    pub targets: usize,
    /// Exactly one terminal kind count per selected input.
    pub histogram: BTreeMap<String, u64>,
    /// Actual nested physical HTTP/TLS attempts.
    pub http_attempts: usize,
    /// Nested robots attempts, including failed handshakes.
    pub robots_attempts: usize,
    /// UTC run start.
    pub started_at_utc: DateTime<Utc>,
    /// UTC observation at summary creation.
    pub finished_at_utc: DateTime<Utc>,
    /// Elapsed monotonic wall seconds, excluding tool compilation.
    pub wall_seconds: f64,
    /// Exact fixed identity sent by this client.
    pub user_agent: String,
    /// Policy version and approval-independent bounded-sample identity.
    pub policy_version: String,
    /// Digest of exact validated configuration.
    pub policy_config_sha256: String,
    /// Digest of normalized sorted operational URLs.
    pub seeds_sha256: String,
    /// Literal pending until the orchestrator records publication evidence after push.
    pub policy_publication_status: String,
    /// Actual source revision observed for the run.
    pub source_revision: String,
    /// Hash of tracked and untracked working changes observed for the run.
    pub dirty_diff_sha256: String,
    /// Explicit live-frozen or owned-loopback capability; never production.
    pub scope: String,
    /// Immutable per-run ledger export relative to the managed store root.
    pub ledger_file: String,
    /// Immutable manifest relative to the managed store root.
    pub manifest_file: String,
}
/// Runs the fixed public research scope; callers must schedule it only after policy publication.
/// This entrypoint never expands the frontier and shares persisted blocks across runs in out.
pub async fn run(seeds: &Path, out: &Path, config: Option<&Path>) -> Result<SampleSummary> {
    let seeds = read_seeds(seeds)?;
    let scope = SeedScope::frozen(&seeds)?;
    let policy = policy(config)?;
    let client = RobotClient::sample(out, policy, &scope, 20)?;
    execute(&seeds, client, "live-frozen").await
}
/// Executes the identical bounded runner with synthetic inputs and an owned loopback-only capability.
/// Invalid raw fixture inputs are admitted and classified; duplicates fail before any request.
pub async fn run_loopback(
    seeds: &[Seed],
    out: &Path,
    policy: &IngestionPolicy,
    endpoint: LoopbackEndpoint,
    clock: Arc<dyn Clock>,
) -> Result<SampleSummary> {
    validate_inputs(seeds)?;
    let original_scope = super::network::CrawlScope::loopback(endpoint.clone());
    let urls: Vec<_> = seeds
        .iter()
        .filter_map(|seed| parse_fetch_url(&seed.url).ok())
        .filter(|url| original_scope.validate(url, false).is_ok())
        .collect();
    let endpoint = endpoint.restrict_targets(&urls)?;
    let client = RobotClient::loopback(out, policy, endpoint, clock, 2)?;
    execute(seeds, client, "owned-loopback").await
}
async fn execute(seeds: &[Seed], client: RobotClient, scope: &str) -> Result<SampleSummary> {
    let started = Instant::now();
    let started_at_utc = client.clock().utc();
    let ledger = client.ledger();
    let root = client.host_registry().root().to_owned();
    let runs = root.join("runs");
    if let Ok(metadata) = fs::symlink_metadata(&runs) {
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "unsafe runs directory"
        );
    } else {
        fs::create_dir(&runs)?;
        fs::set_permissions(&runs, fs::Permissions::from_mode(0o700))?;
    }
    let run_dir = runs.join(ledger.run_id());
    fs::create_dir(&run_dir)?;
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700))?;
    let (source_revision, dirty_diff_sha256) = source_state()?;
    let normalized: BTreeSet<_> = seeds
        .iter()
        .filter_map(|s| normalized_url(&s.url).ok())
        .map(|u| u.to_string())
        .collect();
    let mut summary = SampleSummary {
        schema_version: 1,
        run_id: ledger.run_id().into(),
        store_id: client.host_registry().identity().store_id.clone(),
        complete: false,
        failure: Some("run-incomplete".into()),
        targets: seeds.len(),
        histogram: BTreeMap::new(),
        http_attempts: 0,
        robots_attempts: 0,
        started_at_utc,
        finished_at_utc: started_at_utc,
        wall_seconds: 0.0,
        user_agent: build_user_agent(&client.policy().get().identity)?,
        policy_version: client.policy().get().version.clone(),
        policy_config_sha256: client.policy().sha256(),
        seeds_sha256: sha256(&serde_json::to_vec(&normalized)?),
        policy_publication_status: "pending".into(),
        source_revision,
        dirty_diff_sha256,
        scope: scope.into(),
        ledger_file: format!("runs/{}/ledger.jsonl", ledger.run_id()),
        manifest_file: format!("runs/{}/manifest.json", ledger.run_id()),
    };
    json_create(&run_dir.join("manifest.json"), &summary)?;
    let mut groups = BTreeMap::<String, Vec<_>>::new();
    for (ordinal, seed) in seeds.iter().enumerate() {
        let parsed = parse_fetch_url(&seed.url).ok();
        let target = ledger.admit(
            ordinal.try_into()?,
            TargetKind::Seed,
            seed.category.as_deref(),
            parsed.as_ref(),
        )?;
        let host = parsed
            .as_ref()
            .and_then(|url| HostKey::from_url(url).ok())
            .map(|h| h.as_str().to_owned())
            .unwrap_or_default();
        groups
            .entry(host)
            .or_default()
            .push((target, seed.url.clone()));
    }
    let config = Arc::new(template()?);
    let results: Vec<_> = futures::stream::iter(groups.into_values())
        .map(|inputs| {
            let client = client.clone();
            let config = config.clone();
            async move {
                let domain = inputs
                    .first()
                    .and_then(|(_, raw)| parse_fetch_url(raw).ok())
                    .map(Domain::from)
                    .unwrap_or_else(|| Domain::from(String::new()));
                let mut executor = JobExecutor::new(
                    WorkerJob {
                        domain,
                        urls: Default::default(),
                        wandering_urls: 0,
                    },
                    config,
                    client.local_sink(),
                    client,
                );
                executor.process_targets(inputs).await
            }
        })
        .buffer_unordered(4)
        .collect()
        .await;
    let rows = ledger.rows()?;
    for row in &rows {
        *summary
            .histogram
            .entry(row.outcome.kind().into())
            .or_default() += 1;
        summary.http_attempts += row.fetch_attempts.len();
        summary.robots_attempts += row
            .fetch_attempts
            .iter()
            .filter(|attempt| attempt.kind == FetchKind::Robots)
            .count();
    }
    let check: Result<()> = async {
        for result in results {
            result?;
        }
        ledger.finish()?;
        client.local_sink().finish().await?;
        ensure!(
            rows.len() == seeds.len() && !rows.iter().any(|row| row.fatal),
            "incomplete or fatal sample targets"
        );
        Ok(())
    }
    .await;
    summary.complete = check.is_ok();
    summary.failure = check.as_ref().err().map(|_| "run-incomplete".into());
    summary.finished_at_utc = client.clock().utc();
    summary.wall_seconds = started.elapsed().as_secs_f64();
    let mut bytes = Vec::new();
    for row in &rows {
        serde_json::to_writer(&mut bytes, row)?;
        bytes.push(b'\n');
    }
    atomic_write(&run_dir.join("ledger.jsonl"), &bytes)?;
    atomic_write(
        &run_dir.join("manifest.json"),
        &serde_json::to_vec_pretty(&summary)?,
    )?;
    check?;
    Ok(summary)
}

/// One historical input crosswalk; current outcomes never substitute for missing spike evidence.
#[derive(Debug, Serialize)]
pub struct Crosswalk {
    /// Original input position.
    pub input_ordinal: usize,
    /// Exact safe operational seed URL, preserving query.
    pub url: SafeUrl,
    /// True only if the spike log contains a matching saved event.
    pub baseline_saved: bool,
    /// Known log fact or explicit unrecorded cause, never inferred from this run.
    pub historical_reason: String,
    /// Current observed terminal kind when a ledger is supplied.
    pub current_outcome: Option<String>,
    /// Current observation time, absent for baseline-only reconciliation.
    pub current_observed_at_utc: Option<DateTime<Utc>>,
}
/// Exact input/log/ledger reconciliation with no guessed historical causes.
#[derive(Debug, Serialize)]
pub struct Reconciliation {
    /// Schema version, currently 1.
    pub schema_version: u16,
    /// Number of supplied unique seed inputs.
    pub seeds: usize,
    /// Number of matching historical saved inputs.
    pub baseline_saved: usize,
    /// Number of inputs without a historical saved event.
    pub baseline_not_saved: usize,
    /// Number of nonsaves with an explicit denied robots check.
    pub known_robots_denials: usize,
    /// Number of nonsaves whose historical cause was not recorded.
    pub historical_unrecorded: usize,
    /// Actual event inventory parsed from the retained log.
    pub spike_events: BTreeMap<String, usize>,
    /// Current terminal rows, zero when no ledger was supplied.
    pub current_rows: usize,
    /// Current measured outcome histogram; empty for baseline-only mode.
    pub current_histogram: BTreeMap<String, usize>,
    /// Crosswalk for every historically saved input.
    pub saved_crosswalk: Vec<Crosswalk>,
    /// Crosswalk for every input without a saved event.
    pub nonsaved_crosswalk: Vec<Crosswalk>,
}
fn historic_key(raw: &str) -> Result<String> {
    Ok(parse_fetch_url(raw)
        .map_err(|_| anyhow::anyhow!("invalid historical URL"))?
        .normalize()
        .to_string())
}
/// Reconciles retained events and optional current rows, preserving the 200/178/22 baseline.
/// Current ledger must contain one run and exactly one Seed row per input; unknown wire scope fails.
pub fn reconcile(
    seeds: &Path,
    spike_log: &Path,
    ledger_path: Option<&Path>,
    out: &Path,
) -> Result<Reconciliation> {
    let seeds = read_seeds(seeds)?;
    let keys: BTreeSet<_> = seeds
        .iter()
        .map(|s| historic_key(&s.url))
        .collect::<Result<_>>()?;
    ensure!(keys.len() == seeds.len(), "duplicate historical input key");
    let mut events = BTreeMap::new();
    let mut saved = BTreeSet::new();
    let mut denied = BTreeSet::new();
    for line in BufReader::new(File::open(spike_log)?).lines() {
        let line = line?;
        ensure!(line.len() <= 1_048_576, "spike log line exceeds bound");
        if !line.starts_with('{') {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(&line).context("decode spike event")?;
        let Some(event) = value.get("event").and_then(|v| v.as_str()) else {
            continue;
        };
        ensure!(
            event.len() <= 64
                && event
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "invalid event identifier"
        );
        *events.entry(event.to_owned()).or_insert(0) += 1;
        if matches!(event, "saved" | "robots_check") {
            let raw = value
                .get("url")
                .and_then(|v| v.as_str())
                .context("event URL missing")?;
            let key = historic_key(raw)?;
            ensure!(keys.contains(&key), "spike event outside input scope");
            if event == "saved" {
                ensure!(saved.insert(key), "duplicate spike saved event");
            } else if value.get("allowed").and_then(|v| v.as_bool()) == Some(false) {
                denied.insert(key);
            }
        }
    }
    let rows = ledger_path
        .map(Ledger::read_rows)
        .transpose()?
        .unwrap_or_default();
    let mut by_ordinal = BTreeMap::new();
    let mut histogram = BTreeMap::new();
    if let Some(path) = ledger_path {
        ensure!(
            rows.len() == seeds.len(),
            "current ledger does not cover every input"
        );
        let run_ids: BTreeSet<_> = rows.iter().map(|r| r.run_id.as_str()).collect();
        ensure!(run_ids.len() == 1, "use a single per-run ledger export");
        let exact: BTreeSet<_> = seeds
            .iter()
            .map(|s| normalized_url(&s.url).map(|u| u.to_string()))
            .collect::<Result<_>>()?;
        let origins: BTreeSet<_> = exact
            .iter()
            .map(|s| {
                OriginKey::from_url(&Url::parse(s).expect("validated seed"))
                    .map(|o| o.as_str().to_owned())
            })
            .collect::<std::result::Result<_, _>>()?;
        let store = ledger_store(path)?;
        for row in &rows {
            ensure!(
                row.kind == TargetKind::Seed && !row.fatal,
                "non-seed or fatal current row"
            );
            let ordinal = row.input_ordinal as usize;
            let seed = seeds.get(ordinal).context("ledger ordinal out of range")?;
            let url = normalized_url(&seed.url)?;
            ensure!(
                row.record.requested_url.value() == Some(&safe_url_for_record(&url))
                    && row.record.url_key.value() == Some(&url_key(&url)),
                "ledger seed identity mismatch"
            );
            ensure!(
                by_ordinal.insert(ordinal, row).is_none(),
                "duplicate ledger ordinal"
            );
            for attempt in &row.fetch_attempts {
                let url = normalized_url(attempt.requested_url.as_str())?;
                let bootstrap = attempt.kind == FetchKind::Robots
                    && url.path() == "/robots.txt"
                    && url.query().is_none()
                    && origins.contains(OriginKey::from_url(&url)?.as_str());
                ensure!(
                    exact.contains(url.as_str()) || bootstrap,
                    "wire attempt outside selected scope"
                );
                ensure!(
                    attempt.scope_admitted && attempt.finished_at_utc.value().is_some(),
                    "incomplete wire evidence"
                );
            }
            if matches!(row.outcome, Outcome::Saved | Outcome::SavedNoindex) {
                super::record::validate_success_fields(&row.record)?;
                let expected = super::retention::object_name(&row.target_id)?;
                ensure!(
                    row.body_object.as_deref() == Some(expected.as_str())
                        && row.record.retained_body_bytes > 0,
                    "saved row lacks body acknowledgement"
                );
                let metadata = fs::symlink_metadata(store.join(expected))?;
                ensure!(
                    metadata.is_file()
                        && !metadata.file_type().is_symlink()
                        && metadata.nlink() == 1
                        && metadata.len() > 0,
                    "saved body is not a managed regular object"
                );
            } else {
                ensure!(
                    row.body_object.is_none(),
                    "nonsaved row claims a body object"
                );
            }
            *histogram.entry(row.outcome.kind().to_owned()).or_insert(0) += 1;
        }
    }
    let mut saved_crosswalk = Vec::new();
    let mut nonsaved_crosswalk = Vec::new();
    let mut known_robots_denials = 0;
    for (ordinal, seed) in seeds.iter().enumerate() {
        let key = historic_key(&seed.url)?;
        let was_saved = saved.contains(&key);
        let denied = denied.contains(&key) && !was_saved;
        known_robots_denials += usize::from(denied);
        let current = by_ordinal.get(&ordinal);
        let row = Crosswalk {
            input_ordinal: ordinal,
            url: safe_url_for_record(&normalized_url(&seed.url)?),
            baseline_saved: was_saved,
            historical_reason: if was_saved {
                "saved in #573"
            } else if denied {
                "robots denial recorded in #573"
            } else {
                "unrecorded in #573"
            }
            .into(),
            current_outcome: current.map(|r| r.outcome.kind().into()),
            current_observed_at_utc: current.map(|r| r.finished_at_utc),
        };
        if was_saved {
            saved_crosswalk.push(row);
        } else {
            nonsaved_crosswalk.push(row);
        }
    }
    let result = Reconciliation {
        schema_version: 1,
        seeds: seeds.len(),
        baseline_saved: saved_crosswalk.len(),
        baseline_not_saved: nonsaved_crosswalk.len(),
        known_robots_denials,
        historical_unrecorded: nonsaved_crosswalk.len() - known_robots_denials,
        spike_events: events,
        current_rows: rows.len(),
        current_histogram: histogram,
        saved_crosswalk,
        nonsaved_crosswalk,
    };
    json_create(out, &result)?;
    Ok(result)
}
fn ledger_store(path: &Path) -> Result<PathBuf> {
    let parent = path.parent().context("ledger parent missing")?;
    let root = if parent.join("store.json").is_file() {
        parent.to_owned()
    } else {
        ensure!(
            uuid::Uuid::parse_str(
                parent
                    .file_name()
                    .and_then(|s| s.to_str())
                    .context("run ID missing")?
            )
            .is_ok(),
            "invalid run export directory"
        );
        let runs = parent.parent().context("runs parent missing")?;
        ensure!(
            runs.file_name().is_some_and(|s| s == "runs"),
            "not a managed run export"
        );
        runs.parent().context("store parent missing")?.to_owned()
    };
    validate_store_root(&root)?;
    let marker: serde_json::Value =
        serde_json::from_slice(&read_bounded(&root.join("store.json"), 65536)?)?;
    ensure!(
        marker.get("kind").and_then(|v| v.as_str()) == Some("ava-search-local-crawl"),
        "foreign ledger store"
    );
    Ok(root)
}

/// Read-only WARC compatibility counts and named pre-index admission skips; no index is created.
#[derive(Debug, Serialize)]
pub struct WarcInspection {
    /// Schema version, currently 1.
    pub schema_version: u16,
    /// SHA-256 of exact compressed input bytes.
    pub warc_sha256: String,
    /// Parsed WARC documents, including legacy records and documents later skipped by indexing.
    pub documents: u64,
    /// Actual WARC parse errors; nonzero makes the command fail after saving evidence.
    pub parse_errors: u64,
    /// Documents carrying a valid avaDocumentV1 extension.
    pub extended_documents: u64,
    /// Parsed payload-type inventory; unknown legacy types retain their inherited None behavior.
    pub payload_types: BTreeMap<String, u64>,
    /// Named pre-index rejection counts using the indexer's shared base admission checks.
    pub index_skip_histogram: BTreeMap<String, u64>,
    /// Documents surviving exact-URL duplicate and base title/noindex/text checks; not index doc count.
    pub index_candidates: u64,
    /// Explicit measurement limitation; actual retained indexing belongs to follow-up B.
    pub index_measurement_status: String,
}
fn file_sha256(path: &Path) -> Result<String> {
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    let mut file = File::open(path)?;
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hash
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
/// Reads one explicit local WARC, saves compatibility/skip counts, then fails on any parse error.
pub fn inspect_warc(warc: &Path, out: &Path) -> Result<WarcInspection> {
    let mut result = WarcInspection {schema_version:1,warc_sha256:file_sha256(warc)?,documents:0,parse_errors:0,extended_documents:0,payload_types:BTreeMap::new(),index_skip_histogram:BTreeMap::new(),index_candidates:0,index_measurement_status:"NOT RUN: exact URL set and shared base preparation audit only; actual index counts and Bloom/index effects are FUP-B".into()};
    let file = WarcFile::open(warc)?;
    let mut seen = BTreeSet::new();
    for record in file.records() {
        let record = match record {
            Ok(record) => record,
            Err(_) => {
                result.parse_errors += 1;
                continue;
            }
        };
        result.documents += 1;
        result.extended_documents += u64::from(record.metadata.document.is_some());
        *result
            .payload_types
            .entry(
                record
                    .response
                    .payload_type
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "unknown-legacy".into()),
            )
            .or_default() += 1;
        let skip = if record
            .response
            .payload_type
            .as_ref()
            .is_some_and(|t| !matches!(t, PayloadType::Html))
        {
            Some("non-html-payload".into())
        } else if !seen.insert(record.request.url.clone()) {
            Some("duplicate-exact-url".into())
        } else {
            let page = IndexableWebpage::from(record);
            match IndexingWorker::audit_page(&page) {
                Err(code) => Some(code.replace(' ', "-")),
                Ok(mut html) => {
                    html.parse_text();
                    html.empty_all_text().then(|| "empty-all-text".into())
                }
            }
        };
        if let Some(skip) = skip {
            *result.index_skip_histogram.entry(skip).or_default() += 1;
        } else {
            result.index_candidates += 1;
        }
    }
    ensure!(
        result.documents
            == result.index_candidates + result.index_skip_histogram.values().sum::<u64>(),
        "inspection counts do not reconcile"
    );
    json_create(out, &result)?;
    ensure!(
        result.parse_errors == 0,
        "WARC parse errors recorded in inspection output"
    );
    Ok(result)
}
/// Runs the local raw retention job without constructing any HTTP client or production permission.
pub fn retention(
    store: &Path,
    config: &Path,
    dry_run: bool,
) -> Result<super::retention::RetentionReport> {
    validate_store_root(store)?;
    ensure!(
        store.join("store.json").is_file(),
        "retention requires an initialized managed store"
    );
    let policy = IngestionPolicy::load(config)?;
    let registry = HostRegistry::open(store, policy.clone(), Arc::new(SystemClock::default()))?;
    let report = super::retention::run(&registry, &policy, Utc::now(), dry_run)?;
    println!("{}", serde_json::to_string(&report)?);
    if !dry_run {
        report.ensure_success()?;
        super::retention::scan(&registry, &policy, Utc::now())?;
    }
    Ok(report)
}
