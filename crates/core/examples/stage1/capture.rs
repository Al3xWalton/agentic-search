// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded capture and fixed sample scheduling, with owned children and no evidence-supplied argv.
//! Sample resource ceilings are experiment stops, not production capacity or kernel limits.

use super::*;
use std::io::Read;
use std::net::TcpListener;
use std::os::unix::{ffi::OsStrExt, process::CommandExt};
use std::process::{Child, Command as Process, Stdio};
use std::time::{Duration, Instant};

/// Public source hosts require a stable, noncredentialed client identity.
const SOURCE_USER_AGENT: &str = "AgenticSearch-Stage1-Evaluation/589";

/// One fixed crawl manifest makes segment selection reproducible.
const MANIFEST: &str = "https://data.commoncrawl.org/crawl-data/CC-MAIN-2026-34/warc.paths.gz";
/// The second input must be from a distinct segment, not merely a different WARC.
const ORIGINAL_SEGMENT: &str = "1786091384908.68";
/// Byte ceilings use binary units consistently with transfer receipts.
const MIB: u64 = 1024 * 1024;
/// Disk and transfer budgets use binary units rather than decimal estimates.
const GIB: u64 = 1024 * MIB;

/// Select in published order before inspecting content.
fn select_segment(manifest: &str) -> Result<(usize, String, String)> {
    for (ordinal, path) in manifest.lines().enumerate() {
        let parts: Vec<_> = path.split('/').collect();
        if parts.len() != 6
            || parts[0] != "crawl-data"
            || parts[1] != "CC-MAIN-2026-34"
            || parts[2] != "segments"
            || parts[4] != "warc"
            || !parts[5].ends_with(".warc.gz")
            || parts
                .iter()
                .any(|s| s.is_empty() || *s == "." || *s == "..")
            || !parts[3].bytes().all(|b| b.is_ascii_digit() || b == b'.')
            || !parts[5]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
        {
            return Err(Error::Invalid);
        }
        if parts[3] != ORIGINAL_SEGMENT {
            return Ok((ordinal + 1, path.into(), parts[3].into()));
        }
    }
    Err(Error::Blocked)
}

/// A one-byte sentinel detects decompression beyond the permitted budget.
fn limited_read(reader: impl Read, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Failed)?;
    if bytes.len() as u64 > limit {
        return Err(Error::Failed);
    }
    Ok(bytes)
}

/// Stop owned work before it consumes the reserved scratch margin.
fn free_space(path: &Path) -> Result<u64> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::Invalid)?;
    // statvfs writes a fully allocated C structure and never receives evidence as a pointer.
    let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut stats) } != 0 {
        return Err(Error::Failed);
    }
    (stats.f_bavail as u64)
        .checked_mul(stats.f_frsize as u64)
        .ok_or(Error::Failed)
}

/// Bound dispatches without proxy or redirect fallbacks.
fn http(seconds: u64) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .http1_only()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(seconds))
        .build()
        .map_err(|_| Error::Failed)
}

/// Retain failed transfers while enforcing streamed byte, disk and time limits.
async fn download(url: &str, out: &Out, name: &str, cap: u64, seconds: u64) -> Result<Asset> {
    let mut file = output::create(&out.0.join(name))?;
    let start = Instant::now();
    let mut status = None;
    let attempt = async {
        let mut response = http(seconds)?
            .get(url)
            .header("Accept-Encoding", "identity")
            .send()
            .await
            .map_err(|_| Error::Failed)?;
        status = Some(response.status().as_u16());
        if response.status() != 200 {
            return Err(Error::Failed);
        }
        let mut count = 0u64;
        while let Some(bytes) = response.chunk().await.map_err(|_| Error::Failed)? {
            count = count.checked_add(bytes.len() as u64).ok_or(Error::Failed)?;
            if count > cap || free_space(&out.0)? < 2 * GIB {
                return Err(Error::Failed);
            }
            file.write_all(&bytes).map_err(|_| Error::Failed)?;
        }
        file.sync_all().map_err(|_| Error::Failed)?;
        Ok(count)
    };
    let result = tokio::time::timeout(Duration::from_secs(seconds), attempt)
        .await
        .map_err(|_| Error::Failed)
        .and_then(|r| r);
    let path = out.0.join(name);
    let sha256 = input::hash_file(&path)?;
    out.json(
        &format!("{name}.receipt.json"),
        &json!({"url": url, "sha256": sha256,
        "bytes": fs::metadata(&path).map_err(|_| Error::Failed)?.len(),
        "http_status": status, "complete": result.is_ok(),
        "elapsed_ms": start.elapsed().as_millis()}),
    )?;
    result?;
    Ok(Asset { path, sha256 })
}

/// Select a different segment in published manifest order before fetching its WARC.
pub(super) async fn cc_fetch(out: &Out) -> Result<()> {
    if free_space(&out.0)? < 12 * GIB {
        return Err(Error::Blocked);
    }
    let manifest = download(MANIFEST, out, "warc.paths.gz", 32 * MIB, 120).await?;
    let compressed = input::open(&manifest.path)?;
    let decoded = limited_read(flate2::read::GzDecoder::new(compressed), 256 * MIB)?;
    let text = std::str::from_utf8(&decoded).map_err(|_| Error::Failed)?;
    let (line, path, segment) = select_segment(text)?;
    let url = format!("https://data.commoncrawl.org/{path}");
    out.json(
        "selection.json",
        &json!({"manifest": manifest, "line": line,
        "path": path, "segment": segment, "url": url}),
    )?;
    let warc = download(&url, out, "segment.warc.gz", 5 * GIB / 4, 1800).await?;
    let dates = warc_dates(&warc.path)?;
    let receipt_path = out.0.join("segment.warc.gz.receipt.json");
    let receipt = Asset {
        sha256: input::hash_file(&receipt_path)?,
        path: receipt_path,
    };
    out.json(
        "download.json",
        &json!({"warc": warc, "receipt": receipt, "capture_date_range": dates,
        "inspection": "WARC records parsed; measure-index supplies index measurements"}),
    )?;
    Ok(())
}

/// Local WARC inspection shares the streaming bounds exercised by W13.
fn warc_dates(path: &Path) -> Result<[String; 2]> {
    inspect_warc(
        input::open(path)?,
        Instant::now() + Duration::from_secs(120),
    )
}

/// Bound each decompressor read, including a reader that returns after its deadline.
struct TimedRead<R> {
    reader: R,
    deadline: Instant,
}

/// Check the deadline on both sides of every compressed or decompressed read.
impl<R: Read> Read for TimedRead<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.check_deadline()?;
        let limit = bytes.len().min(8192);
        let count = self.reader.read(&mut bytes[..limit])?;
        self.check_deadline()?;
        Ok(count)
    }
}

/// Share one deadline condition so nested decompressor reads cannot bypass it.
impl<R> TimedRead<R> {
    fn check_deadline(&self) -> std::io::Result<()> {
        if Instant::now() >= self.deadline {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        Ok(())
    }
}

/// Inspect concatenated gzip members with fixed buffers, never allocating a declared length.
fn inspect_warc(reader: impl Read, deadline: Instant) -> Result<[String; 2]> {
    let compressed = TimedRead { reader, deadline };
    let mut reader = TimedRead {
        reader: flate2::read::MultiGzDecoder::new(compressed),
        deadline,
    };
    let mut dates = BTreeSet::new();
    let mut count = 0;
    while let Some(header) = warc_header(&mut reader)? {
        count += 1;
        if count > 1_000_000 {
            return Err(Error::Failed);
        }
        let mut length = None;
        let mut date = None;
        for line in header.lines().skip(1) {
            let (key, value) = line.split_once(':').ok_or(Error::Failed)?;
            match key.to_ascii_lowercase().as_str() {
                "content-length" if length.is_none() => {
                    length = Some(value.trim().parse::<u64>().map_err(|_| Error::Failed)?);
                }
                "warc-date" if date.is_none() => {
                    date = Some(
                        chrono::DateTime::parse_from_rfc3339(value.trim())
                            .map_err(|_| Error::Failed)?,
                    );
                }
                "content-length" | "warc-date" => return Err(Error::Failed),
                _ => {}
            }
        }
        let length = length.ok_or(Error::Failed)?;
        if length > input::MAX_RECORD_BYTES as u64 {
            return Err(Error::Failed);
        }
        let copied = std::io::copy(
            &mut Read::by_ref(&mut reader).take(length),
            &mut std::io::sink(),
        )
        .map_err(|_| Error::Failed)?;
        if copied != length {
            return Err(Error::Failed);
        }
        let mut separator = [0; 4];
        reader
            .read_exact(&mut separator)
            .map_err(|_| Error::Failed)?;
        if separator != *b"\r\n\r\n" {
            return Err(Error::Failed);
        }
        dates.insert(date.ok_or(Error::Failed)?);
    }
    Ok([
        dates.first().ok_or(Error::Failed)?.to_rfc3339(),
        dates.last().ok_or(Error::Failed)?.to_rfc3339(),
    ])
}

/// Reject oversized or incomplete headers before growing beyond the fixed header budget.
fn warc_header(reader: &mut impl Read) -> Result<Option<String>> {
    let mut bytes = Vec::new();
    let mut byte = [0];
    while bytes.len() < 32 * 1024 {
        if reader.read(&mut byte).map_err(|_| Error::Failed)? == 0 {
            return if bytes.is_empty() {
                Ok(None)
            } else {
                Err(Error::Failed)
            };
        }
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            let text = String::from_utf8(bytes).map_err(|_| Error::Failed)?;
            if !text.starts_with("WARC/1.0\r\n") && !text.starts_with("WARC/1.1\r\n") {
                return Err(Error::Failed);
            }
            return Ok(Some(text.trim_end().to_owned()));
        }
    }
    Err(Error::Failed)
}

/// The v1 experiment keeps scholarly search and adult verification disabled.
fn v1_request(query: &str) -> Value {
    json!({"query": query, "page": 0, "num_results": 10,
        "country": "unknown", "adult_verified": false, "scholarly": false})
}

/// Validate the v1 envelope before reusing historical URL scoring.
fn v1_urls(bytes: &[u8]) -> Result<Vec<String>> {
    serde_json::from_slice::<stract::api::v1::dto::V1SearchResponse>(bytes)
        .map_err(|_| Error::Failed)?;
    let value: Value = serde_json::from_slice(bytes).map_err(|_| Error::Failed)?;
    if value["version"] != "v1" {
        return Err(Error::Failed);
    }
    let rows = value["results"].as_array().ok_or(Error::Failed)?;
    rows.iter()
        .map(|r| r["url"].as_str().map(String::from).ok_or(Error::Failed))
        .collect()
}

/// A closed step inventory prevents runtime evidence from changing the experiment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
enum Step {
    Start(bool),
    Verify(bool),
    Recall(String, bool),
    V1(String),
    Load(usize),
    Boundary(usize),
    Slow,
    StopApi,
    Diff(String),
}

/// Every prescribed comparison and resource rung is scheduled exactly once.
fn matrix() -> Vec<Step> {
    #[cfg(test)]
    if tests::layout_fixture() {
        return vec![
            Step::Recall("frozen".into(), false),
            Step::Recall("frozen".into(), true),
            Step::Diff("frozen".into()),
        ];
    }
    let mut steps = Vec::new();
    for on in [false, true] {
        steps.push(Step::Start(on));
        steps.push(Step::Verify(on));
        for set in ["frozen", "held-out"] {
            steps.push(Step::Recall(set.into(), on));
        }
        if !on {
            steps.push(Step::StopApi);
        }
    }
    for set in ["frozen", "held-out"] {
        steps.push(Step::Diff(set.into()));
        steps.push(Step::V1(set.into()));
    }
    for concurrency in [1, 4, 16, 32, 33] {
        steps.push(Step::Load(concurrency));
    }
    for probe in 0..8 {
        steps.push(Step::Boundary(probe));
    }
    steps.push(Step::Slow);
    steps
}

/// Production and fake schedulers share identity, deadline and cleanup control flow.
trait SampleDriver {
    fn elapsed(&self) -> Duration;
    async fn identity(&mut self) -> Result<()>;
    async fn step(&mut self, step: &Step) -> Result<()>;
    async fn cleanup(&mut self) -> Result<()>;
}

/// Cleanup remains mandatory after success, failure or resource exhaustion.
async fn schedule(driver: &mut impl SampleDriver) -> Result<()> {
    let attempt = async {
        driver.identity().await?;
        for step in matrix() {
            if driver.elapsed() >= Duration::from_secs(5400) {
                return Err(Error::Failed);
            }
            driver.step(&step).await?;
        }
        Ok(())
    }
    .await;
    let cleanup = driver.cleanup().await;
    if cleanup.is_err() {
        return Err(Error::Failed);
    }
    attempt
}

/// Platform-specific high-water units must not become a capacity forecast.
fn rss_bytes(raw: u64, linux: bool) -> Option<u64> {
    if linux {
        raw.checked_mul(1024)
    } else {
        Some(raw)
    }
}

/// The copied corpus identity is verified before any search process starts.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexCopy {
    path: PathBuf,
    manifest: Asset,
    documents: u64,
    shard: u64,
}

/// The retained two-shard corpus cannot silently become a rebuilt sample.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SampleInputs {
    indexes: [IndexCopy; 2],
}

/// Reject changed copies, counts or shard roles before launching service processes.
fn identity(spec: &SampleInputs, binary: &Asset) -> Result<()> {
    binary.verify()?;
    let temporary = std::env::temp_dir()
        .canonicalize()
        .map_err(|_| Error::Invalid)?;
    for (ordinal, index) in spec.indexes.iter().enumerate() {
        if index.shard != ordinal as u64
            || index.documents != [19285, 178][ordinal]
            || !index.path.starts_with(&temporary)
        {
            return Err(Error::Invalid);
        }
        let expected: Vec<Value> = index.manifest.read()?;
        let actual = stract::eval::index::manifest(&index.path)?;
        if actual != expected {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}

/// Only directly spawned process groups can be signalled or reaped.
struct Owned {
    child: Child,
    reaped: bool,
}

/// Spawn private process groups and retain wait4 status and high-water resource receipts.
impl Owned {
    fn spawn(binary: &Path, args: &[String], out: &Out, number: usize) -> Result<Self> {
        sample_child_layout(args)?;
        let file = output::create(&out.0.join(format!("child-{number:04}.log")))?;
        let mut command = Process::new(binary);
        #[cfg(test)]
        let args = tests::child_arguments(&mut command, args);
        let child = command
            .args(args)
            .current_dir(std::env::current_dir().map_err(|_| Error::Failed)?)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(file.try_clone().map_err(|_| Error::Failed)?)
            .stderr(file)
            .spawn()
            .map_err(|_| Error::Failed)?;
        Ok(Self {
            child,
            reaped: false,
        })
    }

    fn poll(&mut self) -> Result<Option<Value>> {
        if self.reaped {
            return Err(Error::Failed);
        }
        let mut status = 0;
        // wait4 is limited to this exact child; initialized storage belongs to this call.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::wait4(
                self.child.id() as i32,
                &mut status,
                libc::WNOHANG,
                &mut usage,
            )
        };
        if result < 0 {
            return Err(Error::Failed);
        }
        if result == 0 {
            return Ok(None);
        }
        self.reaped = true;
        Ok(Some(json!({"pid": self.child.id(), "status": status,
            "success": libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "high_water_rss_bytes": rss_bytes(usage.ru_maxrss as u64, cfg!(target_os = "linux")),
            "user_seconds": usage.ru_utime.tv_sec as f64 + usage.ru_utime.tv_usec as f64 / 1e6,
            "system_seconds": usage.ru_stime.tv_sec as f64 + usage.ru_stime.tv_usec as f64 / 1e6})))
    }

    async fn stop(&mut self) -> Result<Value> {
        if self.reaped {
            return Ok(json!({"already_reaped": true}));
        }
        for signal in [libc::SIGTERM, libc::SIGKILL] {
            // A group is signalled only while its directly owned leader remains unreaped.
            unsafe {
                libc::kill(-(self.child.id() as i32), signal);
            }
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(5) {
                if let Some(receipt) = self.poll()? {
                    return Ok(receipt);
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
        Err(Error::Failed)
    }
}

/// Use the engine's guard before spawning, also excluding inputs nested below an output cell.
fn sample_child_layout(args: &[String]) -> Result<()> {
    let mut sources = Vec::new();
    let mut destination = None;
    for pair in args.windows(2) {
        match pair[0].as_str() {
            "--out" => destination = Some(PathBuf::from(&pair[1])),
            "--labels" | "--corpus-jsonl" | "--disjoint-from" | "--index"
            | "--service-manifest" | "--index-manifest" | "--config" | "--before" | "--after" => {
                sources.push(PathBuf::from(&pair[1]))
            }
            _ => {}
        }
    }
    if let Some(path) = destination {
        output::external(&path, &sources).map_err(|_| Error::Invalid)?;
        let path = input::argument_path(&path, true, stract::eval::Argument::Out)
            .map_err(|_| Error::Invalid)?;
        let directory = path.parent().ok_or(Error::Invalid)?;
        for source in sources {
            let source = input::inspect_path(&source, false).map_err(|_| Error::Invalid)?;
            if source.starts_with(directory) {
                return Err(Error::Invalid);
            }
        }
    }
    Ok(())
}

/// Sample only owned processes without exposing arguments or environment.
#[cfg(target_os = "macos")]
fn sampled_rss(pid: u32) -> Option<u64> {
    // libproc reports bytes for an owned child without exposing its arguments or environment.
    let mut info: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::proc_pid_rusage(
            pid as i32,
            libc::RUSAGE_INFO_V2,
            (&mut info as *mut libc::rusage_info_v2).cast(),
        )
    };
    (result == 0).then_some(info.ri_resident_size)
}

/// Sample only owned processes without exposing arguments or environment.
#[cfg(not(target_os = "macos"))]
fn sampled_rss(_pid: u32) -> Option<u64> {
    None
}

/// The supervisor retains owned processes and resource evidence through cleanup.
struct LiveSample<'a> {
    plan: &'a Plan,
    out: &'a Out,
    spec: SampleInputs,
    start: Instant,
    children: Vec<Owned>,
    api: Option<usize>,
    next_child: usize,
    resources: Vec<Value>,
    cleanup: Vec<Value>,
}

/// Bound recursive accounting and reject unsafe filesystem entries.
fn disk_tree(path: &Path, depth: usize, entries: &mut usize) -> Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    if depth > 16 || *entries >= 1_000_000 {
        return Err(Error::Failed);
    }
    *entries += 1;
    let meta = fs::symlink_metadata(path).map_err(|_| Error::Failed)?;
    if meta.file_type().is_symlink() {
        return Err(Error::Invalid);
    }
    if meta.is_file() {
        if meta.nlink() != 1 {
            return Err(Error::Invalid);
        }
        return Ok((
            meta.len(),
            meta.blocks().checked_mul(512).ok_or(Error::Failed)?,
        ));
    }
    if !meta.is_dir() {
        return Err(Error::Invalid);
    }
    let mut total = (0u64, 0u64);
    for entry in fs::read_dir(path).map_err(|_| Error::Failed)? {
        let entry = entry.map_err(|_| Error::Failed)?;
        let (logical, allocated) = disk_tree(&entry.path(), depth + 1, entries)?;
        total.0 = total.0.checked_add(logical).ok_or(Error::Failed)?;
        total.1 = total.1.checked_add(allocated).ok_or(Error::Failed)?;
    }
    Ok(total)
}

/// Supervise fixed sample operations under time, disk and owned-process resource ceilings.
impl LiveSample<'_> {
    /// Engine inputs remain siblings of output cells, never their ancestors.
    fn input_path(&self, name: &str) -> PathBuf {
        self.out.0.join("inputs").join(name)
    }

    /// Every output-producing comparison owns a directory distinct from its inputs.
    fn cell_path(&self, name: &str) -> PathBuf {
        self.out.0.join("outputs").join(name).join("report.json")
    }

    async fn observe<T>(
        &mut self,
        future: impl std::future::Future<Output = Result<T>>,
        seconds: u64,
    ) -> Result<T> {
        let future = tokio::time::timeout(Duration::from_secs(seconds), future);
        tokio::pin!(future);
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        loop {
            tokio::select! {
                result = &mut future => return result.map_err(|_| Error::Failed)?,
                _ = tick.tick() => self.check_resources()?,
            }
        }
    }

    async fn validate_labels(&mut self) -> Result<()> {
        for set in ["frozen", "held-out"] {
            let labels = self.plan.asset(set)?;
            let mut args = vec![
                "eval".into(),
                "validate-labels".into(),
                "--labels".into(),
                labels.path.display().to_string(),
                "--labels-sha256".into(),
                labels.sha256.clone(),
                "--out".into(),
                self.cell_path(&format!("{set}-validation"))
                    .display()
                    .to_string(),
            ];
            for source in ["cc-indexed", "seeds-indexed"] {
                args.extend([
                    "--corpus-jsonl".into(),
                    self.plan.asset(source)?.path.display().to_string(),
                ]);
            }
            if set == "held-out" {
                args.extend([
                    "--disjoint-from".into(),
                    self.plan.asset("frozen")?.path.display().to_string(),
                ]);
            }
            self.command(args).await?;
        }
        Ok(())
    }

    fn check_resources(&mut self) -> Result<()> {
        if self.start.elapsed() >= Duration::from_secs(5400) {
            return Err(Error::Failed);
        }
        let mut disks = Vec::new();
        for path in self
            .spec
            .indexes
            .iter()
            .map(|i| &i.path)
            .chain([&self.out.0])
        {
            let (logical, allocated) = disk_tree(path, 0, &mut 0)?;
            if logical > 10 * GIB {
                return Err(Error::Failed);
            }
            disks.push(json!({"path":path,"logical_bytes":logical,"allocated_bytes":allocated}));
        }
        let samples: Vec<_> = self
            .children
            .iter()
            .filter(|c| !c.reaped)
            .map(|c| (c.child.id(), sampled_rss(c.child.id())))
            .collect();
        let sum: Option<u64> = samples
            .iter()
            .map(|(_, bytes)| *bytes)
            .try_fold(0u64, |sum, bytes| sum.checked_add(bytes?));
        self.resources
            .push(json!({"elapsed_ms": self.start.elapsed().as_millis(),
            "sampled_rss": samples, "aggregate_sampled_rss_bytes": sum,"disk":disks}));
        if sum.is_some_and(|n| n > 8 * GIB) || free_space(&self.out.0)? < 2 * GIB {
            return Err(Error::Failed);
        }
        poll_children(&mut self.children, &mut self.cleanup)?;
        Ok(())
    }

    fn spawn(&mut self, args: Vec<String>) -> Result<usize> {
        self.plan.binary.verify()?;
        let child = Owned::spawn(&self.plan.binary.path, &args, self.out, self.next_child)?;
        self.next_child += 1;
        self.children.push(child);
        Ok(self.children.len() - 1)
    }

    async fn command(&mut self, args: Vec<String>) -> Result<()> {
        let mut child = Owned::spawn(&self.plan.binary.path, &args, self.out, self.next_child)?;
        self.next_child += 1;
        let start = Instant::now();
        let result = loop {
            match child.poll() {
                Ok(Some(receipt)) => {
                    let success = receipt["success"] == true;
                    self.cleanup.push(receipt);
                    break if success { Ok(()) } else { Err(Error::Failed) };
                }
                Err(error) => break Err(error),
                Ok(None) => {}
            }
            if start.elapsed() > Duration::from_secs(180) {
                break Err(Error::Failed);
            }
            if self.check_resources().is_err() {
                break Err(Error::Failed);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        };
        if !child.reaped {
            self.cleanup.push(child.stop().await?);
        }
        result
    }

    fn configs(&self) -> Result<()> {
        let inputs = Out(self.out.0.join("inputs"));
        DirBuilder::new()
            .mode(0o700)
            .create(&inputs.0)
            .map_err(|_| Error::Invalid)?;
        for (i, index) in self.spec.indexes.iter().enumerate() {
            let config = json!({"host": format!("127.0.0.1:{}", 57302 + i),
                "gossip_addr": format!("127.0.0.1:{}", 57306 + i),
                "gossip_seed_nodes": ["127.0.0.1:57305", format!("127.0.0.1:{}", 57307 - i)],
                "shard": i, "index_path": index.path, "collector": {"max_docs_considered": 1000}});
            let config: stract::config::SearchServerConfig =
                serde_json::from_value(config).map_err(|_| Error::Invalid)?;
            inputs.bytes(
                &format!("search-{i}.toml"),
                toml::to_string(&config)
                    .map_err(|_| Error::Invalid)?
                    .as_bytes(),
            )?;
        }
        for on in [false, true] {
            let template = include_str!("../../../../configs/eval/api-off.toml");
            let mut value: toml::Value = toml::from_str(template).map_err(|_| Error::Invalid)?;
            let table = value.as_table_mut().ok_or(Error::Invalid)?;
            table.insert("agent_query_planning".into(), toml::Value::Boolean(on));
            let suppression = inputs.0.join("suppression.json");
            let store = inputs.0.join("compliance");
            let records = inputs.0.join("records");
            for (section, key, setting) in [
                (
                    "v1",
                    "management_http_host",
                    toml::Value::String("127.0.0.1:57312".into()),
                ),
                (
                    "v1",
                    "suppression_store_path",
                    toml::Value::try_from(&suppression).map_err(|_| Error::Invalid)?,
                ),
                (
                    "compliance",
                    "store_dir",
                    toml::Value::try_from(&store).map_err(|_| Error::Invalid)?,
                ),
                (
                    "compliance",
                    "records_dir",
                    toml::Value::try_from(&records).map_err(|_| Error::Invalid)?,
                ),
            ] {
                table
                    .entry(section)
                    .or_insert_with(|| toml::Value::Table(Default::default()))
                    .as_table_mut()
                    .ok_or(Error::Invalid)?
                    .insert(key.into(), setting);
            }
            let text = toml::to_string(&value).map_err(|_| Error::Invalid)?;
            let config: stract::config::ApiConfig =
                toml::from_str(&text).map_err(|_| Error::Invalid)?;
            if config.agent_query_planning != on
                || config.v1.management_http_host.to_string() != "127.0.0.1:57312"
                || config.v1.suppression_store_path != suppression
                || config.compliance.store_dir.as_deref() != Some(store.as_path())
                || config.compliance.records_dir.as_deref() != Some(records.as_path())
            {
                return Err(Error::Invalid);
            }
            inputs.bytes(&format!("api-{on}.toml"), text.as_bytes())?;
        }
        Ok(())
    }

    async fn recall(&mut self, set: &str, on: bool) -> Result<()> {
        let asset = self.plan.asset(set)?;
        let mode = if on { "on" } else { "off" };
        let path = self.cell_path(&format!("{set}-{mode}"));
        let mut args = vec![
            "eval".into(),
            "recall".into(),
            "--labels".into(),
            asset.path.display().to_string(),
            "--labels-sha256".into(),
            asset.sha256.clone(),
            "--endpoint".into(),
            "http://127.0.0.1:57300".into(),
            "--expect-planner".into(),
            mode.into(),
            "--suite".into(),
            set.into(),
            "--cell".into(),
            format!("{set}-{mode}"),
            "--service-manifest".into(),
            self.input_path(&format!("served-{on}.json"))
                .display()
                .to_string(),
            "--out".into(),
            path.display().to_string(),
        ];
        for name in ["cc-indexed", "seeds-indexed"] {
            args.extend([
                "--corpus-jsonl".into(),
                self.plan.asset(name)?.path.display().to_string(),
            ]);
        }
        for i in 0..2 {
            args.extend([
                "--index-manifest".into(),
                self.input_path(&format!("index-{i}.json"))
                    .display()
                    .to_string(),
            ]);
            args.extend([
                "--config".into(),
                self.input_path(&format!("search-{i}.toml"))
                    .display()
                    .to_string(),
            ]);
        }
        args.extend([
            "--config".into(),
            self.input_path(&format!("api-{on}.toml"))
                .display()
                .to_string(),
        ]);
        let result = self.command(args).await;
        if result == Err(Error::Invalid) {
            return result;
        }
        if result.is_err() {
            let receipt: Value = serde_json::from_slice(&read_private(&path, 64 * MIB)?)
                .map_err(|_| Error::Failed)?;
            let rows = receipt["rows"].as_array().ok_or(Error::Failed)?;
            if rows.len() != 50
                || rows.iter().any(|r| r["success"] != true)
                || receipt["acceptance"]["passed"] != false
            {
                return result;
            }
        }
        self.seal_cell(set, "beta", mode)?;
        Ok(())
    }

    /// Bind raw response files and the actual private configs before leaving the capture phase.
    fn seal_cell(&self, set: &str, surface: &str, mode: &str) -> Result<()> {
        let name = if surface == "beta" {
            format!("{set}-{mode}")
        } else {
            format!("v1-{set}")
        };
        let asset = |path: PathBuf| -> Result<Asset> {
            Ok(Asset {
                sha256: input::hash_file(&path)?,
                path,
            })
        };
        let raw = asset(self.cell_path(&name))?;
        let value: Value = raw.read()?;
        let rows = if value.is_array() {
            &value
        } else {
            &value["rows"]
        };
        let responses = rows
            .as_array()
            .ok_or(Error::Invalid)?
            .iter()
            .map(|row| {
                let path = row["raw_path"].as_str().ok_or(Error::Invalid)?;
                let result = asset(PathBuf::from(path))?;
                if row["raw_sha256"] != result.sha256 {
                    return Err(Error::Invalid);
                }
                Ok(result)
            })
            .collect::<Result<Vec<_>>>()?;
        let configs = [
            format!("api-{}.toml", mode == "on"),
            "search-0.toml".into(),
            "search-1.toml".into(),
        ]
        .into_iter()
        .map(|name| asset(self.input_path(&name)))
        .collect::<Result<Vec<_>>>()?;
        evidence::seal_run(
            self.plan,
            self.out,
            (set, surface, mode),
            raw,
            configs,
            responses,
        )
    }

    async fn v1(&mut self, set: &str) -> Result<()> {
        let labels = agreement::labels(self.plan, set)?;
        let path = self.cell_path(&format!("v1-{set}"));
        let cell = Out(path.parent().ok_or(Error::Invalid)?.to_owned());
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&cell.0)
            .map_err(|_| Error::Invalid)?;
        let mut rows = Vec::new();
        for (i, label) in labels.iter().enumerate() {
            self.check_resources()?;
            let start = Instant::now();
            let body = serde_json::to_vec(&v1_request(&label.query)).map_err(|_| Error::Invalid)?;
            let (status, bytes) = local_post(body).await?;
            let path = cell.0.join(format!("response-{i:03}.json"));
            let mut file = output::create(&path)?;
            let elapsed = timed_raw_write(
                &mut file,
                &bytes,
                || start.elapsed().as_secs_f64() * 1000.0,
                |file| file.sync_all().map_err(|_| Error::Failed),
            )?;
            self.check_resources()?;
            let urls = if status == 200 {
                v1_urls(&bytes).ok()
            } else {
                None
            };
            let mut row = evidence::score(label, urls.as_deref(), elapsed)?;
            row.raw_path = Some(path.to_str().ok_or(Error::Invalid)?.to_owned());
            row.raw_sha256 = Some(input::sha256(&bytes));
            rows.push(row);
        }
        cell.json("report.json", &rows)?;
        self.seal_cell(set, "v1", "on")?;
        Ok(())
    }

    async fn load(&mut self, concurrency: usize) -> Result<()> {
        let start = Instant::now();
        let mut rows = Vec::new();
        for chunk in (0..100usize).collect::<Vec<_>>().chunks(concurrency) {
            self.check_resources()?;
            if start.elapsed() >= Duration::from_secs(120) {
                return Err(Error::Failed);
            }
            let futures = chunk.iter().map(|i| async move {
                let query = ["rust", "python", "nasa", "weather", "documentation"][i % 5];
                let start = Instant::now();
                let body = serde_json::to_vec(&v1_request(query)).map_err(|_| Error::Failed)?;
                let result = local_post(body).await;
                Ok(json!({"ordinal": i, "status": result.ok().map(|r| r.0),
                    "elapsed_ms": start.elapsed().as_secs_f64() * 1000.0}))
            });
            let pending = async { Ok(futures::future::join_all(futures).await) };
            let remaining = 120u64.saturating_sub(start.elapsed().as_secs());
            let completed: Vec<Result<Value>> = self.observe(pending, remaining).await?;
            rows.extend(completed.into_iter().collect::<Result<Vec<_>>>()?);
        }
        self.out.json(
            &format!("load-{concurrency}.json"),
            &json!({"rows": rows,
            "elapsed_seconds": start.elapsed().as_secs_f64(), "requests": 100,
            "admission": if rows.iter().any(|r| r["status"] == 503) { "OBSERVED" }
                else { "NOT PROVEN" }}),
        )?;
        Ok(())
    }
}

/// The sample request can reach only the fixed loopback v1 listener.
async fn local_post(body: Vec<u8>) -> Result<(u16, Vec<u8>)> {
    let mut response = http(65)?
        .post("http://127.0.0.1:57300/v1/search")
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|_| Error::Failed)?;
    let status = response.status().as_u16();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Failed)? {
        if bytes.len() + chunk.len() > 8 * MIB as usize {
            return Err(Error::Failed);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok((status, bytes))
}

/// Each boundary fixture isolates one production limit.
fn probe(ordinal: usize) -> Result<Vec<u8>> {
    let mut body = v1_request("rust");
    match ordinal {
        0 | 1 => {
            body["query"] = json!(format!(
                "{} {} {} {}",
                "a".repeat(1024),
                "b".repeat(1023),
                "c".repeat(1023),
                "d".repeat(1023 + ordinal)
            ))
        }
        2 | 3 => {
            body["query"] = json!((0..30 + ordinal)
                .map(|i| format!("term{i}"))
                .collect::<Vec<_>>()
                .join(" "))
        }
        4 | 5 => {}
        6 | 7 => body["num_results"] = json!(94 + ordinal),
        _ => return Err(Error::Invalid),
    }
    validate_probe(ordinal, &body)?;
    let mut bytes = serde_json::to_vec(&body).map_err(|_| Error::Invalid)?;
    if ordinal == 4 || ordinal == 5 {
        bytes.resize(65532 + ordinal, b' ');
    }
    Ok(bytes)
}

/// Pair each invalid probe with the public error discriminator its limit requires.
fn expected_code(ordinal: usize) -> Option<&'static str> {
    match ordinal {
        1 => Some("query_too_long"),
        3 => Some("too_many_terms"),
        5 => Some("request_too_large"),
        7 => Some("invalid_result_count"),
        _ => None,
    }
}

/// Verify the intended scanner boundary before any probe is sent.
fn validate_probe(ordinal: usize, body: &Value) -> Result<()> {
    use stract::query::planner::bounds::{scan_query, InputError};
    let expected = match ordinal {
        1 => Some(InputError::QueryTooLong),
        3 => Some(InputError::TooManyTerms),
        _ => None,
    };
    if scan_query(body["query"].as_str().ok_or(Error::Invalid)?).err() != expected {
        return Err(Error::Invalid);
    }
    Ok(())
}

/// Persist the unexpected exit before returning failure to the supervisor.
fn poll_children(children: &mut [Owned], cleanup: &mut Vec<Value>) -> Result<()> {
    for child in children {
        if !child.reaped {
            if let Some(receipt) = child.poll()? {
                cleanup.push(receipt);
                return Err(Error::Failed);
            }
        }
    }
    Ok(())
}

/// Use beta's raw-write boundary, excluding durability and parsing from latency.
fn timed_raw_write<W: Write>(
    file: &mut W,
    bytes: &[u8],
    now: impl Fn() -> f64,
    sync: impl FnOnce(&mut W) -> Result<()>,
) -> Result<f64> {
    file.write_all(bytes).map_err(|_| Error::Failed)?;
    let elapsed = now();
    sync(file)?;
    Ok(elapsed)
}

/// Execute the fixed sample matrix and persist cleanup evidence on every exit path.
impl SampleDriver for LiveSample<'_> {
    fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    async fn identity(&mut self) -> Result<()> {
        identity(&self.spec, &self.plan.binary)?;
        let mut listeners = Vec::new();
        for port in [
            57300, 57301, 57302, 57303, 57305, 57306, 57307, 57311, 57312,
        ] {
            listeners.push(
                TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
                    .map_err(|_| Error::Blocked)?,
            );
        }
        self.configs()?;
        self.validate_labels().await?;
        #[cfg(test)]
        if tests::layout_identity(self)? {
            return Ok(());
        }
        for i in 0..2 {
            self.command(vec![
                "eval".into(),
                "inspect-index".into(),
                "--index".into(),
                self.spec.indexes[i].path.display().to_string(),
                "--out".into(),
                self.input_path(&format!("index-{i}.json"))
                    .display()
                    .to_string(),
            ])
            .await?;
            let bytes = read_private(&self.input_path(&format!("index-{i}.json")), 64 * MIB)?;
            let inspected: Value = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
            if inspected["documents"] != self.spec.indexes[i].documents {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }

    async fn step(&mut self, step: &Step) -> Result<()> {
        match step {
            Step::Start(on) => {
                if !on {
                    for i in 0..2 {
                        self.spawn(vec![
                            "search-server".into(),
                            self.input_path(&format!("search-{i}.toml"))
                                .display()
                                .to_string(),
                        ])?;
                    }
                }
                self.api = Some(self.spawn(vec!["api".into(),
                    self.input_path(&format!("api-{on}.toml")).display().to_string()])?);
                for _ in 0..40 {
                    self.check_resources()?;
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
            Step::Verify(on) => {
                self.command(vec![
                    "eval".into(),
                    "verify-service".into(),
                    "--shard".into(),
                    "127.0.0.1:57302".into(),
                    "--expect-documents".into(),
                    "19285".into(),
                    "--shard".into(),
                    "127.0.0.1:57303".into(),
                    "--expect-documents".into(),
                    "178".into(),
                    "--out".into(),
                    self.input_path(&format!("served-{on}.json"))
                        .display()
                        .to_string(),
                ])
                .await?
            }
            Step::Recall(set, on) => self.recall(set, *on).await?,
            Step::V1(set) => self.v1(set).await?,
            Step::Diff(set) => {
                let args = vec![
                    "eval".into(),
                    "diff".into(),
                    "--before".into(),
                    self.cell_path(&format!("{set}-off")).display().to_string(),
                    "--after".into(),
                    self.cell_path(&format!("{set}-on")).display().to_string(),
                    "--out".into(),
                    self.cell_path(&format!("{set}-diff")).display().to_string(),
                ];
                let result = self.command(args).await;
                if result.is_err()
                    && !self
                        .cell_path(&format!("{set}-diff"))
                        .with_extension("complete")
                        .is_file()
                {
                    return result;
                }
            }
            Step::Load(n) => self.load(*n).await?,
            Step::Boundary(n) => {
                let start = Instant::now();
                let (status, bytes) = self.observe(local_post(probe(*n)?), 65).await?;
                self.out.json(
                    &format!("boundary-{n}.json"),
                    &json!({"status": status, "expected_code": expected_code(*n),
                    "error_code": serde_json::from_slice::<Value>(&bytes).ok()
                        .and_then(|v| v["error"]["code"].as_str().map(String::from)),
                    "body_sha256": input::sha256(&bytes),
                    "elapsed_ms": start.elapsed().as_millis()}),
                )?;
            }
            Step::Slow => {
                let out = Out(self.out.0.clone());
                self.observe(slow_probe(&out), 66).await?;
                let recovery =
                    serde_json::to_vec(&v1_request("documentation")).map_err(|_| Error::Failed)?;
                let (status, _) = self.observe(local_post(recovery), 65).await?;
                self.out.json("recovery.json", &json!({"status":status}))?;
            }
            Step::StopApi => {
                let index = self.api.take().ok_or(Error::Failed)?;
                self.cleanup.push(self.children[index].stop().await?);
            }
        }
        Ok(())
    }

    async fn cleanup(&mut self) -> Result<()> {
        let mut failed = false;
        for child in self.children.iter_mut().rev() {
            match child.stop().await {
                Ok(receipt) => self.cleanup.push(receipt),
                Err(_) => failed = true,
            }
        }
        self.out.json(
            "cleanup.json",
            &json!({"children": self.cleanup, "failed": failed}),
        )?;
        self.out.json(
            "resources.json",
            &json!({"samples": self.resources,
            "kind": "sampled; high-water values are separate and never summed"}),
        )?;
        if failed {
            Err(Error::Failed)
        } else {
            Ok(())
        }
    }
}

/// A controlled slow client tests timeout and recovery without external traffic.
async fn slow_probe(out: &Out) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let start = Instant::now();
    let mut socket = tokio::net::TcpStream::connect("127.0.0.1:57300")
        .await
        .map_err(|_| Error::Failed)?;
    socket
        .write_all(
            b"POST /v1/search HTTP/1.1\r\nHost: localhost\r\n\
        Content-Type: application/json\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n",
        )
        .await
        .map_err(|_| Error::Failed)?;
    let (mut read, mut write) = socket.into_split();
    let attempt = async {
        let sender = async {
            for _ in 0..65 {
                write.write_all(b" ").await.map_err(|_| Error::Failed)?;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Ok::<(), Error>(())
        };
        let receiver = async {
            let mut bytes = vec![0; 4096];
            let count = read.read(&mut bytes).await.map_err(|_| Error::Failed)?;
            Ok::<usize, Error>(count)
        };
        tokio::select! { result = receiver => result, _ = sender => Err(Error::Failed) }
    };
    let result = tokio::time::timeout(Duration::from_secs(65), attempt).await;
    out.json(
        "slow-body.json",
        &json!({"elapsed_ms": start.elapsed().as_millis(),
        "terminated": matches!(result, Ok(Ok(_))), "configured_ms": 60000}),
    )?;
    if matches!(result, Ok(Ok(_))) {
        Ok(())
    } else {
        Err(Error::Failed)
    }
}

/// Supervise only the sealed binary's fixed sample commands and reap every owned child.
pub(super) async fn sample(plan: &Plan, out: &Out) -> Result<()> {
    evidence::before_run(plan, sample_run(plan, out)).await
}

/// Build the supervisor only after all producing-run identities have passed preflight.
async fn sample_run(plan: &Plan, out: &Out) -> Result<()> {
    let spec = plan.asset("sample-inputs")?.read()?;
    let mut driver = LiveSample {
        plan,
        out,
        spec,
        start: Instant::now(),
        children: vec![],
        api: None,
        next_child: 0,
        resources: vec![],
        cleanup: vec![],
    };
    schedule(&mut driver).await
}

/// Publication checks bind public artifacts to the exact advertised revision.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceInputs {
    revision: String,
    tag_url: String,
    source_url: String,
    source_sha256: String,
    required_files: Vec<PublicFile>,
}

/// Required corresponding-source components have explicit roles and hashes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicFile {
    role: String,
    url: String,
    sha256: String,
}

/// Bound unauthenticated publication checks and the controlled ordinary API request.
async fn source_get(url: &str) -> Result<(Vec<u8>, String)> {
    let parsed = url::Url::parse(url).map_err(|_| Error::Invalid)?;
    let local = parsed
        .host_str()
        .is_some_and(|host| host == "127.0.0.1" || host == "[::1]");
    if !(parsed.scheme() == "https" || (local && parsed.scheme() == "http"))
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(Error::Invalid);
    }
    let attempt = async {
        let client = http(30)?;
        let request = if url.ends_with("/v1/search") {
            client.post(url).json(&v1_request("synthetic"))
        } else {
            client.get(url)
        };
        let mut response = request
            .header(reqwest::header::USER_AGENT, SOURCE_USER_AGENT)
            .header("Accept-Encoding", "identity")
            .send()
            .await
            .map_err(|_| Error::Failed)?;
        if response.status() != 200 {
            return Err(Error::Failed);
        }
        let header = response
            .headers()
            .get("source-offer")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Failed)? {
            if bytes.len() + chunk.len() > 2 * MIB as usize {
                return Err(Error::Failed);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok((bytes, header))
    };
    tokio::time::timeout(Duration::from_secs(30), attempt)
        .await
        .map_err(|_| Error::Failed)?
}

/// Unknown, dirty or generic source offers cannot satisfy an exact-revision gate.
fn source_identity(expected: &str, body: &Value, header: &str) -> Result<()> {
    let url = format!("https://github.com/Al3xWalton/agentic-search/tree/{expected}");
    if !hex(expected, 40)
        || body["revision"] != expected
        || body["licence"] != "AGPL-3.0-only"
        || !matches!(
            body["revision_source"].as_str(),
            Some("git" | "environment")
        )
        || header != url
        || body["source_url"] != url
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

/// Require the exact Git commit API document, not an unrelated repository landing page.
fn corresponding_source(revision: &str, url: &str, bytes: &[u8], hash: &str) -> Result<()> {
    let expected =
        format!("https://api.github.com/repos/Al3xWalton/agentic-search/git/commits/{revision}");
    let body: Value = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
    if url != expected || body["sha"] != revision {
        return Err(Error::Invalid);
    }
    if !hex(hash, 64)
        || input::sha256(bytes) != hash
        || !body["tree"]["sha"].as_str().is_some_and(|s| hex(s, 40))
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

/// An ordinary controlled response must advertise the same exact source offer.
fn api_source_header(revision: &str, header: &str) -> Result<()> {
    if header != format!("https://github.com/Al3xWalton/agentic-search/tree/{revision}") {
        return Err(Error::Invalid);
    }
    Ok(())
}

/// Check unauthenticated exact-source evidence without publishing a tag or deploying a service.
pub(super) async fn source_check(plan: &Plan, out: &Out) -> Result<()> {
    let base = plan.candidate_url.as_ref().ok_or(Error::Blocked)?;
    let revision = plan.candidate_revision.as_ref().ok_or(Error::Blocked)?;
    let source: SourceInputs = plan.asset("source-inputs")?.read()?;
    if source.revision != *revision
        || source.required_files.is_empty()
        || source.required_files.len() > 7
    {
        return Err(Error::Invalid);
    }
    let roles: BTreeSet<_> = source
        .required_files
        .iter()
        .map(|f| f.role.as_str())
        .collect();
    if !["licence", "build", "interfaces", "submodules", "source"]
        .into_iter()
        .all(|role| roles.contains(role))
    {
        return Err(Error::Invalid);
    }
    let mut urls = vec![
        format!("{base}/.well-known/ava-search-source"),
        format!("{base}/v1/source"),
        source.tag_url,
        source.source_url.clone(),
    ];
    urls.extend(source.required_files.iter().map(|f| f.url.clone()));
    let start = Instant::now();
    for (i, url) in urls.iter().enumerate() {
        if start.elapsed() > Duration::from_secs(300) {
            return Err(Error::Invalid);
        }
        let (bytes, header) = source_get(url).await?;
        let asset = out.bytes(&format!("source-{i:02}.json"), &bytes)?;
        if i < 2 {
            let body: Value = asset.read()?;
            source_identity(revision, &body, &header)?;
        } else if i == 2 {
            let reference: Value = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
            if reference["object"]["sha"] != *revision || reference["object"]["type"] != "commit" {
                return Err(Error::Invalid);
            }
        } else if i == 3 {
            corresponding_source(revision, url, &bytes, &source.source_sha256)?;
        } else {
            let expected = &source.required_files[i - 4];
            if !expected.url.contains(revision) || asset.sha256 != expected.sha256 {
                return Err(Error::Invalid);
            }
        }
    }
    let (bytes, header) = source_get(&format!("{base}/v1/search")).await?;
    api_source_header(revision, &header)?;
    out.json(
        "ordinary-api.json",
        &json!({"source_offer":header,
        "body_sha256":input::sha256(&bytes)}),
    )?;
    out.json(
        "source.json",
        &json!({"revision": revision, "publication_signoff": "PENDING"}),
    )?;
    Ok(())
}

/// Offline witnesses exercise production call sites with content-free assertions.
#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        static LAYOUT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// The layout fixture affects only its owning test thread and its explicitly spawned children.
    struct LayoutFixture;

    impl Drop for LayoutFixture {
        fn drop(&mut self) {
            LAYOUT.set(false);
        }
    }

    /// Shorten only the fixture's service matrix while retaining production sample supervision.
    pub(super) fn layout_fixture() -> bool {
        LAYOUT.get()
    }

    /// Child processes run the real engine parser and handlers without requiring a second binary.
    pub(super) fn child_arguments(command: &mut Process, args: &[String]) -> Vec<String> {
        if !layout_fixture() {
            return args.to_vec();
        }
        command.env(
            "STORY589_SAMPLE_CHILD",
            serde_json::to_string(args).unwrap(),
        );
        vec![
            "--exact".into(),
            "capture::tests::sample_identity_before_search".into(),
            "--nocapture".into(),
        ]
    }

    /// Synthetic identities isolate output layout from a live search cluster.
    pub(super) fn layout_identity(driver: &LiveSample<'_>) -> Result<bool> {
        if !layout_fixture() {
            return Ok(false);
        }
        let out = Out(driver.out.0.join("inputs"));
        for (i, documents) in [19285, 178].into_iter().enumerate() {
            out.json(&format!("index-{i}.json"), &json!({"documents":documents}))?;
        }
        for on in [false, true] {
            out.json(
                &format!("served-{on}.json"),
                &json!({"verified":true,
                "total_documents":19463,"shards":[
                    {"shard_id":0,"documents":19285,"socket":"127.0.0.1:57302"},
                    {"shard_id":1,"documents":178,"socket":"127.0.0.1:57303"}]}),
            )?;
        }
        Ok(true)
    }

    /// Reuse the engine command parser so output paths reach the exact production handlers.
    #[derive(clap::Parser)]
    struct EngineCli {
        #[command(subcommand)]
        command: stract::eval::Command,
    }

    /// Only recall needs a loopback responder; validation and paired diff remain entirely real.
    async fn engine_child(encoded: &str) {
        let args: Vec<String> = serde_json::from_str(encoded).unwrap();
        let cli = EngineCli::try_parse_from(args);
        assert!(cli.is_ok(), "W28_CHILD_PARSE");
        let cli = cli.unwrap();
        let mut server = None;
        if let stract::eval::Command::Recall(ref args) = cli.command {
            let on = args.expect_planner == stract::eval::Planner::On;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:57300")
                .await
                .unwrap();
            let app = axum::Router::new().route(
                "/beta/api/search",
                axum::routing::post(move |axum::Json(body): axum::Json<Value>| async move {
                    let query = body["query"].as_str().unwrap();
                    assert!(
                        body == stract::eval::runner::request(query),
                        "W28_CHILD_BODY"
                    );
                    let n: usize = query.strip_prefix("synthetic ").unwrap().parse().unwrap();
                    let url = if on || n < 18 {
                        format!("https://{n}.example.test/frozen/{n}")
                    } else {
                        "https://synthetic.example.test/cc-indexed/0".into()
                    };
                    let pages: Vec<_> = (on || n < 31)
                        .then(|| json!({"url":url,"planStage":"strict"}))
                        .into_iter()
                        .collect();
                    axum::Json(json!({"queryPlan":{"version":1,
                        "mode":if on {"staged"} else {"strict_only"},
                        "stages":[{"id":"strict","renderedQuery":query}]},
                        "webpages":pages,"searchDurationMs":1.0}))
                }),
            );
            server = Some(tokio::spawn(
                async move { axum::serve(listener, app).await },
            ));
        }
        let result = cli.command.run().await;
        if let Some(server) = server {
            server.abort();
            let _ = server.await;
        }
        assert!(result.is_ok(), "W28_CHILD_RUN");
    }

    /// Keep the real frozen protocol and corpus-count checks in the child recall handler.
    fn layout_plan(temp: &crate::fixtures::Temp) -> Plan {
        let mut plan = crate::fixtures::plan();
        plan.candidate_revision = Some("a".repeat(40));
        let labels = crate::fixtures::label_inputs(temp, &mut plan);
        crate::fixtures::corpus_inputs(temp, &mut plan, &labels);
        for (name, extra) in [("cc-indexed", 19185), ("seeds-indexed", 178)] {
            let row = plan.inputs.iter_mut().find(|row| row.name == name).unwrap();
            let mut bytes = fs::read(&row.asset.path).unwrap();
            for i in 0..extra {
                bytes.extend_from_slice(
                    format!(
                        "{}\n",
                        json!({
                    "url":[format!("https://synthetic.example.test/{name}/{i}")]})
                    )
                    .as_bytes(),
                );
            }
            row.asset = temp.asset(&format!("{name}-full"), &bytes);
        }
        let indexes: Vec<_> = (0..2)
            .map(|i| {
                let path = temp.0.join(format!("copy-{i}"));
                fs::create_dir(&path).unwrap();
                let manifest = temp.asset(&format!("manifest-{i}"), b"[]");
                json!({"path":path,"manifest":manifest,"documents":([19285,178][i]),"shard":i})
            })
            .collect();
        plan.inputs.push(NamedAsset {
            name: "sample-inputs".into(),
            asset: temp.asset(
                "sample-inputs",
                &serde_json::to_vec(&json!({
                "indexes":indexes}))
                .unwrap(),
            ),
        });
        plan
    }

    #[tokio::test]
    async fn sample_output_layout() {
        let inputs = crate::fixtures::Temp::new();
        let runs = crate::fixtures::Temp::new();
        let plan = layout_plan(&inputs);
        LAYOUT.set(true);
        let _fixture = LayoutFixture;
        let out = Out::new(&runs.0.join("sample"), &plan).unwrap();
        let result = sample(&plan, &out).await;
        assert!(result.is_ok(), "W28_SAMPLE_LAYOUT");
        written_configs(&out, &inputs.0);
        let cleanup: Value =
            serde_json::from_slice(&fs::read(out.0.join("cleanup.json")).unwrap()).unwrap();
        let children = cleanup["children"].as_array().unwrap();
        assert!(
            cleanup["failed"] == false
                && children.len() == 5
                && children.iter().all(|child| child["success"] == true),
            "W28_CHILD_EXITS"
        );
        for cell in ["frozen-off", "frozen-on", "frozen-diff"] {
            let path = out.0.join("outputs").join(cell).join("report.json");
            assert!(
                path.is_file()
                    && path.with_extension("complete").is_file()
                    && !out.0.join("inputs").join(format!("{cell}.json")).exists(),
                "W28_OUTPUT_FILES"
            );
        }
        let diff: Value = serde_json::from_slice(
            &fs::read(out.0.join("outputs/frozen-diff/report.json")).unwrap(),
        )
        .unwrap();
        assert!(diff["complete_successful_pair"] == true, "W28_PAIRED_DIFF");
        let bad = Out::new(&inputs.0.join("overlap"), &plan).unwrap();
        let result = sample(&plan, &bad).await;
        let cleanup: Value =
            serde_json::from_slice(&fs::read(bad.0.join("cleanup.json")).unwrap()).unwrap();
        assert!(
            result == Err(Error::Invalid)
                && cleanup["children"] == json!([])
                && !bad.0.join("child-0000.log").exists(),
            "W28_BEFORE_CHILD"
        );
    }

    struct FakeSample {
        identity_ok: bool,
        cleanup_ok: bool,
        elapsed: Duration,
        steps: Vec<Step>,
        cleaned: bool,
    }

    impl FakeSample {
        fn new() -> Self {
            Self {
                identity_ok: true,
                cleanup_ok: true,
                elapsed: Duration::ZERO,
                steps: vec![],
                cleaned: false,
            }
        }
    }

    impl SampleDriver for FakeSample {
        fn elapsed(&self) -> Duration {
            self.elapsed
        }
        async fn identity(&mut self) -> Result<()> {
            if self.identity_ok {
                Ok(())
            } else {
                Err(Error::Invalid)
            }
        }
        async fn step(&mut self, step: &Step) -> Result<()> {
            self.steps.push(step.clone());
            Ok(())
        }
        async fn cleanup(&mut self) -> Result<()> {
            self.cleaned = true;
            if self.cleanup_ok {
                Ok(())
            } else {
                Err(Error::Failed)
            }
        }
    }

    #[test]
    fn distinct_cc_segment() {
        let first =
            format!("crawl-data/CC-MAIN-2026-34/segments/{ORIGINAL_SEGMENT}/warc/a.warc.gz");
        let second = first.replace("a.warc", "b.warc");
        let third = "crawl-data/CC-MAIN-2026-34/segments/1786091384909.69/warc/c.warc.gz";
        let manifest = format!("{first}\n{second}\n{third}\n");
        assert!(
            select_segment(&manifest).unwrap() == (3, third.into(), "1786091384909.69".into()),
            "W12_DISTINCT"
        );
        assert!(
            select_segment(&format!("{first}\n{second}\n")).is_err(),
            "W12_ABSENT"
        );
        for invalid in [
            third.replace("/warc/", "/../"),
            format!("https://other.test/{third}"),
        ] {
            assert!(select_segment(&invalid).is_err(), "W12_GRAMMAR");
        }
    }

    #[test]
    fn cc_stream_bounds() {
        warc_bounds();
        assert!(
            limited_read(&b"1234"[..], 4).unwrap() == b"1234",
            "W13_BOUNDARY"
        );
        assert!(limited_read(&b"12345"[..], 4).is_err(), "W13_PLUS_ONE");
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"12345").unwrap();
        let compressed = encoder.finish().unwrap();
        assert!(
            limited_read(flate2::read::GzDecoder::new(&compressed[..]), 4).is_err(),
            "W13_DECOMPRESSED"
        );
        assert!(
            limited_read(
                flate2::read::GzDecoder::new(&compressed[..compressed.len() - 3]),
                10
            )
            .is_err(),
            "W13_TRUNCATED"
        );
    }

    /// Exercise the production streaming inspector with compression amplification and a stall.
    fn warc_bounds() {
        let gzip = |raw: &[u8]| {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
            encoder.write_all(raw).unwrap();
            encoder.finish().unwrap()
        };
        let record = |length| {
            format!(
                "WARC/1.0\r\nWARC-Date: 2026-01-01T00:00:00Z\r\n\
            Content-Length: {length}\r\n\r\n"
            )
        };
        let run = |bytes: &[u8]| inspect_warc(bytes, Instant::now() + Duration::from_secs(2));
        assert!(
            run(&gzip(format!("{}\r\n\r\n", record(0)).as_bytes())).is_ok(),
            "W13_WARC_VALID"
        );
        let length = input::MAX_RECORD_BYTES + 1;
        let mut raw = record(length).into_bytes();
        raw.resize(raw.len() + length, b'x');
        raw.extend_from_slice(b"\r\n\r\n");
        let compressed = gzip(&raw);
        assert!(
            compressed.len() < 100_000 && run(&compressed).is_err(),
            "W13_RECORD_CAP"
        );
        let header = record(0).replacen(
            "WARC/1.0\r\n",
            &format!("WARC/1.0\r\nX: {}\r\n", "x".repeat(32768)),
            1,
        ) + "\r\n\r\n";
        assert!(run(&gzip(header.as_bytes())).is_err(), "W13_HEADER_CAP");
        struct Stalled(std::io::Cursor<Vec<u8>>);
        impl Read for Stalled {
            fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
                std::thread::sleep(Duration::from_millis(3));
                let size = bytes.len().min(8);
                self.0.read(&mut bytes[..size])
            }
        }
        let valid = gzip(format!("{}\r\n\r\n", record(0)).as_bytes());
        assert!(
            inspect_warc(
                Stalled(std::io::Cursor::new(valid.clone())),
                Instant::now() + Duration::from_secs(2)
            )
            .is_ok(),
            "W13_STALL_VALID"
        );
        assert!(
            inspect_warc(
                Stalled(std::io::Cursor::new(valid)),
                Instant::now() + Duration::from_millis(1)
            )
            .is_err(),
            "W13_STALL"
        );
    }

    #[tokio::test]
    async fn sample_identity_before_search() {
        if let Ok(args) = std::env::var("STORY589_SAMPLE_CHILD") {
            engine_child(&args).await;
            return;
        }
        sample_preconditions().await;
        let mut fake = FakeSample::new();
        fake.identity_ok = false;
        assert!(
            schedule(&mut fake).await.is_err() && fake.steps.is_empty() && fake.cleaned,
            "W14_BEFORE_QUERY"
        );
        let temp = crate::fixtures::Temp::new();
        let binary = temp.asset("binary", b"synthetic executable");
        let mut indexes = Vec::new();
        for i in 0..2 {
            let path = temp.0.join(format!("index-{i}"));
            fs::create_dir(&path).unwrap();
            let manifest = temp.asset(&format!("manifest-{i}"), b"[]");
            indexes.push(IndexCopy {
                path,
                manifest,
                documents: [19285, 178][i],
                shard: i as u64,
            });
        }
        let mut spec = SampleInputs {
            indexes: indexes.try_into().ok().unwrap(),
        };
        assert!(identity(&spec, &binary).is_ok(), "W14_SEALED");
        spec.indexes[0].documents = 19253;
        assert!(identity(&spec, &binary).is_err(), "W14_COUNT");
        spec.indexes[0].documents = 19285;
        spec.indexes[0].shard = 1;
        assert!(identity(&spec, &binary).is_err(), "W14_SHARD");
        spec.indexes[0].shard = 0;
        spec.indexes[0].manifest.sha256 = "a".repeat(64);
        assert!(identity(&spec, &binary).is_err(), "W14_HASH");
    }

    /// Complete sample inputs make a child observable when the revision precondition is delayed.
    async fn sample_preconditions() {
        let temp = crate::fixtures::Temp::new();
        let inputs = crate::fixtures::Temp::new();
        let mut plan = crate::fixtures::plan();
        let labels = crate::fixtures::label_inputs(&inputs, &mut plan);
        crate::fixtures::corpus_inputs(&inputs, &mut plan, &labels);
        let indexes: Vec<_> = (0..2)
            .map(|i| {
                let path = temp.0.join(format!("copy-{i}"));
                fs::create_dir(&path).unwrap();
                let manifest = temp.asset(&format!("manifest-{i}"), b"[]");
                json!({"path":path,"manifest":manifest,"documents":([19285,178][i]),"shard":i})
            })
            .collect();
        plan.inputs.push(NamedAsset {
            name: "sample-inputs".into(),
            asset: temp.asset(
                "sample-inputs",
                &serde_json::to_vec(&json!({
                "indexes":indexes}))
                .unwrap(),
            ),
        });
        let out = Out::new(&temp.0.join("blocked"), &plan).unwrap();
        assert!(
            sample(&plan, &out).await == Err(Error::Blocked)
                && !out.0.join("child-0000.log").exists()
                && fs::read_dir(&out.0).unwrap().next().is_none(),
            "W14_PREFLIGHT"
        );
        plan.candidate_revision = Some("a".repeat(40));
        assert!(
            identity(
                &plan.asset("sample-inputs").unwrap().read().unwrap(),
                &plan.binary
            )
            .is_ok(),
            "W14_CONTROL_IDENTITY"
        );
        let control = Out::new(&temp.0.join("control"), &plan).unwrap();
        let result = sample(&plan, &control).await;
        written_configs(&control, &temp.0);
        let cleanup: Value =
            serde_json::from_slice(&fs::read(control.0.join("cleanup.json")).unwrap()).unwrap();
        assert!(result == Err(Error::Failed), "W14_CONTROL_RESULT");
        assert!(
            control.0.join("child-0000.log").is_file(),
            "W14_CONTROL_CHILD"
        );
        assert!(cleanup["failed"] == false, "W14_CONTROL_CLEANUP");
        assert!(
            cleanup["children"].as_array().unwrap().len() == 1,
            "W14_CONTROL_COUNT"
        );
        assert!(cleanup["children"][0]["pid"].is_u64(), "W14_CONTROL_PID");
        assert!(
            cleanup["children"][0]["success"] == false,
            "W14_CONTROL_EXIT"
        );
    }

    /// Real-template outputs retain defaults without serializing unsupported optional arrays.
    fn written_configs(out: &Out, root: &Path) {
        for on in [false, true] {
            let text = fs::read_to_string(out.0.join("inputs").join(format!("api-{on}.toml")));
            assert!(text.is_ok(), "W14_CONFIG_WRITE");
            let text = text.unwrap();
            let config = toml::from_str::<stract::config::ApiConfig>(&text);
            assert!(config.is_ok(), "W14_CONFIG_PARSE");
            let config = config.unwrap();
            assert!(
                config.agent_query_planning == on
                    && config.v1.management_http_host.to_string() == "127.0.0.1:57312"
                    && config.v1.suppression_store_path
                        == out.0.join("inputs").join("suppression.json")
                    && config.compliance.store_dir == Some(out.0.join("inputs").join("compliance"))
                    && config.compliance.records_dir == Some(out.0.join("inputs").join("records"))
                    && config
                        .compliance
                        .priority_kind_labels
                        .iter()
                        .all(Option::is_none),
                "W14_CONFIG_FIELDS"
            );
            let mut actual: toml::Value = toml::from_str(&text).unwrap();
            let table = actual.as_table_mut().unwrap();
            let v1 = table.remove("v1").unwrap();
            let compliance = table.remove("compliance").unwrap();
            assert!(
                v1.as_table()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    == ["management_http_host", "suppression_store_path"]
                    && compliance
                        .as_table()
                        .unwrap()
                        .keys()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        == ["records_dir", "store_dir"],
                "W14_CONFIG_KEYS"
            );
            table.insert("agent_query_planning".into(), toml::Value::Boolean(false));
            let template: toml::Value =
                toml::from_str(include_str!("../../../../configs/eval/api-off.toml")).unwrap();
            assert!(actual == template, "W14_CONFIG_TEMPLATE");
        }
        for i in 0..2 {
            let text =
                fs::read_to_string(out.0.join("inputs").join(format!("search-{i}.toml"))).unwrap();
            let config = toml::from_str::<stract::config::SearchServerConfig>(&text);
            assert!(config.is_ok(), "W14_SEARCH_CONFIG_PARSE");
            let config = config.unwrap();
            assert!(
                config.host.to_string() == format!("127.0.0.1:{}", 57302 + i)
                    && config.shard == i as u64
                    && config.index_path == root.join(format!("copy-{i}")).to_str().unwrap()
                    && config.linear_model_path.is_none()
                    && config.dual_encoder_model_path.is_none(),
                "W14_SEARCH_CONFIG_FIELDS"
            );
        }
    }

    #[test]
    fn v1_request_and_mapping() {
        let body = v1_request("synthetic");
        assert!(
            body == json!({"query":"synthetic","page":0,"num_results":10,
            "country":"unknown","adult_verified":false,"scholarly":false}),
            "W15_BODY"
        );
        let parsed: stract::api::v1::dto::V1SearchRequest = serde_json::from_value(body).unwrap();
        assert!(!parsed.scholarly && parsed.num_results == 10, "W15_DTO");
        let result = |url| {
            stract::api::v1::dto::AttributedResult::try_new(url, "example.test", "synthetic", "")
                .unwrap()
        };
        let reply = json!({"version":"v1","results":[result("https://example.test/b"),
            result("https://example.test/a")],"page":0,"num_results":10,"has_more_results":false});
        assert!(
            v1_urls(&serde_json::to_vec(&reply).unwrap()).unwrap()
                == vec!["https://example.test/b", "https://example.test/a"],
            "W15_ORDER"
        );
        assert!(v1_urls(b"{\"webpages\":[]}").is_err(), "W15_BETA");
        for (ordinal, expected) in [(2, 32), (3, 33)] {
            let bytes = probe(ordinal);
            assert!(bytes.is_ok(), "W15_SCANNER");
            let value: Value = serde_json::from_slice(&bytes.unwrap()).unwrap();
            assert!(
                value["query"].as_str().unwrap().split_whitespace().count() == expected,
                "W15_ATOMS"
            );
        }
        for ordinal in 0..2 {
            assert!(probe(ordinal).is_ok(), "W15_BYTES_SCANNER");
        }
        assert!(
            (0..8).map(expected_code).collect::<Vec<_>>()
                == vec![
                    None,
                    Some("query_too_long"),
                    None,
                    Some("too_many_terms"),
                    None,
                    Some("request_too_large"),
                    None,
                    Some("invalid_result_count")
                ],
            "W15_EXPECTED_CODES"
        );
        let time = std::cell::Cell::new(7.0);
        let elapsed = timed_raw_write(
            &mut Vec::new(),
            b"synthetic",
            || time.get(),
            |_| {
                time.set(time.get() + 100.0);
                Ok(())
            },
        )
        .unwrap();
        time.set(7.0);
        let beta = stract::eval::runner::write_timed(&mut Vec::new(), b"synthetic", || time.get())
            .unwrap();
        time.set(time.get() + 100.0);
        assert!(
            elapsed == beta && beta == 7.0 && time.get() == 107.0,
            "W15_TIMING_BOUNDARY"
        );
    }

    #[tokio::test]
    async fn sample_matrix_and_budget() {
        let expected = vec![
            Step::Start(false),
            Step::Verify(false),
            Step::Recall("frozen".into(), false),
            Step::Recall("held-out".into(), false),
            Step::StopApi,
            Step::Start(true),
            Step::Verify(true),
            Step::Recall("frozen".into(), true),
            Step::Recall("held-out".into(), true),
            Step::Diff("frozen".into()),
            Step::V1("frozen".into()),
            Step::Diff("held-out".into()),
            Step::V1("held-out".into()),
            Step::Load(1),
            Step::Load(4),
            Step::Load(16),
            Step::Load(32),
            Step::Load(33),
            Step::Boundary(0),
            Step::Boundary(1),
            Step::Boundary(2),
            Step::Boundary(3),
            Step::Boundary(4),
            Step::Boundary(5),
            Step::Boundary(6),
            Step::Boundary(7),
            Step::Slow,
        ];
        let mut fake = FakeSample::new();
        assert!(
            schedule(&mut fake).await.is_ok() && fake.steps == expected,
            "W16_MATRIX"
        );
        assert!(
            probe(4).unwrap().len() == 65536 && probe(5).unwrap().len() == 65537,
            "W16_BYTES"
        );
        fake = FakeSample::new();
        fake.elapsed = Duration::from_secs(5400);
        assert!(
            schedule(&mut fake).await.is_err() && fake.steps.is_empty(),
            "W16_DEADLINE"
        );
    }

    #[tokio::test]
    async fn resource_scope_and_cleanup() {
        real_children().await;
        assert!(rss_bytes(1024, true) == Some(1048576), "W17_LINUX_RSS");
        assert!(rss_bytes(1024, false) == Some(1024), "W17_MAC_RSS");
        assert!(rss_bytes(u64::MAX, true).is_none(), "W17_UNKNOWN_RSS");
        let mut fake = FakeSample::new();
        fake.cleanup_ok = false;
        assert!(
            schedule(&mut fake).await.is_err() && fake.cleaned,
            "W17_FAILED_REAP"
        );
        fake = FakeSample::new();
        fake.elapsed = Duration::from_secs(5401);
        assert!(
            schedule(&mut fake).await.is_err() && fake.cleaned && fake.steps.is_empty(),
            "W17_DEADLINE_REAP"
        );
    }

    /// Exercise process groups and wait4 on only children owned by this fixture.
    async fn real_children() {
        let temp = crate::fixtures::Temp::new();
        let out = Out(temp.0.clone());
        let binary = std::env::current_exe().unwrap();
        let mut children = vec![Owned::spawn(&binary, &["--list".into()], &out, 0).unwrap()];
        let mut cleanup = Vec::new();
        let start = Instant::now();
        while !children[0].reaped && start.elapsed() < Duration::from_secs(10) {
            let _ = poll_children(&mut children, &mut cleanup);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let stopped = children[0].stop().await;
        assert!(
            children[0].reaped
                && stopped.is_ok()
                && cleanup.len() == 1
                && cleanup[0]["status"].is_number()
                && cleanup[0]["high_water_rss_bytes"].is_number(),
            "W17_REAP_RECEIPT"
        );
        let mut child = Owned::spawn(&binary, &["--list".into()], &out, 1).unwrap();
        assert!(child.stop().await.is_ok() && child.reaped, "W17_GROUP_STOP");
    }

    /// Exercise the actual bounded D5 transport and inspect its synthetic loopback request.
    async fn source_header_case() {
        for path in ["/source", "/v1/search"] {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut byte = [0];
                while !bytes.ends_with(b"\r\n\r\n") && bytes.len() < 8192 {
                    socket.read_exact(&mut byte).unwrap();
                    bytes.push(byte[0]);
                }
                let headers = String::from_utf8(bytes).unwrap();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                assert!(length <= 8192, "W18_REQUEST_BOUND");
                socket.read_exact(&mut vec![0; length]).unwrap();
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\
                    Connection: close\r\n\r\n{}",
                    )
                    .unwrap();
                headers
            });
            let result = source_get(&format!("http://{address}{path}")).await;
            let request = server.join().unwrap();
            assert!(
                result.is_ok_and(|reply| reply == (b"{}".to_vec(), String::new()))
                    && request.lines().any(|line| line
                        .eq_ignore_ascii_case("user-agent: AgenticSearch-Stage1-Evaluation/589")),
                "W18_USER_AGENT"
            );
        }
    }

    #[tokio::test]
    async fn source_exact_revision() {
        source_header_case().await;
        let sha = "a".repeat(40);
        let url = format!("https://github.com/Al3xWalton/agentic-search/tree/{sha}");
        let body = json!({"revision":sha,"licence":"AGPL-3.0-only",
            "revision_source":"git","source_url":url});
        assert!(source_identity(&sha, &body, &url).is_ok(), "W18_EXACT");
        let mut wrong = body.clone();
        wrong["revision"] = json!("b".repeat(40));
        assert!(source_identity(&sha, &wrong, &url).is_err(), "W18_REVISION");
        assert!(
            source_identity("unknown", &body, &url).is_err(),
            "W18_UNKNOWN"
        );
        wrong = body.clone();
        wrong["source_url"] = json!("https://github.com/Al3xWalton/agentic-search");
        assert!(source_identity(&sha, &wrong, &url).is_err(), "W18_GENERIC");
        wrong = body;
        wrong["revision_source"] = json!("unknown");
        assert!(source_identity(&sha, &wrong, &url).is_err(), "W18_DIRTY");
        let source_url =
            format!("https://api.github.com/repos/Al3xWalton/agentic-search/git/commits/{sha}");
        let source = serde_json::to_vec(&json!({"sha":sha,"tree":{"sha":"b".repeat(40)}})).unwrap();
        let hash = input::sha256(&source);
        assert!(
            corresponding_source(&sha, &source_url, &source, &hash).is_ok(),
            "W18_SOURCE_VALID"
        );
        assert!(
            corresponding_source(&"c".repeat(40), &source_url, &source, &hash).is_err(),
            "W18_SOURCE_REVISION"
        );
        assert!(
            api_source_header(&sha, &url).is_ok()
                && api_source_header(&sha, "https://example.test/generic").is_err(),
            "W18_API_HEADER"
        );
    }
}
