// SPDX-License-Identifier: AGPL-3.0-only
//! Sequential, durable-reservation baseline; uncertainty is terminal and remains charged.
//! Provider contract authenticity and account exclusivity are orchestrator responsibilities.

use super::*;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::time::{Duration, Instant};

/// Paid dispatch has one fixed authenticated destination.
#[cfg(not(test))]
const ENDPOINT: &str = "https://api.firecrawl.dev/v2/search";
/// Caller witnesses exercise the real transport without contacting a provider.
#[cfg(test)]
const ENDPOINT: &str = "http://127.0.0.1:57320/v2/search";
/// The founder's lifetime Story allowance cannot expand after a reset.
const CAP: u64 = 300;
/// Streamed provider bodies are bounded before JSON allocation.
const RESPONSE_CAP: usize = 8 * 1024 * 1024;
/// Reflected provider bodies cannot become ledger diagnostics.
const UNCERTAIN_ATTEMPT: &str = "terminal_uncertain_attempt";

/// Documented price and rate bounds are prerequisites to any paid request.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Contract {
    endpoint: String,
    dated: String,
    documentation: Asset,
    request_example: Value,
    maximum_credits: u64,
    requests_per_minute: u64,
    concurrency: u64,
    balance_url: Option<String>,
    balance_reads_zero_credit: bool,
}

/// Admit only the fixed provider request with documented price, rate and concurrency bounds.
impl Contract {
    fn gap_ms(&self) -> Result<u64> {
        if self.endpoint != ENDPOINT
            || self.dated.is_empty()
            || !(1..=6).contains(&self.maximum_credits)
            || self.requests_per_minute == 0
            || self.concurrency == 0
            || self.request_example != request("synthetic")
            || self.balance_url.is_some() != self.balance_reads_zero_credit
        {
            return Err(Error::Blocked);
        }
        if let Some(url) = &self.balance_url {
            let url = url::Url::parse(url).map_err(|_| Error::Blocked)?;
            if url.scheme() != "https"
                || url.host_str() != Some("api.firecrawl.dev")
                || url.port().is_some()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(Error::Blocked);
            }
        }
        Ok(2000.max(120_000u64.div_ceil(self.requests_per_minute)))
    }
}

/// Pool exclusivity and the canonical ledger bind dispatch accounting.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatchInputs {
    exclusive_pool: bool,
    preflight_balance: u64,
    ledger: PathBuf,
    held_out: bool,
}

/// Unresolved reservations remain charged through uncertainty and restart.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    version: u32,
    settled: u64,
    unresolved: u64,
    complete: bool,
    calls: Vec<Call>,
    pending: Option<Pending>,
}

/// The durable pre-send identity makes an interrupted paid attempt non-repeatable.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    set: String,
    id: String,
    request_sha256: String,
    available_before: u64,
    settled_before: u64,
    unresolved_before: u64,
}

/// Each attempt records its timing and credit transition without credentials.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Call {
    set: String,
    id: String,
    reservation: u64,
    status: Option<u16>,
    credits_used: Option<u64>,
    started_ms: u64,
    elapsed_ms: u64,
    urls: Option<Vec<String>>,
    failure: Option<String>,
    credit_before: Pending,
    settled_after: u64,
    unresolved_after: u64,
}

/// Reserve durable credit before send and prevent restart of an uncertain paid batch.
impl Ledger {
    fn new() -> Self {
        Self {
            version: 1,
            settled: 0,
            unresolved: 0,
            complete: true,
            calls: vec![],
            pending: None,
        }
    }

    fn reserve(&mut self, charge: u64, balance: u64) -> Result<()> {
        let total = self
            .settled
            .checked_add(self.unresolved)
            .and_then(|v| v.checked_add(charge))
            .ok_or(Error::Blocked)?;
        if total > CAP || balance < charge {
            return Err(Error::Blocked);
        }
        self.unresolved = self.unresolved.checked_add(charge).ok_or(Error::Blocked)?;
        self.complete = false;
        Ok(())
    }

    fn settle(&mut self, reserved: u64, usage: u64) -> Result<()> {
        if usage > reserved {
            return Err(Error::Failed);
        }
        self.unresolved = self
            .unresolved
            .checked_sub(reserved)
            .ok_or(Error::Invalid)?;
        self.settled = self.settled.checked_add(usage).ok_or(Error::Failed)?;
        Ok(())
    }

    fn start(&self) -> Result<()> {
        if !self.complete || self.unresolved != 0 || self.pending.is_some() {
            return Err(Error::Blocked);
        }
        if self.version != 1 || self.settled > CAP {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

/// Status and bounded body bytes are preserved independently of parsing success.
struct Reply {
    status: u16,
    bytes: Vec<u8>,
}

/// The same paid-run algorithm accepts real transport or a deterministic offline fake.
trait Driver {
    fn persist(&mut self, ledger: &Ledger) -> Result<()>;
    fn now_ms(&self) -> u64;
    async fn wait_until(&mut self, millis: u64) -> Result<()>;
    async fn balance(&mut self) -> Result<Option<u64>>;
    async fn send(&mut self, body: &Value) -> Result<Reply>;
}

/// Keep the admitted search-only request shape exact.
fn request(query: &str) -> Value {
    json!({"query": query, "limit": 10, "sources": ["web"], "country": "US"})
}

/// Only a validated success envelope can settle its reserved charge.
fn response(reply: &Reply, bound: u64) -> Result<(Vec<String>, u64)> {
    if reply.status != 200 || reply.bytes.len() > RESPONSE_CAP {
        return Err(Error::Failed);
    }
    let value: Value = serde_json::from_slice(&reply.bytes).map_err(|_| Error::Failed)?;
    if value["success"] != true {
        return Err(Error::Failed);
    }
    let usage = value["creditsUsed"]
        .as_u64()
        .filter(|n| *n <= bound)
        .ok_or(Error::Failed)?;
    let rows = value["data"]["web"].as_array().ok_or(Error::Failed)?;
    if rows.len() > 10 {
        return Err(Error::Failed);
    }
    let urls = rows
        .iter()
        .map(|r| {
            let url = r["url"].as_str().ok_or(Error::Failed)?;
            stract::eval::normalize::normalize(url)?;
            Ok(url.to_owned())
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((urls, usage))
}

/// The monotonic clock must prove the gap before another send.
async fn paced<D: Driver>(driver: &mut D, previous: Option<u64>, gap: u64) -> Result<()> {
    if let Some(previous) = previous {
        let next = previous.checked_add(gap).ok_or(Error::Failed)?;
        driver.wait_until(next).await?;
        if driver.now_ms() < next {
            return Err(Error::Failed);
        }
    }
    Ok(())
}

/// Persist every reservation before dispatch and stop on the first uncertainty.
async fn batch<D: Driver>(
    driver: &mut D,
    ledger: &mut Ledger,
    contract: &Contract,
    queries: &[(String, stract::eval::labels::Label)],
    initial_balance: u64,
) -> Result<()> {
    ledger.start()?;
    let gap = contract.gap_ms()?;
    let start = driver.now_ms();
    let budget = (queries.len() as u64)
        .checked_mul(60_000 + gap)
        .ok_or(Error::Blocked)?;
    let mut previous = None;
    let mut balance = initial_balance;
    let mut last_usage = 0;
    for (set, label) in queries {
        if ledger
            .calls
            .iter()
            .any(|c| c.set == *set && c.id == label.id)
        {
            return Err(Error::Blocked);
        }
        paced(driver, previous, gap).await?;
        if driver.now_ms().saturating_sub(start) >= budget {
            return Err(Error::Failed);
        }
        if let Some(observed) = driver.balance().await? {
            if balance.checked_sub(last_usage) != Some(observed) {
                return Err(Error::Blocked);
            }
            balance = observed;
        } else {
            balance = balance.checked_sub(last_usage).ok_or(Error::Blocked)?;
        }
        let pending = Pending {
            set: set.clone(),
            id: label.id.clone(),
            available_before: balance,
            request_sha256: input::sha256(
                &serde_json::to_vec(&request(&label.query)).map_err(|_| Error::Invalid)?,
            ),
            settled_before: ledger.settled,
            unresolved_before: ledger.unresolved,
        };
        ledger.reserve(contract.maximum_credits, balance)?;
        ledger.pending = Some(pending.clone());
        driver.persist(ledger)?;
        let sent = driver.now_ms();
        previous = Some(sent);
        let reply = driver.send(&request(&label.query)).await;
        let error_text = UNCERTAIN_ATTEMPT.to_owned();
        let mut call = Call {
            set: set.clone(),
            id: label.id.clone(),
            reservation: contract.maximum_credits,
            status: reply.as_ref().ok().map(|r| r.status),
            credits_used: None,
            started_ms: sent,
            elapsed_ms: driver.now_ms().saturating_sub(sent),
            urls: None,
            failure: None,
            credit_before: pending,
            settled_after: ledger.settled,
            unresolved_after: ledger.unresolved,
        };
        let mapped = reply.and_then(|reply| {
            if reply.status != 200 {
                return Err(if matches!(reply.status, 402 | 429) {
                    Error::Blocked
                } else {
                    Error::Failed
                });
            }
            response(&reply, contract.maximum_credits)
        });
        match mapped {
            Ok((urls, usage)) => {
                ledger.settle(contract.maximum_credits, usage)?;
                last_usage = usage;
                call.urls = Some(urls);
                call.credits_used = Some(usage);
                call.settled_after = ledger.settled;
                call.unresolved_after = ledger.unresolved;
                ledger.pending = None;
            }
            Err(error) => {
                call.failure = Some(error_text);
                ledger.calls.push(call);
                driver.persist(ledger)?;
                return Err(error);
            }
        }
        ledger.calls.push(call);
        driver.persist(ledger)?;
    }
    if let Some(observed) = driver.balance().await? {
        if balance.checked_sub(last_usage) != Some(observed) {
            return Err(Error::Blocked);
        }
    }
    ledger.complete = true;
    driver.persist(ledger)?;
    Ok(())
}

/// No redirects, proxies or connection reuse can bypass the fixed provider contract.
fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .no_proxy()
        .http1_only()
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|_| Error::Failed)
}

/// Enforce the body cap during streaming rather than after allocation.
async fn bounded_response(mut response: reqwest::Response) -> Result<Reply> {
    let status = response.status().as_u16();
    let mut bytes = Vec::new();
    if response
        .content_length()
        .is_some_and(|n| n > RESPONSE_CAP as u64)
    {
        return Err(Error::Failed);
    }
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Failed)? {
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|n| n > RESPONSE_CAP)
        {
            return Err(Error::Failed);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(Reply { status, bytes })
}

/// Owner-only single-link key files keep credentials outside argv and diagnostics.
fn secret(path: &Path) -> Result<reqwest::header::HeaderValue> {
    let parent = path.parent().ok_or(Error::Invalid)?;
    let meta = fs::metadata(input::inspect_path(parent, false)?).map_err(|_| Error::Invalid)?;
    let file = input::open(path)?;
    let file_meta = file.metadata().map_err(|_| Error::Invalid)?;
    // The effective UID check binds credentials to the invoking account, not a root-owned fixture.
    let uid = unsafe { libc::geteuid() };
    if meta.mode() & 0o077 != 0
        || file_meta.mode() & 0o777 != 0o600
        || file_meta.uid() != uid
        || meta.uid() != uid
        || file_meta.nlink() != 1
    {
        return Err(Error::Invalid);
    }
    let bytes = read_private(path, 4096)?;
    let key = std::str::from_utf8(&bytes)
        .map_err(|_| Error::Invalid)?
        .trim_end_matches('\n');
    if key.is_empty() || key.chars().any(char::is_whitespace) {
        return Err(Error::Invalid);
    }
    let mut header = reqwest::header::HeaderValue::from_str(&format!("Bearer {key}"))
        .map_err(|_| Error::Invalid)?;
    header.set_sensitive(true);
    Ok(header)
}

/// Only the real driver owns the key and locked credit ledger.
struct Live<'a> {
    ledger: fs::File,
    key: reqwest::header::HeaderValue,
    balance_url: Option<String>,
    start: Instant,
    out: &'a Out,
    raw_number: usize,
    balances: Vec<Value>,
}

/// Persist reservations and send bounded requests while keeping credentials out of receipts.
impl Driver for Live<'_> {
    fn persist(&mut self, ledger: &Ledger) -> Result<()> {
        let mut bytes = serde_json::to_vec(ledger).map_err(|_| Error::Failed)?;
        bytes.push(b'\n');
        self.ledger
            .seek(SeekFrom::End(0))
            .map_err(|_| Error::Failed)?;
        self.ledger.write_all(&bytes).map_err(|_| Error::Failed)?;
        self.ledger.sync_all().map_err(|_| Error::Failed)
    }

    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    async fn wait_until(&mut self, millis: u64) -> Result<()> {
        tokio::time::sleep(Duration::from_millis(millis.saturating_sub(self.now_ms()))).await;
        Ok(())
    }

    async fn balance(&mut self) -> Result<Option<u64>> {
        let Some(url) = &self.balance_url else {
            return Ok(None);
        };
        let response = client()?
            .get(url)
            .header(reqwest::header::AUTHORIZATION, self.key.clone())
            .header("Accept-Encoding", "identity")
            .send()
            .await
            .map_err(|_| Error::Failed)?;
        let reply = bounded_response(response).await?;
        if reply.status != 200 {
            return Err(Error::Failed);
        }
        let value: Value = serde_json::from_slice(&reply.bytes).map_err(|_| Error::Failed)?;
        let credits = value["remainingCredits"].as_u64().ok_or(Error::Failed)?;
        self.balances
            .push(json!({"elapsed_ms":self.now_ms(),"remaining_credits":credits}));
        Ok(Some(credits))
    }

    async fn send(&mut self, body: &Value) -> Result<Reply> {
        let attempt = async {
            let response = client()?
                .post(ENDPOINT)
                .header(reqwest::header::AUTHORIZATION, self.key.clone())
                .header("Accept-Encoding", "identity")
                .header("Connection", "close")
                .json(body)
                .send()
                .await
                .map_err(|_| Error::Failed)?;
            let reply = bounded_response(response).await?;
            let secret = self.key.to_str().map_err(|_| Error::Failed)?;
            let secret = secret.strip_prefix("Bearer ").ok_or(Error::Failed)?;
            if reply
                .bytes
                .windows(secret.len())
                .any(|w| w == secret.as_bytes())
            {
                return Err(Error::Failed);
            }
            let record = if reply.status == 200 && self::response(&reply, 6).is_ok() {
                reply.bytes.clone()
            } else {
                serde_json::to_vec(&json!({"status":reply.status,
                    "body_sha256":input::sha256(&reply.bytes),
                    "error":UNCERTAIN_ATTEMPT}))
                .map_err(|_| Error::Failed)?
            };
            self.out
                .bytes(&format!("raw-{:04}.json", self.raw_number), &record)?;
            self.raw_number += 1;
            Ok(reply)
        };
        tokio::time::timeout(Duration::from_secs(60), attempt)
            .await
            .map_err(|_| Error::Failed)?
    }
}

/// Exclusive locking and append history prevent concurrent spending or silent truncation.
fn open_ledger(path: &Path) -> Result<(fs::File, Ledger)> {
    input::inspect_path(path, true)?;
    let existed = path.exists();
    let mut file = if existed {
        let meta = input::open(path)?.metadata().map_err(|_| Error::Invalid)?;
        if meta.nlink() != 1 || meta.mode() & 0o777 != 0o600 {
            return Err(Error::Invalid);
        }
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| Error::Blocked)?
    } else {
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| Error::Blocked)?
    };
    fs4::FileExt::try_lock_exclusive(&file).map_err(|_| Error::Blocked)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(input::MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Invalid)?;
    let ledger = if bytes.is_empty() && !existed {
        Ledger::new()
    } else {
        if bytes.last() != Some(&b'\n') || bytes.len() as u64 > input::MAX_INPUT_BYTES {
            return Err(Error::Invalid);
        }
        let mut ledger = None;
        for line in bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            ledger = Some(serde_json::from_slice(line).map_err(|_| Error::Invalid)?);
        }
        ledger.ok_or(Error::Invalid)?
    };
    fs::File::open(path.parent().ok_or(Error::Invalid)?)
        .and_then(|parent| parent.sync_all())
        .map_err(|_| Error::Failed)?;
    Ok((file, ledger))
}

/// A sealed plan can open only its pre-created canonical ledger, never a fresh allowance.
fn canonical_ledger(plan: &Plan, requested: &Path) -> Result<(fs::File, Ledger)> {
    let canonical = plan.asset("credit-ledger")?;
    canonical.verify()?;
    if requested != canonical.path {
        return Err(Error::Blocked);
    }
    open_ledger(requested)
}

/// Execute only the fixed search request after plan, contract, key and ledger validation.
pub(super) async fn run(plan: &Plan, out: &Out, key: &Path) -> Result<()> {
    evidence::before_run(plan, paid_run(plan, out, key)).await
}

/// All provider and label inputs are checked before opening the canonical ledger.
async fn paid_run(plan: &Plan, out: &Out, key: &Path) -> Result<()> {
    let asset = plan.asset("provider-contract")?;
    let contract: Contract = asset.read()?;
    contract.documentation.verify()?;
    let gap = contract.gap_ms()?;
    let dispatch: DispatchInputs = plan.asset("dispatch-inputs")?.read()?;
    if !dispatch.exclusive_pool {
        return Err(Error::Blocked);
    }
    let sets = if dispatch.held_out {
        vec!["frozen", "held-out"]
    } else {
        vec!["frozen"]
    };
    let mut queries = Vec::new();
    for set in sets {
        queries.extend(
            agreement::labels(plan, set)?
                .into_iter()
                .map(|r| (set.to_owned(), r)),
        );
    }
    let (file, mut ledger) = canonical_ledger(plan, &dispatch.ledger)?;
    let mut driver = Live {
        ledger: file,
        key: secret(key)?,
        balance_url: contract.balance_url.clone(),
        start: Instant::now(),
        out,
        raw_number: 0,
        balances: vec![],
    };
    let result = batch(
        &mut driver,
        &mut ledger,
        &contract,
        &queries,
        dispatch.preflight_balance,
    )
    .await;
    let skipped: Vec<_> = queries
        .iter()
        .filter(|(set, r)| !ledger.calls.iter().any(|c| c.set == *set && c.id == r.id))
        .map(|(set, r)| json!({"set": set, "id": r.id}))
        .collect();
    out.json(
        "run.json",
        &json!({"ledger": ledger, "skipped": skipped,
        "rows": queries.iter().map(|(set, label)| {
            let call = ledger.calls.iter().find(|c| c.set == *set && c.id == label.id);
            json!({"set":set,"id":label.id,"query":label.query,"category":label.category,
                "success":call.is_some_and(|c| c.urls.is_some()),
                "urls":call.and_then(|c| c.urls.as_ref()),
                "latency_ms":call.filter(|c| c.urls.is_some()).map(|c| c.elapsed_ms),
                "status":call.and_then(|c| c.status)})
        }).collect::<Vec<_>>(),
        "gap_ms": gap, "time_budget_ms": queries.len() as u64 * (60_000 + gap),
        "preflight_balance":dispatch.preflight_balance, "balance_reads":driver.balances,
        "postflight_balance":if result.is_ok() {driver.balances.last()
            .and_then(|v|v["remaining_credits"].as_u64())} else {None},
        "complete": result.is_ok(), "credit_cap": CAP,
        "attribution": if contract.balance_url.is_some() { "balance_cross_checked" }
            else { "creditsUsed_only; concurrent spend cannot be excluded" }}),
    )?;
    seal_baseline(plan, out, &queries)?;
    result
}

/// Preserve provider response and contract identities for downstream scoring.
fn seal_baseline(
    plan: &Plan,
    out: &Out,
    queries: &[(String, stract::eval::labels::Label)],
) -> Result<()> {
    let path = out.0.join("run.json");
    let raw = Asset {
        sha256: input::hash_file(&path)?,
        path,
    };
    let mut responses = Vec::new();
    for entry in fs::read_dir(&out.0).map_err(|_| Error::Invalid)? {
        let path = entry.map_err(|_| Error::Invalid)?.path();
        if path
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("raw-"))
        {
            responses.push(Asset {
                sha256: input::hash_file(&path)?,
                path,
            });
        }
    }
    responses.sort_by(|a, b| a.path.cmp(&b.path));
    for set in queries
        .iter()
        .map(|q| q.0.as_str())
        .collect::<BTreeSet<_>>()
    {
        evidence::seal_run(
            plan,
            out,
            (set, "firecrawl", "on"),
            raw.clone(),
            vec![plan.asset("provider-contract")?.clone()],
            responses.clone(),
        )?;
    }
    Ok(())
}

/// Offline witnesses exercise production call sites with content-free assertions.
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct Fake {
        queue: VecDeque<Result<Reply>>,
        bodies: Vec<Value>,
        times: Vec<u64>,
        now: u64,
        stuck: bool,
        write_failure: bool,
        events: Vec<&'static str>,
        balances: VecDeque<Option<u64>>,
        persisted: Vec<Ledger>,
    }

    impl Fake {
        fn new(queue: Vec<Result<Reply>>) -> Self {
            Self {
                queue: queue.into(),
                bodies: vec![],
                times: vec![],
                now: 0,
                stuck: false,
                write_failure: false,
                events: vec![],
                balances: VecDeque::new(),
                persisted: vec![],
            }
        }
    }

    impl Driver for Fake {
        fn persist(&mut self, ledger: &Ledger) -> Result<()> {
            self.events.push("persist");
            self.persisted.push(ledger.clone());
            if self.write_failure {
                Err(Error::Failed)
            } else {
                Ok(())
            }
        }
        fn now_ms(&self) -> u64 {
            self.now
        }
        async fn wait_until(&mut self, value: u64) -> Result<()> {
            if !self.stuck {
                self.now = self.now.max(value);
            }
            Ok(())
        }
        async fn balance(&mut self) -> Result<Option<u64>> {
            Ok(self.balances.pop_front().flatten())
        }
        async fn send(&mut self, body: &Value) -> Result<Reply> {
            self.events.push("send");
            self.bodies.push(body.clone());
            self.times.push(self.now);
            self.queue.pop_front().unwrap_or(Err(Error::Failed))
        }
    }

    fn contract() -> Contract {
        Contract {
            endpoint: ENDPOINT.into(),
            dated: "2026-10-04".into(),
            documentation: Asset {
                path: PathBuf::new(),
                sha256: "a".repeat(64),
            },
            request_example: request("synthetic"),
            maximum_credits: 6,
            requests_per_minute: 60,
            concurrency: 1,
            balance_url: None,
            balance_reads_zero_credit: false,
        }
    }

    fn reply(status: u16, usage: Value) -> Result<Reply> {
        Ok(Reply {
            status,
            bytes: serde_json::to_vec(&json!({"success":true,
            "creditsUsed":usage,"data":{"web":[{"url":"https://example.test/a"}]}}))
            .unwrap(),
        })
    }

    fn queries(n: usize) -> Vec<(String, stract::eval::labels::Label)> {
        (0..n)
            .map(|i| ("frozen".into(), crate::fixtures::label(i)))
            .collect()
    }

    #[tokio::test]
    async fn reserve_before_send() {
        paid_preconditions().await;
        for (spent, expected) in [(0, 50), (294, 1), (295, 0)] {
            let mut fake = Fake::new((0..51).map(|_| reply(200, json!(6))).collect());
            let mut ledger = Ledger::new();
            ledger.settled = spent;
            let _ = batch(&mut fake, &mut ledger, &contract(), &queries(51), 1000).await;
            assert!(fake.bodies.len() == expected, "W07_CAP");
            assert!(
                fake.events
                    .windows(2)
                    .all(|w| w[1] != "send" || w[0] == "persist"),
                "W07_DURABLE_ORDER"
            );
            assert!(ledger.settled + ledger.unresolved <= 300, "W07_TOTAL");
            if expected > 0 {
                let pending = fake.persisted[0].pending.as_ref().unwrap();
                assert!(
                    pending.id == "q00"
                        && pending.set == "frozen"
                        && pending.settled_before == spent
                        && pending.available_before == 1000,
                    "W07_PENDING_BEFORE_SEND"
                );
            }
        }
        let mut fake = Fake::new(vec![reply(200, json!(6))]);
        fake.write_failure = true;
        assert!(
            batch(&mut fake, &mut Ledger::new(), &contract(), &queries(1), 100)
                .await
                .is_err(),
            "W07_WRITE_FAILURE"
        );
        assert!(fake.bodies.is_empty(), "W07_ZERO_SENDS");
        durable_roundtrip();
    }

    fn durable_roundtrip() {
        let temp = crate::fixtures::Temp::new();
        let out = Out(temp.0.clone());
        let path = temp.0.join("ledger");
        let (file, mut ledger) = open_ledger(&path).unwrap();
        ledger.reserve(6, 100).unwrap();
        ledger.pending = Some(Pending {
            set: "frozen".into(),
            id: "q00".into(),
            request_sha256: "a".repeat(64),
            available_before: 100,
            settled_before: 0,
            unresolved_before: 0,
        });
        let mut live = Live {
            ledger: file,
            key: reqwest::header::HeaderValue::from_static("Bearer synthetic"),
            balance_url: None,
            start: Instant::now(),
            out: &out,
            raw_number: 0,
            balances: vec![],
        };
        live.persist(&ledger).unwrap();
        assert!(open_ledger(&path).is_err(), "W07_EXCLUSIVE");
        drop(live);
        let (_, restored) = open_ledger(&path).unwrap();
        assert!(
            restored.start().is_err()
                && restored.pending.as_ref().unwrap().id == "q00"
                && restored.unresolved == 6,
            "W07_DURABLE_PENDING"
        );
    }

    /// The real caller must block before its ledger and transport; a valid plan reaches both.
    async fn paid_preconditions() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        let temp = crate::fixtures::Temp::new();
        let mut plan = crate::fixtures::plan();
        crate::fixtures::label_inputs(&temp, &mut plan);
        let mut contract = contract();
        contract.documentation = temp.asset("documentation", b"synthetic contract");
        let key = temp.asset("key", b"synthetic-key");
        let bytes = format!("{}\n", serde_json::to_string(&Ledger::new()).unwrap());
        let ledger = temp.asset("ledger", bytes.as_bytes());
        for (name, value) in [
            ("provider-contract", json!(contract)),
            (
                "dispatch-inputs",
                json!({"exclusive_pool":true,"preflight_balance":100,
                "ledger":ledger.path,"held_out":false}),
            ),
        ] {
            plan.inputs.push(NamedAsset {
                name: name.into(),
                asset: temp.asset(name, &serde_json::to_vec(&value).unwrap()),
            });
        }
        plan.inputs.push(NamedAsset {
            name: "credit-ledger".into(),
            asset: ledger.clone(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:57320")
            .await
            .unwrap();
        let sends = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&sends);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            observed.fetch_add(1, Ordering::SeqCst);
            paid_reply(stream).await;
        });
        let out = Out::new(&temp.0.join("paid"), &plan).unwrap();
        for revision in [None, Some("unknown".into())] {
            plan.candidate_revision = revision;
            let result = run(&plan, &out, &key.path).await;
            assert!(
                result == Err(Error::Blocked)
                    && fs::read(&ledger.path).unwrap() == bytes.as_bytes()
                    && sends.load(Ordering::SeqCst) == 0
                    && fs::read_dir(&out.0).unwrap().next().is_none(),
                "W07_PREFLIGHT"
            );
        }
        plan.candidate_revision = Some("a".repeat(40));
        let result = run(&plan, &out, &key.path).await;
        server.await.unwrap();
        assert!(
            result == Err(Error::Blocked)
                && sends.load(Ordering::SeqCst) == 1
                && fs::read(&ledger.path).unwrap() != bytes.as_bytes(),
            "W07_CALLER_CONTROL"
        );
    }

    /// A terminal synthetic reply stops the valid caller after one observable request.
    async fn paid_reply(mut stream: tokio::net::TcpStream) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut bytes = Vec::new();
        loop {
            let mut chunk = [0; 1024];
            let count = stream.read(&mut chunk).await.unwrap();
            assert!(count > 0 && bytes.len() < 8192, "W07_FIXTURE_REQUEST");
            bytes.extend_from_slice(&chunk[..count]);
            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let header = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
                let length: usize = header
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length: ")
                            .and_then(|n| n.parse().ok())
                    })
                    .unwrap();
                if bytes.len() >= end + 4 + length {
                    let body: Value = serde_json::from_slice(&bytes[end + 4..]).unwrap();
                    assert!(body == request("synthetic 0"), "W07_CALLER_BODY");
                    break;
                }
            }
        }
        let body = r#"{"success":false,"creditsUsed":0}"#;
        let response = format!(
            "HTTP/1.1 402 Payment Required\r\nContent-Length: {}\r\n\
            Connection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    }

    #[tokio::test]
    async fn first_credit_error_stops() {
        let mut paced_contract = contract();
        paced_contract.requests_per_minute = 20;
        let mut paced = Fake::new(vec![reply(200, json!(2)), reply(200, json!(2))]);
        let result = batch(
            &mut paced,
            &mut Ledger::new(),
            &paced_contract,
            &queries(2),
            100,
        )
        .await;
        assert!(
            result.is_ok() && paced.times == vec![0, 6000],
            "W08_RATE_GAP"
        );
        for status in [402, 429] {
            let mut fake = Fake::new(vec![
                reply(200, json!(2)),
                reply(status, json!(0)),
                reply(200, json!(2)),
            ]);
            let mut ledger = Ledger::new();
            let result = batch(&mut fake, &mut ledger, &contract(), &queries(3), 100).await;
            assert!(
                result.is_err() && fake.bodies.len() == 2 && fake.queue.len() == 1,
                "W08_TERMINAL"
            );
            assert!(fake.times == vec![0, 2000], "W08_GAP");
            assert!(
                ledger.calls.len() == 2 && ledger.calls[1].status == Some(status),
                "W08_RECEIPT"
            );
        }
        let mut fake = Fake::new(vec![reply(200, json!(2)), reply(200, json!(2))]);
        fake.stuck = true;
        assert!(
            batch(&mut fake, &mut Ledger::new(), &contract(), &queries(2), 100)
                .await
                .is_err()
                && fake.bodies.len() == 1,
            "W08_STUCK_CLOCK"
        );
    }

    /// A different output path cannot reset a plan's already pinned credit allowance.
    #[test]
    fn canonical_credit_ledger() {
        let temp = crate::fixtures::Temp::new();
        let mut bytes = serde_json::to_vec(&Ledger::new()).unwrap();
        bytes.push(b'\n');
        let canonical = temp.asset("ledger.jsonl", &bytes);
        let mut plan = crate::fixtures::plan();
        plan.inputs.push(NamedAsset {
            name: "credit-ledger".into(),
            asset: canonical.clone(),
        });
        assert!(
            canonical_ledger(&plan, &canonical.path).is_ok(),
            "W07_CANONICAL_VALID"
        );
        assert!(
            canonical_ledger(&plan, &temp.0.join("fresh.jsonl")).is_err(),
            "W07_CANONICAL_PIN"
        );
    }

    #[tokio::test]
    async fn uncertain_spend_stops() {
        for uncertain in [
            Err(Error::Failed),
            reply(200, Value::Null),
            reply(200, json!(7)),
            reply(500, json!(0)),
            reply(200, json!("synthetic")),
        ] {
            let mut fake = Fake::new(vec![uncertain, reply(200, json!(2))]);
            let mut ledger = Ledger::new();
            assert!(
                batch(&mut fake, &mut ledger, &contract(), &queries(2), 100)
                    .await
                    .is_err(),
                "W09_UNCERTAIN"
            );
            assert!(
                fake.bodies.len() == 1 && ledger.unresolved == 6 && ledger.settled == 0,
                "W09_RESERVATION"
            );
            assert!(ledger.start().is_err(), "W09_RESTART");
        }
        let mut fake = Fake::new(vec![reply(200, json!(2)), reply(200, json!(2))]);
        fake.balances = [Some(100), Some(97)].into_iter().collect();
        assert!(
            batch(&mut fake, &mut Ledger::new(), &contract(), &queries(2), 100)
                .await
                .is_err()
                && fake.bodies.len() == 1,
            "W09_INTERFERENCE"
        );
        let mut missing = contract();
        missing.requests_per_minute = 0;
        assert!(missing.gap_ms().is_err(), "W09_RATE_REQUIRED");
    }

    #[tokio::test]
    async fn baseline_transport_and_secret() {
        let mut fake = Fake::new(vec![Ok(Reply {
            status: 500,
            bytes: b"synthetic reflected credential".to_vec(),
        })]);
        let mut ledger = Ledger::new();
        let _ = batch(&mut fake, &mut ledger, &contract(), &queries(1), 100).await;
        assert!(
            ledger.calls[0].failure.as_deref() == Some("terminal_uncertain_attempt"),
            "W10_REDACTION"
        );
        use std::net::TcpListener;
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let sends = Arc::new(AtomicUsize::new(0));
        let seen = sends.clone();
        let server = std::thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < Duration::from_millis(500) {
                if let Ok((mut stream, _)) = listener.accept() {
                    let ordinal = seen.fetch_add(1, Ordering::SeqCst);
                    stream
                        .set_read_timeout(Some(Duration::from_millis(100)))
                        .unwrap();
                    let mut buffer = [0; 4096];
                    let _ = stream.read(&mut buffer);
                    let reply = format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://{address}/next\r\n\
                        Content-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    if ordinal == 0 {
                        let _ = stream.write_all(reply.as_bytes());
                    } else {
                        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        });
        let response = client()
            .unwrap()
            .get(format!("http://{address}/first"))
            .send()
            .await
            .unwrap();
        assert!(response.status() == 302, "W10_REDIRECT_STATUS");
        server.join().unwrap();
        assert!(sends.load(Ordering::SeqCst) == 1, "W10_REDIRECT_SENDS");
        let huge = Reply {
            status: 200,
            bytes: vec![b' '; RESPONSE_CAP + 1],
        };
        assert!(super::response(&huge, 6).is_err(), "W10_BODY_CAP");
        assert!(
            super::response(
                &Reply {
                    status: 200,
                    bytes: b"synthetic secret".to_vec()
                },
                6
            )
            .is_err(),
            "W10_NON_JSON"
        );
        let mut changed = contract();
        changed.endpoint = "http://127.0.0.1:1".into();
        assert!(changed.gap_ms().is_err(), "W10_ENDPOINT");
        let temp = crate::fixtures::Temp::new();
        let asset = temp.asset("key", b"synthetic-key");
        assert!(
            secret(&asset.path).unwrap().is_sensitive(),
            "W10_SENSITIVE_HEADER"
        );
    }

    #[tokio::test]
    async fn baseline_success_mapping() {
        let queries = queries(50);
        let mut fake = Fake::new((0..50).map(|_| reply(200, json!(2))).collect());
        let mut ledger = Ledger::new();
        assert!(
            batch(&mut fake, &mut ledger, &contract(), &queries, 300)
                .await
                .is_ok(),
            "W11_COMPLETE"
        );
        let expected: Vec<_> = queries
            .iter()
            .map(|(_, label)| {
                json!({"query":label.query,
            "limit":10,"sources":["web"],"country":"US"})
            })
            .collect();
        assert!(
            fake.bodies == expected
                && ledger.calls.len() == 50
                && ledger.complete
                && ledger.settled == 100
                && ledger.unresolved == 0,
            "W11_MAPPING"
        );
        let error = Reply {
            status: 200,
            bytes: serde_json::to_vec(&json!({"success":false,
            "creditsUsed":0,"data":{"web":[]}}))
            .unwrap(),
        };
        assert!(response(&error, 6).is_err(), "W11_ERROR_ENVELOPE");
    }
}
