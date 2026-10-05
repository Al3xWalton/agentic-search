// SPDX-License-Identifier: AGPL-3.0-only
//! Offline evidence tools and explicitly invoked, bounded orchestrator dispatches.
//! No receipt can authorize a launch, a legal sign-off, or an arbitrary command.

/// Build isolated label packs, validate rater evidence and preserve raw agreement.
#[path = "stage1/agreement.rs"]
mod agreement;
/// Durable accounting bounds paid requests before they can be sent.
#[path = "stage1/baseline.rs"]
mod baseline;
/// Bounded capture retains failures and reaps only owned processes.
#[path = "stage1/capture.rs"]
mod capture;
/// Typed evidence and exact run identities drive release reporting.
#[path = "stage1/evidence.rs"]
mod evidence;

use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs::{self, DirBuilder};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use stract::eval::{input, output, EvalError};

/// Sanitized failures keep private evidence out of diagnostics.
type Result<T> = std::result::Result<T, Error>;

/// Stable exit classes distinguish invalid input, blocked work and failed execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Error {
    Invalid,
    Blocked,
    Failed,
}

/// Discard upstream error detail so diagnostics cannot reflect private input bytes.
impl From<EvalError> for Error {
    fn from(_: EvalError) -> Self {
        Self::Invalid
    }
}

/// Preserve stable exit classes for the orchestrator's dispatch receipts.
impl Error {
    fn code(self) -> u8 {
        match self {
            Self::Invalid => 2,
            Self::Blocked => 3,
            Self::Failed => 4,
        }
    }
}

/// Explicit commands keep offline reporting separate from orchestrator dispatch.
#[derive(Parser)]
#[command(
    name = "stage1_eval",
    about = "Bounded Stage 1 evidence; never release approval"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Every dispatch binds a plan and reserves new private output.
#[derive(Args)]
struct Common {
    /// Sealed input identities for this dispatch.
    #[arg(long)]
    plan: PathBuf,
    /// Create-new private output directory.
    #[arg(long)]
    out: PathBuf,
}

/// The finite command inventory prevents evidence from choosing arbitrary operations.
#[derive(Subcommand)]
enum Command {
    /// Build isolated frozen and held-out evidence packs.
    LabelPack(Common),
    /// Validate blind judgements, seal cross inputs and compute agreement.
    Agreement(Common),
    /// Execute a sequential credit-capped search baseline.
    Firecrawl {
        #[command(flatten)]
        common: Common,
        /// Owner-only credential file, read without logging its contents.
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Fetch and inspect one distinct bounded Common Crawl segment.
    CcFetch(Common),
    /// Supervise the sealed binary through the retained sample matrix.
    Sample(Common),
    /// Verify exact-revision publication and ordinary API source offers.
    SourceCheck(Common),
    /// Recompute measured results, typed release gates and memo data.
    Report {
        #[command(flatten)]
        common: Common,
        /// Complete requirement inventory, including applicability.
        #[arg(long)]
        gates: PathBuf,
        /// Sealed receipt and measurement index.
        #[arg(long)]
        receipts: PathBuf,
    },
}

/// Path and digest travel together so later phases cannot silently substitute evidence.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Asset {
    path: PathBuf,
    sha256: String,
}

/// Recheck physical input identity before parsing or exposing sealed evidence.
impl Asset {
    fn verify(&self) -> Result<()> {
        if !hex(&self.sha256, 64) || input::hash_file(&self.path)? != self.sha256 {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    fn read<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        self.verify()?;
        let bytes = read_private(&self.path, input::MAX_INPUT_BYTES)?;
        if input::sha256(&bytes) != self.sha256 {
            return Err(Error::Invalid);
        }
        serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)
    }
}

/// A finite role identifies each sealed input without guessing from a filename.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NamedAsset {
    name: String,
    asset: Asset,
}

/// The orchestrator seals executable, input and candidate identities before dispatch.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    version: u32,
    base: String,
    claimed_tree_sha256: String,
    example_sha256: String,
    binary: Asset,
    inputs: Vec<NamedAsset>,
    candidate_revision: Option<String>,
    candidate_url: Option<String>,
}

/// Admit only known input roles and verify each declared input and executable identity.
impl Plan {
    fn capture_ready(&self) -> Result<()> {
        if self
            .candidate_revision
            .as_deref()
            .is_none_or(|revision| !hex(revision, 40))
            || !hex(&self.example_sha256, 64)
            || !hex(&self.binary.sha256, 64)
        {
            return Err(Error::Blocked);
        }
        Ok(())
    }

    fn asset(&self, name: &str) -> Result<&Asset> {
        self.inputs
            .iter()
            .find(|a| a.name == name)
            .map(|a| &a.asset)
            .ok_or(Error::Blocked)
    }

    fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.base != "e69353a71b63894b01fbe1073919ad748a780874"
            || !hex(&self.claimed_tree_sha256, 64)
            || !hex(&self.example_sha256, 64)
            || self.inputs.len() > 64
        {
            return Err(Error::Invalid);
        }
        let allowed = [
            "frozen",
            "held-out",
            "cc-indexed",
            "seeds-indexed",
            "cc-parsed",
            "captured",
            "sol-frozen",
            "sol-held-out",
            "cross-acceptance",
            "founder-adjudication",
            "provider-contract",
            "dispatch-inputs",
            "sample-inputs",
            "source-inputs",
            "session-frozen",
            "session-held-out",
            "session-cross",
            "cross-pack",
            "label-pack",
            "credit-ledger",
            "measurement-runs",
            "cost-segments",
            "cc-download",
            "cc-download-receipt",
        ];
        let mut names = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for item in &self.inputs {
            if !allowed.contains(&item.name.as_str()) || !names.insert(&item.name) {
                return Err(Error::Invalid);
            }
            if !paths.insert(input::inspect_path(&item.asset.path, false)?) {
                return Err(Error::Invalid);
            }
            item.asset.verify()?;
        }
        if paths.contains(&input::absolute(&self.binary.path)?) {
            return Err(Error::Invalid);
        }
        self.binary.verify()?;
        let executable = std::env::current_exe().map_err(|_| Error::Invalid)?;
        if input::hash_file(&executable)? != self.example_sha256 {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

/// Accept canonical lower-case digests to avoid ambiguous identity spellings.
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Bound reads and reject linked or writable evidence before parsing it.
fn read_private(path: &Path, cap: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let file = input::open(path)?;
    let meta = file.metadata().map_err(|_| Error::Invalid)?;
    if meta.nlink() != 1 || meta.mode() & 0o022 != 0 || meta.len() > cap {
        return Err(Error::Invalid);
    }
    let mut bytes = Vec::new();
    file.take(cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Invalid)?;
    if bytes.len() as u64 > cap || bytes.len() as u64 != meta.len() {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}

/// Create-new outputs preserve previous evidence rather than overwriting it.
struct Out(PathBuf);

/// Create and sync private, exclusive outputs without clobbering earlier evidence.
impl Out {
    fn new(path: &Path, plan: &Plan) -> Result<Self> {
        output::external(path, &[])?;
        for asset in plan.inputs.iter().map(|a| &a.asset).chain([&plan.binary]) {
            if asset.path.starts_with(path) || path == asset.path {
                return Err(Error::Invalid);
            }
        }
        let parent = path.parent().ok_or(Error::Invalid)?;
        input::inspect_path(parent, false)?;
        DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|_| Error::Invalid)?;
        Ok(Self(path.to_owned()))
    }

    fn bytes(&self, name: &str, bytes: &[u8]) -> Result<Asset> {
        if name.contains('/') || name.contains("..") {
            return Err(Error::Invalid);
        }
        let path = self.0.join(name);
        let mut file = output::create(&path)?;
        file.write_all(bytes).map_err(|_| Error::Failed)?;
        file.sync_all().map_err(|_| Error::Failed)?;
        Ok(Asset {
            path,
            sha256: input::sha256(bytes),
        })
    }

    fn json(&self, name: &str, value: &impl Serialize) -> Result<Asset> {
        let mut bytes = serde_json::to_vec_pretty(value).map_err(|_| Error::Failed)?;
        bytes.push(b'\n');
        self.bytes(name, &bytes)
    }
}

/// All real commands share plan validation and explicit completion receipts.
async fn dispatch(cli: Cli) -> Result<()> {
    let common = match &cli.command {
        Command::LabelPack(c)
        | Command::Agreement(c)
        | Command::CcFetch(c)
        | Command::Sample(c)
        | Command::SourceCheck(c) => c,
        Command::Firecrawl { common, .. } | Command::Report { common, .. } => common,
    };
    let bytes = read_private(&common.plan, input::MAX_INPUT_BYTES)?;
    let plan: Plan = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
    plan.validate()?;
    let out = Out::new(&common.out, &plan)?;
    let result = match cli.command {
        Command::LabelPack(_) => agreement::pack(&plan, &out),
        Command::Agreement(_) => agreement::run(&plan, &out),
        Command::Firecrawl { key_file, .. } => baseline::run(&plan, &out, &key_file).await,
        Command::CcFetch(_) => capture::cc_fetch(&out).await,
        Command::Sample(_) => capture::sample(&plan, &out).await,
        Command::SourceCheck(_) => capture::source_check(&plan, &out).await,
        Command::Report {
            gates, receipts, ..
        } => evidence::report(&plan, &out, &gates, &receipts),
    };
    let (exit, status) = match result {
        Ok(()) => (0, "COMPLETE"),
        Err(error) => (
            error.code(),
            match error {
                Error::Invalid => "INVALID",
                Error::Blocked => "BLOCKED",
                Error::Failed => "FAILED",
            },
        ),
    };
    out.json(
        "receipt.json",
        &json!({
            "exit": exit, "status": status, "plan_sha256": input::sha256(&bytes),
            "claimed_tree_sha256": plan.claimed_tree_sha256, "release_approval": false,
        }),
    )?;
    result
}

/// Expose stable content-free exits while retaining useful clap help.
#[tokio::main]
async fn main() -> std::process::ExitCode {
    match Cli::try_parse() {
        Ok(cli) => match dispatch(cli).await {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("stage1 evaluation stopped; exit {}", error.code());
                std::process::ExitCode::from(error.code())
            }
        },
        Err(error) => {
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                let _ = error.print();
                std::process::ExitCode::SUCCESS
            } else {
                eprintln!("invalid stage1 arguments");
                std::process::ExitCode::from(2)
            }
        }
    }
}

/// Private synthetic fixtures cannot depend on retained real sample services.
#[cfg(test)]
mod fixtures {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Private synthetic fixture directory, always removed by its owning test.
    pub(super) struct Temp(pub(super) PathBuf);

    impl Temp {
        /// Create a unique owned directory below the caller's private temporary root.
        pub(super) fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "stage1-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        /// Write content with a recorded exact identity, without output reuse.
        pub(super) fn asset(&self, name: &str, bytes: &[u8]) -> Asset {
            let out = Out(self.0.clone());
            out.bytes(name, bytes).unwrap()
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Synthetic label whose bytes are never included in assertion messages.
    pub(super) fn label(n: usize) -> stract::eval::labels::Label {
        stract::eval::labels::Label {
            id: format!("q{n:02}"),
            query: format!("synthetic {n}"),
            category: stract::eval::labels::CATEGORIES[n % 5].into(),
            acceptable_urls: vec![format!("https://example.test/page/{n}")],
            metadata: Default::default(),
        }
    }

    /// Bind the test CLI to its actual executable, rather than bypassing plan validation.
    pub(super) fn plan() -> Plan {
        let path = std::env::current_exe().unwrap();
        let sha256 = input::hash_file(&path).unwrap();
        Plan {
            version: 1,
            base: "e69353a71b63894b01fbe1073919ad748a780874".into(),
            claimed_tree_sha256: "a".repeat(64),
            example_sha256: sha256.clone(),
            binary: Asset { path, sha256 },
            inputs: vec![],
            candidate_revision: None,
            candidate_url: None,
        }
    }

    /// Fixed synthetic bytes let caller witnesses retain the production hash and protocol checks.
    pub(super) fn label_inputs(
        temp: &Temp,
        plan: &mut Plan,
    ) -> [Vec<stract::eval::labels::Label>; 2] {
        [false, true].map(|held| {
            let rows: Vec<_> = (0..50)
                .map(|n| {
                    let id = if held {
                        format!("h{:02}", n + 1)
                    } else {
                        format!("q{n:02}")
                    };
                    let set = if held { "held" } else { "frozen" };
                    format!(
                        concat!(
                            "{{\"id\":\"{}\",\"category\":\"{}\",\"query\":\"synthetic {}\",",
                            "\"acceptable_urls\":[\"https://{}.example.test/{}/{}\"]}}"
                        ),
                        id,
                        stract::eval::labels::CATEGORIES[n % 5],
                        n,
                        n,
                        set,
                        n
                    )
                })
                .collect();
            let bytes = format!(
                concat!(
                    "{{\"status\":\"frozen\",",
                    "\"labeller\":\"gemini-3.8-flash-high via agy\",",
                    "\"frozen_at_utc\":\"2026-09-12T15:38:56Z\",\"queries\":[{}]}}\n"
                ),
                rows.join(",")
            );
            let set = if held { "held-out" } else { "frozen" };
            plan.inputs.push(NamedAsset {
                name: set.into(),
                asset: temp.asset(set, bytes.as_bytes()),
            });
            agreement::labels(plan, set).unwrap()
        })
    }

    /// Indexed and parsed views use only synthetic pages, including every original answer.
    pub(super) fn corpus_inputs(
        temp: &Temp,
        plan: &mut Plan,
        labels: &[Vec<stract::eval::labels::Label>; 2],
    ) {
        let indexed: String = labels
            .iter()
            .flatten()
            .map(|r| {
                format!(
                    "{}\n",
                    json!({"url":r.acceptable_urls,"title":["synthetic"]})
                )
            })
            .collect();
        let parsed: String = labels
            .iter()
            .flatten()
            .map(|r| {
                format!(
                    "{}\n",
                    json!({"url":r.acceptable_urls[0],
                "title":"synthetic","text_preview":"synthetic"})
                )
            })
            .collect();
        for (name, bytes) in [
            ("cc-indexed", indexed.as_bytes()),
            ("seeds-indexed", b"".as_slice()),
            ("cc-parsed", parsed.as_bytes()),
        ] {
            plan.inputs.push(NamedAsset {
                name: name.into(),
                asset: temp.asset(name, bytes),
            });
        }
    }
}

/// Offline witnesses exercise production call sites with content-free assertions.
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn safe_paths_and_output() {
        let temp = fixtures::Temp::new();
        let file = temp.asset("sentinel", b"synthetic");
        symlink(&file.path, temp.0.join("link")).unwrap();
        fs::hard_link(&file.path, temp.0.join("hard")).unwrap();
        assert!(
            read_private(&temp.0.join("link"), 32).is_err(),
            "W23_SYMLINK"
        );
        assert!(read_private(&file.path, 32).is_err(), "W23_HARDLINK");
        fs::remove_file(temp.0.join("hard")).unwrap();
        assert!(
            read_private(&temp.0.join("../sentinel"), 32).is_err(),
            "W23_TRAVERSAL"
        );
        assert!(read_private(&file.path, 8).is_err(), "W23_LIMIT");
        fs::set_permissions(&file.path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_private(&file.path, 32).is_err(), "W23_MODE");
        fs::set_permissions(&file.path, fs::Permissions::from_mode(0o600)).unwrap();
        let fifo =
            std::ffi::CString::new(temp.0.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
        // mkfifo creates only this test's synthetic special-file boundary case.
        assert!(
            unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) } == 0,
            "W23_FIXTURE"
        );
        assert!(read_private(&temp.0.join("fifo"), 32).is_err(), "W23_FIFO");
        assert!(output::create(&file.path).is_err(), "W23_COLLISION");
        assert!(
            fs::read(&file.path).unwrap() == b"synthetic",
            "W23_SENTINEL"
        );
    }

    #[tokio::test]
    async fn cli_receipt_wiring() {
        let temp = fixtures::Temp::new();
        let plan = fixtures::plan();
        let plan_file = temp.asset("plan.json", &serde_json::to_vec(&plan).unwrap());
        let gates = evidence::test_gates();
        let gates_file = temp.asset("gates.json", &serde_json::to_vec(&gates).unwrap());
        let receipts = temp.asset(
            "evidence.json",
            b"{\"receipts\":[],\"measurements\":[],\"costs\":[]}",
        );
        let mut products = Vec::new();
        for name in ["a", "b"] {
            let out = temp.0.join(name);
            let cli = Cli::try_parse_from([
                "stage1_eval",
                "report",
                "--plan",
                plan_file.path.to_str().unwrap(),
                "--gates",
                gates_file.path.to_str().unwrap(),
                "--receipts",
                receipts.path.to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
            ])
            .unwrap();
            assert!(dispatch(cli).await.is_ok(), "W24_REPORT");
            let receipt: Value =
                serde_json::from_slice(&fs::read(out.join("receipt.json")).unwrap()).unwrap();
            assert!(
                receipt
                    == json!({"exit":0,"status":"COMPLETE",
                "plan_sha256":plan_file.sha256,"claimed_tree_sha256":plan.claimed_tree_sha256,
                "release_approval":false}),
                "W24_RECEIPT"
            );
            products.push(fs::read(out.join("RELEASE-GATES.md")).unwrap());
            products
                .last_mut()
                .unwrap()
                .extend(fs::read(out.join("RESULTS.md")).unwrap());
            let result: Value =
                serde_json::from_slice(&fs::read(out.join("results.json")).unwrap()).unwrap();
            assert!(result["release_recommendation"] == "NO-GO", "W24_NO_GO");
        }
        assert!(products[0] == products[1], "W24_DETERMINISM");
        assert!(
            Cli::try_parse_from(["stage1_eval", "firecrawl", "--endpoint", "synthetic"]).is_err(),
            "W24_FIXED_CLI"
        );
        for (error, code) in [(Error::Invalid, 2), (Error::Blocked, 3), (Error::Failed, 4)] {
            assert!(error.code() == code, "W24_EXIT");
        }
    }
}
