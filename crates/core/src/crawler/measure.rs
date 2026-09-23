//! Measures serial indexer children against explicit retained WARC files.
//!
//! Inspection supplies admission accounting; only the completed index supplies document counts.
//! Each run owns a fresh directory, streams child logs to private files, and uses wait4 as its
//! sole reaper. A successful reap occurs once; uncertain reaping returns a bounded failure.
//! Index, centrality and temporary cleanup precedes row saving; failures remain in the report.
//! A complete report preserves failed runs and count differences before returning a failed outcome.
//! Inputs, the executable, and output ancestors must remain under one owner's control throughout.
//! Path checks reject existing links; they are not a sandbox against concurrent path replacement.
//! The child leads its own process group. Immediately after reaping its positive pid, we
//! probe the negative group id before accepting the run or starting another child.
//! A recycled pid normally joins its parent's group, so it does not revive the old group.
//! An unrelated process could become a group leader with that exact id in the microseconds
//! after the reap; the subsequent group probe or signal could then reach that unrelated group.
//! This residual reuse race is not eliminated by the immediate probe.
//! Group signals cover descendants that remain in the group, not processes that leave it.
//! Reap certainty records successful direct-child ownership; the descendant flag records
//! whether the first group probe found anything other than absence, even after cleanup.
//! RSS remains the direct child's high-water mark, not a process-group sum.
//!
//! Output layout:
//! <out>/report.json
//! <out>/<stem>/inspection.json
//! <out>/<stem>/b<batch>/r<run>/
//!   {config.toml,stdout.log,stderr.log,run.json,index/,centrality-empty/,tmp/}
//! The last three directories are removed after extraction and before saving the row;
//! unsuccessful removals are preserved as cleanup failures in the report.
//!
//! ```text
//! stract crawler measure-index --warcs /scratch/inputs/seeds.warc.gz \
//!   --batch-sizes 128,512,2048 --runs 2 --out /scratch/measurements
//! ```
#![deny(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;

use super::{host_state::validate_store_root, network::sha256, sample};
use crate::config::{IndexerConfig, LocalConfig, WarcSource};
use crate::index::Index;

/// Default per-child deadline in seconds; inspection and evidence writing are outside it.
pub const DEFAULT_CHILD_TIMEOUT_SECONDS: u64 = 1800;

/// Fixed diagnostics deliberately exclude paths, dependency messages, and child log contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MeasureError {
    /// A matrix dimension or deadline is outside its admitted range.
    #[error("invalid-arguments")]
    InvalidArguments,
    /// The output path is unsafe or overlaps protected inputs or source.
    #[error("output-refused")]
    OutputRefused,
    /// An input path, identity, or stem is not admissible.
    #[error("input-refused")]
    InputRefused,
    /// A reserved evidence destination already exists.
    #[error("output-exists")]
    OutputExists,
    /// A private store or temporary directory could not be created.
    #[error("output-unwritable")]
    OutputUnwritable,
    /// The current executable cannot be pinned as a regular stract binary.
    #[error("binary-refused")]
    BinaryRefused,
    /// The existing inspector could not complete its accounting.
    #[error("inspection-failed")]
    InspectionFailed,
    /// Generated configuration did not round-trip to the requested settings.
    #[error("config-invalid")]
    ConfigInvalid,
    /// The child could not be started.
    #[error("spawn-failed")]
    SpawnFailed,
    /// Waiting failed or sole-reaper ownership could no longer be established.
    #[error("wait-failed")]
    WaitFailed {
        /// Numeric wait error, or the fixed deadline/invalid-pid errno.
        errno: i32,
        /// Elapsed time from the original spawn attempt when waiting failed.
        elapsed: Duration,
    },
    /// The child's group was not absent immediately after its direct child was reaped.
    #[error("descendants-remained")]
    DescendantsRemained,
    /// Terminating an owned, unreaped child failed.
    #[error("kill-failed")]
    KillFailed,
    /// A measurement was negative, nonfinite, or outside its representation.
    #[error("measurement-invalid")]
    MeasurementInvalid,
    /// A successful child left no index directory.
    #[error("index-missing")]
    IndexMissing,
    /// The completed index was unsafe, incomplete, or unreadable.
    #[error("index-invalid")]
    IndexInvalid,
    /// A successful child produced zero live documents.
    #[error("no-documents")]
    NoDocuments,
    /// Owned stores could not be removed; further children must not run.
    #[error("cleanup-failed")]
    CleanupFailed,
    /// Evidence could not be durably written; the matrix is incomplete.
    #[error("evidence-failed")]
    EvidenceFailed,
    /// Successful counts differed within a WARC's matrix.
    #[error("counts-differ")]
    CountsDiffer,
    /// At least one row failed in an otherwise complete report.
    #[error("runs-failed")]
    RunsFailed,
    /// An unrelated local I/O operation failed.
    #[error("io")]
    Io,
}

/// Completed matrix summary. It is returned only after report.json has been synced.
#[derive(Debug)]
pub struct Summary {
    /// Number of saved run rows, including failures.
    pub runs: usize,
    /// Number of failed rows, independent of successful-count equality.
    pub failed: usize,
    /// Whether successful positive counts agree within every WARC.
    pub repeatable: bool,
}

impl Summary {
    /// Returns the aggregate outcome after evidence has been saved.
    ///
    /// # Errors
    /// Failed runs take precedence over differing successful counts.
    pub fn outcome(&self) -> Result<(), MeasureError> {
        if self.failed != 0 {
            return Err(MeasureError::RunsFailed);
        }
        if !self.repeatable {
            return Err(MeasureError::CountsDiffer);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
struct Settings {
    batch_sizes: Vec<usize>,
    runs: usize,
    child_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
struct Environment {
    os: String,
    arch: String,
    cpus: Option<u64>,
    ram_bytes: Option<u64>,
    binary_sha256: String,
    revision: String,
    revision_source: String,
    toolchain_pin: String,
    process_group: bool,
    child_env_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct Row {
    warc_sha256: String,
    batch_size: usize,
    run: usize,
    documents: Option<u64>,
    parse_errors: u64,
    index_skip_histogram: BTreeMap<String, u64>,
    index_candidates: u64,
    candidate_delta: Option<i64>,
    wall_seconds: Option<f64>,
    user_cpu_seconds: Option<f64>,
    system_cpu_seconds: Option<f64>,
    peak_rss_bytes: Option<u64>,
    final_disk_bytes: Option<u64>,
    exit_code: Option<i32>,
    signal: Option<i32>,
    timed_out: bool,
    descendants_remained: bool,
    reap_certain: bool,
    failed: bool,
    config_sha256: Option<String>,
    child_stdout_bytes: u64,
    child_stderr_bytes: u64,
}

#[derive(Serialize)]
struct RunEvidence<'a> {
    schema_version: u16,
    environment: &'a Environment,
    row: &'a Row,
}

#[derive(Debug, Clone, Serialize)]
struct Warc {
    stem: String,
    warc_sha256: String,
    inspection_file: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CountTuple {
    warc_sha256: String,
    batch_size: usize,
    run: usize,
    documents: u64,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct Difference {
    reference: CountTuple,
    different: CountTuple,
}

#[derive(Debug, Serialize)]
struct Failure {
    warc_sha256: String,
    batch_size: usize,
    run: usize,
    reason: String,
    kind: &'static str,
}

#[derive(Serialize)]
struct Timing {
    warc_sha256: String,
    batch_size: usize,
    successful_runs: u64,
    wall_seconds_min: Option<f64>,
    wall_seconds_max: Option<f64>,
    user_cpu_seconds_min: Option<f64>,
    user_cpu_seconds_max: Option<f64>,
    system_cpu_seconds_min: Option<f64>,
    system_cpu_seconds_max: Option<f64>,
}

#[derive(Serialize)]
struct Cleanup {
    policy: &'static str,
    all_removed: bool,
}

#[derive(Serialize)]
struct Report {
    schema_version: u16,
    environment: Environment,
    settings: Settings,
    warcs: Vec<Warc>,
    rows: Vec<Row>,
    repeatable: bool,
    count_differences: Vec<Difference>,
    failures: Vec<Failure>,
    timing: Vec<Timing>,
    cleanup: Cleanup,
}

#[derive(Debug, Clone)]
struct Input {
    path: PathBuf,
    stem: String,
    folder: String,
    name: String,
}

struct Inspected {
    input: Input,
    inspection: sample::WarcInspection,
}

fn validate_settings(warcs: usize, settings: &Settings) -> Result<(), MeasureError> {
    let distinct: BTreeSet<_> = settings.batch_sizes.iter().collect();
    if warcs == 0
        || settings.batch_sizes.is_empty()
        || settings.batch_sizes.len() > 8
        || settings.batch_sizes.contains(&0)
        || distinct.len() != settings.batch_sizes.len()
        || !(1..=8).contains(&settings.runs)
        || settings.child_timeout_seconds == 0
        || settings.child_timeout_seconds > 3600
    {
        return Err(MeasureError::InvalidArguments);
    }
    Ok(())
}

fn inspect_components(path: &Path) -> Result<(), MeasureError> {
    if !path.is_absolute()
        || path
            .components()
            .skip(1)
            .any(|c| !matches!(c, Component::Normal(_)))
        || path
            .as_os_str()
            .as_encoded_bytes()
            .split(|b| *b == b'/')
            .any(|c| c == b"." || c == b"..")
    {
        return Err(MeasureError::InputRefused);
    }
    let mut cursor = PathBuf::from("/");
    for component in path.components().skip(1) {
        cursor.push(component.as_os_str());
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(MeasureError::InputRefused);
                }
                if cursor != path && !metadata.is_dir() {
                    return Err(MeasureError::InputRefused);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(MeasureError::InputRefused),
        }
    }
    Ok(())
}

fn validate_output(out: &Path) -> Result<(), MeasureError> {
    if !out.is_absolute() {
        return Err(MeasureError::OutputRefused);
    }
    validate_store_root(out).map_err(|_| MeasureError::OutputRefused)?;
    inspect_components(out).map_err(|_| MeasureError::OutputRefused)?;
    if fs::symlink_metadata(out).is_ok_and(|m| !m.is_dir()) {
        return Err(MeasureError::OutputRefused);
    }
    Ok(())
}

fn identity(path: &Path) -> Option<(u64, u64)> {
    fs::symlink_metadata(path).ok().map(|m| (m.dev(), m.ino()))
}

fn reject_repository_identity(out: &Path) -> Result<(), MeasureError> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|_| MeasureError::OutputRefused)?;
    let repo_id = identity(&repository).ok_or(MeasureError::OutputRefused)?;
    let out_id = identity(out);
    if out.ancestors().any(|p| identity(p) == Some(repo_id))
        || out_id.is_some_and(|id| repository.ancestors().any(|p| identity(p) == Some(id)))
    {
        return Err(MeasureError::OutputRefused);
    }
    Ok(())
}

fn input_stem(name: &str) -> Result<String, MeasureError> {
    let name = name.strip_suffix(".gz").unwrap_or(name);
    let stem = name.strip_suffix(".warc").unwrap_or(name);
    if stem.is_empty()
        || stem.len() > 128
        || !stem.as_bytes()[0].is_ascii_alphanumeric()
        || !stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(MeasureError::InputRefused);
    }
    Ok(stem.to_owned())
}

fn validate_inputs(paths: &[PathBuf], out: &Path) -> Result<Vec<Input>, MeasureError> {
    let mut inputs = Vec::new();
    let mut identities = BTreeSet::new();
    let mut stems = BTreeSet::new();
    for path in paths {
        let path = if path.is_absolute() {
            path.clone()
        } else {
            std::env::current_dir()
                .map_err(|_| MeasureError::InputRefused)?
                .join(path)
        };
        inspect_components(&path)?;
        let path = path
            .canonicalize()
            .map_err(|_| MeasureError::InputRefused)?;
        if !fs::symlink_metadata(&path)
            .map_err(|_| MeasureError::InputRefused)?
            .is_file()
            || path.to_str().is_none()
            || !identities.insert(path.clone())
        {
            return Err(MeasureError::InputRefused);
        }
        let parent = path.parent().ok_or(MeasureError::InputRefused)?;
        if parent.starts_with(out) || out.starts_with(parent) {
            return Err(MeasureError::OutputRefused);
        }
        let name = path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or(MeasureError::InputRefused)?
            .to_owned();
        let stem = input_stem(&name)?;
        if !stems.insert(stem.to_ascii_lowercase()) {
            return Err(MeasureError::InputRefused);
        }
        inputs.push(Input {
            folder: parent.to_str().ok_or(MeasureError::InputRefused)?.into(),
            path,
            stem,
            name,
        });
    }
    Ok(inputs)
}

fn private_parents(path: &Path) -> Result<(), MeasureError> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|_| MeasureError::OutputRefused)
}

fn prospective_path(path: &Path) -> Result<PathBuf, MeasureError> {
    let mut parent = path;
    let mut missing = Vec::new();
    while !parent.exists() {
        missing.push(parent.file_name().ok_or(MeasureError::OutputRefused)?);
        parent = parent.parent().ok_or(MeasureError::OutputRefused)?;
    }
    let mut resolved = parent
        .canonicalize()
        .map_err(|_| MeasureError::OutputRefused)?;
    for name in missing.into_iter().rev() {
        resolved.push(name);
    }
    Ok(resolved)
}

fn absent(path: &Path) -> Result<(), MeasureError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(MeasureError::OutputExists),
        Err(_) => Err(MeasureError::OutputRefused),
    }
}

fn evidence_file(path: &Path) -> Result<File, MeasureError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                MeasureError::OutputExists
            } else {
                MeasureError::EvidenceFailed
            }
        })
}

fn json_create(path: &Path, value: &impl Serialize) -> Result<(), MeasureError> {
    let mut file = evidence_file(path)?;
    serde_json::to_writer_pretty(&mut file, value).map_err(|_| MeasureError::EvidenceFailed)?;
    file.write_all(b"\n")
        .map_err(|_| MeasureError::EvidenceFailed)?;
    file.sync_all().map_err(|_| MeasureError::EvidenceFailed)
}

fn file_sha256(path: &Path) -> Result<String, MeasureError> {
    let mut file = File::open(path).map_err(|_| MeasureError::Io)?;
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer).map_err(|_| MeasureError::Io)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn pin_binary(path: &Path) -> Result<(PathBuf, String), MeasureError> {
    let path = path
        .canonicalize()
        .map_err(|_| MeasureError::BinaryRefused)?;
    if path.file_name() != Some(OsStr::new("stract"))
        || !fs::symlink_metadata(&path)
            .map_err(|_| MeasureError::BinaryRefused)?
            .is_file()
    {
        return Err(MeasureError::BinaryRefused);
    }
    let hash = file_sha256(&path).map_err(|_| MeasureError::BinaryRefused)?;
    Ok((path, hash))
}

fn sysconf_positive(name: libc::c_int) -> Option<u64> {
    // # Safety
    // sysconf takes a supported scalar selector and has no pointer or ownership preconditions.
    let value = unsafe { libc::sysconf(name) };
    u64::try_from(value).ok().filter(|v| *v > 0)
}

fn environment(
    binary_sha256: String,
    child_env: &ChildEnvironment,
) -> Result<Environment, MeasureError> {
    let toolchain: toml::Value = toml::from_str(include_str!("../../../../rust-toolchain.toml"))
        .map_err(|_| MeasureError::MeasurementInvalid)?;
    let toolchain_pin = toolchain
        .get("toolchain")
        .and_then(|v| v.get("channel"))
        .and_then(toml::Value::as_str)
        .ok_or(MeasureError::MeasurementInvalid)?
        .to_owned();
    Ok(Environment {
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        cpus: sysconf_positive(libc::_SC_NPROCESSORS_ONLN),
        ram_bytes: sysconf_positive(libc::_SC_PHYS_PAGES)
            .zip(sysconf_positive(libc::_SC_PAGESIZE))
            .and_then(|(n, size)| n.checked_mul(size)),
        binary_sha256,
        revision: env!("AVA_SEARCH_REVISION").into(),
        revision_source: env!("AVA_SEARCH_REVISION_SOURCE").into(),
        toolchain_pin,
        process_group: true,
        child_env_keys: child_env.keys(),
    })
}

#[derive(Serialize)]
struct LocalIndexerConfig {
    output_path: String,
    host_centrality_store_path: String,
    warc_source: WarcSource,
    limit_warc_files: usize,
    batch_size: usize,
    autocommit_after_num_inserts: usize,
}

fn check_config(bytes: &str, expected: &LocalIndexerConfig) -> Result<(), MeasureError> {
    let parsed: IndexerConfig = toml::from_str(bytes).map_err(|_| MeasureError::ConfigInvalid)?;
    let local_matches = match (&parsed.warc_source, &expected.warc_source) {
        (WarcSource::Local(actual), WarcSource::Local(wanted)) => {
            actual.folder == wanted.folder && actual.names == wanted.names
        }
        _ => false,
    };
    let equal = parsed.output_path == expected.output_path
        && parsed.host_centrality_store_path == expected.host_centrality_store_path
        && parsed.batch_size == expected.batch_size
        && parsed.limit_warc_files == Some(1)
        && parsed.autocommit_after_num_inserts == 5000
        && local_matches
        && parsed.skip_warc_files.is_none()
        && parsed.page_webgraph.is_none()
        && parsed.host_centrality_threshold.is_none()
        && parsed.page_centrality_store_path.is_none()
        && parsed.safety_classifier_path.is_none()
        && parsed.minimum_clean_words.is_none()
        && parsed.dual_encoder.is_none();
    if !equal {
        return Err(MeasureError::ConfigInvalid);
    }
    Ok(())
}

struct RunPaths {
    root: PathBuf,
    index: PathBuf,
    centrality: PathBuf,
    tmp: PathBuf,
}

impl RunPaths {
    fn new(root: PathBuf) -> Self {
        Self {
            index: root.join("index"),
            centrality: root.join("centrality-empty"),
            tmp: root.join("tmp"),
            root,
        }
    }
}

fn config(
    input: &Input,
    paths: &RunPaths,
    batch_size: usize,
) -> Result<LocalIndexerConfig, MeasureError> {
    Ok(LocalIndexerConfig {
        output_path: paths
            .index
            .to_str()
            .ok_or(MeasureError::ConfigInvalid)?
            .into(),
        host_centrality_store_path: paths
            .centrality
            .to_str()
            .ok_or(MeasureError::ConfigInvalid)?
            .into(),
        warc_source: WarcSource::Local(LocalConfig {
            folder: input.folder.clone(),
            names: vec![input.name.clone()],
        }),
        limit_warc_files: 1,
        batch_size,
        autocommit_after_num_inserts: 5000,
    })
}

fn prepare_run(input: &Input, paths: &RunPaths, batch: usize) -> Result<String, MeasureError> {
    absent(&paths.index)?;
    DirBuilder::new()
        .mode(0o700)
        .create(&paths.centrality)
        .map_err(output_creation_error)?;
    DirBuilder::new()
        .mode(0o700)
        .create(&paths.tmp)
        .map_err(output_creation_error)?;
    let expected = config(input, paths, batch)?;
    let text = toml::to_string(&expected).map_err(|_| MeasureError::ConfigInvalid)?;
    check_config(&text, &expected)?;
    let mut file = evidence_file(&paths.root.join("config.toml"))?;
    file.write_all(text.as_bytes())
        .map_err(|_| MeasureError::EvidenceFailed)?;
    file.sync_all().map_err(|_| MeasureError::EvidenceFailed)?;
    Ok(sha256(text.as_bytes()))
}

fn output_creation_error(error: io::Error) -> MeasureError {
    if error.kind() == io::ErrorKind::AlreadyExists {
        MeasureError::OutputExists
    } else {
        MeasureError::OutputUnwritable
    }
}

fn reserve_run(path: &Path) -> Result<(), MeasureError> {
    private_parents(path.parent().ok_or(MeasureError::OutputRefused)?)?;
    DirBuilder::new().mode(0o700).create(path).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            MeasureError::OutputExists
        } else {
            MeasureError::OutputRefused
        }
    })
}

fn disk_bytes(path: &Path) -> Result<u64, MeasureError> {
    let entry = match fs::symlink_metadata(path) {
        Ok(entry) => entry,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(_) => return Err(MeasureError::Io),
    };
    if entry.is_file() {
        return Ok(entry.len());
    }
    let mut bytes = 0_u64;
    if entry.is_dir() {
        for child in fs::read_dir(path).map_err(|_| MeasureError::Io)? {
            let child = child.map_err(|_| MeasureError::Io)?;
            bytes = bytes
                .checked_add(disk_bytes(&child.path())?)
                .ok_or(MeasureError::MeasurementInvalid)?;
        }
    }
    Ok(bytes)
}

fn reject_index_links(path: &Path) -> Result<(), MeasureError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| MeasureError::IndexInvalid)?;
    if metadata.file_type().is_symlink() {
        return Err(MeasureError::IndexInvalid);
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path).map_err(|_| MeasureError::IndexInvalid)? {
            reject_index_links(&entry.map_err(|_| MeasureError::IndexInvalid)?.path())?;
        }
    } else if !metadata.is_file() {
        return Err(MeasureError::IndexInvalid);
    }
    Ok(())
}

fn validate_index(index: &Path) -> Result<(), MeasureError> {
    let metadata = fs::symlink_metadata(index).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            MeasureError::IndexMissing
        } else {
            MeasureError::IndexInvalid
        }
    })?;
    if !metadata.is_dir()
        || index.to_str().is_none()
        || !fs::symlink_metadata(index.join("inverted_index")).is_ok_and(|m| m.is_dir())
        || !fs::symlink_metadata(index.join("region_count.json")).is_ok_and(|m| m.is_file())
    {
        return Err(MeasureError::IndexInvalid);
    }
    reject_index_links(index)
}

fn count_documents(index: &Path) -> Result<u64, MeasureError> {
    // The API can create missing components, so these prerequisites must precede its open.
    validate_index(index)?;
    let index = Index::open(index).map_err(|_| MeasureError::IndexInvalid)?;
    let documents = index.inverted_index.num_documents();
    drop(index);
    if documents == 0 {
        return Err(MeasureError::NoDocuments);
    }
    Ok(documents)
}

fn remove_owned_stores(paths: &RunPaths) -> Result<(), MeasureError> {
    inspect_components(&paths.root).map_err(|_| MeasureError::CleanupFailed)?;
    let mut failed = false;
    for path in [&paths.index, &paths.centrality, &paths.tmp] {
        let removed = match fs::symlink_metadata(path) {
            Ok(m) if m.is_dir() => fs::remove_dir_all(path),
            Ok(_) => fs::remove_file(path),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        };
        failed |= removed.is_err();
    }
    if failed {
        return Err(MeasureError::CleanupFailed);
    }
    Ok(())
}

/// Operating-system unit of the single child's maximum resident set size.
#[derive(Debug, Clone, Copy)]
pub enum RssUnit {
    /// macOS reports ru_maxrss directly in bytes.
    Bytes,
    /// Linux reports ru_maxrss in kibibytes.
    Kibibytes,
}

#[cfg(target_os = "macos")]
const RSS_UNIT: RssUnit = RssUnit::Bytes;
#[cfg(not(target_os = "macos"))]
const RSS_UNIT: RssUnit = RssUnit::Kibibytes;

/// Converts a reported high-water mark to bytes, refusing negatives and multiplication overflow.
pub fn rss_bytes(raw: libc::c_long, unit: RssUnit) -> Option<u64> {
    let value = u64::try_from(raw).ok()?;
    match unit {
        RssUnit::Bytes => Some(value),
        RssUnit::Kibibytes => value.checked_mul(1024),
    }
}

fn cpu_seconds(value: libc::timeval) -> Option<f64> {
    if value.tv_sec < 0 || !(0..1_000_000).contains(&value.tv_usec) {
        return None;
    }
    let seconds = value.tv_sec as f64 + value.tv_usec as f64 / 1_000_000.0;
    seconds.is_finite().then_some(seconds)
}

#[derive(Debug, Clone)]
struct Reaped {
    status: i32,
    user_cpu_seconds: Option<f64>,
    system_cpu_seconds: Option<f64>,
    peak_rss_bytes: Option<u64>,
}

trait WaitBackend {
    fn wait(&mut self, pid: libc::pid_t, options: i32) -> Result<Option<Reaped>, i32>;
    fn kill(&mut self, target: libc::pid_t) -> Result<(), i32>;
    fn probe_group(&mut self, pgid: libc::pid_t) -> Result<(), i32>;
    fn elapsed(&self, started: Instant) -> Duration {
        started.elapsed()
    }
    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

struct SystemWait;

impl WaitBackend for SystemWait {
    fn wait(&mut self, pid: libc::pid_t, options: i32) -> Result<Option<Reaped>, i32> {
        let mut status = 0;
        let mut usage = MaybeUninit::<libc::rusage>::uninit();
        // # Safety
        // The caller owns this positive, unreaped pid. Both output pointers remain valid during
        // the call; usage is read only when wait4 reports that exact child has been reaped.
        let result = unsafe { libc::wait4(pid, &mut status, options, usage.as_mut_ptr()) };
        if result == -1 {
            return Err(io::Error::last_os_error().raw_os_error().unwrap_or(0));
        }
        if result == 0 {
            return Ok(None);
        }
        if result != pid {
            return Err(libc::ECHILD);
        }
        // # Safety
        // Successful wait4 for the requested pid initialized every field of usage.
        let usage = unsafe { usage.assume_init() };
        Ok(Some(Reaped {
            status,
            user_cpu_seconds: cpu_seconds(usage.ru_utime),
            system_cpu_seconds: cpu_seconds(usage.ru_stime),
            peak_rss_bytes: rss_bytes(usage.ru_maxrss, RSS_UNIT),
        }))
    }

    fn kill(&mut self, target: libc::pid_t) -> Result<(), i32> {
        // # Safety
        // Production supplies the negative id of the dedicated child group. The immediate
        // post-reap checks narrow, but cannot eliminate, the group-id reuse race.
        if unsafe { libc::kill(target, libc::SIGKILL) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error().raw_os_error().unwrap_or(0))
        }
    }

    fn probe_group(&mut self, pgid: libc::pid_t) -> Result<(), i32> {
        probe_group(pgid)
    }
}

fn probe_group(pgid: libc::pid_t) -> Result<(), i32> {
    // # Safety
    // The positive id identifies the child-created group, never the harness's own group.
    // Signal zero observes the negative group id; it does not probe a recycled positive pid.
    if unsafe { libc::kill(-pgid, 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error().raw_os_error().unwrap_or(0))
    }
}

#[derive(Debug, Default)]
struct ChildStatus {
    exit_code: Option<i32>,
    signal: Option<i32>,
    timed_out: bool,
}
impl ChildStatus {
    fn success(&self) -> bool {
        self.exit_code == Some(0) && self.signal.is_none() && !self.timed_out
    }
}

#[derive(Debug)]
struct ChildResult {
    status: ChildStatus,
    wall_seconds: Option<f64>,
    usage: Option<Reaped>,
    errors: Vec<MeasureError>,
    reap_certain: bool,
    descendants_remained: bool,
    group_empty: bool,
    stop_error: Option<MeasureError>,
}
impl ChildResult {
    fn pending() -> Self {
        Self {
            status: ChildStatus::default(),
            wall_seconds: None,
            usage: None,
            errors: Vec::new(),
            reap_certain: false,
            descendants_remained: false,
            group_empty: false,
            stop_error: None,
        }
    }
    fn refused(error: MeasureError) -> Self {
        Self {
            errors: vec![error],
            reap_certain: true,
            group_empty: true,
            ..Self::pending()
        }
    }
}

#[derive(Default)]
struct WaitState {
    unexpected: usize,
    last_errno: Option<i32>,
}

fn wait_abort(
    started: Instant,
    timeout: Duration,
    grace: Duration,
    backend: &impl WaitBackend,
    state: &WaitState,
) -> Option<MeasureError> {
    let hard_limit = timeout.saturating_add(grace);
    let elapsed = backend.elapsed(started);
    let unexpected = state.unexpected;
    let last_errno = state.last_errno;
    if elapsed >= hard_limit {
        return Some(MeasureError::WaitFailed {
            errno: last_errno.unwrap_or(libc::ETIMEDOUT),
            elapsed,
        });
    }
    if unexpected >= 2 {
        return Some(MeasureError::WaitFailed {
            errno: last_errno.unwrap_or(libc::EIO),
            elapsed,
        });
    }
    None
}

fn poll_owned(
    pid: libc::pid_t,
    backend: &mut impl WaitBackend,
    state: &mut WaitState,
) -> Result<Option<Reaped>, i32> {
    match backend.wait(pid, libc::WNOHANG) {
        Ok(usage) => {
            state.unexpected = 0;
            Ok(usage)
        }
        Err(errno) if errno == libc::EINTR => {
            state.unexpected = 0;
            state.last_errno = Some(errno);
            Err(errno)
        }
        Err(errno) if errno == libc::EAGAIN => {
            state.unexpected = 0;
            state.last_errno = Some(errno);
            Err(errno)
        }
        Err(errno) => {
            state.unexpected = state.unexpected.saturating_add(1);
            state.last_errno = Some(errno);
            Err(errno)
        }
    }
}

fn record_wait_error(result: &mut ChildResult, error: MeasureError) {
    if let Some(previous) = result
        .errors
        .iter_mut()
        .find(|value| matches!(value, MeasureError::WaitFailed { .. }))
    {
        *previous = error;
    } else {
        result.errors.push(error);
    }
}

fn signal_group(pgid: libc::pid_t, backend: &mut impl WaitBackend, result: &mut ChildResult) {
    if backend.kill(-pgid).is_err() && !result.errors.contains(&MeasureError::KillFailed) {
        result.errors.push(MeasureError::KillFailed);
    }
}

fn stop_wait(
    pid: libc::pid_t,
    backend: &mut impl WaitBackend,
    result: &mut ChildResult,
    error: MeasureError,
) {
    record_wait_error(result, error);
    result.reap_certain = false;
    result.stop_error = Some(error);
    signal_group(pid, backend, result);
}

fn accept_reap(usage: Reaped, elapsed: Duration, hard_limit: Duration, result: &mut ChildResult) {
    result.wall_seconds = Some(elapsed.as_secs_f64());
    result.usage = Some(usage);
    result.reap_certain = result.stop_error.is_none();
    if elapsed >= hard_limit {
        let error = MeasureError::WaitFailed {
            errno: libc::ETIMEDOUT,
            elapsed,
        };
        record_wait_error(result, error);
        result.stop_error = Some(error);
    }
}

fn final_reap(
    pid: libc::pid_t,
    started: Instant,
    timeout: Duration,
    grace: Duration,
    backend: &mut impl WaitBackend,
    state: &mut WaitState,
    result: &mut ChildResult,
) {
    let hard_limit = timeout.saturating_add(grace);
    loop {
        if let Some(error) = wait_abort(started, timeout, grace, backend, state) {
            stop_wait(pid, backend, result, error);
            return;
        }
        match poll_owned(pid, backend, state) {
            Ok(Some(usage)) => {
                accept_reap(usage, backend.elapsed(started), hard_limit, result);
                return;
            }
            Err(libc::ECHILD) => {
                let error = MeasureError::WaitFailed {
                    errno: libc::ECHILD,
                    elapsed: backend.elapsed(started),
                };
                stop_wait(pid, backend, result, error);
                return;
            }
            Err(errno) => {
                if errno != libc::EINTR && errno != libc::EAGAIN {
                    record_wait_error(
                        result,
                        MeasureError::WaitFailed {
                            errno,
                            elapsed: backend.elapsed(started),
                        },
                    );
                }
                continue;
            }
            Ok(None) => {}
        }
        if let Some(error) = wait_abort(started, timeout, grace, backend, state) {
            stop_wait(pid, backend, result, error);
            return;
        }
        let remaining = hard_limit.saturating_sub(backend.elapsed(started));
        backend.sleep(Duration::from_millis(1).min(remaining));
    }
}

fn terminate_and_reap(
    pid: libc::pid_t,
    started: Instant,
    timeout: Duration,
    grace: Duration,
    backend: &mut impl WaitBackend,
    state: &mut WaitState,
    result: &mut ChildResult,
) {
    let pgid = pid;
    if let Err(code) = backend.kill(-pgid) {
        if !result.errors.contains(&MeasureError::KillFailed) {
            result.errors.push(MeasureError::KillFailed);
        }
        // A vanished group cannot establish that the direct child remains ours to reap.
        if code == libc::ESRCH {
            let error = MeasureError::WaitFailed {
                errno: code,
                elapsed: backend.elapsed(started),
            };
            record_wait_error(result, error);
            result.stop_error = Some(error);
        }
    }
    final_reap(pid, started, timeout, grace, backend, state, result);
}

fn verify_group(
    pgid: libc::pid_t,
    started: Instant,
    timeout: Duration,
    grace: Duration,
    backend: &mut impl WaitBackend,
    result: &mut ChildResult,
) {
    if backend.probe_group(pgid) == Err(libc::ESRCH) {
        result.group_empty = true;
        return;
    }
    result.descendants_remained = true;
    result.errors.push(MeasureError::DescendantsRemained);
    signal_group(pgid, backend, result);
    let reaped_elapsed = Duration::from_secs_f64(result.wall_seconds.unwrap_or(0.0));
    let limit = reaped_elapsed
        .saturating_add(grace)
        .min(timeout.saturating_add(grace));
    while backend.elapsed(started) < limit {
        if backend.probe_group(pgid) == Err(libc::ESRCH) {
            result.group_empty = true;
            return;
        }
        let remaining = limit.saturating_sub(backend.elapsed(started));
        backend.sleep(Duration::from_millis(1).min(remaining));
    }
    if result.stop_error.is_none() {
        result.stop_error = Some(MeasureError::DescendantsRemained);
    }
}

fn decode_child(result: &mut ChildResult) {
    if let Some(usage) = &result.usage {
        if libc::WIFEXITED(usage.status) {
            result.status.exit_code = Some(libc::WEXITSTATUS(usage.status));
        } else if libc::WIFSIGNALED(usage.status) {
            result.status.signal = Some(libc::WTERMSIG(usage.status));
        } else {
            result.errors.push(MeasureError::MeasurementInvalid);
        }
        if usage.user_cpu_seconds.is_none()
            || usage.system_cpu_seconds.is_none()
            || usage.peak_rss_bytes.is_none()
            || !result
                .wall_seconds
                .is_some_and(|v| v.is_finite() && v >= 0.0)
        {
            result.errors.push(MeasureError::MeasurementInvalid);
        }
    }
}

fn wait_child(
    pid: libc::pid_t,
    started: Instant,
    timeout: Duration,
    grace: Duration,
    backend: &mut impl WaitBackend,
) -> ChildResult {
    let mut result = ChildResult::pending();
    if pid <= 0 {
        let error = MeasureError::WaitFailed {
            errno: libc::EINVAL,
            elapsed: backend.elapsed(started),
        };
        record_wait_error(&mut result, error);
        result.stop_error = Some(error);
        return result;
    }
    let state = &mut WaitState::default();
    loop {
        if let Some(error) = wait_abort(started, timeout, grace, backend, state) {
            stop_wait(pid, backend, &mut result, error);
            break;
        }
        let elapsed = backend.elapsed(started);
        let poll = if elapsed >= timeout {
            let final_poll = poll_owned(pid, backend, state);
            if matches!(final_poll, Ok(None)) {
                result.status.timed_out = true;
                terminate_and_reap(pid, started, timeout, grace, backend, state, &mut result);
                break;
            }
            final_poll
        } else {
            poll_owned(pid, backend, state)
        };
        match poll {
            Ok(Some(usage)) => {
                accept_reap(
                    usage,
                    backend.elapsed(started),
                    timeout.saturating_add(grace),
                    &mut result,
                );
                break;
            }
            Err(libc::ECHILD) => {
                let error = MeasureError::WaitFailed {
                    errno: libc::ECHILD,
                    elapsed: backend.elapsed(started),
                };
                stop_wait(pid, backend, &mut result, error);
                break;
            }
            Err(errno) => {
                if errno == libc::EINTR || errno == libc::EAGAIN {
                    continue;
                }
                record_wait_error(
                    &mut result,
                    MeasureError::WaitFailed {
                        errno,
                        elapsed: backend.elapsed(started),
                    },
                );
                terminate_and_reap(pid, started, timeout, grace, backend, state, &mut result);
                break;
            }
            Ok(None) => {}
        }
        if let Some(error) = wait_abort(started, timeout, grace, backend, state) {
            stop_wait(pid, backend, &mut result, error);
            break;
        }
        let remaining = timeout.saturating_sub(backend.elapsed(started));
        backend.sleep(grace.min(remaining));
    }
    let pgid = pid;
    if result.usage.is_some() {
        verify_group(pgid, started, timeout, grace, backend, &mut result);
    }
    decode_child(&mut result);
    if (!result.reap_certain || !result.group_empty) && result.stop_error.is_none() {
        let error = MeasureError::WaitFailed {
            errno: state.last_errno.unwrap_or(libc::ECHILD),
            elapsed: backend.elapsed(started),
        };
        record_wait_error(&mut result, error);
        result.stop_error = Some(error);
    }
    result
}

#[derive(Clone)]
struct ChildEnvironment {
    path: OsString,
    home: Option<OsString>,
}
impl ChildEnvironment {
    fn capture() -> Self {
        Self::from_values(std::env::var_os("PATH"), std::env::var_os("HOME"))
    }
    fn from_values(path: Option<OsString>, home: Option<OsString>) -> Self {
        Self {
            path: path.unwrap_or_else(|| OsString::from("/usr/bin:/bin")),
            home,
        }
    }
    fn keys(&self) -> Vec<String> {
        let mut keys = vec!["PATH".into()];
        if self.home.is_some() {
            keys.push("HOME".into());
        }
        keys.extend(["TMPDIR", "LANG", "RUST_LOG", "RUST_BACKTRACE"].map(String::from));
        keys
    }
}

fn configure_child(
    command: &mut Command,
    paths: &RunPaths,
    child_env: &ChildEnvironment,
) -> Result<(), MeasureError> {
    let stdout = evidence_file(&paths.root.join("stdout.log"))?;
    let stderr = evidence_file(&paths.root.join("stderr.log"))?;
    // Pin the inherited default filter; release builds also disable trace/debug statically.
    command
        .env_clear()
        .env("PATH", &child_env.path)
        .env("TMPDIR", &paths.tmp)
        .env("LANG", "C.UTF-8")
        .env("RUST_LOG", "stract=info")
        .env("RUST_BACKTRACE", "1")
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr);
    if let Some(home) = &child_env.home {
        command.env("HOME", home);
    }
    Ok(())
}

fn measured_child(
    executable: &Path,
    args: &[OsString],
    paths: &RunPaths,
    timeout: Duration,
    child_env: &ChildEnvironment,
    backend: &mut impl WaitBackend,
) -> ChildResult {
    let mut command = Command::new(executable);
    command.args(args);
    measured_command(&mut command, paths, timeout, child_env, backend)
}

fn measured_command(
    command: &mut Command,
    paths: &RunPaths,
    timeout: Duration,
    child_env: &ChildEnvironment,
    backend: &mut impl WaitBackend,
) -> ChildResult {
    if let Err(error) = configure_child(command, paths, child_env) {
        return ChildResult::refused(error);
    }
    spawn_and_measure(command, timeout, backend)
}

fn spawn_and_measure(
    command: &mut Command,
    timeout: Duration,
    backend: &mut impl WaitBackend,
) -> ChildResult {
    let started = Instant::now();
    let child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return ChildResult::refused(MeasureError::SpawnFailed),
    };
    // Kernel child identifiers fit positive pid_t on the supported platforms. Check the Rust
    // conversion anyway; never cast a failed conversion into a group or unrelated-process wait.
    let pid = libc::pid_t::try_from(child.id())
        .ok()
        .filter(|pid| *pid > 0);
    let result = wait_child(
        pid.unwrap_or(0),
        started,
        timeout,
        Duration::from_millis(50),
        backend,
    );
    // Child has no reaping Drop implementation. wait4 remains the sole reaper throughout.
    drop(child);
    result
}

trait RunDriver {
    fn child(&mut self, paths: &RunPaths, timeout: Duration) -> ChildResult;
    fn documents(&mut self, index: &Path) -> Result<u64, MeasureError> {
        count_documents(index)
    }
}

struct IndexerDriver {
    binary: PathBuf,
    child_env: ChildEnvironment,
}

impl RunDriver for IndexerDriver {
    fn child(&mut self, paths: &RunPaths, timeout: Duration) -> ChildResult {
        let args = vec![
            OsString::from("indexer"),
            OsString::from("search"),
            paths.root.join("config.toml").into_os_string(),
        ];
        measured_child(
            &self.binary,
            &args,
            paths,
            timeout,
            &self.child_env,
            &mut SystemWait,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Scheduled {
    input: usize,
    batch_size: usize,
    run: usize,
}

fn schedule(inputs: usize, settings: &Settings) -> Vec<Scheduled> {
    (0..inputs)
        .flat_map(|input| {
            settings
                .batch_sizes
                .iter()
                .map(move |batch| (input, *batch))
        })
        .flat_map(|(input, batch_size)| {
            (1..=settings.runs).map(move |run| Scheduled {
                input,
                batch_size,
                run,
            })
        })
        .collect()
}

fn run_path(out: &Path, stem: &str, task: Scheduled) -> PathBuf {
    out.join(stem)
        .join(format!("b{}", task.batch_size))
        .join(format!("r{}", task.run))
}

fn preflight_evidence(
    out: &Path,
    inputs: &[Input],
    settings: &Settings,
) -> Result<(), MeasureError> {
    absent(&out.join("report.json"))?;
    for input in inputs {
        let folder = out.join(&input.stem);
        inspect_components(&folder).map_err(|_| MeasureError::OutputRefused)?;
        if fs::symlink_metadata(&folder).is_ok_and(|m| !m.is_dir()) {
            return Err(MeasureError::OutputRefused);
        }
        absent(&folder.join("inspection.json"))?;
    }
    for task in schedule(inputs.len(), settings) {
        let path = run_path(out, &inputs[task.input].stem, task);
        inspect_components(&path).map_err(|_| MeasureError::OutputRefused)?;
        absent(&path)?;
    }
    Ok(())
}

fn new_row(inspected: &Inspected, task: Scheduled) -> Row {
    let inspection = &inspected.inspection;
    Row {
        warc_sha256: inspection.warc_sha256.clone(),
        batch_size: task.batch_size,
        run: task.run,
        documents: None,
        parse_errors: inspection.parse_errors,
        index_skip_histogram: inspection.index_skip_histogram.clone(),
        index_candidates: inspection.index_candidates,
        candidate_delta: None,
        wall_seconds: None,
        user_cpu_seconds: None,
        system_cpu_seconds: None,
        peak_rss_bytes: None,
        final_disk_bytes: None,
        exit_code: None,
        signal: None,
        timed_out: false,
        descendants_remained: false,
        reap_certain: true,
        failed: false,
        config_sha256: None,
        child_stdout_bytes: 0,
        child_stderr_bytes: 0,
    }
}

fn failure(row: &mut Row, failures: &mut Vec<Failure>, reason: String) {
    row.failed = true;
    failures.push(Failure {
        warc_sha256: row.warc_sha256.clone(),
        batch_size: row.batch_size,
        run: row.run,
        kind: if reason == "cleanup-failed" {
            "cleanup_failed"
        } else {
            "run_failed"
        },
        reason,
    });
}

fn classify_child(row: &mut Row, child_status: &ChildStatus, failures: &mut Vec<Failure>) {
    row.exit_code = child_status.exit_code;
    row.signal = child_status.signal;
    row.timed_out = child_status.timed_out;
    if !child_status.success() {
        let reason = if child_status.timed_out {
            "child-timeout"
        } else if child_status.signal.is_some() {
            "child-signal"
        } else {
            "child-exit"
        };
        failure(row, failures, reason.into());
    }
}

fn extract_run(
    row: &mut Row,
    child: &ChildResult,
    paths: &RunPaths,
    driver: &mut impl RunDriver,
    failures: &mut Vec<Failure>,
) {
    // Classification precedes extraction so a missing index cannot hide a child failure.
    classify_child(row, &child.status, failures);
    row.descendants_remained = child.descendants_remained;
    row.reap_certain = child.reap_certain;
    row.wall_seconds = child.wall_seconds;
    if let Some(usage) = &child.usage {
        row.user_cpu_seconds = usage.user_cpu_seconds;
        row.system_cpu_seconds = usage.system_cpu_seconds;
        row.peak_rss_bytes = usage.peak_rss_bytes;
    }
    for error in &child.errors {
        failure(row, failures, error.to_string());
    }
    if child.usage.is_some() {
        match disk_bytes(&paths.index) {
            Ok(bytes) => row.final_disk_bytes = Some(bytes),
            Err(error) => failure(row, failures, error.to_string()),
        }
    }
    if !row.failed && child.reap_certain && child.group_empty {
        match driver.documents(&paths.index) {
            Ok(documents) => {
                let delta = i128::from(documents) - i128::from(row.index_candidates);
                match i64::try_from(delta) {
                    Ok(delta) => {
                        row.documents = Some(documents);
                        row.candidate_delta = Some(delta);
                    }
                    Err(_) => failure(row, failures, MeasureError::MeasurementInvalid.to_string()),
                }
            }
            Err(error) => failure(row, failures, error.to_string()),
        }
    }
}

fn log_length(path: &Path) -> Result<u64, MeasureError> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => Ok(m.len()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
        _ => Err(MeasureError::EvidenceFailed),
    }
}

struct RunCompletion {
    row: Row,
    stop: Option<MeasureError>,
}

fn execute_run(
    inspected: &Inspected,
    task: Scheduled,
    out: &Path,
    environment: &Environment,
    driver: &mut impl RunDriver,
    settings: &Settings,
    failures: &mut Vec<Failure>,
) -> Result<RunCompletion, MeasureError> {
    let paths = RunPaths::new(run_path(out, &inspected.input.stem, task));
    reserve_run(&paths.root)?;
    let mut row = new_row(inspected, task);
    let mut stop = None;
    let mut evidence_failed = match prepare_run(&inspected.input, &paths, task.batch_size) {
        Ok(hash) => {
            row.config_sha256 = Some(hash);
            let child = driver.child(&paths, Duration::from_secs(settings.child_timeout_seconds));
            stop = child.stop_error;
            extract_run(&mut row, &child, &paths, driver, failures);
            child.errors.contains(&MeasureError::EvidenceFailed)
        }
        Err(error) => {
            failure(&mut row, failures, error.to_string());
            error == MeasureError::EvidenceFailed
        }
    };
    for (name, stdout) in [("stdout.log", true), ("stderr.log", false)] {
        match log_length(&paths.root.join(name)) {
            Ok(bytes) if stdout => row.child_stdout_bytes = bytes,
            Ok(bytes) => row.child_stderr_bytes = bytes,
            Err(error) => {
                evidence_failed = true;
                failure(&mut row, failures, error.to_string());
            }
        }
    }
    let cleanup: Result<(), MeasureError> = remove_owned_stores(&paths);
    if let Err(error) = cleanup {
        failure(&mut row, failures, error.to_string());
    }
    json_create(
        &paths.root.join("run.json"),
        &RunEvidence {
            schema_version: 1,
            environment,
            row: &row,
        },
    )?;
    // A writable row file cannot repair a failed config or log write. Preserve the partial
    // receipt, then stop before another child or a report could imply complete evidence.
    if evidence_failed {
        return Err(MeasureError::EvidenceFailed);
    }
    let stop = cleanup.err().or(stop);
    Ok(RunCompletion { row, stop })
}

fn count_differences(rows: &[Row]) -> Vec<Difference> {
    let mut references = BTreeMap::<&str, CountTuple>::new();
    let mut differences = Vec::new();
    for row in rows.iter().filter(|row| !row.failed) {
        if let Some(documents) = row.documents.filter(|n| *n > 0) {
            let tuple = CountTuple {
                warc_sha256: row.warc_sha256.clone(),
                batch_size: row.batch_size,
                run: row.run,
                documents,
            };
            let reference = references
                .entry(&row.warc_sha256)
                .or_insert_with(|| tuple.clone());
            if reference.documents != documents {
                differences.push(Difference {
                    reference: reference.clone(),
                    different: tuple,
                });
            }
        }
    }
    differences
}

fn assert_repeatable_counts(rows: &[Row]) -> Result<(), MeasureError> {
    if !count_differences(rows).is_empty() {
        return Err(MeasureError::CountsDiffer);
    }
    Ok(())
}

fn range(rows: &[&Row], metric: fn(&Row) -> Option<f64>) -> (Option<f64>, Option<f64>) {
    let mut min: Option<f64> = None;
    let mut max: Option<f64> = None;
    for value in rows.iter().filter_map(|row| metric(row)) {
        min = Some(min.map_or(value, |old| old.min(value)));
        max = Some(max.map_or(value, |old| old.max(value)));
    }
    (min, max)
}

fn timings(warcs: &[Warc], settings: &Settings, rows: &[Row]) -> Vec<Timing> {
    let mut timing = Vec::new();
    for warc in warcs {
        for batch in &settings.batch_sizes {
            let selected: Vec<_> = rows
                .iter()
                .filter(|row| {
                    !row.failed && row.warc_sha256 == warc.warc_sha256 && row.batch_size == *batch
                })
                .collect();
            let (wall_seconds_min, wall_seconds_max) = range(&selected, |r| r.wall_seconds);
            let (user_cpu_seconds_min, user_cpu_seconds_max) =
                range(&selected, |r| r.user_cpu_seconds);
            let (system_cpu_seconds_min, system_cpu_seconds_max) =
                range(&selected, |r| r.system_cpu_seconds);
            timing.push(Timing {
                warc_sha256: warc.warc_sha256.clone(),
                batch_size: *batch,
                successful_runs: selected.len() as u64,
                wall_seconds_min,
                wall_seconds_max,
                user_cpu_seconds_min,
                user_cpu_seconds_max,
                system_cpu_seconds_min,
                system_cpu_seconds_max,
            });
        }
    }
    timing
}

fn completed_report(
    environment: Environment,
    settings: Settings,
    warcs: Vec<Warc>,
    rows: Vec<Row>,
    failures: Vec<Failure>,
) -> Report {
    let repeatable = assert_repeatable_counts(&rows).is_ok();
    let count_differences = count_differences(&rows);
    let timing = timings(&warcs, &settings, &rows);
    let all_removed = !failures
        .iter()
        .any(|failure| failure.kind == "cleanup_failed");
    Report {
        schema_version: 1,
        environment,
        settings,
        warcs,
        rows,
        repeatable,
        count_differences,
        failures,
        timing,
        cleanup: Cleanup {
            policy: "delete-index-centrality-and-tmp-before-row",
            all_removed,
        },
    }
}

fn execute_matrix(
    inputs: &[Inspected],
    out: &Path,
    environment: Environment,
    settings: Settings,
    driver: &mut impl RunDriver,
) -> Result<Summary, MeasureError> {
    let mut rows = Vec::new();
    let mut failures = Vec::new();
    let mut stop = None;
    for task in schedule(inputs.len(), &settings) {
        let completed = execute_run(
            &inputs[task.input],
            task,
            out,
            &environment,
            driver,
            &settings,
            &mut failures,
        )?;
        rows.push(completed.row);
        if let Some(error) = completed.stop {
            stop = Some(error);
            break;
        }
    }
    let warcs = inputs
        .iter()
        .map(|i| Warc {
            stem: i.input.stem.clone(),
            warc_sha256: i.inspection.warc_sha256.clone(),
            inspection_file: format!("{}/inspection.json", i.input.stem),
        })
        .collect();
    let report = completed_report(environment, settings, warcs, rows, failures);
    json_create(&out.join("report.json"), &report)?;
    if let Some(error) = stop {
        return Err(error);
    }
    Ok(Summary {
        runs: report.rows.len(),
        failed: report.rows.iter().filter(|r| r.failed).count(),
        repeatable: report.repeatable,
    })
}

/// Measures each retained input across the supplied batches and runs, preserving caller order.
///
/// The current executable must be named `stract`; callers must keep its bytes and the input
/// files immutable until completion. All indexes are transient and each row is synced after
/// removing its stores. The completed summary's `outcome` determines the command exit status.
/// Cleanup or child-ownership failure saves a partial report with the actual row prefix and
/// returns an error before another child. Evidence-write failure may prevent that report.
///
/// # Errors
/// Refuses invalid paths/settings before reading inputs. Inspection, lost reap certainty,
/// failed cleanup, or evidence failure returns a fixed error and leaves partial evidence.
pub fn run(
    warcs: &[PathBuf],
    batch_sizes: &[usize],
    runs: usize,
    out: &Path,
    child_timeout_seconds: u64,
) -> Result<Summary, MeasureError> {
    let settings = Settings {
        batch_sizes: batch_sizes.to_vec(),
        runs,
        child_timeout_seconds,
    };
    validate_settings(warcs.len(), &settings)?;
    validate_output(out)?;
    let inputs = validate_inputs(warcs, &prospective_path(out)?)?;
    let (binary, hash) =
        pin_binary(&std::env::current_exe().map_err(|_| MeasureError::BinaryRefused)?)?;
    let child_env = ChildEnvironment::capture();
    let environment = environment(hash, &child_env)?;
    preflight_evidence(out, &inputs, &settings)?;
    // Check existing identities before creation too, so case aliases cannot create a directory
    // inside the repository. Recheck the admitted directory after all missing parents exist.
    reject_repository_identity(out)?;
    private_parents(out)?;
    validate_output(out)?;
    reject_repository_identity(out)?;
    let out = out
        .canonicalize()
        .map_err(|_| MeasureError::OutputRefused)?;
    let inputs = validate_inputs(warcs, &out)?;
    preflight_evidence(&out, &inputs, &settings)?;
    let mut inspected = Vec::new();
    for input in inputs {
        let folder = out.join(&input.stem);
        private_parents(&folder)?;
        let inspection = sample::inspect_warc(&input.path, &folder.join("inspection.json"))
            .map_err(|_| MeasureError::InspectionFailed)?;
        inspected.push(Inspected { input, inspection });
    }
    execute_matrix(
        &inspected,
        &out,
        environment,
        settings,
        &mut IndexerDriver { binary, child_env },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{symlink, PermissionsExt};

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let root = PathBuf::from(std::env::var_os("STORY584_SCRATCH").unwrap());
            let path = root.join(format!("measure-test-{}", uuid::Uuid::new_v4()));
            private_parents(&path).unwrap();
            Self(path)
        }

        fn paths(&self, name: &str) -> RunPaths {
            let root = self.0.join(name);
            private_parents(&root).unwrap();
            RunPaths::new(root)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn special_file(path: &Path) {
        let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // # Safety
        // The CString is NUL-terminated and remains live; the unique owned path is never opened.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    }

    fn settings() -> Settings {
        Settings {
            batch_sizes: vec![128, 512],
            runs: 2,
            child_timeout_seconds: DEFAULT_CHILD_TIMEOUT_SECONDS,
        }
    }

    fn synthetic(dir: &TestDir, stem: &str) -> Inspected {
        let folder = dir.0.join("inputs");
        private_parents(&folder).unwrap();
        let name = format!("{stem}.warc.gz");
        let path = folder.join(&name);
        fs::write(&path, b"synthetic retained input identity").unwrap();
        Inspected {
            input: Input {
                path,
                stem: stem.into(),
                folder: folder.to_str().unwrap().into(),
                name,
            },
            inspection: sample::WarcInspection {
                schema_version: 1,
                warc_sha256: sha256(stem.as_bytes()),
                documents: 3,
                parse_errors: 0,
                extended_documents: 0,
                payload_types: BTreeMap::new(),
                index_skip_histogram: BTreeMap::new(),
                index_candidates: 3,
                index_measurement_status: "synthetic accounting".into(),
            },
        }
    }

    fn row(inspected: &Inspected, batch_size: usize, run: usize, documents: u64) -> Row {
        let mut row = new_row(
            inspected,
            Scheduled {
                input: 0,
                batch_size,
                run,
            },
        );
        row.documents = Some(documents);
        row.wall_seconds = Some(0.125);
        row.user_cpu_seconds = Some(0.1);
        row.system_cpu_seconds = Some(0.025);
        row.peak_rss_bytes = Some(7168);
        row.exit_code = Some(0);
        row
    }

    fn reaped(status: i32) -> Reaped {
        Reaped {
            status,
            user_cpu_seconds: Some(0.1),
            system_cpu_seconds: Some(0.025),
            peak_rss_bytes: Some(7),
        }
    }

    fn completed_child(status: i32) -> ChildResult {
        ChildResult {
            status: ChildStatus {
                exit_code: Some(status),
                signal: None,
                timed_out: false,
            },
            wall_seconds: Some(0.125),
            usage: Some(reaped(status << 8)),
            errors: Vec::new(),
            reap_certain: true,
            descendants_remained: false,
            group_empty: true,
            stop_error: None,
        }
    }

    #[test]
    fn measure_units() {
        assert_eq!(rss_bytes(7, RssUnit::Bytes), Some(7));
        assert_eq!(rss_bytes(7, RssUnit::Kibibytes), Some(7168));
        for unit in [RssUnit::Bytes, RssUnit::Kibibytes] {
            assert_eq!(rss_bytes(0, unit), Some(0));
            assert_eq!(rss_bytes(-1, unit), None);
        }
        assert_eq!(rss_bytes(libc::c_long::MAX, RssUnit::Kibibytes), None);
        assert_eq!(
            cpu_seconds(libc::timeval {
                tv_sec: 2,
                tv_usec: 125_000
            }),
            Some(2.125)
        );
        assert_eq!(
            cpu_seconds(libc::timeval {
                tv_sec: -1,
                tv_usec: 0
            }),
            None
        );
        assert_eq!(
            cpu_seconds(libc::timeval {
                tv_sec: 0,
                tv_usec: 1_000_000
            }),
            None
        );
    }

    #[test]
    fn measure_counts() {
        let dir = TestDir::new();
        let input = synthetic(&dir, "counts");
        let mut rows = vec![
            row(&input, 128, 1, 3),
            row(&input, 128, 2, 3),
            row(&input, 512, 1, 3),
        ];
        assert_eq!(assert_repeatable_counts(&rows), Ok(()));
        rows[1].documents = Some(4);
        assert_eq!(
            assert_repeatable_counts(&rows),
            Err(MeasureError::CountsDiffer)
        );
        let differences = count_differences(&rows);
        assert_eq!(differences.len(), 1);
        assert_eq!(
            differences[0].reference,
            CountTuple {
                warc_sha256: rows[0].warc_sha256.clone(),
                batch_size: 128,
                run: 1,
                documents: 3
            }
        );
        assert_eq!(
            differences[0].different,
            CountTuple {
                warc_sha256: rows[1].warc_sha256.clone(),
                batch_size: 128,
                run: 2,
                documents: 4
            }
        );
        rows[1].documents = Some(3);
        rows[2].documents = Some(5);
        assert_eq!(
            assert_repeatable_counts(&rows),
            Err(MeasureError::CountsDiffer)
        );
        rows[2].failed = true;
        assert_eq!(assert_repeatable_counts(&rows), Ok(()));
        assert_eq!(
            Summary {
                runs: 3,
                failed: 1,
                repeatable: true
            }
            .outcome(),
            Err(MeasureError::RunsFailed)
        );
    }

    /// Self-reexec support stays inert in the parent suite and has a finite child lifetime.
    #[test]
    fn measure_child_fixture() {
        let Ok(mode) = std::env::var("MEASURE_CHILD_MODE") else {
            return;
        };
        println!("measure-child-ready");
        io::stdout().flush().unwrap();
        if mode == "fail" {
            std::process::exit(7);
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    #[derive(Default)]
    struct RecordingWait {
        calls: Vec<(libc::pid_t, i32)>,
        reaps: usize,
        kills: usize,
        ready_log: Option<PathBuf>,
    }

    impl WaitBackend for RecordingWait {
        fn wait(&mut self, pid: libc::pid_t, options: i32) -> Result<Option<Reaped>, i32> {
            assert_eq!(self.reaps, 0, "no wait after reap");
            assert!(pid > 0);
            self.calls.push((pid, options));
            let result = SystemWait.wait(pid, options)?;
            if result.is_some() {
                self.reaps += 1;
            } else if self.kills == 0
                && self.ready_log.as_ref().is_some_and(|path| {
                    fs::read_to_string(path).is_ok_and(|text| text.contains("measure-child-ready"))
                })
            {
                self.kill(-pid)?;
            }
            Ok(result)
        }

        fn kill(&mut self, pid: libc::pid_t) -> Result<(), i32> {
            assert!(pid < 0, "only negative group signals are permitted");
            self.kills += 1;
            SystemWait.kill(pid)
        }
        fn probe_group(&mut self, pgid: libc::pid_t) -> Result<(), i32> {
            SystemWait.probe_group(pgid)
        }
    }

    fn fixture(
        paths: &RunPaths,
        mode: &str,
        timeout: Duration,
        backend: &mut RecordingWait,
    ) -> ChildResult {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args([
            "crawler::measure::tests::measure_child_fixture",
            "--exact",
            "--nocapture",
        ]);
        private_parents(&paths.tmp).unwrap();
        configure_child(&mut command, paths, &ChildEnvironment::capture()).unwrap();
        command.env("MEASURE_CHILD_MODE", mode);
        let result = spawn_and_measure(&mut command, timeout, backend);
        rescue_fixture(backend);
        result
    }

    fn rescue_fixture(backend: &mut RecordingWait) {
        if backend.reaps != 0 {
            return;
        }
        let Some((pid, _)) = backend.calls.first().copied() else {
            return;
        };
        let _ = SystemWait.kill(-pid);
        let until = Instant::now() + Duration::from_secs(2);
        while backend.reaps == 0 && Instant::now() < until {
            if backend.wait(pid, libc::WNOHANG).is_err() {
                break;
            }
            if backend.reaps == 0 {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    fn assert_reaped(backend: &RecordingWait) {
        assert_eq!(backend.reaps, 1);
        assert!(!backend.calls.is_empty());
        let owned = backend.calls[0].0;
        assert!(owned > 0);
        assert!(backend.calls.iter().all(|(pid, _)| *pid == owned));
    }

    #[test]
    fn measure_child_failure() {
        let dir = TestDir::new();
        let input = synthetic(&dir, "child");
        let paths = dir.paths("filter");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.env("RUST_LOG", "trace");
        configure_child(&mut command, &paths, &ChildEnvironment::capture()).unwrap();
        let actual_filter = command
            .get_envs()
            .find_map(|(key, value)| (key == "RUST_LOG").then_some(value).flatten());
        assert_eq!(actual_filter, Some(OsStr::new("stract=info")));
        let mut backend = RecordingWait::default();
        let child = fixture(
            &dir.paths("failure"),
            "fail",
            Duration::from_secs(10),
            &mut backend,
        );
        assert!(child.status.exit_code.is_some_and(|code| code != 0));
        assert_eq!(child.status.signal, None);
        assert_reaped(&backend);
        let mut failed = new_row(
            &input,
            Scheduled {
                input: 0,
                batch_size: 128,
                run: 1,
            },
        );
        let mut failures = Vec::new();
        classify_child(&mut failed, &child.status, &mut failures);
        assert!(
            failed.failed,
            "nonzero status must fail before index extraction"
        );
        assert_eq!(failed.documents, None);
        let paths = dir.paths("signal");
        let mut backend = RecordingWait {
            ready_log: Some(paths.root.join("stdout.log")),
            ..Default::default()
        };
        let child = fixture(&paths, "sleep", Duration::from_secs(10), &mut backend);
        assert_eq!(child.status.signal, Some(libc::SIGKILL));
        assert_eq!(child.status.exit_code, None);
        let mut signal_row = new_row(
            &input,
            Scheduled {
                input: 0,
                batch_size: 128,
                run: 2,
            },
        );
        classify_child(&mut signal_row, &child.status, &mut failures);
        assert!(signal_row.failed && signal_row.documents.is_none());
        assert!(
            !child.status.timed_out,
            "readiness must precede the bounded fallback deadline"
        );
        assert_eq!(backend.kills, 1);
        assert_reaped(&backend);
        let mut backend = RecordingWait::default();
        let child = fixture(
            &dir.paths("timeout"),
            "sleep",
            Duration::from_millis(5),
            &mut backend,
        );
        assert!(child.status.timed_out);
        assert!(!child.status.success());
        assert_reaped(&backend);
    }

    #[test]
    fn measure_timeout() {
        let dir = TestDir::new();
        let mut backend = RecordingWait::default();
        let child = fixture(
            &dir.paths("timeout"),
            "sleep",
            Duration::from_millis(5),
            &mut backend,
        );
        assert!(
            child.status.timed_out,
            "a finite sleeper must cross the tiny deadline"
        );
        assert!(!child.status.success());
        assert_eq!(child.status.signal, Some(libc::SIGKILL));
        assert_eq!(child.status.exit_code, None);
        assert!(child.usage.as_ref().unwrap().peak_rss_bytes.is_some());
        assert_eq!(backend.kills, 1);
        assert_reaped(&backend);
        assert_eq!(backend.calls.last().unwrap().1, libc::WNOHANG);
    }

    #[test]
    fn measure_deadline_cap() {
        assert_eq!(DEFAULT_CHILD_TIMEOUT_SECONDS, 1800);
        let mut settings = settings();
        for seconds in [1, 1800, 3600] {
            settings.child_timeout_seconds = seconds;
            assert_eq!(validate_settings(1, &settings), Ok(()));
        }
        for seconds in [0, 3601, u64::MAX] {
            settings.child_timeout_seconds = seconds;
            assert_eq!(
                validate_settings(1, &settings),
                Err(MeasureError::InvalidArguments)
            );
        }
        settings.child_timeout_seconds = 1;
        for batches in [vec![], vec![0], vec![1, 1], (1..=9).collect()] {
            settings.batch_sizes = batches;
            assert_eq!(
                validate_settings(1, &settings),
                Err(MeasureError::InvalidArguments)
            );
        }
        settings.batch_sizes = vec![1];
        for runs in [0, 9] {
            settings.runs = runs;
            assert_eq!(
                validate_settings(1, &settings),
                Err(MeasureError::InvalidArguments)
            );
        }
        settings.runs = 8;
        assert_eq!(
            validate_settings(0, &settings),
            Err(MeasureError::InvalidArguments)
        );
        assert_eq!(validate_settings(1, &settings), Ok(()));
    }

    fn fixture_index(path: &Path, documents: usize) {
        let mut index = Index::open(path).unwrap();
        index.prepare_writer().unwrap();
        for number in 0..documents {
            let page = crate::webpage::Webpage::test_parse(
                "<title>Example</title><p>Recorded example text.</p>",
                &format!("https://example.com/{number}"),
            )
            .unwrap();
            index.insert(&page).unwrap();
        }
        index.commit().unwrap();
    }

    #[test]
    fn measure_nonempty_documents() {
        let dir = TestDir::new();
        let empty = dir.0.join("empty");
        fixture_index(&empty, 0);
        assert_eq!(count_documents(&empty), Err(MeasureError::NoDocuments));
        let positive = dir.0.join("positive");
        fixture_index(&positive, 1);
        fs::write(dir.0.join("stdout.log"), b"documents=999").unwrap();
        assert_eq!(count_documents(&positive), Ok(1));
    }

    #[test]
    fn measure_disk() {
        let dir = TestDir::new();
        let root = dir.0.join("disk");
        private_parents(&root.join("nested/empty")).unwrap();
        fs::write(root.join("one"), b"abc").unwrap();
        fs::write(root.join("nested/two"), b"12345").unwrap();
        fs::write(dir.0.join("outside"), b"external bytes").unwrap();
        symlink(dir.0.join("outside"), root.join("file-link")).unwrap();
        symlink(root.join("nested"), root.join("dir-link")).unwrap();
        special_file(&root.join("fifo"));
        assert_eq!(disk_bytes(&root), Ok(8));
        assert_eq!(disk_bytes(&root.join("nested/empty")), Ok(0));
        assert_eq!(fs::read(dir.0.join("outside")).unwrap(), b"external bytes");
    }

    #[test]
    fn measure_index_directory() {
        let dir = TestDir::new();
        let missing = dir.0.join("missing");
        assert_eq!(count_documents(&missing), Err(MeasureError::IndexMissing));
        assert!(!missing.exists());
        let file = dir.0.join("file");
        fs::write(&file, b"regular").unwrap();
        assert_eq!(count_documents(&file), Err(MeasureError::IndexInvalid));
        symlink(&missing, dir.0.join("link")).unwrap();
        assert_eq!(
            count_documents(&dir.0.join("link")),
            Err(MeasureError::IndexInvalid)
        );
        let incomplete = dir.0.join("incomplete");
        private_parents(&incomplete).unwrap();
        assert_eq!(
            count_documents(&incomplete),
            Err(MeasureError::IndexInvalid)
        );
        assert!(!incomplete.join("inverted_index").exists());
        private_parents(&incomplete.join("inverted_index")).unwrap();
        assert_eq!(
            count_documents(&incomplete),
            Err(MeasureError::IndexInvalid)
        );
        assert!(!incomplete.join("region_count.json").exists());
        fs::write(incomplete.join("region_count.json"), b"{}").unwrap();
        symlink(&file, incomplete.join("inverted_index/segment")).unwrap();
        assert_eq!(
            count_documents(&incomplete),
            Err(MeasureError::IndexInvalid)
        );
    }

    #[test]
    fn measure_config() {
        let dir = TestDir::new();
        let inspected = synthetic(&dir, "config");
        let paths = dir.paths("quoted\"folder\n");
        for batch in [128, 512, 2048] {
            let expected = config(&inspected.input, &paths, batch).unwrap();
            let bytes = toml::to_string(&expected).unwrap();
            assert_eq!(check_config(&bytes, &expected), Ok(()));
            assert_eq!(
                sha256(bytes.as_bytes()),
                sha256(toml::to_string(&expected).unwrap().as_bytes())
            );
            let parsed: IndexerConfig = toml::from_str(&bytes).unwrap();
            assert!(parsed.dual_encoder.is_none() && parsed.page_webgraph.is_none());
            if batch != 512 {
                let typo = bytes.replace("batch_size", "batch_siz");
                assert_eq!(
                    toml::from_str::<IndexerConfig>(&typo).unwrap().batch_size,
                    512
                );
                assert_eq!(
                    check_config(&typo, &expected),
                    Err(MeasureError::ConfigInvalid)
                );
            }
            for corrupted in [
                bytes.replace("limit_warc_files = 1", "limit_warc_files = 2"),
                bytes.replace("5000", "5001"),
                bytes.replace("centrality-empty", "elsewhere"),
                bytes.replace("config.warc.gz", "other.warc.gz"),
                bytes.replace("output_path =", "minimum_clean_words = 1\noutput_path ="),
            ] {
                assert_eq!(
                    check_config(&corrupted, &expected),
                    Err(MeasureError::ConfigInvalid)
                );
            }
        }
        let paths = dir.paths("exact");
        let hash = prepare_run(&inspected.input, &paths, 128).unwrap();
        assert_eq!(hash, file_sha256(&paths.root.join("config.toml")).unwrap());
    }

    #[test]
    fn measure_output_paths() {
        let dir = TestDir::new();
        assert_eq!(
            validate_output(Path::new("relative")),
            Err(MeasureError::OutputRefused)
        );
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let descendant = repo.join("measure-output-must-not-exist");
        assert_eq!(
            validate_output(&descendant),
            Err(MeasureError::OutputRefused)
        );
        assert!(!descendant.exists());
        assert_eq!(
            validate_output(repo.parent().unwrap()),
            Err(MeasureError::OutputRefused)
        );
        assert_eq!(
            validate_output(&dir.0.join("a/../b")),
            Err(MeasureError::OutputRefused)
        );
        assert_eq!(
            validate_output(&dir.0.join("./dot")),
            Err(MeasureError::OutputRefused)
        );
        symlink(&dir.0, dir.0.join("link")).unwrap();
        assert_eq!(
            validate_output(&dir.0.join("link/out")),
            Err(MeasureError::OutputRefused)
        );
        assert_eq!(validate_output(&dir.0.join("fresh")), Ok(()));
        assert_eq!(MeasureError::OutputRefused.to_string(), "output-refused");
        let alias = repo.with_file_name(repo.file_name().unwrap().to_str().unwrap().to_uppercase());
        if identity(&alias) == identity(&repo) {
            assert_eq!(
                reject_repository_identity(&alias),
                Err(MeasureError::OutputRefused)
            );
            assert_eq!(
                reject_repository_identity(&alias.join("fresh")),
                Err(MeasureError::OutputRefused)
            );
        } else {
            println!("case-variant identity check skipped: case-sensitive filesystem");
        }
    }

    #[test]
    fn measure_order() {
        let dir = TestDir::new();
        let inputs = [synthetic(&dir, "first"), synthetic(&dir, "second")];
        let settings = Settings {
            batch_sizes: vec![512, 128],
            ..settings()
        };
        let tasks = schedule(inputs.len(), &settings);
        let tuples: Vec<_> = tasks
            .iter()
            .map(|s| (inputs[s.input].input.stem.as_str(), s.batch_size, s.run))
            .collect();
        assert_eq!(
            tuples,
            vec![
                ("first", 512, 1),
                ("first", 512, 2),
                ("first", 128, 1),
                ("first", 128, 2),
                ("second", 512, 1),
                ("second", 512, 2),
                ("second", 128, 1),
                ("second", 128, 2)
            ]
        );
    }

    #[test]
    fn measure_binary() {
        assert_eq!(
            pin_binary(&std::env::current_exe().unwrap()),
            Err(MeasureError::BinaryRefused)
        );
        let dir = TestDir::new();
        let path = dir.0.join("stract");
        private_parents(&path).unwrap();
        assert_eq!(pin_binary(&path), Err(MeasureError::BinaryRefused));
        fs::remove_dir(&path).unwrap();
        fs::write(&path, b"regular fixture, never executable").unwrap();
        let (canonical, hash) = pin_binary(&path).unwrap();
        assert_eq!(canonical, path.canonicalize().unwrap());
        assert_eq!(hash, sha256(b"regular fixture, never executable"));
    }

    #[test]
    fn measure_run_directory() {
        let dir = TestDir::new();
        let input = synthetic(&dir, "reservation");
        let paths = RunPaths::new(dir.0.join("runs/r1"));
        reserve_run(&paths.root).unwrap();
        fs::write(paths.root.join("sentinel"), b"keep").unwrap();
        assert_eq!(reserve_run(&paths.root), Err(MeasureError::OutputExists));
        assert_eq!(fs::read(paths.root.join("sentinel")).unwrap(), b"keep");
        assert_eq!(
            fs::metadata(&paths.root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        prepare_run(&input.input, &paths, 128).unwrap();
        assert!(fs::symlink_metadata(&paths.index).is_err());
        assert_eq!(fs::read_dir(&paths.centrality).unwrap().count(), 0);
        for name in ["config.toml", "stdout.log", "stderr.log", "report.json"] {
            let path = paths.root.join(name);
            if !path.exists() {
                fs::write(&path, b"keep").unwrap();
            }
            let bytes = fs::read(&path).unwrap();
            assert!(matches!(
                evidence_file(&path),
                Err(MeasureError::OutputExists)
            ));
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
    }

    fn keys(value: &serde_json::Value, expected: &[&str]) {
        let actual: BTreeSet<_> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(actual, expected.iter().copied().collect());
    }

    fn no_content(value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    assert!(!["body", "html", "title"].contains(&key.as_str()));
                    no_content(value);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    no_content(value);
                }
            }
            _ => {}
        }
    }

    fn test_environment() -> Environment {
        environment(
            sha256(b"fixture binary"),
            &ChildEnvironment::from_values(
                Some(OsString::from("/usr/bin:/bin")),
                Some(OsString::from("/fixture-home")),
            ),
        )
        .unwrap()
    }

    fn report_fixture(dir: &TestDir) -> Report {
        let input = synthetic(dir, "report");
        let mut rows = vec![
            row(&input, 128, 1, 3),
            row(&input, 128, 2, 4),
            new_row(
                &input,
                Scheduled {
                    input: 0,
                    batch_size: 512,
                    run: 1,
                },
            ),
        ];
        let mut failures = Vec::new();
        failure(&mut rows[2], &mut failures, "spawn-failed".into());
        let warcs = vec![Warc {
            stem: input.input.stem,
            warc_sha256: input.inspection.warc_sha256,
            inspection_file: "report/inspection.json".into(),
        }];
        completed_report(test_environment(), settings(), warcs, rows, failures)
    }

    fn report_keys(value: &serde_json::Value) {
        keys(
            value,
            &[
                "schema_version",
                "environment",
                "settings",
                "warcs",
                "rows",
                "repeatable",
                "count_differences",
                "failures",
                "timing",
                "cleanup",
            ],
        );
        keys(
            &value["environment"],
            &[
                "os",
                "arch",
                "cpus",
                "ram_bytes",
                "binary_sha256",
                "revision",
                "revision_source",
                "toolchain_pin",
                "process_group",
                "child_env_keys",
            ],
        );
        keys(
            &value["settings"],
            &["batch_sizes", "runs", "child_timeout_seconds"],
        );
        keys(
            &value["warcs"][0],
            &["stem", "warc_sha256", "inspection_file"],
        );
        keys(
            &value["rows"][0],
            &[
                "warc_sha256",
                "batch_size",
                "run",
                "documents",
                "parse_errors",
                "index_skip_histogram",
                "index_candidates",
                "candidate_delta",
                "wall_seconds",
                "user_cpu_seconds",
                "system_cpu_seconds",
                "peak_rss_bytes",
                "final_disk_bytes",
                "exit_code",
                "signal",
                "timed_out",
                "descendants_remained",
                "reap_certain",
                "failed",
                "config_sha256",
                "child_stdout_bytes",
                "child_stderr_bytes",
            ],
        );
        keys(&value["count_differences"][0], &["reference", "different"]);
        keys(
            &value["count_differences"][0]["reference"],
            &["warc_sha256", "batch_size", "run", "documents"],
        );
        keys(
            &value["failures"][0],
            &["warc_sha256", "batch_size", "run", "reason", "kind"],
        );
        keys(
            &value["timing"][0],
            &[
                "warc_sha256",
                "batch_size",
                "successful_runs",
                "wall_seconds_min",
                "wall_seconds_max",
                "user_cpu_seconds_min",
                "user_cpu_seconds_max",
                "system_cpu_seconds_min",
                "system_cpu_seconds_max",
            ],
        );
        keys(&value["cleanup"], &["policy", "all_removed"]);
    }

    #[test]
    fn measure_report() {
        let dir = TestDir::new();
        let report = report_fixture(&dir);
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["environment"]["process_group"], true);
        assert_eq!(
            value["environment"]["child_env_keys"],
            serde_json::to_value(vec![
                "PATH",
                "HOME",
                "TMPDIR",
                "LANG",
                "RUST_LOG",
                "RUST_BACKTRACE"
            ],)
            .unwrap()
        );
        assert_eq!(value["rows"][0]["descendants_remained"], false);
        assert_eq!(value["rows"][0]["reap_certain"], true);
        assert_eq!(
            value["cleanup"]["policy"],
            "delete-index-centrality-and-tmp-before-row"
        );
        assert_eq!(value["failures"][0]["kind"], "run_failed");
        report_keys(&value);
        assert!(value["rows"][2]["documents"].is_null());
        assert!(value["rows"][2]["wall_seconds"].is_null());
        assert!(value["timing"][1]["wall_seconds_min"].is_null());
        assert_eq!(value["rows"][0]["peak_rss_bytes"], 7168);
        assert_eq!(value["rows"][0]["wall_seconds"], 0.125);
        no_content(&value);
        let path = dir.0.join("report.json");
        json_create(&path, &report).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read(&path).unwrap().last(), Some(&b'\n'));
        assert_eq!(json_create(&path, &report), Err(MeasureError::OutputExists));
        let standalone = serde_json::to_value(RunEvidence {
            schema_version: 1,
            environment: &report.environment,
            row: &report.rows[0],
        })
        .unwrap();
        keys(&standalone, &["schema_version", "environment", "row"]);
        no_content(&standalone);
    }

    #[test]
    fn measure_inputs() {
        let dir = TestDir::new();
        let first = synthetic(&dir, "first");
        let out = dir.0.join("out");
        let path = first.input.path.clone();
        let admitted = validate_inputs(std::slice::from_ref(&path), &out).unwrap();
        assert_eq!(admitted[0].folder, first.input.folder);
        assert_eq!(admitted[0].name, "first.warc.gz");
        assert!(matches!(
            validate_inputs(&[path.clone(), path.clone()], &out),
            Err(MeasureError::InputRefused)
        ));
        symlink(&path, dir.0.join("linked.warc.gz")).unwrap();
        symlink(path.parent().unwrap(), dir.0.join("linked-parent")).unwrap();
        let socket = dir.0.join("socket");
        special_file(&socket);
        let bad_utf8 = dir.0.join(OsString::from_vec(vec![b'x', 255]));
        if let Err(error) = fs::write(&bad_utf8, b"input") {
            assert_eq!(error.raw_os_error(), Some(libc::EILSEQ));
            println!("filesystem refuses non-UTF-8 names; path refusal is still asserted");
        }
        let bad_stem = dir.0.join("inputs/.hidden.warc.gz");
        fs::write(&bad_stem, b"input").unwrap();
        for refused in [
            dir.0.join("linked.warc.gz"),
            dir.0.join("linked-parent/first.warc.gz"),
            dir.0.clone(),
            dir.0.join("inputs/../inputs/first.warc.gz"),
            socket,
            bad_utf8,
            bad_stem,
        ] {
            let actual = validate_inputs(std::slice::from_ref(&refused), &out);
            assert!(
                matches!(actual, Err(MeasureError::InputRefused)),
                "unexpected refusal for {refused:?}: {actual:?}"
            );
        }
        let duplicate_stem = dir.0.join("other-inputs/first.warc");
        private_parents(duplicate_stem.parent().unwrap()).unwrap();
        fs::write(&duplicate_stem, b"input").unwrap();
        assert!(matches!(
            validate_inputs(&[path.clone(), duplicate_stem], &out),
            Err(MeasureError::InputRefused)
        ));
        for overlap in [
            path.parent().unwrap().to_owned(),
            dir.0.clone(),
            path.parent().unwrap().join("nested"),
        ] {
            assert!(matches!(
                validate_inputs(std::slice::from_ref(&path), &overlap),
                Err(MeasureError::OutputRefused)
            ));
        }
    }

    struct ScriptedWait {
        replies: VecDeque<Result<Option<Reaped>, i32>>,
        calls: Vec<(libc::pid_t, i32)>,
        kills: Vec<libc::pid_t>,
        kill_error: Option<i32>,
        clock: Duration,
        probes: Vec<libc::pid_t>,
        group_response: Result<(), i32>,
    }

    impl ScriptedWait {
        fn new(replies: Vec<Result<Option<Reaped>, i32>>) -> Self {
            Self {
                replies: replies.into(),
                calls: Vec::new(),
                kills: Vec::new(),
                kill_error: None,
                clock: Duration::ZERO,
                probes: Vec::new(),
                group_response: Err(libc::ESRCH),
            }
        }
    }

    impl WaitBackend for ScriptedWait {
        fn wait(&mut self, pid: libc::pid_t, options: i32) -> Result<Option<Reaped>, i32> {
            assert_eq!(pid, 123, "only the owned positive pid reaches the backend");
            self.calls.push((pid, options));
            self.replies.pop_front().expect("unexpected extra reap")
        }
        fn kill(&mut self, target: libc::pid_t) -> Result<(), i32> {
            assert_eq!(target, -123);
            self.kills.push(target);
            self.kill_error.map_or(Ok(()), Err)
        }
        fn probe_group(&mut self, pgid: libc::pid_t) -> Result<(), i32> {
            assert_eq!(pgid, 123);
            self.probes.push(pgid);
            self.group_response
        }
        fn elapsed(&self, _: Instant) -> Duration {
            self.clock
        }
        fn sleep(&mut self, duration: Duration) {
            self.clock += duration;
        }
    }

    fn scripted_child(backend: &mut ScriptedWait, timeout: Duration) -> ChildResult {
        wait_child(
            123,
            Instant::now(),
            timeout,
            Duration::from_millis(50),
            backend,
        )
    }

    fn check_wait_ownership() {
        let mut backend = ScriptedWait::new(vec![Err(libc::ECHILD)]);
        let result = scripted_child(&mut backend, Duration::from_secs(1));
        assert!(!result.reap_certain && result.usage.is_none());
        assert_eq!(backend.kills, vec![-123]);
        assert!(matches!(
            result.stop_error,
            Some(MeasureError::WaitFailed {
                errno: libc::ECHILD,
                ..
            })
        ));
        for final_reply in [Err(libc::ECHILD), Ok(Some(reaped(0)))] {
            let mut backend = ScriptedWait::new(vec![Ok(None), final_reply]);
            backend.kill_error = Some(libc::ESRCH);
            let result = scripted_child(&mut backend, Duration::ZERO);
            assert!(!result.reap_certain);
            assert!(result.errors.contains(&MeasureError::KillFailed));
            assert!(matches!(
                result.stop_error,
                Some(MeasureError::WaitFailed { .. })
            ));
            assert!(result
                .errors
                .iter()
                .any(|e| matches!(e, MeasureError::WaitFailed { .. })));
            assert!(backend
                .calls
                .iter()
                .all(|(_, options)| *options == libc::WNOHANG));
        }
        let mut backend = ScriptedWait::new(Vec::new());
        let result = wait_child(
            0,
            Instant::now(),
            Duration::ZERO,
            Duration::from_millis(50),
            &mut backend,
        );
        assert!(matches!(
            result.stop_error,
            Some(MeasureError::WaitFailed {
                errno: libc::EINVAL,
                ..
            })
        ));
        assert!(backend.calls.is_empty() && backend.kills.is_empty());
    }

    #[test]
    fn measure_wait_protocol() {
        let mut backend = ScriptedWait::new(vec![
            Err(libc::EINTR),
            Err(libc::EAGAIN),
            Ok(None),
            Ok(Some(reaped(0))),
        ]);
        let result = scripted_child(&mut backend, Duration::from_secs(1));
        assert!(
            result.errors.is_empty(),
            "EINTR must retry without becoming a row failure"
        );
        assert!(result.status.success() && result.reap_certain && result.group_empty);
        assert_eq!(backend.calls, vec![(123, libc::WNOHANG); 4]);
        assert!(backend.kills.is_empty());
        let mut backend = ScriptedWait::new(vec![
            Ok(None),
            Err(libc::EINTR),
            Ok(Some(reaped(libc::SIGKILL))),
        ]);
        let result = scripted_child(&mut backend, Duration::ZERO);
        assert!(result.status.timed_out && result.reap_certain);
        assert_eq!(result.status.signal, Some(libc::SIGKILL));
        assert_eq!(backend.calls, vec![(123, libc::WNOHANG); 3]);
        assert_eq!(backend.kills, vec![-123]);
        for retry in [libc::EINTR, libc::EAGAIN] {
            let mut backend = ScriptedWait::new(vec![
                Err(libc::EIO),
                Err(retry),
                Err(libc::EIO),
                Ok(Some(reaped(libc::SIGKILL))),
            ]);
            let result = scripted_child(&mut backend, Duration::from_secs(1));
            assert!(matches!(
                result.errors.as_slice(),
                [MeasureError::WaitFailed {
                    errno: libc::EIO,
                    ..
                }]
            ));
            assert!(result.reap_certain && result.group_empty);
            assert!(result.stop_error.is_none());
            assert_eq!(backend.kills, vec![-123]);
        }
        check_wait_ownership();
    }

    struct ErrorStream {
        clock: Duration,
        step: Duration,
        error_calls: usize,
        reply: Result<Option<Reaped>, i32>,
    }

    impl WaitBackend for ErrorStream {
        fn wait(&mut self, pid: libc::pid_t, options: i32) -> Result<Option<Reaped>, i32> {
            assert_eq!((pid, options), (123, libc::WNOHANG));
            self.error_calls += 1;
            self.clock += self.step;
            match self.reply {
                Err(errno) => Err(errno),
                _ => Ok(None),
            }
        }
        fn kill(&mut self, target: libc::pid_t) -> Result<(), i32> {
            assert_eq!(target, -123);
            Err(libc::EINVAL)
        }
        fn probe_group(&mut self, _: libc::pid_t) -> Result<(), i32> {
            panic!("an unreaped child must not be probed");
        }
        fn elapsed(&self, _: Instant) -> Duration {
            self.clock
        }
        fn sleep(&mut self, duration: Duration) {
            self.clock += duration;
        }
    }

    struct RescuedErrors(std::sync::Arc<std::sync::atomic::AtomicBool>);

    impl WaitBackend for RescuedErrors {
        fn wait(&mut self, pid: libc::pid_t, options: i32) -> Result<Option<Reaped>, i32> {
            assert_eq!((pid, options), (123, libc::WNOHANG));
            if self.0.load(std::sync::atomic::Ordering::SeqCst) {
                Err(libc::ECHILD)
            } else {
                Err(libc::EIO)
            }
        }
        fn kill(&mut self, target: libc::pid_t) -> Result<(), i32> {
            assert_eq!(target, -123);
            Err(libc::EINVAL)
        }
        fn probe_group(&mut self, _: libc::pid_t) -> Result<(), i32> {
            panic!("an unreaped child must not be probed");
        }
    }

    fn check_real_wait_bound() {
        let rescue = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = rescue.clone();
        let (send, receive) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = wait_child(
                123,
                Instant::now(),
                Duration::ZERO,
                Duration::from_millis(50),
                &mut RescuedErrors(flag),
            );
            send.send(result).unwrap();
        });
        let received = receive.recv_timeout(Duration::from_millis(250));
        let returned_in_budget = received.is_ok();
        rescue.store(true, std::sync::atomic::Ordering::SeqCst);
        worker.join().unwrap();
        assert!(
            returned_in_budget,
            "persistent wait errors must return within the shared budget"
        );
        let child = received.unwrap();
        let wait_error = child.stop_error.unwrap();
        let hard_limit = Duration::from_millis(50);
        assert!(
            matches!(wait_error, MeasureError::WaitFailed { errno: libc::EIO, elapsed }
            if elapsed <= hard_limit)
        );
        assert!(!child.reap_certain);
        assert!(child.usage.is_none());
        assert_eq!(wait_error.to_string(), "wait-failed");
    }

    #[test]
    fn measure_wait_error_bound() {
        let hard_limit = Duration::from_millis(50);
        let mut backend = ErrorStream {
            clock: Duration::ZERO,
            step: hard_limit,
            error_calls: 0,
            reply: Err(libc::EIO),
        };
        let child = wait_child(
            123,
            Instant::now(),
            Duration::ZERO,
            hard_limit,
            &mut backend,
        );
        let wait_elapsed = backend.clock;
        assert!(
            wait_elapsed <= hard_limit,
            "the final reap exceeded the shared deadline"
        );
        assert!(!child.reap_certain && child.usage.is_none());
        backend.clock = Duration::ZERO;
        backend.step = Duration::from_millis(10);
        backend.error_calls = 0;
        let child = wait_child(
            123,
            Instant::now(),
            Duration::from_secs(1),
            hard_limit,
            &mut backend,
        );
        assert_eq!(
            backend.error_calls, 2,
            "two consecutive unexpected errnos end reaping"
        );
        assert!(!child.reap_certain && child.usage.is_none());
        for reply in [Err(libc::EINTR), Err(libc::EAGAIN), Ok(None)] {
            backend.clock = Duration::ZERO;
            backend.error_calls = 0;
            backend.reply = reply;
            let child = wait_child(
                123,
                Instant::now(),
                Duration::ZERO,
                hard_limit,
                &mut backend,
            );
            assert!(!child.reap_certain && child.usage.is_none());
            assert!(backend.clock <= hard_limit + backend.step);
            assert!(backend.error_calls <= 5);
        }
        check_real_wait_bound();
    }

    fn fixture_option(key: &str) -> Option<String> {
        let prefix = format!("measure-{key}=");
        std::env::args().find_map(|arg| arg.strip_prefix(&prefix).map(str::to_owned))
    }

    fn support_command(name: &str, mode: &str, root: &Path) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args([
            format!("crawler::measure::tests::{name}"),
            "--exact".into(),
            "--nocapture".into(),
            "--skip".into(),
            format!("measure-mode={mode}"),
            "--skip".into(),
            format!("measure-root={}", root.display()),
        ]);
        command
    }

    /// Argument-gated descendants have finite lifetimes even if a protocol assertion fails.
    #[test]
    fn measure_group_fixture() {
        let Some(mode) = fixture_option("mode") else {
            return;
        };
        let root = PathBuf::from(fixture_option("root").unwrap());
        if mode == "leaf" {
            fs::write(root.join("grandchild-ready"), b"ready").unwrap();
            std::thread::sleep(Duration::from_secs(2));
            return;
        }
        if mode == "exit" || mode == "timeout" {
            let mut grandchild = support_command("measure_group_fixture", "leaf", &root);
            let child = grandchild.spawn().unwrap();
            let until = Instant::now() + Duration::from_secs(1);
            while !root.join("grandchild-ready").exists() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(root.join("grandchild-ready").exists());
            drop(child);
        }
        // # Safety
        // getpgrp takes no pointers and only reads this fixture's process-group identity.
        let pgid = unsafe { libc::getpgrp() };
        println!("owned-group={pgid}");
        io::stdout().flush().unwrap();
        if mode == "timeout" {
            std::thread::sleep(Duration::from_secs(2));
        }
        if mode == "equal" {
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    #[derive(Default)]
    struct GroupWait {
        pid: Option<libc::pid_t>,
        reaps: usize,
        signals: Vec<libc::pid_t>,
    }

    impl WaitBackend for GroupWait {
        fn wait(&mut self, pid: libc::pid_t, options: i32) -> Result<Option<Reaped>, i32> {
            assert!(pid > 0);
            assert_eq!(self.reaps, 0, "no wait after reap");
            assert_eq!(*self.pid.get_or_insert(pid), pid);
            assert_eq!(options, libc::WNOHANG);
            let reply = SystemWait.wait(pid, options)?;
            if reply.is_some() {
                self.reaps += 1;
            }
            Ok(reply)
        }
        fn kill(&mut self, target: libc::pid_t) -> Result<(), i32> {
            self.signals.push(target);
            SystemWait.kill(target)
        }
        fn probe_group(&mut self, pgid: libc::pid_t) -> Result<(), i32> {
            SystemWait.probe_group(pgid)
        }
    }

    fn clean_group(backend: &mut GroupWait) {
        let Some(pid) = backend.pid else {
            return;
        };
        let _ = SystemWait.kill(-pid);
        let until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < until {
            if backend.reaps == 0 {
                match backend.wait(pid, libc::WNOHANG) {
                    Err(libc::ECHILD) => break,
                    Err(_) => break,
                    _ => {}
                }
            }
            if backend.reaps != 0 && probe_group(pid) == Err(libc::ESRCH) {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[derive(Default)]
    struct DocumentSpy {
        document_calls: usize,
    }

    impl RunDriver for DocumentSpy {
        fn child(&mut self, _: &RunPaths, _: Duration) -> ChildResult {
            panic!("extraction never spawns a second child");
        }
        fn documents(&mut self, _: &Path) -> Result<u64, MeasureError> {
            self.document_calls += 1;
            Ok(3)
        }
    }

    fn group_case(
        dir: &TestDir,
        mode: &str,
        timeout: Duration,
    ) -> (
        ChildResult,
        Row,
        DocumentSpy,
        GroupWait,
        Result<(), i32>,
        Option<i32>,
    ) {
        let input = synthetic(dir, mode);
        let paths = dir.paths(mode);
        private_parents(&paths.tmp).unwrap();
        private_parents(&paths.index).unwrap();
        let mut backend = GroupWait::default();
        let mut command = support_command("measure_group_fixture", mode, &paths.root);
        let child = measured_command(
            &mut command,
            &paths,
            timeout,
            &ChildEnvironment::capture(),
            &mut backend,
        );
        let mut row = new_row(
            &input,
            Scheduled {
                input: 0,
                batch_size: 128,
                run: 1,
            },
        );
        let mut driver = DocumentSpy::default();
        extract_run(&mut row, &child, &paths, &mut driver, &mut Vec::new());
        let second_probe = probe_group(backend.pid.unwrap());
        let observed = fs::read_to_string(paths.root.join("stdout.log"))
            .unwrap()
            .lines()
            .find_map(|line| {
                line.strip_prefix("owned-group=")
                    .and_then(|s| s.parse().ok())
            });
        clean_group(&mut backend);
        (child, row, driver, backend, second_probe, observed)
    }

    struct PersistentGroup {
        calls: usize,
        elapsed: Duration,
    }

    impl RunDriver for PersistentGroup {
        fn child(&mut self, _: &RunPaths, _: Duration) -> ChildResult {
            self.calls += 1;
            let mut backend = ScriptedWait::new(vec![Ok(Some(reaped(0)))]);
            backend.group_response = Err(libc::EPERM);
            let child = scripted_child(&mut backend, Duration::from_secs(1));
            self.elapsed = backend.clock;
            assert!(!child.group_empty && child.reap_certain);
            child
        }
    }

    fn check_persistent_group(dir: &TestDir) {
        let input = synthetic(dir, "persistent");
        let out = dir.0.join("prefix");
        private_parents(&out).unwrap();
        let mut driver = PersistentGroup {
            calls: 0,
            elapsed: Duration::ZERO,
        };
        let result = execute_matrix(&[input], &out, test_environment(), settings(), &mut driver);
        assert!(matches!(result, Err(MeasureError::DescendantsRemained)));
        assert_eq!(driver.calls, 1);
        assert_eq!(driver.elapsed, Duration::from_millis(50));
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(out.join("report.json")).unwrap()).unwrap();
        assert_eq!(report["rows"].as_array().unwrap().len(), 1);
        assert_eq!(report["rows"][0]["failed"], true);
        assert_eq!(report["rows"][0]["descendants_remained"], true);
        assert!(!out.join("persistent/b128/r2").exists());
    }

    #[test]
    fn measure_descendants() {
        let dir = TestDir::new();
        let (child, row, driver, backend, second_probe, _) =
            group_case(&dir, "exit", Duration::from_secs(1));
        assert!(row.descendants_remained);
        assert!(row.failed);
        assert!(row.reap_certain);
        assert_eq!(row.documents, None);
        assert_eq!(driver.document_calls, 0);
        assert_eq!(second_probe, Err(libc::ESRCH));
        assert_eq!(probe_group(backend.pid.unwrap()), Err(libc::ESRCH));
        assert_eq!(child.status.exit_code, Some(0));
        check_persistent_group(&dir);
    }

    #[test]
    fn measure_timeout_descendants() {
        let dir = TestDir::new();
        let (child, row, _, backend, second_probe, observed) =
            group_case(&dir, "timeout", Duration::from_millis(250));
        let pgid = backend.pid.unwrap();
        let first_signal_target = backend.signals.first().copied();
        assert_eq!(first_signal_target, Some(-pgid));
        assert!(row.failed);
        assert!(row.timed_out);
        assert!(row.reap_certain);
        assert_eq!(child.status.signal, Some(libc::SIGKILL));
        assert_eq!(second_probe, Err(libc::ESRCH));
        assert_eq!(
            observed,
            Some(pgid),
            "both processes became ready before timeout"
        );
    }

    #[test]
    fn measure_child_group() {
        let dir = TestDir::new();
        let (child, row, driver, backend, _, observed) =
            group_case(&dir, "empty", Duration::from_secs(1));
        let owned_pid = backend.pid.unwrap();
        let observed_pgid = observed.unwrap();
        assert_eq!(observed_pgid, owned_pid);
        assert!(child.status.success());
        assert!(child.errors.is_empty());
        assert!(child.reap_certain && child.group_empty);
        assert!(!child.descendants_remained);
        assert_eq!(probe_group(owned_pid), Err(libc::ESRCH));
        assert!(!row.failed);
        assert_eq!(row.documents, Some(3));
        assert_eq!(driver.document_calls, 1);
    }

    /// The leaf runs only by an exact argument; no fixture variable enters its environment.
    #[test]
    fn measure_environment_fixture() {
        let Some(mode) = fixture_option("mode") else {
            return;
        };
        assert_eq!(mode, "outer");
        let paths = RunPaths::new(PathBuf::from(fixture_option("root").unwrap()));
        private_parents(&paths.tmp).unwrap();
        let tmp_mode = fs::metadata(&paths.tmp).unwrap().permissions().mode();
        let child_env = ChildEnvironment::capture();
        let mut command = Command::new(paths.root.join("environment-leaf"));
        let child = measured_command(
            &mut command,
            &paths,
            Duration::from_secs(1),
            &child_env,
            &mut SystemWait,
        );
        assert!(child.status.success() && child.errors.is_empty());
        let text = fs::read_to_string(paths.root.join("stdout.log")).unwrap();
        let observed: BTreeMap<String, String> = text
            .lines()
            .map(|line| {
                let (key, value) = line.split_once('=').unwrap();
                (key.to_owned(), value.to_owned())
            })
            .collect();
        let evidence = (observed, tmp_mode, child_env.keys());
        json_create(&paths.root.join("environment.json"), &evidence).unwrap();
        remove_owned_stores(&paths).unwrap();
    }

    fn environment_case(dir: &TestDir, inherited: bool) {
        let paths = dir.paths(if inherited { "inherited" } else { "fallback" });
        // A minimal Rust leaf avoids platform libraries adding keys during startup.
        // Its source and executable are private test artifacts, removed with this directory.
        let source = paths.root.join("environment-leaf.rs");
        fs::write(
            &source,
            r#"fn main() {
    let values: std::collections::BTreeMap<String, String> = std::env::vars().collect();
    for (key, value) in values { println!("{key}={value}"); }
}
"#,
        )
        .unwrap();
        let compiled = Command::new("rustc")
            .arg(&source)
            .arg("-o")
            .arg(paths.root.join("environment-leaf"))
            .output()
            .unwrap();
        assert!(compiled.status.success());
        let mut command = support_command("measure_environment_fixture", "outer", &paths.root);
        command
            .env_clear()
            .env("GATE2_ENV_CANARY", "gate2-env-canary")
            .env("UNRELATED_FIXTURE_VALUE", "unrelated")
            .env("RUST_LOG", "trace");
        if inherited {
            command
                .env("PATH", "/fixture-bin")
                .env("HOME", "/fixture-home");
        }
        let status = command.output().unwrap().status;
        assert!(status.success());
        let (observed, tmp_mode, ordered): (BTreeMap<String, String>, u32, Vec<String>) =
            serde_json::from_slice(&fs::read(paths.root.join("environment.json")).unwrap())
                .unwrap();
        let mut expected = BTreeMap::from([
            (
                "PATH".into(),
                if inherited {
                    "/fixture-bin"
                } else {
                    "/usr/bin:/bin"
                }
                .into(),
            ),
            ("TMPDIR".into(), paths.tmp.to_str().unwrap().into()),
            ("LANG".into(), "C.UTF-8".into()),
            ("RUST_LOG".into(), "stract=info".into()),
            ("RUST_BACKTRACE".into(), "1".into()),
        ]);
        let mut expected_keys = vec!["PATH"];
        if inherited {
            expected.insert("HOME".into(), "/fixture-home".into());
            expected_keys.push("HOME");
        }
        expected_keys.extend(["TMPDIR", "LANG", "RUST_LOG", "RUST_BACKTRACE"]);
        assert!(!observed.contains_key("GATE2_ENV_CANARY"));
        assert_eq!(
            observed.keys().cloned().collect::<BTreeSet<_>>(),
            expected.keys().cloned().collect()
        );
        assert_eq!(observed, expected);
        assert_eq!(tmp_mode & 0o777, 0o700);
        assert!(!paths.tmp.exists());
        assert_eq!(ordered, expected_keys);
        let child_env = ChildEnvironment::from_values(
            inherited.then(|| OsString::from("/fixture-bin")),
            inherited.then(|| OsString::from("/fixture-home")),
        );
        assert_eq!(
            environment(sha256(b"fixture"), &child_env)
                .unwrap()
                .child_env_keys,
            ordered
        );
    }

    #[test]
    fn measure_child_environment() {
        let dir = TestDir::new();
        environment_case(&dir, true);
        environment_case(&dir, false);
        let empty = ChildEnvironment::from_values(Some(OsString::new()), Some(OsString::new()));
        assert_eq!(empty.path, OsString::new());
        assert_eq!(empty.home, Some(OsString::new()));
        let bytes = OsString::from_vec(vec![255]);
        let opaque = ChildEnvironment::from_values(Some(bytes.clone()), Some(bytes.clone()));
        assert_eq!(opaque.path, bytes);
        assert_eq!(opaque.home, Some(bytes));
    }

    struct RestorePermissions(PathBuf);

    impl Drop for RestorePermissions {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        }
    }

    #[derive(Default)]
    struct CleanupDriver {
        calls: usize,
        guard: Option<RestorePermissions>,
    }

    impl RunDriver for CleanupDriver {
        fn child(&mut self, paths: &RunPaths, _: Duration) -> ChildResult {
            self.calls += 1;
            private_parents(&paths.index).unwrap();
            self.guard = Some(RestorePermissions(paths.index.clone()));
            fs::write(paths.index.join("readonly"), b"owned fixture").unwrap();
            fs::set_permissions(
                paths.index.join("readonly"),
                fs::Permissions::from_mode(0o400),
            )
            .unwrap();
            fs::set_permissions(&paths.index, fs::Permissions::from_mode(0o500)).unwrap();
            completed_child(0)
        }
        fn documents(&mut self, _: &Path) -> Result<u64, MeasureError> {
            Ok(3)
        }
    }

    fn cleanup_case(
        dir: &TestDir,
        out: &Path,
    ) -> (
        Result<Summary, MeasureError>,
        usize,
        Option<serde_json::Value>,
        Inspected,
    ) {
        // # Safety
        // geteuid has no pointer arguments and only reads the current effective identity.
        assert_ne!(
            unsafe { libc::geteuid() },
            0,
            "permission proof requires an unprivileged user"
        );
        let input = synthetic(dir, "cleanup");
        private_parents(out).unwrap();
        let mut driver = CleanupDriver::default();
        let result = execute_matrix(
            std::slice::from_ref(&input),
            out,
            test_environment(),
            settings(),
            &mut driver,
        );
        let report = fs::read(out.join("report.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok());
        drop(driver.guard.take());
        let index = out.join("cleanup/b128/r1/index");
        if index.exists() {
            fs::remove_dir_all(index).unwrap();
        }
        (result, driver.calls, report, input)
    }

    /// Reexecution exercises the command's error-to-exit mapping without exiting libtest.
    #[test]
    fn measure_cleanup_fixture() {
        if fixture_option("mode").as_deref() != Some("cleanup") {
            return;
        }
        let dir = TestDir(PathBuf::from(fixture_option("root").unwrap()));
        let (result, _, _, _) = cleanup_case(&dir, &dir.0.join("out"));
        let code = if result.and_then(|summary| summary.outcome()).is_err() {
            1
        } else {
            0
        };
        // The parent owns this directory and needs to inspect the durable evidence.
        std::mem::forget(dir);
        std::process::exit(code);
    }

    #[test]
    fn measure_cleanup_failure() {
        let dir = TestDir::new();
        let out = dir.0.join("out");
        let (result, calls, report, input) = cleanup_case(&dir, &out);
        assert!(
            report.is_some(),
            "cleanup failure must preserve report.json"
        );
        let report = report.unwrap();
        assert_eq!(report["cleanup"]["all_removed"], false);
        assert_eq!(report["failures"].as_array().unwrap().len(), 1);
        assert_eq!(report["failures"][0]["kind"], "cleanup_failed");
        assert_eq!(report["failures"][0]["reason"], "cleanup-failed");
        assert_eq!(
            report["failures"][0]["warc_sha256"],
            input.inspection.warc_sha256
        );
        assert_eq!(report["failures"][0]["batch_size"], 128);
        assert_eq!(report["failures"][0]["run"], 1);
        assert!(matches!(result, Err(MeasureError::CleanupFailed)));
        assert_eq!(calls, 1);
        let run: serde_json::Value =
            serde_json::from_slice(&fs::read(out.join("cleanup/b128/r1/run.json")).unwrap())
                .unwrap();
        assert_eq!(run["row"], report["rows"][0]);
        assert_eq!(run["row"]["failed"], true);
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains(out.to_str().unwrap()));
        assert!(!out.join("cleanup/b128/r2").exists());
        let wrapper = dir.0.join("wrapper");
        private_parents(&wrapper).unwrap();
        let status = support_command("measure_cleanup_fixture", "cleanup", &wrapper)
            .output()
            .unwrap()
            .status;
        assert!(wrapper.join("out/report.json").is_file());
        assert_eq!(status.code(), Some(1));
    }

    fn equal_sleep_diagnostics() {
        let dir = TestDir::new();
        let mut normal = 0;
        for trial in 0..20 {
            let paths = dir.paths(&format!("trial-{trial}"));
            private_parents(&paths.tmp).unwrap();
            let mut command = support_command("measure_group_fixture", "equal", &paths.root);
            let mut backend = GroupWait::default();
            let child = measured_command(
                &mut command,
                &paths,
                Duration::from_millis(100),
                &ChildEnvironment::capture(),
                &mut backend,
            );
            clean_group(&mut backend);
            if child.status.success() {
                normal += 1;
            }
            println!(
                "equal-sleep trial={trial} normal={} timed_out={} wall={:?}",
                child.status.success(),
                child.status.timed_out,
                child.wall_seconds
            );
            assert!(child.reap_certain && child.group_empty);
        }
        println!("equal-sleep diagnostic normal={normal}/20; scheduling ratio is not an assertion");
    }

    #[test]
    fn measure_deadline_exit() {
        let mut normal_exits = 0;
        for _ in 0..20 {
            let mut backend = ScriptedWait::new(vec![Ok(None), Ok(Some(reaped(0)))]);
            let child = wait_child(
                123,
                Instant::now(),
                Duration::from_millis(10),
                Duration::from_millis(200),
                &mut backend,
            );
            assert_eq!(child.status.exit_code, Some(0));
            assert!(!child.status.timed_out);
            assert!(child.errors.is_empty());
            assert!(child.reap_certain && child.group_empty);
            assert!(backend.kills.is_empty());
            assert_eq!(backend.clock, Duration::from_millis(10));
            normal_exits += 1;
        }
        assert_eq!(normal_exits, 20);
        equal_sleep_diagnostics();
    }

    #[test]
    fn measure_case_stems() {
        let dir = TestDir::new();
        let inputs: Vec<_> = ["inputs-a/seeds.warc.gz", "inputs-b/Seeds.warc"]
            .iter()
            .map(|name| {
                let path = dir.0.join(name);
                private_parents(path.parent().unwrap()).unwrap();
                fs::write(&path, b"invalid retained input").unwrap();
                path
            })
            .collect();
        let out = dir.0.join("out");
        let result = run(&inputs, &[128], 1, &out, 1);
        assert!(matches!(result, Err(MeasureError::InputRefused)));
        assert!(!out.join("seeds/inspection.json").exists());
        assert!(!out.join("Seeds/inspection.json").exists());
        assert!(!out.exists());
        assert!(matches!(
            validate_inputs(&inputs, &out),
            Err(MeasureError::InputRefused)
        ));
    }

    #[test]
    fn measure_centrality_errors() {
        let dir = TestDir::new();
        let input = synthetic(&dir, "centrality");
        let paths = dir.paths("existing");
        private_parents(&paths.centrality).unwrap();
        assert!(matches!(
            prepare_run(&input.input, &paths, 128),
            Err(MeasureError::OutputExists)
        ));
        let paths = dir.paths("unwritable");
        let guard = RestorePermissions(paths.root.clone());
        fs::set_permissions(&paths.root, fs::Permissions::from_mode(0o500)).unwrap();
        let result = prepare_run(&input.input, &paths, 128);
        drop(guard);
        assert!(matches!(result, Err(MeasureError::OutputUnwritable)));
        assert_eq!(
            MeasureError::OutputUnwritable.to_string(),
            "output-unwritable"
        );
        assert!(!paths.root.join("config.toml").exists());
        for kind in [
            io::ErrorKind::AlreadyExists,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::NotFound,
            io::ErrorKind::Other,
        ] {
            let expected = if kind == io::ErrorKind::AlreadyExists {
                MeasureError::OutputExists
            } else {
                MeasureError::OutputUnwritable
            };
            assert_eq!(output_creation_error(io::Error::from(kind)), expected);
        }
    }

    struct MatrixDriver {
        calls: usize,
        rows: Vec<PathBuf>,
        collide_report: bool,
        output: PathBuf,
    }

    impl RunDriver for MatrixDriver {
        fn child(&mut self, paths: &RunPaths, _: Duration) -> ChildResult {
            assert!(!paths.index.exists());
            assert_eq!(fs::read_dir(&paths.centrality).unwrap().count(), 0);
            assert!(
                self.rows.iter().all(|p| p.exists()),
                "earlier rows precede each next child"
            );
            private_parents(&paths.index).unwrap();
            fs::write(paths.index.join("partial"), b"index bytes").unwrap();
            fs::write(paths.centrality.join("store"), b"centrality bytes").unwrap();
            self.rows.push(paths.root.join("run.json"));
            self.calls += 1;
            if self.collide_report && self.calls == 3 {
                fs::write(self.output.join("report.json"), b"preserve").unwrap();
            }
            completed_child(if self.calls == 1 { 7 } else { 0 })
        }
        fn documents(&mut self, _: &Path) -> Result<u64, MeasureError> {
            Ok(self.calls as u64 + 1)
        }
    }

    fn check_matrix_cleanup(out: &Path, input: &Inspected, settings: &Settings) {
        for task in schedule(1, settings) {
            let path = run_path(out, &input.input.stem, task);
            assert!(path.join("run.json").is_file());
            assert!(
                !path.join("index").exists(),
                "every partial or complete index is removed"
            );
            assert!(
                !path.join("centrality-empty").exists(),
                "every centrality store is removed"
            );
            assert!(!path.join("tmp").exists());
        }
    }

    struct EvidenceFailureDriver(usize);

    impl RunDriver for EvidenceFailureDriver {
        fn child(&mut self, _: &RunPaths, _: Duration) -> ChildResult {
            self.0 += 1;
            ChildResult::refused(MeasureError::EvidenceFailed)
        }
    }

    fn check_evidence_abort(dir: &TestDir, input: &Inspected, settings: &Settings) {
        let out = dir.0.join("evidence-failure");
        private_parents(&out).unwrap();
        let mut driver = EvidenceFailureDriver(0);
        let result = execute_matrix(
            std::slice::from_ref(input),
            &out,
            test_environment(),
            settings.clone(),
            &mut driver,
        );
        assert!(matches!(result, Err(MeasureError::EvidenceFailed)));
        assert_eq!(
            driver.0, 1,
            "evidence failure must stop subsequent children"
        );
        assert!(!out.join("report.json").exists());
        let path = run_path(
            &out,
            &input.input.stem,
            Scheduled {
                input: 0,
                batch_size: 128,
                run: 1,
            },
        );
        assert!(path.join("run.json").is_file());
        assert!(!path.join("index").exists());
        assert!(!path.join("centrality-empty").exists());
        assert!(!path.parent().unwrap().join("r2").exists());
    }

    #[test]
    fn measure_matrix_completion() {
        let dir = TestDir::new();
        let input = synthetic(&dir, "matrix");
        let settings = Settings {
            batch_sizes: vec![128],
            runs: 3,
            ..settings()
        };
        for collide_report in [false, true] {
            let out = dir.0.join(if collide_report {
                "collision"
            } else {
                "complete"
            });
            private_parents(&out).unwrap();
            let mut driver = MatrixDriver {
                calls: 0,
                rows: Vec::new(),
                collide_report,
                output: out.clone(),
            };
            let result = execute_matrix(
                std::slice::from_ref(&input),
                &out,
                test_environment(),
                settings.clone(),
                &mut driver,
            );
            assert_eq!(driver.calls, 3);
            check_matrix_cleanup(&out, &input, &settings);
            if collide_report {
                assert!(matches!(result, Err(MeasureError::OutputExists)));
                assert_eq!(fs::read(out.join("report.json")).unwrap(), b"preserve");
            } else {
                let summary = result.unwrap();
                let report: serde_json::Value =
                    serde_json::from_slice(&fs::read(out.join("report.json")).unwrap()).unwrap();
                assert_eq!(report["rows"].as_array().unwrap().len(), 3);
                assert_eq!(report["failures"].as_array().unwrap().len(), 1);
                assert_eq!(report["failures"][0]["reason"], "child-exit");
                assert_eq!(report["count_differences"].as_array().unwrap().len(), 1);
                assert_eq!(summary.failed, 1);
                assert!(!summary.repeatable);
                assert_eq!(summary.outcome(), Err(MeasureError::RunsFailed));
            }
        }
        check_evidence_abort(&dir, &input, &settings);
    }
}
