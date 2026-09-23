//! Probes the real bounded decoder, hardened file entries, startup recovery and receipt clocks.
//! Synthetic snapshots are encoded independently and opened through the production owner.

use super::*;
use crate::crawler::politeness::ManualClock;
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::PathBuf,
    sync::atomic::AtomicUsize,
};

struct RecordingClock {
    clock: Arc<ManualClock>,
    deadlines: StdMutex<Vec<(u64, u64)>>,
    changed: tokio::sync::Notify,
}

impl Clock for RecordingClock {
    fn utc(&self) -> chrono::DateTime<chrono::Utc> {
        self.clock.utc()
    }

    fn ticks(&self) -> u64 {
        self.clock.ticks()
    }

    fn wait_until(&self, deadline: u64) -> crate::crawler::politeness::WaitFuture<'_> {
        Box::pin(async move {
            self.deadlines
                .lock()
                .unwrap()
                .push((self.ticks(), deadline));
            self.changed.notify_one();
            self.clock.wait_until(deadline).await;
        })
    }
}

#[test]
fn maintenance_interval_matches_live_index() {
    let fixture = Fixture::new();
    let clock = Arc::new(RecordingClock {
        clock: fixture.clock.clone(),
        deadlines: StdMutex::new(Vec::new()),
        changed: tokio::sync::Notify::new(),
    });
    let register = Arc::new(
        IngestRegister::open(
            &fixture.suppression,
            IngestSeams {
                clock: clock.clone(),
                ..fixture.seams()
            },
        )
        .unwrap(),
    );
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        assert!(register.start_maintenance().await);
        clock.changed.notified().await;
        let deadlines = clock.deadlines.lock().unwrap().clone();
        register.shutdown().await;
        assert_eq!(deadlines.len(), 1);
        let (start, deadline) = deadlines[0];
        assert_eq!(
            Duration::from_millis(deadline - start),
            crate::live_index::AUTO_COMMIT_INTERVAL
        );
        assert_eq!(
            crate::live_index::AUTO_COMMIT_INTERVAL,
            Duration::from_secs(600)
        );
    });
}

#[derive(Default)]
struct Stages {
    decode: AtomicUsize,
    opens: AtomicUsize,
}

impl IngestHooks for Stages {
    fn at(&self, stage: IngestStage) -> io::Result<()> {
        if stage == IngestStage::Decode {
            self.decode.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }
}

impl ComplianceHooks for Stages {
    fn at(&self, _: crate::compliance::disk::ComplianceStage) -> io::Result<()> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct Fixture {
    _directory: file_store::temp::TempDir,
    suppression: PathBuf,
    snapshot: PathBuf,
    clock: Arc<ManualClock>,
    stages: Arc<Stages>,
}

impl Fixture {
    fn new() -> Self {
        let directory = crate::gen_temp_dir().unwrap();
        let suppression = directory.as_ref().join("suppression.json");
        let snapshot = directory
            .as_ref()
            .join("suppression.json.ingest/snapshot.json");
        let fixture = Self {
            _directory: directory,
            suppression,
            snapshot,
            clock: Arc::new(ManualClock::new(
                chrono::DateTime::from_timestamp(1_790_000_000, 0).unwrap(),
            )),
            stages: Arc::new(Stages::default()),
        };
        drop(fixture.open().unwrap());
        fixture
    }

    fn seams(&self) -> IngestSeams {
        IngestSeams {
            clock: self.clock.clone(),
            hooks: self.stages.clone(),
            compliance_hooks: self.stages.clone(),
        }
    }

    fn open(&self) -> io::Result<IngestRegister> {
        IngestRegister::open(&self.suppression, self.seams())
    }

    fn write(&self, value: &Value) {
        fs::write(&self.snapshot, serde_json::to_vec(value).unwrap()).unwrap();
    }

    fn valid(&self) -> Value {
        let url = "https://example.com/page";
        let (_, id) = canonical_identity(url).unwrap();
        json!({"format_version":1,"entries":[{"id":id.as_str(),"canonical_url":url,
            "body_sha256":digest(b"fixture html"),"version":1,"received_at":1_790_000_000_i64,
            "retrieved_at":1_789_999_999_i64,"fetch_time_ms":10,"source":"fixture",
            "admission":"admitted","delivery":"acknowledged"}]})
    }
}

#[test]
fn snapshot_decode_is_bounded_and_strict() {
    let fixture = Fixture::new();
    let valid = fixture.valid();
    fixture.write(&valid);
    assert!(fixture.open().is_ok(), "valid nonempty snapshot reopens");
    let mut padded = serde_json::to_vec(&valid).unwrap();
    padded.resize(16_777_216, b' ');
    fs::write(&fixture.snapshot, &padded).unwrap();
    assert!(fixture.open().is_ok(), "inclusive snapshot byte cap");
    let before = fixture.stages.decode.load(Ordering::SeqCst);
    padded.push(b' ');
    fs::write(&fixture.snapshot, padded).unwrap();
    let oversized = fixture.open();
    assert_eq!(
        fixture.stages.decode.load(Ordering::SeqCst),
        before,
        "overflow before Decode"
    );
    assert!(oversized.is_err(), "snapshot cap refuses before decoding");
    for (key, value) in [
        ("id", json!("invalid")),
        ("canonical_url", json!("https://example.com/other")),
        ("body_sha256", json!("invalid")),
        ("version", json!(0)),
        ("version", json!(1.5)),
        ("admission", json!("rejected")),
        ("delivery", json!("pending")),
        ("retrieved_at", json!(1_790_000_001_i64)),
        ("received_at", json!(-1)),
        ("fetch_time_ms", json!(86_400_001)),
        ("source", json!("../private")),
        ("unknown", json!("field")),
    ] {
        let mut corrupt = valid.clone();
        corrupt["entries"][0][key] = value;
        fixture.write(&corrupt);
        assert!(fixture.open().is_err(), "invalid entry invariant: {key}");
    }
    snapshot_shape_refusals(&fixture, &valid);
    let bytes = fs::read(&fixture.snapshot).unwrap();
    assert!(fixture.open().is_err());
    assert_eq!(
        fs::read(&fixture.snapshot).unwrap(),
        bytes,
        "corruption is never repaired"
    );
    let reader = std::io::Cursor::new(vec![b' '; 17]);
    assert!(
        crate::compliance::disk::read_capped(reader, 1, 16).is_err(),
        "growing reader cap"
    );
}

fn snapshot_shape_refusals(fixture: &Fixture, valid: &Value) {
    let source = serde_json::to_string(valid).unwrap();
    for bytes in [
        source.replace("\"format_version\":1", "\"format_version\":2"),
        source.replace(
            "\"format_version\":1",
            "\"format_version\":1,\"format_version\":1",
        ),
        source.replace("\"version\":1", "\"version\":1,\"version\":1"),
        format!("{source} false"),
        source[..source.len() - 1].to_owned(),
    ] {
        fs::write(&fixture.snapshot, bytes).unwrap();
        assert!(fixture.open().is_err(), "strict snapshot syntax");
    }
    let mut duplicate = valid.clone();
    duplicate["entries"]
        .as_array_mut()
        .unwrap()
        .push(valid["entries"][0].clone());
    fixture.write(&duplicate);
    assert!(
        fixture.open().is_err(),
        "duplicate identifiers must not overwrite"
    );
    let mut second = valid["entries"][0].clone();
    let (url, id) = canonical_identity("https://example.com/second").unwrap();
    second["canonical_url"] = json!(url);
    second["id"] = json!(id.as_str());
    let mut entries = vec![valid["entries"][0].clone(), second];
    entries.sort_by(|a, b| b["id"].as_str().cmp(&a["id"].as_str()));
    fixture.write(&json!({"format_version":1,"entries":entries}));
    assert!(
        fixture.open().is_err(),
        "snapshot identifiers must be strictly sorted"
    );
}

#[test]
fn all_ingest_file_entries_use_shared_hardening() {
    let fixture = Fixture::new();
    let valid = fixture.valid();
    fixture.write(&valid);
    let root = fixture.snapshot.parent().unwrap();
    let target = root.join("safe-copy");
    fs::copy(&fixture.snapshot, &target).unwrap();
    for name in ["snapshot.json", "owner.lock"] {
        let path = root.join(name);
        let bytes = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        symlink(&target, &path).unwrap();
        assert!(fixture.open().is_err(), "symlink refused at {name}");
        fs::remove_file(&path).unwrap();
        fs::hard_link(&target, &path).unwrap();
        assert!(fixture.open().is_err(), "hard link refused at {name}");
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(
            fixture.open().is_err(),
            "nonregular entry refused at {name}"
        );
        fs::remove_dir(&path).unwrap();
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(fixture.open().is_err(), "public mode refused at {name}");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let temp = root.join("snapshot.1.0.tmp");
    symlink(&target, &temp).unwrap();
    let opens = fixture.stages.opens.load(Ordering::SeqCst);
    let result = fixture.open();
    assert_eq!(
        fixture.stages.opens.load(Ordering::SeqCst),
        opens + 1,
        "unsafe temp never reaches shared BeforeOpen; owner.lock alone opens"
    );
    assert!(result.is_err(), "unsafe temporary refused");
    assert!(fs::symlink_metadata(&temp)
        .unwrap()
        .file_type()
        .is_symlink());
    fs::remove_file(temp).unwrap();
    fs::set_permissions(root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(fixture.open().is_err(), "public parent refused");
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(fixture.open().is_ok(), "private normal files remain usable");
    assert!(crate::compliance::disk::validate_file_facts(true, 1, 2, 0o600, 1).is_err());
    assert!(crate::compliance::disk::validate_parent_facts(2, 0o700, 1).is_err());
    unsafe_ingest_temps_and_parent(&fixture, &target);
}

fn unsafe_ingest_temps_and_parent(fixture: &Fixture, target: &std::path::Path) {
    let root = fixture.snapshot.parent().unwrap();
    let temp = root.join("snapshot.1.0.tmp");
    for kind in 0..4 {
        match kind {
            0 => symlink(target, &temp).unwrap(),
            1 => fs::hard_link(target, &temp).unwrap(),
            2 => fs::create_dir(&temp).unwrap(),
            _ => {
                fs::write(&temp, b"unsafe mode").unwrap();
                fs::set_permissions(&temp, fs::Permissions::from_mode(0o644)).unwrap();
            }
        }
        let before = fixture.stages.opens.load(Ordering::SeqCst);
        let observed = fixture.open();
        assert_eq!(
            fixture.stages.opens.load(Ordering::SeqCst),
            before + 1,
            "unsafe temporary must not reach its open boundary"
        );
        assert!(observed.is_err());
        assert!(
            fs::symlink_metadata(&temp).is_ok(),
            "unsafe temporary is never removed"
        );
        if kind == 2 {
            fs::remove_dir(&temp).unwrap();
        } else {
            fs::remove_file(&temp).unwrap();
        }
    }
    let moved = root.with_file_name("moved-private");
    fs::rename(root, &moved).unwrap();
    symlink(&moved, root).unwrap();
    let before = fixture.stages.opens.load(Ordering::SeqCst);
    let observed = fixture.open();
    fs::remove_file(root).unwrap();
    fs::rename(moved, root).unwrap();
    assert_eq!(
        fixture.stages.opens.load(Ordering::SeqCst),
        before,
        "symlinked parent must fail before any file opens"
    );
    assert!(observed.is_err());
    assert!(fixture.open().is_ok());
}

#[test]
fn owned_ingest_temps_are_swept_only_under_lock() {
    let fixture = Fixture::new();
    let root = fixture.snapshot.parent().unwrap();
    let stale = root.join(format!("snapshot.{}.0.tmp", std::process::id()));
    let foreign = root.join("snapshot.01.00.tmp");
    for path in [&stale, &foreign] {
        fs::write(path, b"torn temporary").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let prior = fs::read(&fixture.snapshot).unwrap();
    let reopened = fixture.open();
    assert!(
        !stale.exists(),
        "owned stale temporary is removed before reopening"
    );
    assert!(foreign.exists(), "noncanonical names are retained");
    assert_eq!(
        fs::read(&fixture.snapshot).unwrap(),
        prior,
        "temp is never promoted"
    );
    assert!(reopened.is_ok());
    let owner = reopened.unwrap();
    fs::write(&stale, b"in-flight").unwrap();
    fs::set_permissions(&stale, fs::Permissions::from_mode(0o600)).unwrap();
    let second = fixture.open();
    assert!(stale.exists(), "a competing owner cannot sweep");
    assert!(second.is_err());
    drop(owner);
    for index in 0..1022 {
        fs::write(root.join(format!("foreign-{index}")), []).unwrap();
    }
    let crowded = fixture.open();
    assert!(
        stale.exists(),
        "directory overflow refuses before any cleanup"
    );
    assert!(crowded.is_err(), "the complete directory scan is bounded");
    for index in 0..1022 {
        fs::remove_file(root.join(format!("foreign-{index}"))).unwrap();
    }
    let recovered = fixture.open();
    assert!(!stale.exists(), "bounded reopening sweeps the stale name");
    assert!(recovered.is_ok());
    let owner = recovered.unwrap();
    let bytes = serde_json::to_vec(&fixture.valid()).unwrap();
    owner.disk.persist(&bytes, &mut false).unwrap();
    assert_eq!(fs::read(&fixture.snapshot).unwrap(), bytes);
}

#[test]
fn snapshot_clocks_and_counters_never_wrap() {
    let fixture = Fixture::new();
    let mut valid = fixture.valid();
    valid["entries"][0]["received_at"] = json!(1_790_000_001_i64);
    fixture.write(&valid);
    let future = fixture.open();
    assert!(
        future.is_err(),
        "loaded future receipts must refuse startup"
    );
    valid["entries"][0]["received_at"] = json!(i64::MAX);
    fixture.write(&valid);
    assert!(
        fixture.open().is_err(),
        "unrepresentable expiry cannot wrap"
    );
    valid = fixture.valid();
    valid["entries"][0]["version"] = json!(u64::MAX);
    fixture.write(&valid);
    let register = fixture.open().unwrap();
    let before = fs::read(&fixture.snapshot).unwrap();
    let entry: Entry = serde_json::from_value(valid["entries"][0].clone()).unwrap();
    assert_eq!(
        next_version(Some(&entry))
            .err()
            .map(|error| error.to_string()),
        Some("The ingest register is full".into()),
        "version overflow is a healthy refusal"
    );
    assert_eq!(fs::read(&fixture.snapshot).unwrap(), before);
    let now = register.now().unwrap();
    fixture
        .clock
        .set_utc(chrono::DateTime::from_timestamp(now - 100, 0).unwrap())
        .unwrap();
    assert_eq!(
        register.now().unwrap(),
        now,
        "clock rollback never renews or reverses receipts"
    );
    fixture
        .clock
        .set_utc(chrono::DateTime::from_timestamp(now + 1, 0).unwrap())
        .unwrap();
    assert_eq!(register.now().unwrap(), now + 1);
    let mut adjacent = entry.clone();
    adjacent.version = u64::MAX - 1;
    assert_eq!(next_version(Some(&adjacent)).unwrap(), u64::MAX);
    assert_eq!(deadline(&entry), Some(entry.received_at + 5_184_000));
}
