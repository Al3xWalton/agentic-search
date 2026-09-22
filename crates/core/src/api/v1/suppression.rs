//! Defines canonical URL identities and the final serving gate.
//! Identifiers are public URL hashes, independent of content, ranking, process and shard ordinals.

use super::{error::V1Error, search::ServingContext};
use crate::compliance::disk::{checked_open, lock_exclusive, private_parent};
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, RwLock},
    task::JoinSet,
};

/// Public SHA-256 identifier of the v1 canonical URL; never an authorization credential.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct DocumentId(String);

impl utoipa::PartialSchema for DocumentId {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::schema::ObjectBuilder::new()
            .schema_type(utoipa::openapi::schema::Type::String)
            .min_length(Some(64))
            .max_length(Some(64))
            .pattern(Some("^[0-9a-f]{64}$"))
            .into()
    }
}
impl utoipa::ToSchema for DocumentId {
    fn name() -> std::borrow::Cow<'static, str> {
        "V1DocumentId".into()
    }
}

impl DocumentId {
    /// Validates borrowed raw bytes before allocating an identifier, including raw URI segments.
    /// Rejects anything except exactly 64 lowercase ASCII hexadecimal characters.
    pub fn parse(raw: &str) -> Result<Self, V1Error> {
        if raw.len() != 64
            || !raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(V1Error::invalid_document_id());
        }
        Ok(Self(raw.to_owned()))
    }

    /// Returns the immutable lowercase hexadecimal representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for DocumentId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// Canonicalizes an HTTP(S) URL with locked url 2.5.4 semantics and computes its public ID.
/// Preserves query order, trailing slashes, trailing host dots and parser-serialized escapes.
/// Rejects credentials, whitespace, controls, backslashes, relative URLs and missing hosts.
pub fn canonical_identity(raw: &str) -> Result<(String, DocumentId), V1Error> {
    if raw.is_empty()
        || raw
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace() || b == b'\\')
    {
        return Err(V1Error::invalid_result());
    }
    let mut parsed = url::Url::parse(raw).map_err(|_| V1Error::invalid_result())?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(V1Error::invalid_result());
    }
    parsed.set_fragment(None);
    let canonical = parsed.to_string();
    let digest = ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes());
    let id = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    Ok((canonical, DocumentId(id)))
}

/// Serializes final response assembly against changes to the local suppression set.
pub struct SuppressionStore {
    /// Final assembly/write gate; never held while retrieving backend results.
    pub(super) state: Arc<RwLock<ServingState>>,
    /// Read-only startup path metadata for the sibling-resource builder.
    pub(super) disk: Arc<Disk>,
    tasks: Mutex<JoinSet<()>>,
}

/// Live state published only after durable replacement, or marked unavailable on uncertainty.
pub(super) struct ServingState {
    /// Strict, sorted public URL identifiers.
    pub(super) ids: BTreeSet<DocumentId>,
    /// Prevents serving when a post-rename failure makes agreement uncertain.
    pub(super) unavailable: bool,
    generation: u64,
}

impl SuppressionStore {
    /// Opens one local Unix snapshot owner, creating an empty durable snapshot if absent.
    /// Call from startup blocking work. Invalid paths, files, locks or snapshots fail startup.
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::open_with_hooks(path, Arc::new(NoHooks))
    }

    /// Opens the production store with bounded instrumentation at its actual filesystem stages.
    /// Hook failures are handled exactly like I/O errors; no hook receives request URLs or text.
    pub fn open_with_hooks(path: &Path, hooks: Arc<dyn StoreHooks>) -> io::Result<Self> {
        let disk = Disk::open(path, hooks)?;
        let ids = match read_snapshot(&disk) {
            Ok(Some(ids)) => ids,
            Ok(None) => {
                let ids = BTreeSet::new();
                let mut renamed = false;
                disk.persist(&ids, &mut renamed)?;
                ids
            }
            Err(error) => return Err(error),
        };
        Ok(Self {
            state: Arc::new(RwLock::new(ServingState {
                ids,
                unavailable: false,
                generation: 0,
            })),
            disk: Arc::new(disk),
            tasks: Mutex::new(JoinSet::new()),
        })
    }

    /// Returns the number of newly published suppressions for lifecycle instrumentation.
    pub async fn generation(&self) -> u64 {
        self.state.read().await.generation
    }

    /// Reports whether an uncertain commit has disabled serving until restart.
    pub(super) async fn unavailable(&self) -> bool {
        self.state.read().await.unavailable
    }

    /// Joins every started transaction during shutdown; completed tasks are pruned on admission.
    pub async fn shutdown(&self) {
        let mut tasks = self.tasks.lock().await;
        while tasks.join_next().await.is_some() {}
    }

    /// Runs one serialized, cancellation-safe transaction while retaining its admission lease.
    /// Waiting for the write gate is cancellable. Once started, the tracked task always completes
    /// persistence/publication or makes the store unavailable before releasing its permit.
    pub(super) async fn suppress(
        &self,
        id: DocumentId,
        lease: Arc<OwnedSemaphorePermit>,
    ) -> Result<(), V1Error> {
        let mut tasks = self.tasks.lock().await;
        while tasks.try_join_next().is_some() {}
        let mut state = self.state.clone().write_owned().await;
        if state.unavailable {
            return Err(unavailable());
        }
        if state.ids.contains(&id) {
            return Ok(());
        }
        let disk = self.disk.clone();
        let live = self.state.clone();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tasks.spawn(async move {
            let outcome = tokio::task::spawn_blocking(move || {
                let _lease = lease;
                let mut renamed = false;
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut candidate = state.ids.clone();
                    candidate.insert(id);
                    disk.persist(&candidate, &mut renamed)?;
                    state.ids = candidate;
                    state.generation += 1;
                    Ok::<_, io::Error>(())
                }));
                match outcome {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(_)) => {
                        if renamed {
                            state.unavailable = true;
                        }
                        Err(unavailable())
                    }
                    Err(_) => {
                        state.unavailable = true;
                        Err(unavailable())
                    }
                }
            })
            .await;
            let result = match outcome {
                Ok(result) => result,
                Err(_) => {
                    live.write().await.unavailable = true;
                    Err(unavailable())
                }
            };
            let _ = sender.send(result);
        });
        drop(tasks);
        receiver.await.unwrap_or_else(|_| Err(unavailable()))
    }
}

impl ServingState {
    /// Applies global suppression independently of the caller's conservative serving context.
    pub(super) fn allows_document(&self, id: &DocumentId, _context: &ServingContext) -> bool {
        !self.ids.contains(id)
    }
}

/// Maximum complete on-disk snapshot, including its terminating newline, in bytes.
pub const MAX_STORE_BYTES: usize = 16_777_216;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Actual persistence/decode stages available to deterministic fault instrumentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreStage {
    /// Bounded bytes have been read and are about to be decoded.
    Decode,
    /// A new transaction has passed its serialized-size check.
    Open,
    /// The owned temporary file is about to receive the snapshot bytes.
    Write,
    /// The temporary file is about to be synced.
    SyncFile,
    /// The synced temporary file is about to replace the snapshot.
    Rename,
    /// Rename completed; a failure here requires fail-closed serving until restart.
    SyncDirectory,
}

/// Synchronous bounded hooks, called only inside blocking startup or persistence work.
pub trait StoreHooks: Send + Sync + 'static {
    /// Observes or fails a real production stage; a blocking hook must eventually return.
    fn at(&self, stage: StoreStage) -> io::Result<()>;
}
struct NoHooks;
impl StoreHooks for NoHooks {
    fn at(&self, _: StoreStage) -> io::Result<()> {
        Ok(())
    }
}

/// Persistence owner; only its already-validated path is visible to the parent resource builder.
pub(super) struct Disk {
    /// Actual opened path, which can differ from configuration in an injected-store caller.
    pub(super) path: PathBuf,
    directory: File,
    hooks: Arc<dyn StoreHooks>,
    _lock: crate::compliance::disk::OwnerLock,
}

fn unavailable() -> V1Error {
    V1Error::failure(super::error::V1Failure::SuppressionUnavailable)
}

impl Disk {
    fn open(path: &Path, hooks: Arc<dyn StoreHooks>) -> io::Result<Self> {
        let path = private_parent(path)?;
        let mut lock_path = path.as_os_str().to_owned();
        lock_path.push(".lock");
        let lock = checked_open(Path::new(&lock_path), true)?;
        let lock = lock_exclusive(lock)?;
        let directory = File::open(path.parent().expect("validated parent"))?;
        Ok(Self {
            path,
            directory,
            _lock: lock,
            hooks,
        })
    }

    fn persist(&self, ids: &BTreeSet<DocumentId>, renamed: &mut bool) -> io::Result<()> {
        #[derive(Serialize)]
        struct Snapshot<'a> {
            format_version: u8,
            ids: &'a BTreeSet<DocumentId>,
        }
        let mut bytes = serde_json::to_vec(&Snapshot {
            format_version: 1,
            ids,
        })
        .map_err(io::Error::other)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_STORE_BYTES {
            return Err(io::Error::other("suppression store is full"));
        }
        self.hooks.at(StoreStage::Open)?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut temp = self.path.as_os_str().to_owned();
        temp.push(format!(".{}.{}.tmp", std::process::id(), sequence));
        let temp = PathBuf::from(temp);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)?;
        let temporary = OwnedTemporary(temp);
        self.replace(&mut file, &temporary.0, &bytes, renamed)
    }

    fn replace(
        &self,
        file: &mut File,
        temp: &Path,
        bytes: &[u8],
        renamed: &mut bool,
    ) -> io::Result<()> {
        self.hooks.at(StoreStage::Write)?;
        file.write_all(bytes)?;
        self.hooks.at(StoreStage::SyncFile)?;
        file.sync_all()?;
        self.hooks.at(StoreStage::Rename)?;
        fs::rename(temp, &self.path)?;
        *renamed = true;
        self.hooks.at(StoreStage::SyncDirectory)?;
        self.directory.sync_all()?;
        Ok(())
    }
}

struct OwnedTemporary(PathBuf);
impl Drop for OwnedTemporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn read_snapshot(disk: &Disk) -> io::Result<Option<BTreeSet<DocumentId>>> {
    let file = match checked_open(&disk.path, false) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if file.metadata()?.len() > MAX_STORE_BYTES as u64 {
        return Err(io::Error::other(
            "suppression snapshot exceeds its byte limit",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_STORE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_STORE_BYTES {
        return Err(io::Error::other(
            "suppression snapshot exceeds its byte limit",
        ));
    }
    disk.hooks.at(StoreStage::Decode)?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Snapshot {
        format_version: u64,
        ids: Vec<DocumentId>,
    }
    let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if snapshot.format_version != 1 || !snapshot.ids.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(io::Error::other(
            "invalid suppression snapshot version or ordering",
        ));
    }
    Ok(Some(snapshot.ids.into_iter().collect()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_url_hash_vectors_are_fixed() {
        let fixed = "0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7";
        for raw in [
            "HTTPS://EXAMPLE.COM:443",
            "https://example.com/",
            "https://example.com/#part",
            "https://example.com/#",
        ] {
            let (url, id) = canonical_identity(raw).unwrap();
            assert_eq!(url, "https://example.com/");
            assert_eq!(id.as_str(), fixed);
        }
        let (url, id) = canonical_identity("https://example.com/a?b=2&a=1#fragment").unwrap();
        assert_eq!(url, "https://example.com/a?b=2&a=1");
        assert_eq!(
            id.as_str(),
            "9e1b7931d74ecb77efdde8e79ca52c2b63da671a086a011e1c949e9da31640be"
        );
        for (raw, canonical) in [
            ("http://EXAMPLE.COM:80", "http://example.com/"),
            ("https://example.com:444/", "https://example.com:444/"),
            ("https://example.com/a/../b", "https://example.com/b"),
            ("https://example.com/a?", "https://example.com/a?"),
            ("https://example.com./a", "https://example.com./a"),
            (
                "https://example.com/A//%2f?x=1&x=2&y=",
                "https://example.com/A//%2f?x=1&x=2&y=",
            ),
            ("https://[2001:0db8:0:0:0:0:0:1]/", "https://[2001:db8::1]/"),
            ("https://bücher.example/", "https://xn--bcher-kva.example/"),
        ] {
            assert_eq!(canonical_identity(raw).unwrap().0, canonical);
        }
        for (left, right) in [
            ("http://example.com/", "https://example.com/"),
            ("https://example.com:444/", "https://example.com/"),
            ("https://example.com/a", "https://example.com/a/"),
            (
                "https://example.com/a?b=2&a=1",
                "https://example.com/a?a=1&b=2",
            ),
            ("https://example.com/a?", "https://example.com/a"),
            ("https://example.com./a", "https://example.com/a"),
        ] {
            assert_ne!(
                canonical_identity(left).unwrap().1,
                canonical_identity(right).unwrap().1
            );
        }
        for raw in [
            "",
            " ",
            "relative",
            "file:///x",
            "https://user@example.com/",
            "https://example.com/a\\b",
            "https://example.com/\n",
            "https://example.com/a b",
            "https://",
        ] {
            assert!(canonical_identity(raw).is_err(), "accepted {raw:?}");
        }
    }
}
