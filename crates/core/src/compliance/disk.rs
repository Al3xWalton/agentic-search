//! Shares Unix owner, mode, link and nonblocking-lock checks with the original suppression store.
//! Kind adapters invoke these checks at every file entry; hooks observe finite stages only.
//! Same-privilege concurrent filesystem attackers and distributed filesystems are outside this model.

#![deny(missing_docs)]

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::{Component, Path, PathBuf},
};

/// Actual durable-work boundaries; no stage carries personal content, paths or identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceStage {
    /// Metadata checks passed, immediately before the actual operating-system open.
    BeforeOpen,
    /// Bounded bytes are about to be decoded.
    BeforeDecode,
    /// A fully reserved personal file is about to be written.
    BeforePayloadWrite,
    /// Personal bytes have been synced and verified.
    AfterPayloadSync,
    /// Appended journal bytes have been synced.
    AfterJournalSync,
    /// A synced checkpoint replaced the prior checkpoint.
    AfterHeadRename,
    /// The checkpoint's directory has been synced.
    AfterHeadSync,
    /// A rule-changing intent and checkpoint are durable.
    AfterIntentSync,
    /// Serving rules have been persisted and published.
    AfterRulesSync,
    /// The completion row is about to be appended.
    BeforeCompletionRow,
    /// A committed purge is about to delete a verified personal revision.
    BeforePurgeDelete,
    /// A verified personal revision has been deleted.
    AfterPurgeDelete,
    /// Reserved record-stage boundary, unused by Part C.
    AfterRecordStageSync,
    /// Reserved record durability boundary, unused by Part C.
    AfterRecordSync,
}

/// Bounded synchronous instrumentation inside actual blocking storage work.
pub trait ComplianceHooks: Send + Sync + 'static {
    /// Observes or fails a real stage. A blocking fixture must eventually release its wait.
    fn at(&self, stage: ComplianceStage) -> io::Result<()>;
}

/// Production hook implementation with no side effects or personal-data access.
pub struct NoHooks;
impl ComplianceHooks for NoHooks {
    fn at(&self, _: ComplianceStage) -> io::Result<()> {
        Ok(())
    }
}

/// Sticky request progress, reset only after acquiring the serialized case owner.
#[derive(Default)]
pub(crate) struct WriteProgress {
    started: bool,
}
impl WriteProgress {
    pub(crate) fn reset(&mut self) {
        self.started = false;
    }
    pub(crate) fn mark_started(&mut self) {
        self.started = true;
    }
    pub(crate) fn started(&self) -> bool {
        self.started
    }
}

/// Explicit file-open intent; immutable writes never clobber an existing inode.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenMode {
    /// Reads an existing safe file without creating directories.
    Read,
    /// Creates a new private file, refusing every preexisting leaf.
    CreateNew,
    /// Appends without truncation to an existing safe journal.
    Append,
    /// Opens or creates a lifetime lock and acquires it nonblockingly.
    OwnerLock,
}

fn owner() -> u32 {
    // # Safety
    // geteuid takes no pointers and reads the effective identity of this process.
    unsafe { libc::geteuid() }
}

/// Resolves normal components, creates missing private directories and checks the immediate parent.
pub(crate) fn private_parent(path: &Path) -> io::Result<PathBuf> {
    private_parent_impl(path, &mut WriteProgress::default())
}

fn private_parent_impl(path: &Path, progress: &mut WriteProgress) -> io::Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("store has no parent"))?;
    let mut walked = PathBuf::new();
    for component in parent.components() {
        if !matches!(component, Component::RootDir | Component::Normal(_)) {
            return Err(io::Error::other("store path must use normal components"));
        }
        walked.push(component);
        match fs::symlink_metadata(&walked) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(io::Error::other("unsafe store parent")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new().mode(0o700).create(&walked)?;
                progress.mark_started();
            }
            Err(error) => return Err(error),
        }
    }
    let metadata = fs::metadata(parent)?;
    validate_parent_facts(metadata.uid(), metadata.mode(), owner())?;
    Ok(path)
}

/// Checks captured directory facts so an unprivileged fixture can exercise foreign ownership.
/// Production supplies actual stat values and effective uid; this pure check never opens a path.
pub fn validate_parent_facts(uid: u32, mode: u32, effective_uid: u32) -> io::Result<()> {
    if uid != effective_uid || mode & 0o077 != 0 {
        return Err(io::Error::other(
            "store directory must be private and owned",
        ));
    }
    Ok(())
}

/// Requires a private, singly linked regular inode owned by the current effective user.
pub(crate) fn check_file(metadata: &fs::Metadata) -> io::Result<()> {
    validate_file_facts(
        metadata.is_file(),
        metadata.nlink(),
        metadata.uid(),
        metadata.mode(),
        owner(),
    )
}

/// Checks the unchanged shared file predicates against captured stat facts without privileged chown.
/// Production supplies unmodified metadata and effective uid before and after every open.
pub fn validate_file_facts(
    is_file: bool,
    links: u64,
    uid: u32,
    mode: u32,
    effective_uid: u32,
) -> io::Result<()> {
    if !is_file || links != 1 || uid != effective_uid || mode & 0o077 != 0 {
        return Err(io::Error::other(
            "store file must be regular, private, singly linked and owned",
        ));
    }
    Ok(())
}

/// Preserves the original suppression store's read/create semantics and pre/post-open checks.
pub(crate) fn checked_open(path: &Path, create: bool) -> io::Result<File> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => check_file(&metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound && create => {}
        Err(error) => return Err(error),
    }
    let file = OpenOptions::new()
        .read(true)
        .write(create)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    check_file(&file.metadata()?)?;
    Ok(file)
}

/// Acquires the original nonblocking exclusive flock; the caller retains the File for its lifetime.
pub(crate) fn lock_exclusive(lock: &File) -> io::Result<()> {
    // # Safety
    // The borrowed descriptor belongs to a live File and is retained for the store lifetime.
    let status = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Validates absolute normal path components without creating anything or following symlinks.
pub(crate) fn normalized(path: &Path) -> io::Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(io::Error::other("empty private path"));
    }
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut walked = PathBuf::new();
    for component in absolute.components() {
        if !matches!(component, Component::RootDir | Component::Normal(_)) {
            return Err(io::Error::other("private path must use normal components"));
        }
        walked.push(component);
        match fs::symlink_metadata(&walked) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(io::Error::other("linked private path"))
            }
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }
    Ok(absolute)
}

/// Applies shared path/inode checks at a kind's real open boundary, before decoding or mutation.
pub(crate) fn open_for(
    path: &Path,
    mode: OpenMode,
    hooks: &dyn ComplianceHooks,
) -> io::Result<File> {
    open_impl(path, mode, hooks, &mut WriteProgress::default())
}

/// Applies the same hardening while recording the first successful mutating filesystem operation.
pub(crate) fn open_for_tracked(
    path: &Path,
    mode: OpenMode,
    hooks: &dyn ComplianceHooks,
    progress: &mut WriteProgress,
) -> io::Result<File> {
    open_impl(path, mode, hooks, progress)
}

fn open_impl(
    path: &Path,
    mode: OpenMode,
    hooks: &dyn ComplianceHooks,
    progress: &mut WriteProgress,
) -> io::Result<File> {
    let path = normalized(path)?;
    if matches!(mode, OpenMode::Read | OpenMode::Append) {
        fs::symlink_metadata(
            path.parent()
                .ok_or_else(|| io::Error::other("missing parent"))?,
        )?;
    }
    let path = private_parent_impl(&path, progress)?;
    match fs::symlink_metadata(&path) {
        Ok(meta) => check_file(&meta)?,
        Err(err)
            if err.kind() == io::ErrorKind::NotFound
                && matches!(mode, OpenMode::CreateNew | OpenMode::OwnerLock) => {}
        Err(err) => return Err(err),
    }
    hooks.at(ComplianceStage::BeforeOpen)?;
    let file = OpenOptions::new()
        .read(true)
        .write(matches!(mode, OpenMode::CreateNew | OpenMode::OwnerLock))
        .create_new(mode == OpenMode::CreateNew)
        .create(mode == OpenMode::OwnerLock)
        .append(mode == OpenMode::Append)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    if mode == OpenMode::CreateNew {
        progress.mark_started();
    }
    check_file(&file.metadata()?)?;
    if mode == OpenMode::OwnerLock {
        lock_exclusive(&file)?;
    }
    Ok(file)
}

/// Reads within a validated cap, checking both metadata and the growing stream before decode.
pub(crate) fn read_bounded(file: File, maximum: u64) -> io::Result<Vec<u8>> {
    let observed_length = file.metadata()?.len();
    read_capped(file, observed_length, maximum)
}

/// Collects at most a validated byte cap from an already authorised reader.
/// Metadata is checked before any read; growth after that observation is checked independently.
/// The caller retains responsibility for path hardening and supplies the actual metadata length.
pub fn read_capped(reader: impl Read, observed_length: u64, maximum: u64) -> io::Result<Vec<u8>> {
    let check = |length| {
        super::bounds::validate_range(length, 0, maximum)
            .map_err(|_| io::Error::other("private file exceeds its byte limit"))
    };
    check(observed_length)?;
    let mut bytes = Vec::new();
    reader
        .take(
            maximum
                .checked_add(1)
                .ok_or_else(|| io::Error::other("invalid cap"))?,
        )
        .read_to_end(&mut bytes)?;
    check(bytes.len() as u64)?;
    Ok(bytes)
}

/// Syncs an already validated private directory after a create, rename or deletion.
pub(crate) fn sync_parent(path: &Path) -> io::Result<()> {
    let path = private_parent(path)?;
    File::open(path.parent().expect("validated parent"))?.sync_all()
}
