// SPDX-License-Identifier: AGPL-3.0-only
//! Inspect bounded local feature assets and compare independently measured feature panels.
//! Store readers operate only on private independent snapshots, with source identities
//! checked before and after use. Counts retain duplicates; coverage uses unique host ids.
//! Same-binary control identity includes deterministic keyword extraction; retained indexes
//! supply acceptance anchors, not the equality operand for centrality comparisons.
//! Input directories must be below a trusted temporary root, as
//! input::trusted_temporary_root defines it; the shared root itself is never an input.
//! Bloom preflight bounds both file bytes and decoding: a claimed length is an allocation
//! request, so a small file alone does not establish a safe decoded size.
//! Empty, over-long and non-HTTP graph endpoint names are classified without dropping
//! their Node::into_host identities. Stored-record and set bounds keep the walk finite;
//! graph node names are normalization outputs, so a URL-name bound is not an admission rule.
//! This module does not train, ingest, score relevance, serve data, or change ranking.

use super::{
    input,
    output::{self, Output},
    Argument, ArgumentReason, EvalError, Planner,
};
use crate::webgraph::{Node, NodeID};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, DirBuilder},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};
use tantivy::schema::Value as TantivyValue;

/// Maximum bloom decoder byte budget: the production metadata ceiling of 64 MiB.
const BLOOM_DECODE_LIMIT: usize = 64 * 1024 * 1024;

/// Local diagnostics inputs; indexes are exactly two distinct copies in shard order.
#[derive(Debug, Clone, Args)]
pub struct Arguments {
    /// Graph root containing `edges`, below a trusted temporary root as defined by input.
    #[arg(long)]
    pub graph: PathBuf,
    /// Both harmonic host stores' parent, below a trusted temporary root as defined by input.
    #[arg(long)]
    pub centrality: PathBuf,
    /// Two independent index roots, shard zero followed by shard one.
    #[arg(long, required = true)]
    pub index: Vec<PathBuf>,
    /// Optional checker root with canonical language directories; missing supplied paths fail.
    #[arg(long)]
    pub spell_model: Option<PathBuf>,
    /// Absolute create-new JSON outside the repository and every input root.
    #[arg(long)]
    pub out: PathBuf,
}

/// Finite diagnostic ceilings; callers may reduce but never enlarge production bounds.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Limits {
    /// Maximum directory depth, with each supplied root at zero (16).
    pub depth: usize,
    /// Total files and directories below all roots (1,000,000).
    pub entries: usize,
    /// Individual metadata and serialized report ceiling, in bytes (64 MiB).
    pub metadata_bytes: u64,
    /// Gate management and shard response frame ceiling, in bytes (64 KiB).
    /// Checked on the native length header before allocating the response buffer.
    pub native_response_bytes: usize,
    /// Individual binary file ceiling, in bytes (4 GiB).
    pub file_bytes: u64,
    /// Aggregate copied file ceiling, in bytes (16 GiB).
    pub total_bytes: u64,
    /// Aggregate live index document and unique indexed host ceiling (1,000,000).
    pub documents: usize,
    /// Stored graph edge record ceiling (10,000,000).
    pub edges: usize,
    /// Unique page or host graph node ceiling (20,000,000).
    pub nodes: usize,
    /// Maximum segments per graph, index, store or term dictionary (256).
    pub segments: usize,
    /// Maximum discovered language directories (256).
    pub languages: usize,
    /// Individual stored document and extracted text ceiling, in bytes (8 MiB).
    pub record_bytes: usize,
    /// Individual URL ceiling, in UTF-8 bytes (8192).
    pub url_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            depth: 16,
            entries: 1_000_000,
            metadata_bytes: 64 * 1024 * 1024,
            native_response_bytes: 64 * 1024,
            file_bytes: 4 * 1024 * 1024 * 1024,
            total_bytes: 16 * 1024 * 1024 * 1024,
            documents: 1_000_000,
            edges: 10_000_000,
            nodes: 20_000_000,
            segments: 256,
            languages: 256,
            record_bytes: 8 * 1024 * 1024,
            url_bytes: 8192,
        }
    }
}

impl Limits {
    fn validate(&self) -> Result<(), EvalError> {
        let maximum = Self::default();
        if self.depth > maximum.depth
            || self.entries > maximum.entries
            || self.metadata_bytes > maximum.metadata_bytes
            || self.native_response_bytes > maximum.native_response_bytes
            || self.file_bytes > maximum.file_bytes
            || self.total_bytes > maximum.total_bytes
            || self.documents > maximum.documents
            || self.edges > maximum.edges
            || self.nodes > maximum.nodes
            || self.segments > maximum.segments
            || self.languages > maximum.languages
            || self.record_bytes > maximum.record_bytes
            || self.url_bytes > maximum.url_bytes
        {
            return Err(EvalError::InputLimit);
        }
        Ok(())
    }
}

/// Sorted relative file identity; no absolute path contributes to its content hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileIdentity {
    /// Relative path with no dot, parent or link components.
    pub path: String,
    /// Exact streamed regular-file size in bytes.
    pub bytes: u64,
    /// SHA-256 of exact file bytes.
    pub sha256: String,
}

/// Complete tree identity, including empty directory membership for change detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeIdentity {
    /// Files in sorted relative-path order.
    pub files: Vec<FileIdentity>,
    /// Directories in sorted relative-path order, excluding the supplied root.
    pub directories: Vec<String>,
    /// SHA-256 over length-prefixed file paths, sizes and decoded file SHA bytes.
    pub sha256: String,
}

fn digest_parts(parts: impl IntoIterator<Item = Vec<u8>>) -> String {
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    for part in parts {
        digest.update(&(part.len() as u64).to_le_bytes());
        digest.update(&part);
    }
    digest
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn decoded_sha(text: &str) -> Result<Vec<u8>, EvalError> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(EvalError::IdentityMismatch);
    }
    (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| EvalError::IdentityMismatch))
        .collect()
}

fn directory(path: &Path, argument: Argument) -> Result<PathBuf, EvalError> {
    directory_inner(path, argument).map_err(|error| error.argument(argument))
}

// Input admission and live gate binding share this rule so Linux /dev/shm and
// other trusted roots cannot diverge from the process temporary directory.
fn has_trusted_temporary_ancestor(path: &Path) -> Result<bool, EvalError> {
    let mut ancestor = PathBuf::new();
    for component in path.components() {
        ancestor.push(component);
        if ancestor.components().eq(path.components()) {
            break;
        }
        let metadata = fs::symlink_metadata(&ancestor).map_err(|_| EvalError::Io)?;
        if input::trusted_temporary_root(&ancestor, metadata.uid(), metadata.mode()) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn directory_inner(path: &Path, argument: Argument) -> Result<PathBuf, EvalError> {
    let path = input::argument_path(path, false, argument).or_else(|error| {
        // Raw dot components stay invalid, but aliases of a shared root must fail
        // as IndexTemporary before ownership is considered, including for UID 0.
        let normalized: PathBuf = path.components().collect();
        if let Ok(root) = input::argument_path(&normalized, false, argument) {
            let metadata = fs::symlink_metadata(&root).map_err(|_| EvalError::Io)?;
            if input::trusted_temporary_root(&root, metadata.uid(), metadata.mode()) {
                return Err(EvalError::Argument {
                    argument,
                    reason: ArgumentReason::IndexTemporary,
                });
            }
        }
        Err(error)
    })?;
    let metadata = fs::symlink_metadata(&path).map_err(|_| EvalError::Io)?;
    if !metadata.is_dir() {
        return Err(EvalError::InvalidInput.argument(argument));
    }
    if !has_trusted_temporary_ancestor(&path)? {
        return Err(EvalError::Argument {
            argument,
            reason: ArgumentReason::IndexTemporary,
        });
    }
    // Unlike input::argument_path, even root-owned copies are rejected: these are
    // independently owned scratch inputs, rather than merely trusted readable ancestors.
    // SAFETY: geteuid has no arguments or memory preconditions and cannot fail.
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(EvalError::Argument {
            argument,
            reason: ArgumentReason::Owner,
        });
    }
    Ok(path)
}

fn distinct(roots: &[PathBuf]) -> Result<(), EvalError> {
    for (i, a) in roots.iter().enumerate() {
        for b in &roots[..i] {
            if a.starts_with(b) || b.starts_with(a) {
                return Err(EvalError::IdentityMismatch);
            }
            let am = fs::symlink_metadata(a).map_err(|_| EvalError::Io)?;
            let bm = fs::symlink_metadata(b).map_err(|_| EvalError::Io)?;
            if (am.dev(), am.ino()) == (bm.dev(), bm.ino()) {
                return Err(EvalError::IdentityMismatch);
            }
        }
    }
    Ok(())
}

/// Validate exact index arity and every supplied root before snapshot or store opening.
/// Inputs must be below a trusted temporary root as input::trusted_temporary_root defines it.
/// Returns ordered graph, centrality, index and optional checker roots; unsafe aliases fail.
pub fn input_roots(args: &Arguments) -> Result<Vec<PathBuf>, EvalError> {
    if args.index.len() != 2 {
        return Err(EvalError::InvalidInput.argument(Argument::Index));
    }
    let mut roots = vec![
        directory(&args.graph, Argument::Graph)?,
        directory(&args.centrality, Argument::Centrality)?,
    ];
    for path in &args.index {
        roots.push(directory(path, Argument::Index)?);
    }
    if let Some(path) = &args.spell_model {
        roots.push(directory(path, Argument::SpellModel)?);
    }
    distinct(&roots).map_err(|error| error.argument(Argument::Index))?;
    Ok(roots)
}

#[derive(Default)]
struct Enumerated {
    directories: Vec<String>,
    files: Vec<(PathBuf, u64)>,
}

fn enumerate(
    root: &Path,
    path: &Path,
    limits: &Limits,
    count: &mut usize,
    total: &mut u64,
    depth: usize,
    tree: &mut Enumerated,
) -> Result<(), EvalError> {
    if depth > limits.depth {
        return Err(EvalError::InputLimit);
    }
    input::inspect_path(path, false)?;
    for entry in fs::read_dir(path).map_err(|_| EvalError::Io)? {
        let entry = entry.map_err(|_| EvalError::Io)?;
        let entries_seen = *count;
        if entries_seen >= limits.entries {
            return Err(EvalError::InputLimit);
        }
        *count = count.checked_add(1).ok_or(EvalError::InputLimit)?;
        let path = input::inspect_path(&entry.path(), false)?;
        let metadata = fs::symlink_metadata(&path).map_err(|_| EvalError::Io)?;
        if metadata.is_dir() {
            tree.directories.push(
                path.strip_prefix(root)
                    .map_err(|_| EvalError::UnsafePath)?
                    .to_str()
                    .ok_or(EvalError::UnsafePath)?
                    .to_owned(),
            );
            enumerate(root, &path, limits, count, total, depth + 1, tree)?;
        } else if metadata.is_file() {
            sole_linked(&metadata)?;
            *total = total
                .checked_add(metadata.len())
                .ok_or(EvalError::InputLimit)?;
            check_bytes(metadata.len(), *total, limits)?;
            tree.files.push((path, metadata.len()));
        } else {
            return Err(EvalError::UnsafePath);
        }
    }
    Ok(())
}

fn sole_linked(metadata: &fs::Metadata) -> Result<(), EvalError> {
    if metadata.nlink() != 1 {
        return Err(EvalError::UnsafePath);
    }
    Ok(())
}

/// Open a regular input through the shared no-follow reader, requiring a sole hard link.
/// The opened descriptor is checked, so copying cannot accept a newly linked source file.
/// Returns UnsafePath for linked files; callers attach the source root's argument.
pub fn open_input(path: &Path) -> Result<fs::File, EvalError> {
    let file = input::open(path)?;
    sole_linked(&file.metadata().map_err(|_| EvalError::Io)?)?;
    Ok(file)
}

fn check_bytes(copied: u64, total_bytes: u64, limits: &Limits) -> Result<(), EvalError> {
    if copied > limits.file_bytes || total_bytes > limits.total_bytes {
        return Err(EvalError::InputLimit);
    }
    Ok(())
}

/// Copy a bounded stream in 64 KiB chunks, checking actual length and checked sums.
/// Returns InputLimit on either byte ceiling/overflow and InputChanged on size drift.
pub fn copy_stream(
    reader: &mut impl Read,
    writer: &mut impl Write,
    expected: u64,
    aggregate: &mut u64,
    limits: &Limits,
) -> Result<(), EvalError> {
    limits.validate()?;
    check_bytes(
        expected,
        aggregate
            .checked_add(expected)
            .ok_or(EvalError::InputLimit)?,
        limits,
    )?;
    let mut copied = 0u64;
    let mut buffer = [0; 64 * 1024];
    loop {
        let n = reader.read(&mut buffer).map_err(|_| EvalError::Io)?;
        if n == 0 {
            break;
        }
        copied = copied.checked_add(n as u64).ok_or(EvalError::InputLimit)?;
        let total_bytes = aggregate
            .checked_add(n as u64)
            .ok_or(EvalError::InputLimit)?;
        check_bytes(copied, total_bytes, limits)?;
        writer.write_all(&buffer[..n]).map_err(|_| EvalError::Io)?;
        *aggregate = total_bytes;
    }
    if copied != expected {
        return Err(EvalError::InputChanged);
    }
    Ok(())
}

/// Hash complete guarded trees with one aggregate entry and binary-byte budget.
/// Each source descriptor is sole-linked; no store reader is opened.
pub fn tree_identities(roots: &[PathBuf], limits: &Limits) -> Result<Vec<TreeIdentity>, EvalError> {
    tree_identities_for(
        &roots
            .iter()
            .cloned()
            .map(|root| (root, Argument::Index))
            .collect::<Vec<_>>(),
        limits,
    )
}

fn tree_identities_for(
    roots: &[(PathBuf, Argument)],
    limits: &Limits,
) -> Result<Vec<TreeIdentity>, EvalError> {
    limits.validate()?;
    let mut count = 0;
    let mut preflight_total = 0u64;
    let mut total = 0u64;
    let mut result = Vec::new();
    if roots.len() > 5 {
        return Err(EvalError::InputLimit);
    }
    // Enumeration enforces the aggregate bound across every root before hashing starts.
    let mut all_directories = Vec::new();
    for (root, argument) in roots {
        let mut tree = Enumerated::default();
        enumerate(
            root,
            root,
            limits,
            &mut count,
            &mut preflight_total,
            0,
            &mut tree,
        )
        .map_err(|error| error.argument(*argument))?;
        tree.directories.sort();
        tree.files.sort_by(|a, b| a.0.cmp(&b.0));
        all_directories.push(tree);
    }
    for ((root, argument), tree) in roots.iter().zip(all_directories) {
        let mut files = Vec::new();
        // The shared index walker cannot inject a descriptor link check. Reuse the
        // preflight membership here so every source hash opens through open_input.
        for (path, bytes) in tree.files {
            struct DigestWriter(ring::digest::Context);
            impl Write for DigestWriter {
                fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                    self.0.update(bytes);
                    Ok(bytes.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            let mut file = open_input(&path).map_err(|error| error.argument(*argument))?;
            let mut digest = DigestWriter(ring::digest::Context::new(&ring::digest::SHA256));
            copy_stream(&mut file, &mut digest, bytes, &mut 0, limits)
                .map_err(|error| error.argument(*argument))?;
            files.push(FileIdentity {
                path: path
                    .strip_prefix(root)
                    .map_err(|_| EvalError::UnsafePath)?
                    .to_str()
                    .ok_or(EvalError::UnsafePath)?
                    .to_owned(),
                bytes,
                sha256: digest
                    .0
                    .finish()
                    .as_ref()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
            });
        }
        let mut parts = Vec::new();
        for file in &files {
            // This second sum guards size drift between enumeration and streamed hashing.
            total = total.checked_add(file.bytes).ok_or(EvalError::InputLimit)?;
            check_bytes(file.bytes, total, limits).map_err(|error| error.argument(*argument))?;
            parts.push(file.path.as_bytes().to_vec());
            parts.push(file.bytes.to_le_bytes().to_vec());
            parts.push(decoded_sha(&file.sha256)?);
        }
        result.push(TreeIdentity {
            files,
            directories: tree.directories,
            sha256: digest_parts(parts),
        });
    }
    Ok(result)
}

/// Private independent diagnostic working copies; explicit finish verifies and deletes them.
/// Dropping on an error also attempts deletion; normal callers must propagate finish errors.
pub struct Snapshots {
    root: PathBuf,
    sources: Vec<(PathBuf, Argument)>,
    paths: Vec<PathBuf>,
    manifests: Vec<TreeIdentity>,
    limits: Limits,
}

impl Snapshots {
    /// Snapshot paths in exactly the supplied source order; valid only until finish/drop.
    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }
    /// Source manifests captured before any store reader could write metadata.
    pub fn manifests(&self) -> &[TreeIdentity] {
        &self.manifests
    }
    /// Verify source bytes/membership and remove every snapshot, including on mismatch.
    /// Returns InputChanged for drift and Io for deletion failure; no completion is implied.
    pub fn finish(self) -> Result<(), EvalError> {
        let verified = (|| {
            let before_manifest = &self.manifests;
            let after = tree_identities_for(&self.sources, &self.limits)?;
            let after_manifest = &after;
            if before_manifest != after_manifest {
                return Err(EvalError::InputChanged);
            }
            Ok(())
        })();
        input::inspect_path(&self.root, false)?;
        fs::remove_dir_all(&self.root).map_err(|_| EvalError::Io)?;
        verified
    }
}

impl Drop for Snapshots {
    fn drop(&mut self) {
        if input::inspect_path(&self.root, false).is_ok() {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

/// Validate and snapshot up to five owned temporary roots without links or hardlinks.
/// Required store metadata is preflighted separately before calling existing open APIs.
pub fn snapshot_inputs(
    roots: &[(PathBuf, Argument)],
    limits: &Limits,
) -> Result<Snapshots, EvalError> {
    for (source, argument) in roots {
        directory(source, *argument)?;
    }
    distinct(
        &roots
            .iter()
            .map(|(root, _)| root.clone())
            .collect::<Vec<_>>(),
    )?;
    let manifests = tree_identities_for(roots, limits)?;
    static NONCE: AtomicU64 = AtomicU64::new(0);
    let temporary = input::inspect_path(&std::env::temp_dir(), false)?;
    let root = temporary.join(format!(
        "features-read-{}-{}",
        std::process::id(),
        NONCE.fetch_add(1, Ordering::Relaxed)
    ));
    DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .map_err(|_| EvalError::Io)?;
    let mut snapshots = Snapshots {
        root,
        sources: roots.to_vec(),
        paths: Vec::new(),
        manifests,
        limits: *limits,
    };
    let mut aggregate = 0;
    for (ordinal, ((source, argument), manifest)) in
        roots.iter().zip(&snapshots.manifests).enumerate()
    {
        let destination = snapshots.root.join(ordinal.to_string());
        DirBuilder::new()
            .mode(0o700)
            .create(&destination)
            .map_err(|_| EvalError::Io)?;
        for relative in &manifest.directories {
            DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(destination.join(relative))
                .map_err(|_| EvalError::Io)?;
        }
        for file in &manifest.files {
            let source_path = source.join(&file.path);
            let mut input = open_input(&source_path).map_err(|error| error.argument(*argument))?;
            let mut output = output::create(&destination.join(&file.path))?;
            copy_stream(&mut input, &mut output, file.bytes, &mut aggregate, limits)
                .map_err(|error| error.argument(*argument))?;
            output
                .sync_all()
                .map_err(|_| EvalError::Io.argument(Argument::Out))?;
            if input.metadata().map_err(|_| EvalError::Io)?.len() != file.bytes {
                return Err(EvalError::InputChanged);
            }
        }
        snapshots.paths.push(destination);
    }
    if tree_identities(&snapshots.paths, limits)? != snapshots.manifests {
        return Err(EvalError::InputChanged);
    }
    Ok(snapshots)
}

/// Read bounded JSON metadata through the shared no-follow reader, before store opening.
/// The raw metadata ceiling is checked before allocation; malformed JSON fails closed.
pub fn read_metadata(path: &Path, limits: &Limits) -> Result<Value, EvalError> {
    limits.validate()?;
    let document = read_input_bytes(path, limits.metadata_bytes)?;
    let mut remaining = limits.entries;
    let mut decoder = serde_json::Deserializer::from_slice(&document);
    let value = serde::de::DeserializeSeed::deserialize(
        JsonSeed {
            remaining: &mut remaining,
            depth: 0,
        },
        &mut decoder,
    )
    .map_err(|_| EvalError::InvalidInput)?;
    decoder.end().map_err(|_| EvalError::InvalidInput)?;
    Ok(value)
}

fn read_input_bytes(path: &Path, ceiling: u64) -> Result<Vec<u8>, EvalError> {
    let file = open_input(path)?;
    let length = file.metadata().map_err(|_| EvalError::Io)?.len();
    let limits = Limits {
        metadata_bytes: ceiling,
        ..Default::default()
    };
    if length > limits.metadata_bytes {
        return Err(EvalError::InputLimit);
    }
    let mut document = Vec::new();
    file.take(ceiling.checked_add(1).ok_or(EvalError::InputLimit)?)
        .read_to_end(&mut document)
        .map_err(|_| EvalError::Io)?;
    if document.len() as u64 != length {
        return Err(EvalError::InputChanged);
    }
    Ok(document)
}

struct JsonSeed<'a> {
    remaining: &'a mut usize,
    depth: usize,
}
impl<'de> serde::de::DeserializeSeed<'de> for JsonSeed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        if *self.remaining == 0 || self.depth > 32 {
            return Err(serde::de::Error::custom("metadata limit"));
        }
        *self.remaining -= 1;
        decoder.deserialize_any(self)
    }
}
impl<'de> serde::de::Visitor<'de> for JsonSeed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("bounded JSON metadata")
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(json!(value))
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(json!(value))
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(json!(value))
    }
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("nonfinite"))
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(json!(value))
    }
    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(JsonSeed {
            remaining: self.remaining,
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom("duplicate metadata key"));
            }
            let value = map.next_value_seed(JsonSeed {
                remaining: self.remaining,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

fn uuid(value: &Value) -> Result<String, EvalError> {
    let text = value.as_str().ok_or(EvalError::InvalidInput)?;
    let id = uuid::Uuid::parse_str(text).map_err(|_| EvalError::InvalidInput)?;
    if text != id.to_string() && text != id.simple().to_string() {
        return Err(EvalError::InvalidInput);
    }
    Ok(text.to_owned())
}

fn metadata_array<'a>(value: &'a Value, key: &str, bound: usize) -> Result<&'a [Value], EvalError> {
    let values = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or(EvalError::InvalidInput)?;
    if values.len() > bound {
        return Err(EvalError::InputLimit);
    }
    Ok(values)
}

fn preflight_index(path: &Path, limits: &Limits, max_records: usize) -> Result<(), EvalError> {
    let meta = read_metadata(&path.join("meta.json"), limits)?;
    let segments = metadata_array(&meta, "segments", limits.segments)?;
    let mut records = 0u64;
    for segment in segments {
        uuid(&segment["segment_id"])?;
        let count = segment["max_doc"].as_u64().ok_or(EvalError::InvalidInput)?;
        records = records.checked_add(count).ok_or(EvalError::InputLimit)?;
        if records > max_records as u64 {
            return Err(EvalError::InputLimit);
        }
    }
    let managed = path.join(".managed.json");
    if managed.exists() {
        let value = read_metadata(&managed, limits)?;
        let names = value.as_array().ok_or(EvalError::InvalidInput)?;
        if names.len() > limits.entries {
            return Err(EvalError::InputLimit);
        }
        for name in names {
            let name = name.as_str().ok_or(EvalError::InvalidInput)?;
            if name.is_empty()
                || name.contains('/')
                || name == "."
                || name == ".."
                || name.chars().any(char::is_control)
            {
                return Err(EvalError::UnsafePath);
            }
        }
    }
    Ok(())
}

/// Bound whole-decoded store files before any store open, including on private snapshots.
/// Bloom files must decode completely within 64 MiB; reduced limits also cap file bytes.
/// Returns Centrality-attributed structure/path/limit errors; the store is never mutated.
pub fn preflight_store(path: &Path, limits: &Limits) -> Result<(), EvalError> {
    preflight_store_inner(path, limits).map_err(|error| error.argument(Argument::Centrality))
}

fn preflight_store_inner(path: &Path, limits: &Limits) -> Result<(), EvalError> {
    // speedy-kv reads meta.json as a whole string and bincode-decodes each .blm.
    // The .ids FST, .bid random lookup and .blobs store are memory-mapped instead.
    let meta = read_metadata(&path.join("meta.json"), limits)?;
    let segments = metadata_array(&meta, "segments", limits.segments)?;
    if segments.len().checked_add(1).ok_or(EvalError::InputLimit)? > limits.entries {
        return Err(EvalError::InputLimit);
    }
    for id in segments {
        let id = uuid(id)?;
        for suffix in ["ids", "bid", "blobs", "blm"] {
            let file = open_input(&path.join(format!("{id}.{suffix}")))?;
            if suffix == "blm"
                && file.metadata().map_err(|_| EvalError::Io)?.len() > limits.metadata_bytes
            {
                return Err(EvalError::InputLimit);
            }
            if suffix == "blm" {
                let mut bytes = Vec::new();
                file.take(
                    limits
                        .metadata_bytes
                        .checked_add(1)
                        .ok_or(EvalError::InputLimit)?,
                )
                .read_to_end(&mut bytes)
                .map_err(|_| EvalError::Io)?;
                // The size check is the bound; the extra byte detects growth after it.
                if bytes.len() as u64 > limits.metadata_bytes {
                    return Err(EvalError::InputChanged);
                }
                // The store's Serialized<NodeID> parameter is PhantomData and encodes no bytes.
                let (_, consumed): (bloom::BytesBloomFilter<()>, usize) =
                    bincode::decode_from_slice(
                        &bytes,
                        common::bincode_config().with_limit::<BLOOM_DECODE_LIMIT>(),
                    )
                    .map_err(|_| EvalError::InvalidInput)?;
                if consumed != bytes.len() {
                    return Err(EvalError::InvalidInput);
                }
            }
        }
    }
    Ok(())
}

/// Validate all model entries before checker loading, with bounded language and entry counts.
/// Returns sorted language codes or a SpellModel-attributed path/structure/limit error.
pub fn preflight_model(path: &Path, limits: &Limits) -> Result<Vec<String>, EvalError> {
    preflight_model_inner(path, limits).map_err(|error| error.argument(Argument::SpellModel))
}

fn preflight_model_inner(path: &Path, limits: &Limits) -> Result<Vec<String>, EvalError> {
    let mut languages = Vec::new();
    for (ordinal, entry) in fs::read_dir(path).map_err(|_| EvalError::Io)?.enumerate() {
        if ordinal >= limits.entries {
            return Err(EvalError::InputLimit);
        }
        let entry = entry.map_err(|_| EvalError::Io)?;
        let path = input::inspect_path(&entry.path(), false)?;
        if !fs::symlink_metadata(&path)
            .map_err(|_| EvalError::Io)?
            .is_dir()
        {
            continue;
        }
        if languages.len() >= limits.languages {
            return Err(EvalError::InputLimit);
        }
        let code = path
            .file_name()
            .and_then(|p| p.to_str())
            .ok_or(EvalError::InvalidInput)?;
        let language = whatlang::Lang::from_str(code).map_err(|_| EvalError::InvalidInput)?;
        if code != language.code() {
            return Err(EvalError::InvalidInput);
        }
        let meta = read_metadata(&path.join("term_dict/meta.json"), limits)?;
        let dicts = metadata_array(&meta, "dicts", limits.segments)?;
        if dicts.is_empty() {
            return Err(EvalError::InvalidInput);
        }
        for id in dicts {
            open_input(&path.join("term_dict").join(format!("{}.dict", uuid(id)?)))?;
        }
        for file in ["ngrams.bin", "rotated_ngrams.bin"] {
            open_input(&path.join("stupid_backoff").join(file))?;
        }
        let counts_path = path.join("stupid_backoff/n_counts.bin");
        if open_input(&counts_path)?
            .metadata()
            .map_err(|_| EvalError::Io)?
            .len()
            > 1024
        {
            return Err(EvalError::InputLimit);
        }
        let counts = read_input_bytes(&counts_path, 1024)?;
        let config = bincode::config::standard().with_limit::<1024>();
        let (decoded, used): (Vec<u64>, usize) =
            bincode::decode_from_slice(&counts, config).map_err(|_| EvalError::InvalidInput)?;
        if decoded.len() != 3 || used != counts.len() {
            return Err(EvalError::InvalidInput);
        }
        let errors = read_metadata(&path.join("error_model.json"), limits)?;
        let entries = errors["errors"]
            .as_object()
            .ok_or(EvalError::InvalidInput)?;
        errors["total"].as_u64().ok_or(EvalError::InvalidInput)?;
        for (sequence, count) in entries {
            validate_error_sequence(sequence)?;
            count.as_u64().ok_or(EvalError::InvalidInput)?;
        }
        languages.push(code.to_owned());
    }
    if languages.is_empty() {
        return Err(EvalError::InvalidInput);
    }
    languages.sort();
    Ok(languages)
}

fn validate_error_sequence(sequence: &str) -> Result<(), EvalError> {
    let value: Value = serde_json::from_str(sequence).map_err(|_| EvalError::InvalidInput)?;
    let edits = value.as_array().ok_or(EvalError::InvalidInput)?;
    let character = |v: &Value| v.as_str().is_some_and(|s| s.chars().count() == 1);
    for edit in edits {
        let fields = edit.as_object().ok_or(EvalError::InvalidInput)?;
        if fields.len() != 1 {
            return Err(EvalError::InvalidInput);
        }
        for (kind, value) in fields {
            let valid = match kind.as_str() {
                "Insertion" | "Deletion" => character(value),
                "Substitution" | "Transposition" => value
                    .as_array()
                    .is_some_and(|pair| pair.len() == 2 && pair.iter().all(character)),
                _ => false,
            };
            if !valid {
                return Err(EvalError::InvalidInput);
            }
        }
    }
    Ok(())
}

fn insert_bounded<T: Ord>(set: &mut BTreeSet<T>, value: T, limit: usize) -> Result<(), EvalError> {
    if !set.contains(&value) && set.len() >= limit {
        return Err(EvalError::InputLimit);
    }
    set.insert(value);
    Ok(())
}

fn host_id(url: &str, limits: &Limits) -> Result<NodeID, EvalError> {
    if url.len() > limits.url_bytes {
        return Err(EvalError::UrlLimit);
    }
    let url = url::Url::parse(url).map_err(|_| EvalError::InvalidUrl)?;
    if url.host_str().is_none() {
        return Err(EvalError::InvalidUrl);
    }
    Ok(Node::from(url).into_host().id())
}

#[derive(Clone, Copy)]
enum StoredKind {
    Text,
    Json,
    Boolean,
    Region,
    Timestamp,
}

fn content_kind(field: crate::schema::Field) -> Option<StoredKind> {
    use crate::schema::{Field, NumericalFieldEnum as N, TextFieldEnum as T};
    match field {
        Field::Text(
            T::Title(_)
            | T::Url(_)
            | T::StemmedCleanBody(_)
            | T::AllBody(_)
            | T::Description(_)
            | T::DmozDescription(_)
            | T::Keywords(_)
            | T::RecipeFirstIngredientTagId(_),
        ) => Some(StoredKind::Text),
        Field::Text(T::SchemaOrgJson(_)) => Some(StoredKind::Json),
        Field::Numerical(N::LastUpdated(_)) => Some(StoredKind::Timestamp),
        Field::Numerical(N::Region(_)) => Some(StoredKind::Region),
        Field::Numerical(N::LikelyHasAds(_) | N::LikelyHasPaywall(_)) => Some(StoredKind::Boolean),
        _ => None,
    }
}

fn content_record(
    doc: &tantivy::TantivyDocument,
    schema: &tantivy::schema::Schema,
    limits: &Limits,
) -> Result<(String, String), EvalError> {
    let mut values: BTreeMap<u32, Value> = BTreeMap::new();
    let mut text_bytes = 0usize;
    for (id, value) in doc.field_values() {
        let field =
            crate::schema::Field::get(id.field_id() as usize).ok_or(EvalError::InvalidInput)?;
        if let Some(text) = value.as_str() {
            text_bytes = text_bytes
                .checked_add(text.len())
                .ok_or(EvalError::InputLimit)?;
            if text_bytes > limits.record_bytes {
                return Err(EvalError::InputLimit);
            }
        }
        let Some(kind) = content_kind(field) else {
            continue;
        };
        let converted = match kind {
            StoredKind::Text => json!(value.as_str().ok_or(EvalError::InvalidInput)?),
            StoredKind::Json => {
                let text = value.as_str().ok_or(EvalError::InvalidInput)?;
                let parsed: Vec<crate::webpage::schema_org::Item> =
                    serde_json::from_str(text).map_err(|_| EvalError::InvalidInput)?;
                serde_json::to_value(parsed).map_err(|_| EvalError::InvalidInput)?
            }
            StoredKind::Timestamp => {
                let timestamp = value.as_u64().ok_or(EvalError::InvalidInput)?;
                if timestamp != 0
                    && (timestamp > i64::MAX as u64
                        || chrono::DateTime::from_timestamp(timestamp as i64, 0).is_none())
                {
                    return Err(EvalError::InvalidInput);
                }
                json!(timestamp)
            }
            StoredKind::Region => {
                let region = value.as_u64().ok_or(EvalError::InvalidInput)?;
                if region >= crate::webpage::region::ALL_REGIONS.len() as u64 {
                    return Err(EvalError::InvalidInput);
                }
                json!(region)
            }
            StoredKind::Boolean => json!(value.as_bool().ok_or(EvalError::InvalidInput)?),
        };
        if values.insert(id.field_id(), converted).is_some() {
            return Err(EvalError::InvalidInput);
        }
    }
    let url_field = schema
        .get_field("url")
        .map_err(|_| EvalError::InvalidInput)?;
    let url = values
        .get(&url_field.field_id())
        .and_then(Value::as_str)
        .ok_or(EvalError::InvalidInput)?
        .to_owned();
    host_id(&url, limits).map_err(|_| EvalError::InvalidInput)?;
    for required in ["title", "stemmed_body"] {
        let field = schema
            .get_field(required)
            .map_err(|_| EvalError::InvalidInput)?;
        if !values.contains_key(&field.field_id()) {
            return Err(EvalError::InvalidInput);
        }
    }
    // Explicit field names and nulls distinguish absent stored fields from empty values.
    let fields: Vec<Value> = crate::schema::Field::all()
        .enumerate()
        .filter(|(_, field)| content_kind(*field).is_some())
        .map(|(id, field)| json!([field.name(), values.get(&(id as u32))]))
        .collect();
    let bytes = serde_json::to_vec(&fields).map_err(|_| EvalError::InvalidInput)?;
    if bytes.len() > limits.record_bytes {
        return Err(EvalError::InputLimit);
    }
    Ok((url, input::sha256(&bytes)))
}

/// Semantic document identity for one ordered shard; physical segments are excluded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexIdentity {
    /// Zero-based shard ordinal, fixed by the caller's index order.
    pub shard: u64,
    /// Live document count, including duplicate URL occurrences.
    pub documents: usize,
    /// Unique indexed host count in this shard.
    pub hosts: usize,
    /// Hash of exact URL bytes and thirteen canonical stored fields, including deterministic keywords.
    /// Sorted duplicate occurrences remain distinct; this is not a physical-file or ranking identity.
    pub content_sha256: String,
    /// Physical pre-open inspect-manifest hash attached by the control driver.
    /// A semantic snapshot alone has no producer binding and leaves this empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub manifest_sha256: String,
    /// Frozen executable hash attached by the control driver with its manifest binding.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub executable_sha256: String,
    /// Internal multiset for semantic comparisons; never serialized into diagnostics.
    #[serde(skip)]
    pub records: Vec<(String, String)>,
    #[serde(skip)]
    host_ids: BTreeSet<NodeID>,
}

fn inspect_documents(
    path: &Path,
    shard: usize,
    limits: &Limits,
    total: &mut usize,
) -> Result<IndexIdentity, EvalError> {
    let index = tantivy::Index::open_in_dir(path.join("inverted_index"))
        .map_err(|_| EvalError::InvalidInput)?;
    if index.schema() != crate::schema::create_schema() {
        return Err(EvalError::InvalidInput);
    }
    let reader = index.reader().map_err(|_| EvalError::InvalidInput)?;
    let searcher = reader.searcher();
    let mut records = Vec::new();
    let mut hosts = BTreeSet::new();
    for (ordinal, segment) in searcher.segment_readers().iter().enumerate() {
        let store = segment
            .get_store_reader(0)
            .map_err(|_| EvalError::InvalidInput)?;
        for id in segment.doc_ids() {
            if *total >= limits.documents {
                return Err(EvalError::InputLimit);
            }
            *total = total.checked_add(1).ok_or(EvalError::InputLimit)?;
            if store
                .get_document_bytes(id)
                .map_err(|_| EvalError::InvalidInput)?
                .len()
                > limits.record_bytes
            {
                return Err(EvalError::InputLimit);
            }
            let doc = searcher
                .doc::<tantivy::TantivyDocument>(tantivy::DocAddress::new(ordinal as u32, id))
                .map_err(|_| EvalError::InvalidInput)?;
            let (url, content) = content_record(&doc, &index.schema(), limits)?;
            insert_bounded(
                &mut hosts,
                host_id(&url, limits).map_err(|_| EvalError::InvalidInput)?,
                limits.documents,
            )?;
            records.push((url, content));
        }
    }
    records.sort();
    let content_sha256 = digest_parts(records.iter().flat_map(|(url, digest)| {
        [
            url.as_bytes().to_vec(),
            decoded_sha(digest).expect("generated SHA-256"),
        ]
    }));
    Ok(IndexIdentity {
        manifest_sha256: String::new(),
        executable_sha256: String::new(),
        shard: shard as u64,
        documents: records.len(),
        hosts: hosts.len(),
        content_sha256,
        records,
        host_ids: hosts,
    })
}

/// Compare-ready identities for exactly two copied indexes, using private reader snapshots.
/// No supplied index is opened; malformed schemas, records, limits or source changes fail.
/// The thirteen canonical stored fields include keywords because extraction is deterministic.
/// Same-binary, same-WARC content under fixed ingestion settings compares across centrality stores.
/// This semantic identity does not imply physical segment identity or identical rankings.
pub fn document_identities(
    paths: &[PathBuf],
    limits: &Limits,
) -> Result<Vec<IndexIdentity>, EvalError> {
    if paths.len() != 2 {
        return Err(EvalError::InvalidInput);
    }
    for path in paths {
        directory(path, Argument::Index)?;
        preflight_index(&path.join("inverted_index"), limits, limits.documents)?;
    }
    let snapshots = snapshot_inputs(
        &paths
            .iter()
            .cloned()
            .map(|path| (path, Argument::Index))
            .collect::<Vec<_>>(),
        limits,
    )?;
    let mut total = 0;
    let result = snapshots
        .paths()
        .iter()
        .enumerate()
        .map(|(shard, path)| {
            preflight_index(&path.join("inverted_index"), limits, limits.documents)?;
            inspect_documents(path, shard, limits, &mut total)
        })
        .collect();
    snapshots.finish()?;
    result
}

/// Count graph records and classify empty, over-long and non-HTTP endpoint occurrences.
/// Every name retains Node::into_host's identity; record bytes and set sizes bound memory.
/// Malformed stores or counter/set/record overflows fail, but node-name properties do not.
fn inspect_graph(path: &Path, limits: &Limits) -> Result<Value, EvalError> {
    let index =
        tantivy::Index::open_in_dir(path.join("edges")).map_err(|_| EvalError::InvalidInput)?;
    if index.schema() != crate::webgraph::schema::create_schema() {
        return Err(EvalError::InvalidInput);
    }
    let segments = index
        .searchable_segment_ids()
        .map_err(|_| EvalError::InvalidInput)?
        .len();
    if segments > limits.segments {
        return Err(EvalError::InputLimit);
    }
    let reader = index.reader().map_err(|_| EvalError::InvalidInput)?;
    let searcher = reader.searcher();
    let (mut pages, mut hosts, mut page_edges, mut host_edges) = (
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
    );
    let mut records = 0usize;
    let (mut empty_name, mut over_long_name, mut non_http_name) = (0usize, 0usize, 0usize);
    for (ordinal, segment) in searcher.segment_readers().iter().enumerate() {
        let store = segment
            .get_store_reader(0)
            .map_err(|_| EvalError::InvalidInput)?;
        for id in segment.doc_ids() {
            if records >= limits.edges {
                return Err(EvalError::InputLimit);
            }
            records = records.checked_add(1).ok_or(EvalError::InputLimit)?;
            if store
                .get_document_bytes(id)
                .map_err(|_| EvalError::InvalidInput)?
                .len()
                > limits.record_bytes
            {
                return Err(EvalError::InputLimit);
            }
            let address = tantivy::DocAddress::new(ordinal as u32, id);
            let edge = searcher
                .doc::<crate::webgraph::Edge>(address)
                .map_err(|_| EvalError::InvalidInput)?;
            let host_ids = [
                edge.from.clone().into_host().id(),
                edge.to.clone().into_host().id(),
            ];
            for (node, host_id) in [&edge.from, &edge.to].into_iter().zip(host_ids) {
                // Stored-record bounds protect this normalization output; URL admission
                // rules would discard endpoint identities the graph builder retained.
                if node.as_str().is_empty() {
                    empty_name = empty_name.checked_add(1).ok_or(EvalError::InputLimit)?;
                } else if node.as_str().len() > limits.url_bytes {
                    over_long_name = over_long_name.checked_add(1).ok_or(EvalError::InputLimit)?;
                } else if url::Url::parse(&format!("http://{}", node.as_str()))
                    .map_or(true, |url| url.host_str().is_none())
                {
                    non_http_name = non_http_name.checked_add(1).ok_or(EvalError::InputLimit)?;
                }
                insert_bounded(&mut pages, node.id(), limits.nodes)?;
                insert_bounded(&mut hosts, host_id, limits.nodes)?;
            }
            insert_bounded(
                &mut page_edges,
                (edge.from.id(), edge.to.id()),
                limits.edges,
            )?;
            insert_bounded(&mut host_edges, (host_ids[0], host_ids[1]), limits.edges)?;
        }
    }
    let occurrences = empty_name
        .checked_add(over_long_name)
        .and_then(|count| count.checked_add(non_http_name))
        .ok_or(EvalError::InputLimit)?;
    Ok(
        json!({"page_nodes":pages.len(),"host_nodes":hosts.len(),"edge_records":records,"unique_page_edges":page_edges.len(),"unique_host_edges":host_edges.len(),"segments":segments,"rejected_endpoints":{"occurrences":occurrences,"empty_name":empty_name,"over_long_name":over_long_name,"non_http_name":non_http_name},"endpoint_policy":"Node names are normalize_url outputs, not URLs; empty, over-long and non-http names are counted here and still contribute to page/host/edge counts through into_host(), exactly as the indexer derives host identity.","edge_policy":"Stored records retain duplicates and self-edges; unique directed pairs deduplicate duplicates and retain self-pairs."}),
    )
}

fn fraction(numerator: usize, denominator: usize) -> Value {
    json!({"numerator":numerator,"denominator":denominator,"fraction":(denominator != 0).then(|| numerator as f64 / denominator as f64)})
}

fn coverage(
    hosts: &BTreeSet<NodeID>,
    harmonic: &speedy_kv::Db<NodeID, f64>,
    ranks: &speedy_kv::Db<NodeID, u64>,
) -> Result<Value, EvalError> {
    let (mut present, mut positive, mut zero, mut ranked) = (0, 0, 0, 0);
    for host in hosts {
        if let Some(value) = harmonic.get(host).map_err(|_| EvalError::InvalidInput)? {
            if !value.is_finite() || value < 0.0 {
                return Err(EvalError::InvalidInput);
            }
            present += 1;
            if value.is_finite() && value > 0.0 {
                positive += 1;
            }
            if value == 0.0 {
                zero += 1;
            }
        }
        if ranks
            .get(host)
            .map_err(|_| EvalError::InvalidInput)?
            .is_some_and(|rank| rank != u64::MAX)
        {
            ranked += 1;
        }
    }
    Ok(
        json!({"nonzero":fraction(positive,hosts.len()),"rank":fraction(ranked,hosts.len()),"present":present,"explicit_zero":zero,"absent":hosts.len()-present}),
    )
}

fn inspect_centrality(
    path: &Path,
    indexes: &[IndexIdentity],
    limits: &Limits,
) -> Result<Value, EvalError> {
    let identity = tree_identities(&[path.join("harmonic"), path.join("harmonic_rank")], limits)?;
    let harmonic = speedy_kv::Db::<NodeID, f64>::open_or_create(path.join("harmonic"))
        .map_err(|_| EvalError::InvalidInput)?;
    let ranks = speedy_kv::Db::<NodeID, u64>::open_or_create(path.join("harmonic_rank"))
        .map_err(|_| EvalError::InvalidInput)?;
    for (i, (key, value)) in harmonic.iter_raw().enumerate() {
        if i >= limits.nodes {
            return Err(EvalError::InputLimit);
        }
        let (_, used): (NodeID, usize) = bincode::decode_from_slice(
            key.as_bytes(),
            bincode::config::standard().with_limit::<64>(),
        )
        .map_err(|_| EvalError::InvalidInput)?;
        if used != key.as_bytes().len() {
            return Err(EvalError::InvalidInput);
        }
        let (number, used): (f64, usize) = bincode::decode_from_slice(
            value.as_bytes(),
            bincode::config::standard().with_limit::<64>(),
        )
        .map_err(|_| EvalError::InvalidInput)?;
        if used != value.as_bytes().len() || !number.is_finite() || number < 0.0 {
            return Err(EvalError::InvalidInput);
        }
    }
    for (i, (key, value)) in ranks.iter_raw().enumerate() {
        if i >= limits.nodes {
            return Err(EvalError::InputLimit);
        }
        let (_, used): (NodeID, usize) = bincode::decode_from_slice(
            key.as_bytes(),
            bincode::config::standard().with_limit::<64>(),
        )
        .map_err(|_| EvalError::InvalidInput)?;
        if used != key.as_bytes().len() {
            return Err(EvalError::InvalidInput);
        }
        let (_, used): (u64, usize) = bincode::decode_from_slice(
            value.as_bytes(),
            bincode::config::standard().with_limit::<64>(),
        )
        .map_err(|_| EvalError::InvalidInput)?;
        if used != value.as_bytes().len() {
            return Err(EvalError::InvalidInput);
        }
    }
    let mut union = BTreeSet::new();
    let mut shards = Vec::new();
    for index in indexes {
        for host in &index.host_ids {
            insert_bounded(&mut union, *host, limits.documents)?;
        }
        shards.push(coverage(&index.host_ids, &harmonic, &ranks)?);
    }
    Ok(
        json!({"harmonic":identity[0],"harmonic_rank":identity[1],"shards":shards,"union":coverage(&union,&harmonic,&ranks)?}),
    )
}

fn inspect_optional_spell_model(
    path: Option<&Path>,
    languages: Option<&[String]>,
) -> Result<Option<Value>, EvalError> {
    match path {
        None => Ok(None),
        Some(path) => {
            let languages = languages.ok_or(EvalError::InvalidInput)?;
            let _checker = web_spell::SpellChecker::open(
                path,
                web_spell::CorrectionConfig {
                    correction_threshold: 0.0,
                    lm_prob_weight: 1.0,
                    ..Default::default()
                },
            )
            .map_err(|_| EvalError::InvalidInput)?;
            // SpellChecker::open fails if any discovered language cannot load, so
            // successful loading proves equality of these two language lists.
            Ok(Some(
                json!({"discovered_languages":languages,"loadable_languages":languages,"configured_language":"eng","eng_covered":languages.iter().any(|language| language == "eng")}),
            ))
        }
    }
}

/// Serialize a report only after a counting pass proves the ordinary 64 MiB read ceiling.
/// Returns InputLimit without a completion marker on oversize or failed serialization preflight.
pub fn finish_report(
    output: Output,
    value: &impl Serialize,
    limits: &Limits,
) -> Result<(), EvalError> {
    limits.validate()?;
    struct Counter {
        bytes: u64,
        limit: u64,
    }
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| std::io::Error::other("report limit"))?;
            // Output::finish appends one newline after the serialized value.
            if self.bytes >= self.limit {
                return Err(std::io::Error::other("report limit"));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer_pretty(
        &mut Counter {
            bytes: 0,
            limit: limits.metadata_bytes,
        },
        value,
    )
    .map_err(|_| EvalError::InputLimit)?;
    output.finish(value)
}

/// Produce feature diagnostics with the fixed production limits and no injected observer.
/// Inputs remain unopened by mutable APIs; all failures leave no completion marker.
pub fn run(args: Arguments) -> Result<(), EvalError> {
    run_with(args, Limits::default(), || {})
}

/// Run the production diagnostics with smaller ceilings and a deterministic post-copy observer.
/// The observer permits source-change witnesses; no CLI or HTTP setting can inject it.
pub fn run_with(
    args: Arguments,
    limits: Limits,
    after_snapshot: impl FnOnce(),
) -> Result<(), EvalError> {
    limits.validate()?;
    let input_roots = input_roots(&args)?;
    output::external(&args.out, &input_roots).map_err(|error| error.argument(Argument::Out))?;
    let output =
        Output::reserve(&args.out, false).map_err(|error| error.argument(Argument::Out))?;
    preflight_index(&args.graph.join("edges"), &limits, limits.edges)
        .map_err(|e| e.argument(Argument::Graph))?;
    for name in ["harmonic", "harmonic_rank"] {
        preflight_store(&args.centrality.join(name), &limits)
            .map_err(|e| e.argument(Argument::Centrality))?;
    }
    for path in &args.index {
        preflight_index(&path.join("inverted_index"), &limits, limits.documents)
            .map_err(|e| e.argument(Argument::Index))?;
    }
    let languages = args
        .spell_model
        .as_ref()
        .map(|path| preflight_model(path, &limits))
        .transpose()
        .map_err(|e| e.argument(Argument::SpellModel))?;
    let attributed_roots: Vec<_> = input_roots
        .into_iter()
        .zip([
            Argument::Graph,
            Argument::Centrality,
            Argument::Index,
            Argument::Index,
            Argument::SpellModel,
        ])
        .collect();
    let snapshots = snapshot_inputs(&attributed_roots, &limits)
        .map_err(|error| error.argument(Argument::Out))?;
    after_snapshot();
    let result = (|| {
        let paths = snapshots.paths();
        // Revalidate copied metadata so a source edit between preflight and copying
        // cannot introduce unchecked reader references into the private working tree.
        preflight_index(&paths[0].join("edges"), &limits, limits.edges)
            .map_err(|error| error.argument(Argument::Graph))?;
        for name in ["harmonic", "harmonic_rank"] {
            preflight_store(&paths[1].join(name), &limits)
                .map_err(|error| error.argument(Argument::Centrality))?;
        }
        for path in &paths[2..4] {
            preflight_index(&path.join("inverted_index"), &limits, limits.documents)
                .map_err(|error| error.argument(Argument::Index))?;
        }
        if let Some(path) = paths.get(4) {
            if Some(
                preflight_model(path, &limits)
                    .map_err(|error| error.argument(Argument::SpellModel))?,
            ) != languages
            {
                return Err(EvalError::InputChanged.argument(Argument::SpellModel));
            }
        }
        let graph = inspect_graph(&paths[0], &limits).map_err(|e| e.argument(Argument::Graph))?;
        let mut total = 0;
        let indexes: Vec<_> = paths[2..4]
            .iter()
            .enumerate()
            .map(|(shard, path)| inspect_documents(path, shard, &limits, &mut total))
            .collect::<Result<_, _>>()
            .map_err(|e| e.argument(Argument::Index))?;
        let centrality = inspect_centrality(&paths[1], &indexes, &limits)
            .map_err(|e| e.argument(Argument::Centrality))?;
        let mut model =
            inspect_optional_spell_model(paths.get(4).map(PathBuf::as_path), languages.as_deref())
                .map_err(|e| e.argument(Argument::SpellModel))?;
        if let Some(model) = model.as_mut() {
            model["identity"] = json!(snapshots.manifests()[4]);
        }
        Ok(
            json!({"schema_version":1,"inputs":snapshots.manifests(),"limits":limits,"graph":graph,"indexes":indexes,"centrality":centrality,"spell_model":model,"spell_model_status":if model.is_some() {"loaded"} else {"not_supplied"},"source_unchanged":true,"caveat":"A graph from one Common Crawl segment plus seeds is sparse and has incomplete incoming/outgoing context. Storage segments are a separate count. Only host centrality is measured. Offered spelling never rewrites retrieval. Corpus-bounded labels do not establish production precision or full-web relevance."}),
        )
    })();
    snapshots
        .finish()
        .map_err(|error| error.argument(Argument::Out))?;
    finish_report(output, &result?, &limits).map_err(|error| error.argument(Argument::Out))
}

/// Sealed, unlabelled control queries, in immutable execution order for each planner mode.
pub const FIXED_CONTROL_QUERIES: [&str; 8] = [
    "example",
    "privacy policy",
    "contact information",
    "rust programming",
    "alpha quux zorb",
    "\"privacy policy\"",
    "site:example.com example",
    "please find information about software documentation",
];

/// Remove only documented whole-request and per-stage duration fields from an API result.
/// All ordered URLs, snippets, counts, response shape and provenance remain comparable.
pub fn retrieval_identity(response: &Value) -> Result<Value, EvalError> {
    let mut result = response.clone();
    let object = result.as_object_mut().ok_or(EvalError::InvalidResponse)?;
    object.remove("searchDurationMs");
    if let Some(plan) = object.get_mut("queryPlan") {
        let stages = plan
            .get_mut("stages")
            .and_then(Value::as_array_mut)
            .ok_or(EvalError::InvalidResponse)?;
        if stages.len() > 4 {
            return Err(EvalError::InvalidResponse);
        }
        for stage in stages {
            stage
                .as_object_mut()
                .ok_or(EvalError::InvalidResponse)?
                .remove("elapsedMs");
        }
    }
    Ok(result)
}

/// Validate sixteen fixed-query observations (off then on) and preserve all nontiming content.
/// A missing/reordered query, wrong mode, failed HTTP attempt or malformed response fails,
/// or a response outside the fixed control contract checked by `control_response_shape`.
/// An explicit `error: null` is required; an absent key is not a recorded attempt.
pub fn fixed_query_identities(rows: &[Value]) -> Result<Vec<Value>, EvalError> {
    if rows.len() != 16 {
        return Err(EvalError::IdentityMismatch);
    }
    let mut values = Vec::new();
    for (ordinal, row) in rows.iter().enumerate() {
        let mode = if ordinal < 8 { "off" } else { "on" };
        if row["query"] != FIXED_CONTROL_QUERIES[ordinal % 8]
            || row["mode"] != mode
            || row["status"] != 200
            || row.get("error") != Some(&Value::Null)
        {
            return Err(EvalError::IdentityMismatch);
        }
        let expected = if ordinal < 8 {
            Planner::Off
        } else {
            Planner::On
        };
        observation_shape(&row["response"], expected)?;
        values.push(json!({"query":row["query"],"mode":mode,"status":row["status"],"response":retrieval_identity(&row["response"])?}));
    }
    Ok(values)
}

/// Validate the retrieval response and project the fixed contract used for comparison.
fn control_response_shape(response: &Value, expected: Planner) -> Result<Value, EvalError> {
    super::runner::response(response, expected)?;
    if !response.is_object()
        || response["_type"] != "websites"
        || !response["hasMoreResults"].is_boolean()
    {
        return Err(EvalError::InvalidResponse);
    }
    let _: crate::collector::approx_count::Count =
        serde_json::from_value(response["numHits"].clone())
            .map_err(|_| EvalError::InvalidResponse)?;
    let pages = response["webpages"]
        .as_array()
        .filter(|pages| pages.len() <= 10)
        .ok_or(EvalError::InvalidResponse)?;
    for page in pages {
        if ["url", "title", "planStage"]
            .iter()
            .any(|key| page[*key].as_str().is_none())
            || !page["snippet"].is_object()
        {
            return Err(EvalError::InvalidResponse);
        }
    }
    // Centrality can select different documents and stages. Validate their provenance,
    // then compare this fixed contract rather than optional result content or array size.
    Ok(json!({
        "_type":"websites", "numHits":response["numHits"]["_type"].clone(),
        "hasMoreResults":"boolean", "webpages":"array of validated webpages",
        "queryPlan":{"mode":response["queryPlan"]["mode"],"version":1,"stages":"ordered valid producers"}
    }))
}

/// Timing-stripped receipts omit the request duration; restore a neutral value for validation.
fn observation_shape(response: &Value, expected: Planner) -> Result<Value, EvalError> {
    let mut timed = response.clone();
    if timed.get("searchDurationMs").is_none() {
        timed["searchDurationMs"] = json!(0);
    }
    control_response_shape(&timed, expected)
}

/// Take order/mode/status from `fixed_query_identities`; each row projects its validated shape.
fn fixed_query_shapes(rows: &[Value]) -> Result<Vec<Value>, EvalError> {
    fixed_query_identities(rows)?;
    rows.iter()
        .enumerate()
        .map(|(ordinal, row)| {
            let planner = if ordinal < 8 {
                Planner::Off
            } else {
                Planner::On
            };
            Ok(
                json!({"query":row["query"],"mode":row["mode"],"status":200,"error":null,
                "response":observation_shape(&row["response"], planner)?}),
            )
        })
        .collect()
}

/// Content and fixed-query identities of one ordered pair, independent of physical segments.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlIdentity {
    /// Ordered (backbone shard id, live document count) pairs.
    pub counts: Vec<(u64, u64)>,
    /// One sorted document-multiset SHA-256 per shard, in the same order.
    pub documents: Vec<String>,
    /// Sixteen gate-measured observations on this pair, validated during comparison.
    /// Retained observations are reporting only and never affect the verdict.
    pub rankings: Vec<Value>,
}

/// Opaque control components derived from observations and content identities.
/// Deserialization is only transport: the gate recomputes every flag before accepting it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlVerdict {
    /// Whether the control comparison completed and the expected tuple is well-formed.
    /// Measured mismatches still count as completed comparisons.
    completed: bool,
    /// Both control-mode receipts contain eight valid observations each.
    control_receipts_present: bool,
    /// Both centrality-mode receipts contain eight valid observations each.
    centrality_receipts_present: bool,
    /// Four gate receipt hashes in control off/on, centrality off/on order; absent slots are null.
    observation_digests: Vec<Option<String>>,
    /// Ordered control counts agree with the independently audited expected pair.
    counts_match: bool,
    /// Valid control/centrality content multisets and counts agree per shard.
    content_matches: bool,
    /// Legacy name: valid control/centrality responses agree in fixed schema shape.
    rankings_match: bool,
    /// Compatibility component derived from counts_match and content_matches.
    centrality_content_matches: bool,
    /// All comparison components agree; required only for centrality contrasts.
    comparable: bool,
    /// SHA-256 of frozen input/config/executable identities supplied by the driver.
    input_identity: String,
    /// SHA-256 of the exact three comparison inputs and expected counts, never verdict flags.
    comparison_identity: String,
    /// Digest binding comparison inputs and the driver's frozen identity envelope.
    seal: String,
}

impl ControlIdentity {
    /// Compare same-binary control/centrality counts, content and response shapes.
    /// Retained document evidence must be valid; its rankings are reporting only.
    /// Expected counts are independently audited caller inputs, never inferred from totals.
    pub fn comparable(
        &self,
        control: &Self,
        centrality: &Self,
        expected: [(u64, u64); 2],
    ) -> ControlVerdict {
        let retained = self;
        let counts_match = control.counts == expected;
        // Value identities gate completeness only; shapes are the compared contract.
        // Raw rankings remain in the seal for reporting legitimate retrieval differences.
        let control_rankings = fixed_query_identities(&control.rankings).ok();
        let centrality_rankings = fixed_query_identities(&centrality.rankings).ok();
        let control_shapes = fixed_query_shapes(&control.rankings).ok();
        let centrality_shapes = fixed_query_shapes(&centrality.rankings).ok();
        let rankings_match = control_shapes == centrality_shapes
            && control_shapes.is_some()
            && centrality_shapes.is_some();
        let valid_documents = |identity: &Self| {
            identity.counts.len() == 2
                && identity
                    .counts
                    .iter()
                    .enumerate()
                    .all(|(shard, (id, count))| {
                        *id == shard as u64 && *count <= Limits::default().documents as u64
                    })
                && identity.documents.len() == 2
                && identity
                    .documents
                    .iter()
                    .all(|digest| decoded_sha(digest).is_ok())
        };
        let completed = [retained, control, centrality]
            .into_iter()
            .all(valid_documents)
            && control_rankings.is_some()
            && centrality_rankings.is_some()
            && expected.iter().enumerate().all(|(shard, (id, count))| {
                *id == shard as u64 && *count <= Limits::default().documents as u64
            });
        let content_matches = control.documents == centrality.documents
            && centrality.counts == control.counts
            && valid_documents(control)
            && valid_documents(centrality);
        let centrality_content_matches = counts_match && content_matches;
        ControlVerdict {
            completed,
            control_receipts_present: control_rankings.as_ref().map(Vec::len) == Some(16),
            centrality_receipts_present: centrality_rankings.as_ref().map(Vec::len) == Some(16),
            observation_digests: Vec::new(),
            counts_match,
            content_matches,
            rankings_match,
            centrality_content_matches,
            comparable: completed && counts_match && content_matches && rankings_match,
            input_identity: String::new(),
            comparison_identity: input::sha256(
                &serde_json::to_vec(&(retained, control, centrality, expected))
                    .expect("JSON-valued comparison inputs serialize"),
            ),
            seal: String::new(),
        }
    }
}

impl ControlVerdict {
    fn calculated_seal(&self) -> Result<String, EvalError> {
        Ok(digest_parts([
            decoded_sha(&self.comparison_identity)?,
            decoded_sha(&self.input_identity)?,
        ]))
    }
    /// Bind this measured verdict to the SHA-256 of frozen input/config/executable identities.
    /// Rejects malformed SHA strings; callers retain the actual identity envelope as evidence.
    pub fn sealed(mut self, input_identity: &str) -> Result<Self, EvalError> {
        decoded_sha(input_identity)?;
        self.input_identity = input_identity.to_owned();
        self.seal = self.calculated_seal()?;
        Ok(self)
    }

    /// Whether validated identities and all sixteen observations per pair are present,
    /// and the expected tuple is well-formed.
    pub fn completed(&self) -> bool {
        self.completed
    }
    /// Whether both control modes have valid gate measurements.
    pub fn control_receipts_present(&self) -> bool {
        self.control_receipts_present
    }
    /// Whether both centrality modes have valid gate measurements.
    pub fn centrality_receipts_present(&self) -> bool {
        self.centrality_receipts_present
    }
    /// Whether every control component matched; required for centrality feature cells.
    pub fn comparable(&self) -> bool {
        self.comparable
    }
    /// Whether ordered control counts matched the independently audited per-shard counts.
    pub fn counts_match(&self) -> bool {
        self.counts_match
    }
    /// Whether valid control/centrality document multisets and counts matched per shard.
    pub fn content_matches(&self) -> bool {
        self.content_matches
    }
    /// Whether control/centrality observations agreed on the validated response-shape contract.
    pub fn rankings_match(&self) -> bool {
        self.rankings_match
    }
    /// Whether the control/centrality counts and content matched the expected pair.
    pub fn centrality_content_matches(&self) -> bool {
        self.centrality_content_matches
    }
}

/// Derive a control from bounded identity JSON and gate measurement receipts.
/// The six slots are retained/control/centrality off/on; retained slots are reporting only.
/// Missing control/centrality receipts produce an incomplete verdict, never authorization.
/// The envelope binds each shard to its physical inspect manifest and each observation to
/// its pair, mode, served-service receipt, resolved API config and frozen executable.
/// Producer mismatches make the comparison incomplete; legitimate equal rankings remain valid.
pub fn control_from_files(
    identities: &Path,
    observations: &[PathBuf; 6],
    expected: [(u64, u64); 2],
    envelope: &Value,
) -> Result<ControlVerdict, EvalError> {
    let documents = read_metadata(identities, &Limits::default())?;
    let provenance = &envelope["provenance"];
    let executable = &envelope["freeze"]["binary_sha256"];
    let mut producers_valid = valid_digest(executable);
    let mut observation_valid = [true; 3];
    let mut comparisons = Vec::new();
    for (ordinal, pair) in ["retained", "reindexed", "centrality"]
        .into_iter()
        .enumerate()
    {
        let indexes = documents[pair]
            .as_array()
            .filter(|values| values.len() == 2)
            .ok_or(EvalError::IdentityMismatch)?;
        let mut identity = ControlIdentity {
            counts: Vec::new(),
            documents: Vec::new(),
            rankings: Vec::new(),
        };
        for (shard, index) in indexes.iter().enumerate() {
            producers_valid &= index["manifest_sha256"] == provenance["indexes"][pair][shard]
                && valid_digest(&provenance["indexes"][pair][shard])
                && index["executable_sha256"] == *executable;
            identity.counts.push((
                index["shard"].as_u64().ok_or(EvalError::IdentityMismatch)?,
                index["documents"]
                    .as_u64()
                    .ok_or(EvalError::IdentityMismatch)?,
            ));
            identity.documents.push(
                index["content_sha256"]
                    .as_str()
                    .ok_or(EvalError::IdentityMismatch)?
                    .to_owned(),
            );
        }
        for (mode, path) in ["off", "on"]
            .into_iter()
            .zip(&observations[ordinal * 2..ordinal * 2 + 2])
        {
            if ordinal == 0 {
                continue;
            }
            if !path.try_exists().map_err(|_| EvalError::Io)? {
                continue;
            }
            let Ok(observation) = read_measurement(path) else {
                observation_valid[ordinal] = false;
                continue;
            };
            observation_valid[ordinal] &= observation["pair"]
                == if pair == "reindexed" { "control" } else { pair }
                && observation["mode"] == mode
                && observation["service_sha256"] == provenance["services"][pair][mode]
                && valid_digest(&provenance["services"][pair][mode])
                && observation["config_sha256"] == provenance["configs"][mode]
                && valid_digest(&provenance["configs"][mode])
                && observation["executable_sha256"] == *executable
                && indexes.iter().enumerate().all(|(shard, index)| {
                    let binding = &observation["pair_binding"]["shards"][shard];
                    binding["manifest_sha256"] == index["manifest_sha256"]
                        && binding["documents"] == index["documents"]
                        && binding["config_sha256"]
                            == provenance["search_configs"][pair][shard]["sha256"]
                        && binding["config_path"]
                            == provenance["search_configs"][pair][shard]["path"]
                });
            let rows = &observation["rows"];
            let rows = rows
                .as_array()
                .filter(|rows| rows.len() <= 8)
                .ok_or(EvalError::IdentityMismatch)?;
            identity.rankings.extend(rows.iter().cloned());
        }
        comparisons.push(identity);
    }
    let mut verdict = comparisons[0].comparable(&comparisons[1], &comparisons[2], expected);
    verdict.control_receipts_present &= producers_valid && observation_valid[1];
    verdict.centrality_receipts_present &= producers_valid && observation_valid[2];
    verdict.completed &= producers_valid && observation_valid[1] && observation_valid[2];
    verdict.rankings_match &= producers_valid && observation_valid[1] && observation_valid[2];
    verdict.comparable &= producers_valid && observation_valid[1] && observation_valid[2];
    let envelope = bind_receipt_envelope(envelope, observations)?;
    verdict.observation_digests = envelope["gate_receipts"]
        .as_array()
        .ok_or(EvalError::IdentityMismatch)?
        .iter()
        .map(|entry| entry["sha256"].as_str().map(str::to_owned))
        .collect();
    verdict.sealed(&input::sha256(
        &serde_json::to_vec(&envelope).map_err(|_| EvalError::IdentityMismatch)?,
    ))
}

/// Require a present, correctly encoded SHA-256 before comparing producer bindings.
fn valid_digest(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|digest| decoded_sha(digest).is_ok())
}

/// The six isolated feature cells; there is deliberately no combined-feature variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FeatureCell {
    /// Base indexes, planner off, no spelling; the run's pair and suite identify the base.
    BaseOff,
    /// Base indexes, planner on, no spelling; the run's pair and suite identify the base.
    BaseOn,
    /// Host-centrality indexes, planner off, no spelling.
    CentralityOff,
    /// Host-centrality indexes, planner on, no spelling.
    CentralityOn,
    /// Retained indexes, planner off, offered spelling enabled.
    SpellOff,
    /// Retained indexes, planner on, offered spelling enabled.
    SpellOn,
}

impl FeatureCell {
    /// Fixed planner mode of this cell, independent of its measured feature.
    pub fn planner(self) -> Planner {
        match self {
            Self::BaseOff | Self::CentralityOff | Self::SpellOff => Planner::Off,
            Self::BaseOn | Self::CentralityOn | Self::SpellOn => Planner::On,
        }
    }
    /// Whether this cell requires the comparable centrality control gate.
    pub fn centrality(self) -> bool {
        matches!(self, Self::CentralityOff | Self::CentralityOn)
    }
    /// Whether this cell offers corrections without changing retrieval.
    pub fn spelling(self) -> bool {
        matches!(self, Self::SpellOff | Self::SpellOn)
    }
}

/// Return the base cell with the same planner mode; its measured pair is bound separately.
pub fn matching_base(cell: FeatureCell) -> FeatureCell {
    match cell.planner() {
        Planner::Off => FeatureCell::BaseOff,
        Planner::On => FeatureCell::BaseOn,
    }
}

/// Validate sealed evidence before held-out access and centrality comparisons.
/// This offline check does not authorize a diagnostic launch: the gate must measure it.
/// A completed mismatch permits independent base/spelling cells; stale or changed seals fail.
pub fn validate_control_evidence(
    control: &ControlVerdict,
    held_out: bool,
    cell: FeatureCell,
    expected_envelope: &Value,
    identities: &Path,
    observations: &[PathBuf; 6],
    expected_counts: [(u64, u64); 2],
) -> Result<(), EvalError> {
    let recomputed =
        control_from_files(identities, observations, expected_counts, expected_envelope)?;
    let expected_input_identity = input::sha256(
        &serde_json::to_vec(&bind_receipt_envelope(expected_envelope, observations)?)
            .map_err(|_| EvalError::IdentityMismatch)?,
    );
    if *control != recomputed {
        return Err(EvalError::IdentityMismatch);
    }
    if held_out && !control.control_receipts_present {
        return Err(EvalError::IdentityMismatch);
    }
    if control.input_identity != expected_input_identity
        || control.seal != control.calculated_seal()?
    {
        return Err(EvalError::IdentityMismatch);
    }
    if cell.centrality() && (!control.completed || !control.comparable) {
        return Err(EvalError::IdentityMismatch);
    }
    Ok(())
}

/// Canonical receipt digest. The seal covers every field except the seal itself.
pub fn measurement_seal(receipt: &Value) -> Result<String, EvalError> {
    let mut value = receipt.clone();
    value
        .as_object_mut()
        .ok_or(EvalError::InvalidInput)?
        .remove("seal");
    Ok(input::sha256(
        &serde_json::to_vec(&value).map_err(|_| EvalError::InvalidInput)?,
    ))
}

/// Read a bounded, sealed measurement and validate all eight ordered, timing-stripped rows.
/// This proves integrity; a fresh launch still has to measure rather than adopt this file.
pub fn read_measurement(path: &Path) -> Result<Value, EvalError> {
    let receipt = read_metadata(path, &Limits::default())?;
    if receipt["seal"] != measurement_seal(&receipt)? {
        return Err(EvalError::IdentityMismatch);
    }
    validate_pair_binding(&receipt)?;
    let planner: Planner =
        serde_json::from_value(receipt["mode"].clone()).map_err(|_| EvalError::IdentityMismatch)?;
    if receipt["schema_version"] != 1
        || receipt["status"] != "passed"
        || !matches!(
            receipt["pair"].as_str(),
            Some("retained" | "control" | "centrality")
        )
        || ["service_sha256", "config_sha256", "executable_sha256"]
            .iter()
            .any(|key| !valid_digest(&receipt[*key]))
        || receipt["measured_at"]
            .as_str()
            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
            .is_none()
    {
        return Err(EvalError::IdentityMismatch);
    }
    let rows = receipt["rows"]
        .as_array()
        .filter(|rows| rows.len() == 8)
        .ok_or(EvalError::IdentityMismatch)?;
    for (ordinal, row) in rows.iter().enumerate() {
        if row["query"] != FIXED_CONTROL_QUERIES[ordinal]
            || row["mode"] != receipt["mode"]
            || row["status"] != 200
            || row.get("error") != Some(&Value::Null)
            || row["response"] != retrieval_identity(&row["response"])?
        {
            return Err(EvalError::IdentityMismatch);
        }
        observation_shape(&row["response"], planner)?;
    }
    Ok(receipt)
}

fn validate_pair_binding(receipt: &Value) -> Result<(), EvalError> {
    let binding = &receipt["pair_binding"];
    let shards = binding["shards"]
        .as_array()
        .filter(|v| v.len() == 2)
        .ok_or(EvalError::IdentityMismatch)?;
    let members = binding["cluster_members"]
        .as_array()
        .filter(|v| v.len() == 2)
        .ok_or(EvalError::IdentityMismatch)?;
    if binding["verified"] != true
        || binding["management_endpoint"] != receipt["management_endpoint"]
    {
        return Err(EvalError::IdentityMismatch);
    }
    super::endpoint::Endpoint::parse(
        receipt["management_endpoint"]
            .as_str()
            .ok_or(EvalError::IdentityMismatch)?,
    )?;
    for member in members {
        if member.as_array().map(Vec::len) != Some(2) || member[0].as_u64().is_none() {
            return Err(EvalError::IdentityMismatch);
        }
        super::endpoint::Endpoint::shard(member[1].as_str().ok_or(EvalError::IdentityMismatch)?)?;
    }
    for (ordinal, shard) in shards.iter().enumerate() {
        if shard["shard_id"] != ordinal
            || shard["documents"].as_u64().is_none()
            || shard["documents"] != shard["wire_documents"]
            || ["config_sha256", "manifest_sha256", "files_sha256"]
                .iter()
                .any(|key| !valid_digest(&shard[*key]))
            || ["config_path", "index_path"].iter().any(|key| {
                shard[*key]
                    .as_str()
                    .is_none_or(|v| !Path::new(v).is_absolute())
            })
        {
            return Err(EvalError::IdentityMismatch);
        }
        super::endpoint::Endpoint::shard(
            shard["socket"]
                .as_str()
                .ok_or(EvalError::IdentityMismatch)?,
        )?;
    }
    Ok(())
}

/// Locate the earlier control-phase report corresponding to a gate receipt.
/// Reporting files are never read by the verdict's observation component.
pub fn reporting_observation_path(receipt: &Path) -> Result<PathBuf, EvalError> {
    let root = receipt
        .parent()
        .and_then(Path::parent)
        .ok_or(EvalError::UnsafePath)?;
    let stem = receipt
        .file_stem()
        .and_then(|v| v.to_str())
        .ok_or(EvalError::UnsafePath)?;
    let (pair, mode) = stem.rsplit_once('-').ok_or(EvalError::UnsafePath)?;
    if !matches!(pair, "retained" | "control" | "centrality") || !matches!(mode, "off" | "on") {
        return Err(EvalError::UnsafePath);
    }
    Ok(root
        .join("control")
        .join(format!(
            "{}-{mode}",
            if pair == "control" { "reindexed" } else { pair }
        ))
        .join("fixed.json"))
}

/// Bind exactly the four diagnostic receipt files, including explicit missing slots.
pub fn bind_receipt_envelope(
    envelope: &Value,
    receipts: &[PathBuf; 6],
) -> Result<Value, EvalError> {
    let mut bound = envelope.clone();
    let mut files = Vec::new();
    for path in receipts.iter().skip(2) {
        files.push(if path.try_exists().map_err(|_| EvalError::Io)? {
            let document = input::read(path)?;
            json!({"path":path,"sha256":document.sha256})
        } else {
            Value::Null
        });
    }
    bound["gate_receipts"] = json!(files);
    Ok(bound)
}

/// Immutable content/audit inputs and the receipt slots used to derive launch authorization.
pub struct ControlGateInputs<'a> {
    /// Whether this cell may access the held-out set.
    pub held_out: bool,
    /// Diagnostic cell being authorized.
    pub cell: FeatureCell,
    /// Frozen producer and file identities; receipt digests are always rederived.
    pub envelope: &'a Value,
    /// Three ordered pairs' document identities.
    pub identities: &'a Path,
    /// Retained/control/centrality off/on measurement receipt paths.
    pub observations: &'a [PathBuf; 6],
    /// Counts independently derived from the admission ledger.
    pub expected_counts: [(u64, u64); 2],
    /// Created-new final verdict output, outside every evidence input.
    pub final_verdict: &'a Path,
}

/// One mode of a continuously running pair of index services.
/// API mode switches may restart the API; they do not restart the measured index services.
pub struct LiveControlCheck<'a> {
    /// Literal loopback endpoint, validated by the recall runner.
    pub endpoint: &'a str,
    /// Literal loopback management endpoint from the same frozen API config.
    pub management_endpoint: &'a str,
    /// The pair's two resolved, digest-bound search configs in shard order.
    pub search_configs: &'a [PathBuf; 2],
    /// Document identities whose physical inspect manifests bind this pair.
    pub identities: &'a Path,
    /// Frozen configs, executable and inspect-manifest provenance.
    pub envelope: &'a Value,
    /// Exactly retained (reporting), control or centrality.
    pub pair: &'a str,
    /// Expected planner mode.
    pub planner: Planner,
    /// This pair launch's successful native served-shard manifest.
    pub served: &'a Path,
    /// Frozen resolved API config for this mode.
    pub config: &'a Path,
    /// Frozen executable digest.
    pub executable_sha256: &'a str,
    /// Created-new measurement output; numeric raw responses use its raw sibling.
    pub receipt: &'a Path,
}

/// Fixed errors name only a failed ordinal or a missing prerequisite.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum LiveControlError {
    /// Bounded evidence, I/O or identity failure.
    #[error(transparent)]
    Evidence(#[from] EvalError),
    /// A request or response failed validation at this one-based ordinal.
    #[error("gate measurement failed at query ordinal {ordinal}")]
    Observation {
        /// One-based fixed-query ordinal.
        ordinal: usize,
    },
    /// Measurement was retained, but both modes of both diagnostic pairs are not yet present.
    #[error("centrality requires all four gate measurement receipts")]
    PendingMeasurements,
}

/// Private capability created by this process's measurement, never by deserialization.
#[derive(Debug)]
pub struct LiveControlReceipt {
    path: PathBuf,
    seal: String,
    binding: Value,
}

impl LiveControlReceipt {
    fn verify(
        &self,
        live: Option<&LiveControlCheck<'_>>,
        expected: [(u64, u64); 2],
    ) -> Result<(), EvalError> {
        let receipt = read_measurement(&self.path)?;
        if receipt["seal"] != self.seal
            || self
                .binding
                .as_object()
                .ok_or(EvalError::IdentityMismatch)?
                .iter()
                .any(|(key, value)| receipt[key] != *value)
            || live
                .map(|live| measurement_binding(live, expected))
                .transpose()?
                .is_some_and(|binding| binding != self.binding)
        {
            return Err(EvalError::IdentityMismatch);
        }
        Ok(())
    }
}

/// Process-owned measurements across the ordered control and centrality pair launches.
/// A fresh state never adopts prewritten files. Retain it for the round; never reuse it for
/// another index-service launch. Only the gate can insert measurement capabilities.
#[derive(Debug, Default)]
pub struct GateMeasurements {
    receipts: BTreeMap<String, LiveControlReceipt>,
    final_file: Option<(PathBuf, String)>,
    binding_limits: Limits,
}

impl GateMeasurements {
    /// Reduce the native-frame and physical-walk ceilings for a new measurement state.
    /// Limits cannot exceed production defaults; existing capabilities cannot be imported.
    pub fn with_binding_limits(limits: Limits) -> Result<Self, EvalError> {
        limits.validate()?;
        Ok(Self {
            binding_limits: limits,
            ..Self::default()
        })
    }

    /// Measure once for reporting anchors; diagnostic callers use the gate below.
    pub async fn measure_once(
        &mut self,
        live: &LiveControlCheck<'_>,
        expected: [(u64, u64); 2],
    ) -> Result<(), LiveControlError> {
        let key = format!(
            "{}-{}",
            live.pair,
            if live.planner == Planner::Off {
                "off"
            } else {
                "on"
            }
        );
        if let Some(receipt) = self.receipts.get(&key) {
            receipt.verify(Some(live), expected)?;
        } else {
            let receipt = measure_fixed_queries(live, expected, &self.binding_limits).await?;
            self.receipts.insert(key, receipt);
        }
        Ok(())
    }

    /// Derive the current envelope from trusted measurement capabilities and their files.
    pub fn envelope(&self, inputs: &ControlGateInputs<'_>) -> Result<Value, EvalError> {
        let mut envelope = inputs.envelope.clone();
        for (i, path) in inputs.observations.iter().enumerate().skip(2) {
            let pair = if i < 4 { "control" } else { "centrality" };
            let mode = if i % 2 == 0 { "off" } else { "on" };
            if let Some(receipt) = self.receipts.get(&format!("{pair}-{mode}")) {
                if receipt.path != *path {
                    return Err(EvalError::IdentityMismatch);
                }
                receipt.verify(None, inputs.expected_counts)?;
                let key = if pair == "control" { "reindexed" } else { pair };
                envelope["provenance"]["services"][key][mode] =
                    receipt.binding["service_sha256"].clone();
            } else if path.try_exists().map_err(|_| EvalError::Io)? {
                return Err(EvalError::IdentityMismatch);
            }
        }
        bind_receipt_envelope(&envelope, inputs.observations)
    }

    /// Derive a partial or final verdict without trusting serialized flags.
    pub fn verdict(&self, inputs: &ControlGateInputs<'_>) -> Result<ControlVerdict, EvalError> {
        control_from_files(
            inputs.identities,
            inputs.observations,
            inputs.expected_counts,
            &self.envelope(inputs)?,
        )
    }

    fn finish_verdict(
        &mut self,
        inputs: &ControlGateInputs<'_>,
        verdict: &ControlVerdict,
    ) -> Result<(), EvalError> {
        let envelope = self.envelope(inputs)?;
        let value = json!({"schema_version":1,"inputs":envelope,"input_identity":verdict.input_identity,
            "verdict":verdict,"expected_counts":inputs.expected_counts,"fixed_queries":FIXED_CONTROL_QUERIES});
        if let Some((path, hash)) = &self.final_file {
            if path != inputs.final_verdict
                || input::hash_file(path)? != *hash
                || read_metadata(path, &Limits::default())? != value
            {
                return Err(EvalError::IdentityMismatch);
            }
        } else {
            let mut sources = inputs.observations.to_vec();
            sources.push(inputs.identities.to_path_buf());
            for receipt in self.receipts.values() {
                sources.extend(measurement_sources(&receipt.binding, inputs.identities)?);
            }
            output::external(inputs.final_verdict, &sources)?;
            finish_report(
                Output::reserve(inputs.final_verdict, false)?,
                &value,
                &Limits::default(),
            )?;
            self.final_file = Some((
                inputs.final_verdict.to_path_buf(),
                input::hash_file(inputs.final_verdict)?,
            ));
        }
        Ok(())
    }
}

fn config_socket(config: &toml::Value, key: &str) -> Result<std::net::SocketAddr, EvalError> {
    super::endpoint::Endpoint::shard(
        config
            .get(key)
            .and_then(toml::Value::as_str)
            .ok_or(EvalError::InvalidInput)?,
    )
}

/// Re-walk a copied index with metadata byte limits before computing any file hash.
/// Entry/depth and per-file/aggregate ceilings share the snapshot preflight rule.
/// Hash only the admitted paths, bound each read by its admitted length, and report
/// each completed hash to the observer. The observer cannot supply digest values.
/// Failures are attributed to --index; the returned order matches inspect-index.
pub fn bounded_index_manifest(
    path: &Path,
    limits: &Limits,
    mut on_hashed: impl FnMut(&Path),
) -> Result<Vec<Value>, EvalError> {
    let result = (|| {
        limits.validate()?;
        let root = directory(path, Argument::Index)?;
        let mut tree = Enumerated::default();
        enumerate(&root, &root, limits, &mut 0, &mut 0, 0, &mut tree)?;
        tree.files
            .sort_by(|(a, _), (b, _)| a.components().cmp(b.components()));
        let mut files = Vec::new();
        for (path, bytes) in tree.files {
            let file = open_input(&path)?;
            if file.metadata().map_err(|_| EvalError::Io)?.len() != bytes {
                return Err(EvalError::InputChanged);
            }
            // One extra byte detects growth without allowing an unbounded hash read.
            let mut reader = file.take(bytes.checked_add(1).ok_or(EvalError::InputLimit)?);
            let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
            let mut hashed = 0_u64;
            let mut chunk = [0_u8; 64 * 1024];
            loop {
                let count = reader.read(&mut chunk).map_err(|_| EvalError::Io)?;
                if count == 0 {
                    break;
                }
                hashed = hashed
                    .checked_add(count as u64)
                    .ok_or(EvalError::InputLimit)?;
                digest.update(&chunk[..count]);
            }
            if hashed != bytes {
                return Err(EvalError::InputChanged);
            }
            let sha256 = digest
                .finish()
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            on_hashed(&path);
            files.push(json!({"path":path.strip_prefix(&root).map_err(|_| EvalError::UnsafePath)?,"bytes":bytes,"sha256":sha256}));
        }
        Ok(files)
    })();
    result.map_err(|error: EvalError| error.argument(Argument::Index))
}

/// Recreate the exact inspect-index JSON bytes, including its terminal newline.
fn walked_inspect_digest(
    path: &Path,
    documents: u64,
    limits: &Limits,
) -> Result<(String, String), EvalError> {
    let files = bounded_index_manifest(path, limits, |_| {})?;
    if files.is_empty() {
        return Err(EvalError::InvalidInput);
    }
    let files_sha256 =
        input::sha256(&serde_json::to_vec(&files).map_err(|_| EvalError::InvalidInput)?);
    let mut bytes = serde_json::to_vec_pretty(&json!({"schema_version":1,"index":path,
        "pre_open_files":files,"documents":documents}))
    .map_err(|_| EvalError::InvalidInput)?;
    bytes.push(b'\n');
    Ok((input::sha256(&bytes), files_sha256))
}

/// The gate implements Sonic's native-usize frame header with its own small ceiling.
/// This connection is used only under the enclosing 60-second binding deadline.
struct GateNativeConnection(tokio::net::TcpStream);

impl GateNativeConnection {
    async fn create(socket: std::net::SocketAddr) -> Result<Self, EvalError> {
        let stream = tokio::net::TcpStream::connect(socket)
            .await
            .map_err(|_| EvalError::Network)?;
        stream.set_nodelay(true).map_err(|_| EvalError::Network)?;
        Ok(Self(stream))
    }

    async fn send<Req: bincode::Encode, Res: bincode::Decode>(
        &mut self,
        request: &Req,
        limits: &Limits,
    ) -> Result<Res, EvalError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let request = bincode::encode_to_vec(request, common::bincode_config())
            .map_err(|_| EvalError::InvalidInput)?;
        self.0
            .write_all(&request.len().to_ne_bytes())
            .await
            .map_err(|_| EvalError::Network)?;
        self.0
            .write_all(&request)
            .await
            .map_err(|_| EvalError::Network)?;
        self.0.flush().await.map_err(|_| EvalError::Network)?;
        let mut header = [0_u8; std::mem::size_of::<usize>()];
        self.0
            .read_exact(&mut header)
            .await
            .map_err(|_| EvalError::Network)?;
        let native_bytes = usize::from_ne_bytes(header);
        if native_bytes > limits.native_response_bytes {
            return Err(EvalError::InputLimit);
        }
        let mut bytes = vec![0_u8; native_bytes];
        self.0
            .read_exact(&mut bytes)
            .await
            .map_err(|_| EvalError::Network)?;
        // Bound decoded collection claims too; malformed input must not panic.
        let (response, consumed) = bincode::decode_from_slice(
            &bytes,
            common::bincode_config().with_limit::<{ 64 * 1024 }>(),
        )
        .map_err(|_| EvalError::InvalidResponse)?;
        if consumed != bytes.len() {
            return Err(EvalError::InvalidResponse);
        }
        Ok(response)
    }
}

async fn bind_live_pair(binding: &Value, limits: &Limits) -> Result<Value, EvalError> {
    use crate::{
        distributed::{
            member::Service as MemberService,
            sonic::service::{Service, Wrapper},
        },
        entrypoint::api::{ClusterStatus, ManagementService},
        inverted_index::ShardId,
        OneOrMany,
    };
    let management = super::endpoint::Endpoint::parse(
        binding["management_endpoint"]
            .as_str()
            .ok_or(EvalError::InvalidInput)?,
    )?;
    let status = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let mut connection = GateNativeConnection::create(management.socket).await?;
        let response: OneOrMany<<ManagementService as Service>::Response> = connection
            .send(
                &OneOrMany::One(ClusterStatus::wrap_request(ClusterStatus)),
                limits,
            )
            .await?;
        let response = response.one().ok_or(EvalError::InvalidResponse)?;
        ClusterStatus::unwrap_response(response).ok_or(EvalError::InvalidResponse)
    })
    .await
    .map_err(|_| EvalError::Timeout)?
    .map_err(|error| error.argument(Argument::ServiceManifest))?;
    if status.members.len() > 16 {
        return Err(EvalError::InputLimit.argument(Argument::ServiceManifest));
    }
    let mut members = Vec::new();
    for member in status.members {
        match member.service {
            MemberService::Searcher {
                host,
                shard: ShardId::Backbone(shard),
            } => members.push((shard, host)),
            // API entries are not shard members. Only the bound HTTP address is allowed.
            MemberService::Api { host }
                if host
                    == super::endpoint::Endpoint::parse(
                        binding["endpoint"]
                            .as_str()
                            .ok_or(EvalError::InvalidInput)?,
                    )?
                    .socket => {}
            _ => return Err(EvalError::IdentityMismatch),
        }
    }
    members.sort();
    let shards = binding["shards"]
        .as_array()
        .ok_or(EvalError::IdentityMismatch)?;
    let expected_members = shards
        .iter()
        .map(|shard| {
            Ok((
                shard["shard_id"]
                    .as_u64()
                    .ok_or(EvalError::IdentityMismatch)?,
                super::endpoint::Endpoint::shard(
                    shard["socket"]
                        .as_str()
                        .ok_or(EvalError::IdentityMismatch)?,
                )?,
            ))
        })
        .collect::<Result<Vec<_>, EvalError>>()?;
    if members != expected_members {
        return Err(EvalError::IdentityMismatch);
    }
    let mut verified = shards.clone();
    for shard in &mut verified {
        let path = Path::new(
            shard["index_path"]
                .as_str()
                .ok_or(EvalError::IdentityMismatch)?,
        );
        let count = shard["documents"]
            .as_u64()
            .ok_or(EvalError::IdentityMismatch)?;
        let (actual_manifest, files_sha256) = walked_inspect_digest(path, count, limits)?;
        if actual_manifest != shard["manifest_sha256"] {
            return Err(EvalError::IdentityMismatch);
        }
        // The bound inspect digest is emitted only after this fresh physical comparison.
        shard["files_sha256"] = json!(files_sha256);
    }
    for shard in &mut verified {
        let socket = super::endpoint::Endpoint::shard(
            shard["socket"]
                .as_str()
                .ok_or(EvalError::IdentityMismatch)?,
        )?;
        let ordinal = shard["shard_id"]
            .as_u64()
            .ok_or(EvalError::IdentityMismatch)?;
        let expected = shard["documents"]
            .as_u64()
            .ok_or(EvalError::IdentityMismatch)?;
        shard["wire_documents"] = json!(wire_documents(socket, ordinal, expected, limits).await?);
    }
    Ok(
        json!({"verified":true,"management_endpoint":management.base,"cluster_members":members,
        "shards":verified,"protocol":"ClusterStatus; SizeQuery then SizeQueryRetrieve; one connection per shard; no HTTP searches"}),
    )
}

async fn wire_documents(
    socket: std::net::SocketAddr,
    ordinal: u64,
    expected: u64,
    limits: &Limits,
) -> Result<u64, EvalError> {
    use crate::{
        distributed::sonic::service::{Service, Wrapper},
        entrypoint::search_server::{SearchService, SizeQueryRetrieve},
        generic_query::SizeQuery,
        inverted_index::ShardId,
        OneOrMany,
    };
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let mut conn = GateNativeConnection::create(socket).await?;
        let response: OneOrMany<<SearchService as Service>::Response> = conn
            .send(&OneOrMany::One(SizeQuery::wrap_request(SizeQuery)), limits)
            .await?;
        let response = response.one().ok_or(EvalError::InvalidResponse)?;
        let fruit = SizeQuery::unwrap_response(response)
            .ok_or(EvalError::InvalidResponse)?
            .map_err(|_| EvalError::InvalidResponse)?;
        if fruit.len() != 1
            || fruit
                .get(&ShardId::Backbone(ordinal))
                .is_none_or(|v| v.pages != expected)
        {
            return Err(EvalError::IdentityMismatch);
        }
        let response: OneOrMany<<SearchService as Service>::Response> = conn
            .send(
                &OneOrMany::One(SizeQueryRetrieve::wrap_request(SizeQueryRetrieve {
                    query: SizeQuery,
                    fruit,
                })),
                limits,
            )
            .await?;
        let response = response.one().ok_or(EvalError::InvalidResponse)?;
        let size = SizeQueryRetrieve::unwrap_response(response)
            .ok_or(EvalError::InvalidResponse)?
            .map_err(|_| EvalError::InvalidResponse)?;
        if size.pages != expected {
            return Err(EvalError::IdentityMismatch);
        }
        Ok(size.pages)
    })
    .await
    .map_err(|_| EvalError::Timeout)?
    .map_err(|error| error.argument(Argument::Shard))
}

fn measurement_binding(
    live: &LiveControlCheck<'_>,
    expected: [(u64, u64); 2],
) -> Result<Value, EvalError> {
    if !matches!(live.pair, "retained" | "control" | "centrality") {
        return Err(EvalError::IdentityMismatch);
    }
    decoded_sha(live.executable_sha256)?;
    let endpoint = super::endpoint::Endpoint::parse(live.endpoint)?;
    let served = read_metadata(live.served, &Limits::default())?;
    if served["verified"] != true
        || served["schema_version"] != 1
        || served["shards"].as_array().map(Vec::len) != Some(2)
        || expected.iter().enumerate().any(|(i, (shard, count))| {
            served["shards"][i]["shard_id"] != *shard || served["shards"][i]["documents"] != *count
        })
    {
        return Err(EvalError::IdentityMismatch);
    }
    let config = input::read(live.config)?;
    let api: toml::Value =
        toml::from_str(std::str::from_utf8(&config.bytes).map_err(|_| EvalError::InvalidInput)?)
            .map_err(|_| EvalError::InvalidInput)?;
    let management = super::endpoint::Endpoint::parse(live.management_endpoint)?;
    if config_socket(&api, "host")? != endpoint.socket
        || config_socket(&api, "management_host")? != management.socket
    {
        return Err(EvalError::IdentityMismatch);
    }
    let pair = if live.pair == "control" {
        "reindexed"
    } else {
        live.pair
    };
    let documents = read_metadata(live.identities, &Limits::default())?;
    let indexes = documents[pair]
        .as_array()
        .filter(|v| v.len() == 2)
        .ok_or(EvalError::IdentityMismatch)?;
    let mut shards = Vec::new();
    for (ordinal, path) in live.search_configs.iter().enumerate() {
        let document = input::read(path)?;
        let config: toml::Value = toml::from_str(
            std::str::from_utf8(&document.bytes).map_err(|_| EvalError::InvalidInput)?,
        )
        .map_err(|_| EvalError::InvalidInput)?;
        let index = &indexes[ordinal];
        let bound = &live.envelope["provenance"]["search_configs"][pair][ordinal];
        if bound["path"] != json!(path)
            || bound["sha256"] != document.sha256
            || config.get("shard").and_then(toml::Value::as_integer) != Some(ordinal as i64)
            || expected[ordinal].0 != ordinal as u64
            || index["shard"] != ordinal
            || index["documents"] != expected[ordinal].1
            || index["manifest_sha256"] != live.envelope["provenance"]["indexes"][pair][ordinal]
            || !valid_digest(&index["manifest_sha256"])
            || index["executable_sha256"] != live.executable_sha256
        {
            return Err(EvalError::IdentityMismatch);
        }
        let socket = config_socket(&config, "host")?;
        let index_path = config
            .get("index_path")
            .and_then(toml::Value::as_str)
            .ok_or(EvalError::InvalidInput)?;
        let index_path = input::inspect_path(Path::new(index_path), false)?;
        if !has_trusted_temporary_ancestor(&index_path)? {
            return Err(EvalError::UnsafePath);
        }
        shards.push(
            json!({"shard_id":ordinal,"socket":socket,"config_path":path,
            "config_sha256":document.sha256,"index_path":index_path,
            "manifest_sha256":index["manifest_sha256"],"documents":expected[ordinal].1}),
        );
    }
    if shards[0]["socket"] == shards[1]["socket"] {
        return Err(EvalError::IdentityMismatch);
    }
    Ok(
        json!({"pair":live.pair,"mode":live.planner,"endpoint":endpoint.base,
        "management_endpoint":management.base,"shards":shards,
        "service_path":live.served,"service_sha256":input::hash_file(live.served)?,
        "config_path":live.config,"config_sha256":config.sha256,"executable_sha256":live.executable_sha256}),
    )
}

fn measurement_sources(binding: &Value, identities: &Path) -> Result<Vec<PathBuf>, EvalError> {
    let mut sources = vec![identities.to_path_buf()];
    for key in ["service_path", "config_path"] {
        sources.push(PathBuf::from(
            binding[key].as_str().ok_or(EvalError::IdentityMismatch)?,
        ));
    }
    for shard in binding["shards"]
        .as_array()
        .ok_or(EvalError::IdentityMismatch)?
    {
        for key in ["config_path", "index_path"] {
            sources.push(PathBuf::from(
                shard[key].as_str().ok_or(EvalError::IdentityMismatch)?,
            ));
        }
    }
    Ok(sources)
}

async fn measure_fixed_queries(
    live: &LiveControlCheck<'_>,
    expected: [(u64, u64); 2],
    limits: &Limits,
) -> Result<LiveControlReceipt, LiveControlError> {
    let binding = measurement_binding(live, expected)?;
    let pair_binding = bind_live_pair(&binding, limits).await?;
    output::external(
        live.receipt,
        &measurement_sources(&binding, live.identities)?,
    )?;
    let output = Output::reserve(live.receipt, true)?;
    let endpoint = super::endpoint::Endpoint::parse(live.endpoint)?;
    let started = chrono::Utc::now().to_rfc3339();
    let mut rows = Vec::new();
    for (ordinal, query) in FIXED_CONTROL_QUERIES.iter().enumerate() {
        let measured = measure_query(&endpoint, query, ordinal, live.planner, &output).await;
        match measured {
            Ok(row) => rows.push(row),
            Err(_) => {
                finish_report(
                    output,
                    &json!({"schema_version":1,"status":"failed","binding":binding,
                    "failed_ordinal":ordinal+1,"rows":rows}),
                    &Limits::default(),
                )?;
                return Err(LiveControlError::Observation {
                    ordinal: ordinal + 1,
                });
            }
        }
    }
    if measurement_binding(live, expected)? != binding {
        return Err(EvalError::InputChanged.into());
    }
    let mut receipt = binding.clone();
    receipt["pair_binding"] = pair_binding;
    receipt["schema_version"] = json!(1);
    receipt["status"] = json!("passed");
    receipt["rows"] = json!(rows);
    receipt["started_at"] = json!(started);
    receipt["measured_at"] = json!(chrono::Utc::now().to_rfc3339());
    let seal = measurement_seal(&receipt)?;
    receipt["seal"] = json!(seal);
    finish_report(output, &receipt, &Limits::default())?;
    Ok(LiveControlReceipt {
        path: live.receipt.to_path_buf(),
        seal,
        binding,
    })
}

async fn measure_query(
    endpoint: &super::endpoint::Endpoint,
    query: &str,
    ordinal: usize,
    planner: Planner,
    output: &Output,
) -> Result<Value, EvalError> {
    let attempt = super::runner::attempt(
        endpoint,
        query,
        output,
        ordinal,
        std::time::Duration::from_secs(super::runner::TIMEOUT_SECONDS),
        super::runner::MAX_RESPONSE_BYTES,
    )
    .await?;
    if let Some(error) = attempt.error {
        return Err(error);
    }
    if attempt.status != Some(200) {
        return Err(EvalError::HttpStatus);
    }
    let response: Value =
        serde_json::from_slice(&attempt.bytes).map_err(|_| EvalError::InvalidResponse)?;
    control_response_shape(&response, planner)?;
    Ok(
        json!({"query":query,"mode":planner,"status":200,"error":null,
        "response":retrieval_identity(&response)?,"raw_path":attempt.raw_path,"raw_sha256":input::sha256(&attempt.bytes)}),
    )
}

/// Measure the fixed queries at the first call, then authorize only from gate-owned receipts.
/// The runner supplies the exact request protocol, fresh connections, timeout and body bound.
/// Later calls verify the seal and service/config/executable bindings without another query.
/// Both centrality modes must be measured before either centrality cell is authorized.
pub async fn require_control_before_held_out(
    inputs: &ControlGateInputs<'_>,
    live: &LiveControlCheck<'_>,
    measurements: &mut GateMeasurements,
) -> Result<ControlVerdict, LiveControlError> {
    let pair = if inputs.cell.centrality() {
        "centrality"
    } else {
        "control"
    };
    let mode = if live.planner == Planner::Off {
        "off"
    } else {
        "on"
    };
    if live.pair != pair
        || live.planner != inputs.cell.planner()
        || inputs.cell.spelling()
        || inputs.envelope["freeze"]["binary_sha256"] != live.executable_sha256
        || inputs.envelope["provenance"]["configs"][mode] != input::hash_file(live.config)?
        || live.identities != inputs.identities
        || live.envelope != inputs.envelope
    {
        return Err(EvalError::IdentityMismatch.into());
    }
    measurements
        .measure_once(live, inputs.expected_counts)
        .await?;
    let envelope = measurements.envelope(inputs)?;
    let verdict = control_from_files(
        inputs.identities,
        inputs.observations,
        inputs.expected_counts,
        &envelope,
    )?;
    if inputs.cell.centrality() && !verdict.completed() {
        return Err(LiveControlError::PendingMeasurements);
    }
    validate_control_evidence(
        &verdict,
        inputs.held_out,
        inputs.cell,
        &envelope,
        inputs.identities,
        inputs.observations,
        inputs.expected_counts,
    )?;
    if inputs.cell.centrality() {
        measurements.finish_verdict(inputs, &verdict)?;
    }
    Ok(verdict)
}

fn cell(value: &Value) -> Result<FeatureCell, EvalError> {
    serde_json::from_value(value["cell"].clone()).map_err(|_| EvalError::IdentityMismatch)
}

fn config_values(run: &Value) -> Result<Vec<Value>, EvalError> {
    let configs = run["configs"]
        .as_array()
        .ok_or(EvalError::IdentityMismatch)?;
    if configs.len() != 3 {
        return Err(EvalError::IdentityMismatch);
    }
    configs
        .iter()
        .map(|config| {
            config
                .get("resolved")
                .cloned()
                .ok_or(EvalError::IdentityMismatch)
        })
        .collect()
}

/// Check pair cardinality and the measured control required by centrality contrasts.
fn validate_contrast_inputs(
    before: &Value,
    after: &Value,
    diagnostics: &Value,
    control: &ControlIdentity,
    feature: FeatureCell,
) -> Result<(), EvalError> {
    if [before, after].iter().any(|run| {
        run["indexes"]
            .as_array()
            .is_none_or(|indexes| indexes.len() != 2)
    }) {
        return Err(EvalError::IdentityMismatch);
    }
    if feature.centrality()
        && (before["suite"] != "diagnostic"
            || after["suite"] != "diagnostic"
            || control.counts.len() != 2
            || control.documents.len() != 2
            || diagnostics["indexes"]
                .as_array()
                .is_none_or(|indexes| indexes.len() != 2))
    {
        return Err(EvalError::IdentityMismatch);
    }
    Ok(())
}

/// Validate a native run contrast before the existing evaluator diff is called.
/// Requires the matching-mode base, identical labels/executable/timing/request/corpus, and
/// only the declared spelling section or centrality index-path/config identity changes.
/// Centrality uses diagnostic runs bound to the supplied measured control identity.
/// Every contrast requires exactly two index entries. Centrality manifests are the driver's
/// bound `*-index-bound.json` files carrying `shard` and `content_sha256`; raw
/// `eval inspect-index` manifests contain neither and are rejected by design.
pub fn validate_contrast(
    before: &Value,
    after: &Value,
    diagnostics: &Value,
    control: &ControlIdentity,
) -> Result<(), EvalError> {
    let feature = cell(after)?;
    validate_contrast_inputs(before, after, diagnostics, control, feature)?;
    if cell(before)? != matching_base(feature)
        || matches!(feature, FeatureCell::BaseOff | FeatureCell::BaseOn)
    {
        return Err(EvalError::IdentityMismatch);
    }
    for (run, current) in [(before, cell(before)?), (after, feature)] {
        if run["planner_expectation"] != json!(current.planner()) || run["schema_version"] != 1 {
            return Err(EvalError::IdentityMismatch);
        }
        let identity = &run["executable"];
        for key in ["sha256", "dirty_tree_sha256"] {
            decoded_sha(identity[key].as_str().ok_or(EvalError::IdentityMismatch)?)?;
        }
        if identity["revision"].as_str().is_none_or(str::is_empty) {
            return Err(EvalError::IdentityMismatch);
        }
    }
    for key in [
        "executable",
        "request",
        "timing_policy",
        "corpus",
        "endpoint",
        "metric_version",
    ] {
        if before[key].is_null() || before[key] != after[key] {
            return Err(EvalError::IdentityMismatch);
        }
    }
    if before["labels"]["sha256"].is_null()
        || before["labels"]["sha256"] != after["labels"]["sha256"]
    {
        return Err(EvalError::IdentityMismatch);
    }
    let old = before["rows"]
        .as_array()
        .ok_or(EvalError::IdentityMismatch)?;
    let new = after["rows"]
        .as_array()
        .ok_or(EvalError::IdentityMismatch)?;
    if old.is_empty() || old.len() != new.len() || old.len() > input::MAX_LABELS {
        return Err(EvalError::IdentityMismatch);
    }
    for (old, new) in old.iter().zip(new) {
        for key in ["id", "query", "category", "acceptable_urls"] {
            if old[key].is_null() || old[key] != new[key] {
                return Err(EvalError::IdentityMismatch);
            }
        }
    }
    let old = config_values(before)?;
    let mut new = config_values(after)?;
    if old[2].get("spell_check").is_some()
        || old[2]["agent_query_planning"] != json!(feature.planner() == Planner::On)
    {
        return Err(EvalError::IdentityMismatch);
    }
    if feature.spelling() {
        let model = new[2]
            .as_object_mut()
            .ok_or(EvalError::IdentityMismatch)?
            .remove("spell_check")
            .ok_or(EvalError::IdentityMismatch)?;
        if model["path"].as_str().is_none_or(str::is_empty) {
            return Err(EvalError::IdentityMismatch);
        }
    } else if new[2].get("spell_check").is_some() {
        return Err(EvalError::IdentityMismatch);
    }
    if old[2] != new[2] {
        return Err(EvalError::IdentityMismatch);
    }
    for ordinal in 0..2 {
        if feature.centrality() {
            let path = new[ordinal]
                .get("index_path")
                .and_then(Value::as_str)
                .ok_or(EvalError::IdentityMismatch)?;
            if path
                == old[ordinal]["index_path"]
                    .as_str()
                    .ok_or(EvalError::IdentityMismatch)?
            {
                return Err(EvalError::IdentityMismatch);
            }
            new[ordinal]["index_path"] = old[ordinal]["index_path"].clone();
        }
        if old[ordinal] != new[ordinal] {
            return Err(EvalError::IdentityMismatch);
        }
        let old_index = &before["indexes"][ordinal]["manifest"];
        let new_index = &after["indexes"][ordinal]["manifest"];
        validate_index_identity(old_index, new_index, feature, diagnostics, control, ordinal)?;
    }
    if before["service"]["manifest"] != after["service"]["manifest"] {
        return Err(EvalError::IdentityMismatch);
    }
    Ok(())
}

/// Validate driver-bound centrality manifests containing `shard` and `content_sha256`.
/// Raw `eval inspect-index` manifests lack those fields and are rejected by design.
fn validate_index_identity(
    old_index: &Value,
    new_index: &Value,
    feature: FeatureCell,
    diagnostics: &Value,
    control: &ControlIdentity,
    ordinal: usize,
) -> Result<(), EvalError> {
    if old_index["documents"].is_null() || old_index["documents"] != new_index["documents"] {
        return Err(EvalError::IdentityMismatch);
    }
    let old_digest = old_index["content_sha256"]
        .as_str()
        .ok_or(EvalError::IdentityMismatch)?;
    let new_digest = new_index["content_sha256"]
        .as_str()
        .ok_or(EvalError::IdentityMismatch)?;
    decoded_sha(old_digest)?;
    decoded_sha(new_digest)?;
    let expected_digest = if feature.centrality() {
        let index = &diagnostics["indexes"][ordinal];
        let (shard, count) = control.counts[ordinal];
        let control_digest = &control.documents[ordinal];
        decoded_sha(control_digest)?;
        if old_digest != control_digest {
            return Err(EvalError::IdentityMismatch);
        }
        if shard != ordinal as u64
            || count > Limits::default().documents as u64
            || old_index["documents"] != count
            || old_index["shard"] != ordinal
            || new_index["shard"] != ordinal
            || index["shard"] != ordinal
            || index["documents"] != new_index["documents"]
            || index["content_sha256"] != *control_digest
        {
            return Err(EvalError::IdentityMismatch);
        }
        index["content_sha256"]
            .as_str()
            .ok_or(EvalError::IdentityMismatch)?
    } else {
        old_digest
    };
    if new_digest != expected_digest {
        return Err(EvalError::IdentityMismatch);
    }
    if !feature.centrality() && old_index != new_index {
        return Err(EvalError::IdentityMismatch);
    }
    Ok(())
}
