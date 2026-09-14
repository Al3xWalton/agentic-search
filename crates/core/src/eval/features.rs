// SPDX-License-Identifier: AGPL-3.0-only
//! Inspect bounded local feature assets and compare independently measured feature panels.
//! Store readers operate only on private independent snapshots, with source identities
//! checked before and after use. Counts retain duplicates; coverage uses unique host ids.
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
    /// Graph root containing the existing `edges` index, below canonical TMPDIR.
    #[arg(long)]
    pub graph: PathBuf,
    /// Parent containing both harmonic host stores, below canonical TMPDIR.
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

fn directory_inner(path: &Path, argument: Argument) -> Result<PathBuf, EvalError> {
    let path = input::argument_path(path, false, argument)?;
    let metadata = fs::symlink_metadata(&path).map_err(|_| EvalError::Io)?;
    let temporary = input::inspect_path(&std::env::temp_dir(), false)?
        .canonicalize()
        .map_err(|_| EvalError::Io)?;
    if !metadata.is_dir() {
        return Err(EvalError::InvalidInput.argument(argument));
    }
    if path == temporary || !path.starts_with(&temporary) {
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
            | T::RecipeFirstIngredientTagId(_)
            | T::Keywords(_),
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
    /// Hash of the sorted multiset of exact URL bytes and canonical content hashes.
    pub content_sha256: String,
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
/// A missing/reordered query, wrong mode, failed HTTP attempt or malformed response fails.
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
            || !row["error"].is_null()
        {
            return Err(EvalError::IdentityMismatch);
        }
        let expected = if ordinal < 8 {
            Planner::Off
        } else {
            Planner::On
        };
        super::runner::response(&row["response"], expected)?;
        values.push(json!({"query":row["query"],"mode":mode,"status":row["status"],"response":retrieval_identity(&row["response"])?}));
    }
    Ok(values)
}

/// Content and fixed-query identities of one ordered pair, independent of physical segments.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlIdentity {
    /// Ordered (backbone shard id, live document count) pairs.
    pub counts: Vec<(u64, u64)>,
    /// One sorted document-multiset SHA-256 per shard, in the same order.
    pub documents: Vec<String>,
    /// Sixteen raw fixed-query observations, validated during comparison; empty for centrality.
    pub rankings: Vec<Value>,
}

/// Opaque control components derived from observations and content identities.
/// Deserialization is only transport: the gate recomputes every flag before accepting it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlVerdict {
    /// Whether the control comparison actually completed, including measured mismatches.
    completed: bool,
    /// Ordered retained/control counts agree with each other and the expected pair.
    counts_match: bool,
    /// Retained/control document-content multisets agree per shard.
    content_matches: bool,
    /// Both fixed-query modes agree in all nontiming result content.
    rankings_match: bool,
    /// Control/centrality counts and content agree; their rankings may differ.
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
    /// Compare ordered counts/content and validated fixed-query rankings against a control.
    /// Expected counts are caller-supplied fixture/retained facts, never inferred from totals.
    pub fn comparable(
        &self,
        control: &Self,
        centrality: &Self,
        expected: [(u64, u64); 2],
    ) -> ControlVerdict {
        let retained = self;
        let counts_match = retained.counts == control.counts;
        let content_matches = retained.documents == control.documents;
        let retained_rankings = fixed_query_identities(&retained.rankings).ok();
        let control_rankings = fixed_query_identities(&control.rankings).ok();
        let rankings_match = retained_rankings == control_rankings;
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
            && retained_rankings.is_some()
            && control_rankings.is_some();
        let counts_match = counts_match && retained.counts == expected;
        let content_matches = content_matches
            && retained.documents.len() == 2
            && retained
                .documents
                .iter()
                .all(|digest| decoded_sha(digest).is_ok());
        let rankings_match =
            rankings_match && retained_rankings.is_some() && control_rankings.is_some();
        let centrality_content_matches = centrality.counts == control.counts
            && centrality.counts == expected
            && centrality.documents == control.documents;
        ControlVerdict {
            completed,
            counts_match,
            content_matches,
            rankings_match,
            centrality_content_matches,
            comparable: completed
                && counts_match
                && content_matches
                && rankings_match
                && centrality_content_matches,
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

    /// Whether validated identities and all sixteen observations per measured pair are present.
    pub fn completed(&self) -> bool {
        self.completed
    }
    /// Whether every control component matched; required for centrality feature cells.
    pub fn comparable(&self) -> bool {
        self.comparable
    }
    /// Whether ordered counts matched the retained pair and expected per-shard counts.
    pub fn counts_match(&self) -> bool {
        self.counts_match
    }
    /// Whether the retained/control document multisets matched per shard.
    pub fn content_matches(&self) -> bool {
        self.content_matches
    }
    /// Whether all validated fixed-query responses matched apart from durations.
    pub fn rankings_match(&self) -> bool {
        self.rankings_match
    }
    /// Whether the control/centrality counts and content matched the expected pair.
    pub fn centrality_content_matches(&self) -> bool {
        self.centrality_content_matches
    }
}

/// Derive a control from bounded identity JSON and four observation files in retained-off,
/// retained-on, control-off, control-on order. Missing/malformed evidence fails closed.
/// The input seal binds these comparison inputs and the caller's frozen envelope SHA-256.
pub fn control_from_files(
    identities: &Path,
    observations: &[PathBuf; 4],
    expected: [(u64, u64); 2],
    input_identity: &str,
) -> Result<ControlVerdict, EvalError> {
    let documents = read_metadata(identities, &Limits::default())?;
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
        for index in indexes {
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
        if ordinal < 2 {
            for path in &observations[ordinal * 2..ordinal * 2 + 2] {
                let observation = read_metadata(path, &Limits::default())?;
                let rows = observation["rows"]
                    .as_array()
                    .filter(|rows| rows.len() <= 8)
                    .ok_or(EvalError::IdentityMismatch)?;
                identity.rankings.extend(rows.iter().cloned());
            }
        }
        comparisons.push(identity);
    }
    comparisons[0]
        .comparable(&comparisons[1], &comparisons[2], expected)
        .sealed(input_identity)
}

/// The six isolated feature cells; there is deliberately no combined-feature variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FeatureCell {
    /// Retained indexes, planner off, no spelling.
    BaseOff,
    /// Retained indexes, planner on, no spelling.
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

/// Return the retained baseline with the same planner mode; never attribute feature gain to planning.
pub fn matching_base(cell: FeatureCell) -> FeatureCell {
    match cell.planner() {
        Planner::Off => FeatureCell::BaseOff,
        Planner::On => FeatureCell::BaseOn,
    }
}

/// Enforce the completed control gate before held-out access and comparability for centrality.
/// A completed mismatch permits retained-base/spelling cells; stale or changed seals fail.
pub fn require_control_before_held_out(
    control: &ControlVerdict,
    held_out: bool,
    cell: FeatureCell,
    expected_input_identity: &str,
    identities: &Path,
    observations: &[PathBuf; 4],
    expected_counts: [(u64, u64); 2],
) -> Result<(), EvalError> {
    let recomputed = control_from_files(
        identities,
        observations,
        expected_counts,
        expected_input_identity,
    )?;
    if *control != recomputed {
        return Err(EvalError::IdentityMismatch);
    }
    if held_out && !control.completed {
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

/// Validate a native run contrast before the existing evaluator diff is called.
/// Requires the matching-mode base, identical labels/executable/timing/request/corpus, and
/// only the declared spelling section or centrality index-path/config identity changes.
pub fn validate_contrast(
    before: &Value,
    after: &Value,
    diagnostics: &Value,
) -> Result<(), EvalError> {
    let feature = cell(after)?;
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
        validate_index_identity(old_index, new_index, feature, diagnostics, ordinal)?;
    }
    if before["service"]["manifest"] != after["service"]["manifest"] {
        return Err(EvalError::IdentityMismatch);
    }
    Ok(())
}

fn validate_index_identity(
    old_index: &Value,
    new_index: &Value,
    feature: FeatureCell,
    diagnostics: &Value,
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
        if index["shard"] != ordinal || index["documents"] != new_index["documents"] {
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
