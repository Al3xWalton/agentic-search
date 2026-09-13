// SPDX-License-Identifier: AGPL-3.0-only
//! Prove copied-index contents and direct served document counts without timed HTTP queries.
//! Pre-open file hashes are retained; shard requests use one literal socket and no retries.
//! This module neither copies nor serves the retained corpus and never opens a source index.

use super::{
    endpoint::Endpoint,
    input,
    output::{self, Output},
    Argument, ArgumentReason, EvalError,
};
use crate::{
    distributed::sonic::{
        self,
        service::{Service, Wrapper},
    },
    entrypoint::search_server::{SearchService, SizeQueryRetrieve},
    generic_query::SizeQuery,
    inverted_index::ShardId,
};
use clap::Args;
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

/// Copied-index inspection inputs.
#[derive(Debug, Args)]
pub struct Inspect {
    /// Independently copied index below the process temporary root.
    #[arg(long)]
    pub index: PathBuf,
    /// Absolute create-new manifest outside the copied index.
    #[arg(long)]
    pub out: PathBuf,
}

/// Direct shard/count pairs, at most eight, in expected backbone-id order.
#[derive(Debug, Args)]
pub struct Verify {
    /// Literal loopback socket, repeated in backbone-id order starting at zero.
    #[arg(long, required = true)]
    pub shard: Vec<String>,
    /// Expected document count for the corresponding shard.
    #[arg(long, required = true)]
    pub expect_documents: Vec<u64>,
    /// Absolute create-new verification report.
    #[arg(long)]
    pub out: PathBuf,
}

/// Maximum copied-index directory depth; the root is depth zero.
pub const MAX_INDEX_DEPTH: usize = 16;

fn collect_paths(
    directory: &Path,
    paths: &mut Vec<PathBuf>,
    entries_seen: &mut usize,
    max_entries: usize,
    max_depth: usize,
    depth: usize,
) -> Result<(), EvalError> {
    if depth > max_depth {
        return Err(EvalError::InputLimit);
    }
    input::inspect_path(directory, false)?;
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(directory).map_err(|_| EvalError::Io)? {
        let entry = entry.map_err(|_| EvalError::Io)?;
        if *entries_seen >= max_entries {
            return Err(EvalError::InputLimit);
        }
        *entries_seen += 1;
        entries.push(entry);
    }
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = input::inspect_path(&entry.path(), false)?;
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| EvalError::Io)?;
        if metadata.is_dir() {
            collect_paths(
                &path,
                paths,
                entries_seen,
                max_entries,
                max_depth,
                depth + 1,
            )?;
        } else {
            paths.push(path);
        }
    }
    Ok(())
}

/// Enumerate bounded entries before hashing any manifest file, preserving sorted relative order.
/// Files and directories share max_entries; directories deeper than max_depth return InputLimit.
/// The supplied depth describes dir relative to root; production begins at zero with empty files.
pub fn walk_bounded(
    root: &Path,
    dir: &Path,
    files: &mut Vec<Value>,
    max_entries: usize,
    max_depth: usize,
    depth: usize,
) -> Result<(), EvalError> {
    let mut paths = Vec::new();
    let mut entries_seen = files.len();
    collect_paths(
        dir,
        &mut paths,
        &mut entries_seen,
        max_entries,
        max_depth,
        depth,
    )?;
    for path in paths {
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| EvalError::Io)?;
        files.push(json!({"path": path.strip_prefix(root).map_err(|_| EvalError::UnsafePath)?, "bytes": metadata.len(), "sha256": input::hash_file(&path)?}));
    }
    Ok(())
}

/// Hash the complete pre-open directory using sorted relative filenames and streamed SHA-256.
pub fn manifest(path: &Path) -> Result<Vec<Value>, EvalError> {
    let path = input::inspect_path(path, false)?;
    let mut files = Vec::new();
    walk_bounded(
        &path,
        &path,
        &mut files,
        input::MAX_RECORDS,
        MAX_INDEX_DEPTH,
        0,
    )?;
    Ok(files)
}

/// Open only a temporary copied index after recording its immutable pre-open manifest.
pub async fn inspect(args: Inspect) -> Result<(), EvalError> {
    output::external(&args.out, std::slice::from_ref(&args.index))?;
    let output =
        Output::reserve(&args.out, false).map_err(|error| error.argument(Argument::Out))?;
    let path = input::argument_path(&args.index, false, Argument::Index)?;
    let temporary = std::env::temp_dir()
        .canonicalize()
        .map_err(|_| EvalError::Io)?;
    if !path.starts_with(temporary) {
        return Err(EvalError::Argument {
            argument: Argument::Index,
            reason: ArgumentReason::IndexTemporary,
        });
    }
    let files = manifest(&path).map_err(|error| error.argument(Argument::Index))?;
    if files.is_empty() {
        return Err(EvalError::InvalidInput.argument(Argument::Index));
    }
    let index = crate::index::Index::open(&path)
        .map_err(|_| EvalError::InvalidInput.argument(Argument::Index))?;
    let searcher =
        crate::searcher::LocalSearcher::builder(Arc::new(tokio::sync::RwLock::new(index))).build();
    let documents = searcher.num_documents().await;
    output.finish(&json!({"schema_version": 1, "index": path, "pre_open_files": files, "documents": documents}))
}

/// Validate pairing and membership before opening any connection.
pub fn pairs(args: &Verify) -> Result<Vec<std::net::SocketAddr>, EvalError> {
    if args.shard.is_empty()
        || args.shard.len() > 8
        || args.shard.len() != args.expect_documents.len()
    {
        return Err(EvalError::InvalidInput);
    }
    let sockets: Vec<_> = args
        .shard
        .iter()
        .map(|s| Endpoint::shard(s))
        .collect::<Result<_, _>>()?;
    if sockets.iter().collect::<HashSet<_>>().len() != sockets.len() {
        return Err(EvalError::InvalidInput);
    }
    Ok(sockets)
}

/// Send exactly SizeQuery and its retrieve pair on one direct connection per named shard.
pub async fn verify(args: Verify) -> Result<(), EvalError> {
    let sockets = pairs(&args).map_err(|error| error.argument(Argument::Shard))?;
    output::external(&args.out, &[])?;
    let output =
        Output::reserve(&args.out, false).map_err(|error| error.argument(Argument::Out))?;
    let mut shards = Vec::new();
    let mut total = 0u64;
    for (ordinal, (socket, expected)) in sockets.into_iter().zip(args.expect_documents).enumerate()
    {
        let result = tokio::time::timeout(Duration::from_secs(60), async {
            let mut conn = sonic::Connection::<
                crate::OneOrMany<<SearchService as Service>::Request>,
                crate::OneOrMany<<SearchService as Service>::Response>,
            >::create(socket)
            .await
            .map_err(|_| EvalError::Network)?;
            let response = conn
                .send(&crate::OneOrMany::One(SizeQuery::wrap_request(SizeQuery)))
                .await
                .map_err(|_| EvalError::Network)?
                .one()
                .ok_or(EvalError::InvalidResponse)?;
            let fruit = SizeQuery::unwrap_response(response)
                .ok_or(EvalError::InvalidResponse)?
                .map_err(|_| EvalError::InvalidResponse)?;
            let id = ShardId::Backbone(ordinal as u64);
            if fruit.len() != 1 || fruit.get(&id).is_none_or(|v| v.pages != expected) {
                return Err(EvalError::IdentityMismatch);
            }
            let response = conn
                .send(&crate::OneOrMany::One(SizeQueryRetrieve::wrap_request(
                    SizeQueryRetrieve {
                        query: SizeQuery,
                        fruit,
                    },
                )))
                .await
                .map_err(|_| EvalError::Network)?
                .one()
                .ok_or(EvalError::InvalidResponse)?;
            let size = SizeQueryRetrieve::unwrap_response(response)
                .ok_or(EvalError::InvalidResponse)?
                .map_err(|_| EvalError::InvalidResponse)?;
            if size.pages != expected {
                return Err(EvalError::IdentityMismatch);
            }
            Ok::<_, EvalError>(size.pages)
        })
        .await
        .map_err(|_| EvalError::Timeout)??;
        total = total
            .checked_add(result)
            .ok_or(EvalError::IdentityMismatch)?;
        shards.push(json!({"socket": socket, "shard_id": ordinal, "documents": result}));
    }
    output.finish(&json!({"schema_version": 1, "verified": true, "shards": shards, "total_documents": total, "protocol": "SizeQuery then SizeQueryRetrieve; one connection per shard; no HTTP searches"}))
}
