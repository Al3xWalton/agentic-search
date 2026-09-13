// SPDX-License-Identifier: AGPL-3.0-only
//! Local, reproducible recall evaluation over an already running loopback search service.
//! Inputs and outputs are bounded, identities explicit, and failures never become scored zeros.
//! This module does not fetch pages, serve indexes, tune queries, or implement feature panels.

use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub mod diff;
pub mod endpoint;
pub mod index;
pub mod input;
pub mod labels;
pub mod metrics;
pub mod normalize;
pub mod output;
pub mod runner;

/// Finite, query-independent failures emitted by the local evaluator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[error("evaluation failed: {self:?}")]
pub enum EvalError {
    /// Argument validation failed for a fixed argument name and fixed, non-echoing reason.
    #[error("evaluation failed: {argument}: {reason}")]
    Argument {
        /// CLI argument responsible for the rejected input or output.
        argument: Argument,
        /// Finite rule that rejected the argument.
        reason: ArgumentReason,
    },
    /// A path contains forbidden components, aliases, permissions, or a special file.
    UnsafePath,
    /// Filesystem operation failed without exposing its input text.
    Io,
    /// An input changed identity while in use.
    InputChanged,
    /// An ordinary input exceeds 64 MiB or a record exceeds 8 MiB.
    InputLimit,
    /// Corpus record count exceeds one million.
    CorpusLimit,
    /// Label count exceeds one thousand.
    LabelLimit,
    /// An answer list exceeds 32 entries.
    AnswerLimit,
    /// A URL exceeds 8192 UTF-8 bytes.
    UrlLimit,
    /// A URL has malformed components.
    InvalidUrl,
    /// A scoring field or document structure is invalid.
    InvalidInput,
    /// Frozen label protocol or corpus membership failed.
    InvalidLabels,
    /// The output or a reserved sibling already exists.
    OutputExists,
    /// The raw endpoint is not an explicit literal loopback address.
    InvalidEndpoint,
    /// A single network attempt failed.
    Network,
    /// The whole network attempt exceeded its deadline.
    Timeout,
    /// A response exceeds 8 MiB.
    ResponseLimit,
    /// HTTP status is unsuccessful, including every redirect.
    HttpStatus,
    /// Returned JSON or provenance violates the contract.
    InvalidResponse,
    /// Served/index/config identities are inconsistent.
    IdentityMismatch,
    /// An acceptance run completed but did not satisfy its gates.
    AcceptanceFailed,
}

/// Fixed CLI argument names used in validation diagnostics; paths and labels are never interpolated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum Argument {
    /// Input index copy.
    #[error("--index")]
    Index,
    /// Output report.
    #[error("--out")]
    Out,
    /// Label document.
    #[error("--labels")]
    Labels,
    /// Reference labels for disjointness.
    #[error("--disjoint-from")]
    DisjointFrom,
    /// Corpus JSONL export.
    #[error("--corpus-jsonl")]
    Corpus,
    /// Served shard proof.
    #[error("--service-manifest")]
    ServiceManifest,
    /// Pre-open index proof.
    #[error("--index-manifest")]
    IndexManifest,
    /// Resolved configuration.
    #[error("--config")]
    Config,
    /// Before run.
    #[error("--before")]
    Before,
    /// After run.
    #[error("--after")]
    After,
    /// Shard/count argument pairing.
    #[error("--shard")]
    Shard,
}

/// Finite validation reasons; messages contain no user-controlled text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum ArgumentReason {
    /// Absolute output paths are required.
    #[error("output must be an absolute path")]
    AbsoluteOutput,
    /// Raw dot, control or invalid path components.
    #[error("path has forbidden components")]
    Components,
    /// No path component may be a symbolic link.
    #[error("path has a symlink component")]
    Symlink,
    /// Only private descendants of trusted temporary/root boundaries are accepted.
    #[error("writable ancestor outside the trusted temporary boundary")]
    WritableAncestor,
    /// Ancestors must belong to the runner or root.
    #[error("path ancestor has an untrusted owner")]
    Owner,
    /// File inputs must be regular.
    #[error("input must be a regular file with directory ancestors")]
    RegularFile,
    /// Byte, entry or depth cap.
    #[error("input exceeds its byte, entry or depth limit")]
    Limit,
    /// Required typed input structure.
    #[error("input has missing, mistyped or invalid fields")]
    Structure,
    /// Index inspection only opens independent temporary copies.
    #[error("index must be a copy under the canonical temporary directory")]
    IndexTemporary,
    /// Product contents must remain read-only to the harness.
    #[error("output inside the repository")]
    OutputRepository,
    /// Output cannot alias a source directory.
    #[error("output inside an input directory")]
    OutputInput,
}

impl EvalError {
    /// Attach a fixed CLI argument to path, structure or limit failures; preserve other errors.
    pub fn argument(self, argument: Argument) -> Self {
        let reason = match self {
            Self::UnsafePath => ArgumentReason::Components,
            Self::InvalidInput => ArgumentReason::Structure,
            Self::InputLimit => ArgumentReason::Limit,
            _ => return self,
        };
        Self::Argument { argument, reason }
    }
}

/// Planner expectation validates provenance without changing the HTTP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Planner {
    /// The service must execute strict-only mode.
    Off,
    /// The service must execute staged mode.
    On,
}

/// Explicit evaluation protocol; diagnostic results never certify Story acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Suite {
    /// The retained regression label set.
    Frozen,
    /// The frozen, balanced second-rater label set.
    HeldOut,
    /// Generic synthetic or exploratory measurements.
    Diagnostic,
}

/// Recall inputs and output identities; paths are guarded before networking.
#[derive(Debug, Args)]
pub struct Recall {
    /// Frozen labels, at most 64 MiB and 1000 rows.
    #[arg(long)]
    pub labels: PathBuf,
    /// Expected SHA-256 of exact label bytes.
    #[arg(long)]
    pub labels_sha256: String,
    /// Indexed JSONL exports, streamed with 8 MiB record bounds.
    #[arg(long, required = true)]
    pub corpus_jsonl: Vec<PathBuf>,
    /// Explicit literal HTTP loopback base.
    #[arg(long)]
    pub endpoint: String,
    /// Required service planner mode.
    #[arg(long, value_enum)]
    pub expect_planner: Planner,
    /// Explicit acceptance protocol.
    #[arg(long, value_enum)]
    pub suite: Suite,
    /// Local feature-cell identity.
    #[arg(long)]
    pub cell: String,
    /// Successful direct-shard verification report.
    #[arg(long)]
    pub service_manifest: PathBuf,
    /// Pre-open copied-index reports.
    #[arg(long, required = true)]
    pub index_manifest: Vec<PathBuf>,
    /// Resolved service configuration files.
    #[arg(long, required = true)]
    pub config: Vec<PathBuf>,
    /// Absolute create-new output, outside repository and input directories.
    #[arg(long)]
    pub out: PathBuf,
}

/// Existing binary's evaluation subtree; each helper shares guarded I/O.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Measure each label once in file order with a fresh HTTP/1 connection.
    Recall(Recall),
    /// Compare runs by label identity, optionally importing the frozen spike.
    Diff(diff::Arguments),
    /// Validate label identities, membership and optional held-out disjointness.
    ValidateLabels(labels::Arguments),
    /// Inspect an independently copied index after recording its pre-open hashes.
    InspectIndex(index::Inspect),
    /// Prove direct shard ids and document counts without any HTTP search.
    VerifyService(index::Verify),
}

impl Command {
    /// Execute one local operation; returns a finite error and never retries a failed run.
    pub async fn run(self) -> Result<(), EvalError> {
        self.validate_paths()?;
        match self {
            Self::Recall(args) => runner::run(args).await,
            Self::Diff(args) => diff::run(args),
            Self::ValidateLabels(args) => labels::run(args),
            Self::InspectIndex(args) => index::inspect(args).await,
            Self::VerifyService(args) => index::verify(args).await,
        }
    }

    fn validate_paths(&self) -> Result<(), EvalError> {
        let mut paths = Vec::new();
        let out = match self {
            Self::Recall(a) => {
                paths.push((&a.labels, Argument::Labels, false));
                paths.push((&a.service_manifest, Argument::ServiceManifest, false));
                paths.extend(a.corpus_jsonl.iter().map(|p| (p, Argument::Corpus, false)));
                paths.extend(
                    a.index_manifest
                        .iter()
                        .map(|p| (p, Argument::IndexManifest, false)),
                );
                paths.extend(a.config.iter().map(|p| (p, Argument::Config, false)));
                &a.out
            }
            Self::Diff(a) => {
                paths.push((&a.before, Argument::Before, false));
                paths.push((&a.after, Argument::After, false));
                paths.extend(a.labels.iter().map(|p| (p, Argument::Labels, false)));
                &a.out
            }
            Self::ValidateLabels(a) => {
                paths.push((&a.labels, Argument::Labels, false));
                paths.extend(a.corpus_jsonl.iter().map(|p| (p, Argument::Corpus, false)));
                paths.extend(
                    a.disjoint_from
                        .iter()
                        .map(|p| (p, Argument::DisjointFrom, false)),
                );
                &a.out
            }
            Self::InspectIndex(a) => {
                paths.push((&a.index, Argument::Index, true));
                &a.out
            }
            Self::VerifyService(a) => &a.out,
        };
        input::argument_path(out, true, Argument::Out)?;
        for (path, argument, directory) in paths {
            let path = input::argument_path(path, false, argument)?;
            if !directory
                && !std::fs::symlink_metadata(path)
                    .map_err(|_| EvalError::Io)?
                    .is_file()
            {
                return Err(EvalError::Argument {
                    argument,
                    reason: ArgumentReason::RegularFile,
                });
            }
        }
        Ok(())
    }
}
