// SPDX-License-Identifier: AGPL-3.0-only
//! Validate scoring fields independently of flexible label metadata.
//! Corpus membership uses only each indexed record's first URL; held-out rules are explicit.
//! This module does not infer answers, relabel failures, or inspect query performance.

use super::{input, normalize::normalize, output::Output, EvalError};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeSet, HashSet},
    path::{Path, PathBuf},
};

/// Allowed category values, independent of category output ordering.
pub const CATEGORIES: [&str; 5] = [
    "factual",
    "how_to_technical",
    "product_commerce",
    "recent_news",
    "image_bearing",
];
/// Frozen second-rater identity, ratified independently of retrieval results.
pub const SECOND_RATER: &str = "gemini-3.8-flash-high via agy";

/// One strictly typed scoring record with separately preserved metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Label {
    /// Unique, nonempty identifier; never used as a filesystem name.
    pub id: String,
    /// One of the five evaluation categories.
    pub category: String,
    /// Original bounded query bytes sent unchanged.
    pub query: String,
    /// One to 32 acceptable URL strings, each at most 8192 bytes.
    pub acceptable_urls: Vec<String>,
    /// Non-scoring fields retained without imposing one metadata shape.
    #[serde(flatten)]
    pub metadata: serde_json::Map<String, Value>,
}

impl Label {
    /// Distinct normalized answers form the recall denominator; an empty set is invalid.
    pub fn answers(&self) -> Result<BTreeSet<String>, EvalError> {
        self.acceptable_urls.iter().map(|s| normalize(s)).collect()
    }
}

/// A hash-verified label document, preserving root metadata as JSON.
#[derive(Debug)]
pub struct Labels {
    /// Immutable source bytes and identity.
    pub document: input::Document,
    /// Query records in original file order.
    pub rows: Vec<Label>,
    /// Root fields other than queries, including nullable or structured corpus data.
    pub metadata: Value,
}

impl Labels {
    /// Read and validate scoring shape, bounds and the supplied exact SHA before use.
    pub fn read(path: &Path, expected: &str) -> Result<Self, EvalError> {
        let document = input::read(path)?;
        if expected.len() != 64 || document.sha256 != expected {
            return Err(EvalError::InputChanged);
        }
        let mut value: Value =
            serde_json::from_slice(&document.bytes).map_err(|_| EvalError::InvalidInput)?;
        let object = value.as_object_mut().ok_or(EvalError::InvalidInput)?;
        let queries = object.remove("queries").ok_or(EvalError::InvalidInput)?;
        let array = queries.as_array().ok_or(EvalError::InvalidInput)?;
        if array.len() > input::MAX_LABELS {
            return Err(EvalError::LabelLimit);
        }
        if array.is_empty() {
            return Err(EvalError::InvalidLabels);
        }
        let rows: Vec<Label> =
            serde_json::from_value(queries).map_err(|_| EvalError::InvalidInput)?;
        let mut ids = HashSet::new();
        for label in &rows {
            if label.id.is_empty()
                || !ids.insert(&label.id)
                || !CATEGORIES.contains(&label.category.as_str())
            {
                return Err(EvalError::InvalidLabels);
            }
            if label.acceptable_urls.len() > input::MAX_ANSWERS {
                return Err(EvalError::AnswerLimit);
            }
            if label.acceptable_urls.is_empty() {
                return Err(EvalError::InvalidLabels);
            }
            crate::query::planner::bounds::validate_query(&label.query)
                .map_err(|_| EvalError::InvalidLabels)?;
            label.answers()?;
        }
        input::verify(&document.path, expected)?;
        Ok(Self {
            document,
            rows,
            metadata: value,
        })
    }

    /// Require frozen status and a recorded rater; held-out additionally fixes balance and identity.
    pub fn protocol(&self, held_out: bool) -> Result<(), EvalError> {
        if self.metadata["status"] != "frozen"
            || self.metadata["labeller"].as_str().is_none_or(str::is_empty)
        {
            return Err(EvalError::InvalidLabels);
        }
        if held_out {
            if self.rows.len() != 50
                || self.metadata["labeller"] != SECOND_RATER
                || self.metadata["frozen_at_utc"] != "2026-09-12T15:38:56Z"
            {
                return Err(EvalError::InvalidLabels);
            }
            let ids: BTreeSet<_> = self.rows.iter().map(|r| r.id.clone()).collect();
            if ids != (1..=50).map(|n| format!("h{n:02}")).collect() {
                return Err(EvalError::InvalidLabels);
            }
            if CATEGORIES
                .iter()
                .any(|cat| self.rows.iter().filter(|r| r.category == *cat).count() != 10)
            {
                return Err(EvalError::InvalidLabels);
            }
            let mut answers = HashSet::new();
            for row in &self.rows {
                if row.acceptable_urls.len() != 1
                    || !answers.insert(normalize(&row.acceptable_urls[0])?)
                {
                    return Err(EvalError::InvalidLabels);
                }
            }
        }
        Ok(())
    }

    /// Every normalized answer must occur in the copied indexed corpus, with optional disjointness.
    pub fn membership(&self, corpus: &Corpus, disjoint: Option<&Labels>) -> Result<(), EvalError> {
        let forbidden: BTreeSet<String> = disjoint
            .map(|set| {
                set.rows
                    .iter()
                    .map(Label::answers)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default()
            .into_iter()
            .flatten()
            .collect();
        for row in &self.rows {
            for answer in row.answers()? {
                if !corpus.urls.contains(&answer) || forbidden.contains(&answer) {
                    return Err(EvalError::InvalidLabels);
                }
            }
        }
        Ok(())
    }
}

/// Streamed corpus membership and exact export identities.
#[derive(Debug)]
pub struct Corpus {
    /// Unique normalized first-URL identities.
    pub urls: HashSet<String>,
    /// Total JSONL records, including normalized duplicates.
    pub total: usize,
    /// Per-file SHA-256 and counts in supplied order.
    pub files: Vec<Value>,
}

impl Corpus {
    /// Read indexed exports without allocating their complete contents.
    pub fn read(paths: &[PathBuf]) -> Result<Self, EvalError> {
        let mut corpus = Self {
            urls: HashSet::new(),
            total: 0,
            files: Vec::new(),
        };
        for path in paths {
            let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
            let before = input::file_identity(path)?;
            let count = input::records(path, &mut corpus.total, |record| {
                digest.update(record);
                let value: Value =
                    serde_json::from_slice(record).map_err(|_| EvalError::InvalidInput)?;
                let url = value["url"]
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(Value::as_str)
                    .ok_or(EvalError::InvalidInput)?;
                corpus.urls.insert(normalize(url)?);
                Ok(())
            })?;
            if before != input::file_identity(path)? {
                return Err(EvalError::InputChanged);
            }
            let sha256: String = digest
                .finish()
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            corpus
                .files
                .push(json!({"path": input::absolute(path)?, "sha256": sha256, "records": count, "identity": before}));
        }
        Ok(corpus)
    }

    /// Serializable corpus record and normalized-identity totals.
    pub fn manifest(&self) -> Value {
        json!({"files": self.files, "total_documents": self.total, "unique_normalized_urls": self.urls.len()})
    }

    /// Re-hash every recorded corpus export before publishing a completed run.
    /// Same-length, same-mtime edits still return InputChanged; malformed identities fail closed.
    pub fn verify_unchanged(&self) -> Result<(), EvalError> {
        for file in &self.files {
            let path =
                std::path::Path::new(file["path"].as_str().ok_or(EvalError::IdentityMismatch)?);
            let expected = file["sha256"].as_str().ok_or(EvalError::IdentityMismatch)?;
            if input::hash_file(path)? != expected {
                return Err(EvalError::InputChanged);
            }
        }
        Ok(())
    }
}

/// Label validation arguments; disjointness explicitly selects the held-out protocol.
#[derive(Debug, Args)]
pub struct Arguments {
    /// Labels, bounded to 64 MiB.
    #[arg(long)]
    pub labels: PathBuf,
    /// Expected SHA-256.
    #[arg(long)]
    pub labels_sha256: String,
    /// Indexed corpus exports.
    #[arg(long, required = true)]
    pub corpus_jsonl: Vec<PathBuf>,
    /// Frozen reference whose answers must not overlap.
    #[arg(long)]
    pub disjoint_from: Option<PathBuf>,
    /// Private, absolute create-new report.
    #[arg(long)]
    pub out: PathBuf,
}

/// Validate labels and write a completion report only after post-use hash verification.
pub fn run(args: Arguments) -> Result<(), EvalError> {
    use super::Argument;
    let mut inputs = vec![args.labels.clone()];
    inputs.extend(args.corpus_jsonl.iter().cloned());
    inputs.extend(args.disjoint_from.iter().cloned());
    super::output::external(&args.out, &inputs)?;
    let output = Output::reserve(&args.out, false).map_err(|e| e.argument(Argument::Out))?;
    let labels = Labels::read(&args.labels, &args.labels_sha256)
        .map_err(|e| e.argument(Argument::Labels))?;
    labels.protocol(args.disjoint_from.is_some())?;
    let corpus = Corpus::read(&args.corpus_jsonl).map_err(|e| e.argument(Argument::Corpus))?;
    let other = args
        .disjoint_from
        .as_ref()
        .map(|p| {
            let doc = input::read(p).map_err(|e| e.argument(Argument::DisjointFrom))?;
            Labels::read(p, &doc.sha256).map_err(|e| e.argument(Argument::DisjointFrom))
        })
        .transpose()?;
    labels.membership(&corpus, other.as_ref())?;
    input::verify(&args.labels, &args.labels_sha256)?;
    if let Some(other) = other {
        input::verify(&other.document.path, &other.document.sha256)?;
    }
    output.finish(&json!({"schema_version": 1, "valid": true, "labels_sha256": args.labels_sha256, "metadata": labels.metadata, "rows": labels.rows.len(), "corpus": corpus.manifest(), "held_out": args.disjoint_from.is_some()}))
}
