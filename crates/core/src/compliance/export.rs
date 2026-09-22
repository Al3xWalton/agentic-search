//! Exports every immutable envelope as inert HTML with an independently checkable receipt.
//! Private wrappers never reach the renderer; output creation cannot replace an existing path.

#![deny(missing_docs)]

use super::{
    bounds::{self, BoundKey},
    clock,
    disk::{self, ComplianceHooks, OpenMode},
    model::sha256,
    record_types::{RecordEnvelope, RecordRef},
    records::{canonical, open_records, RecordView},
    Error, Result,
};
use crate::crawler::politeness::Clock;
use serde::Serialize;
use serde_json::Value;
use std::{fs, io, io::Write, os::unix::fs::DirBuilderExt, path::Path, time::Instant};

/// Canonical envelope digest, excluding the private salt and commitment wrapper.
#[derive(Clone, Serialize)]
pub struct RecordHash {
    /// Exported immutable version.
    pub record_ref: RecordRef,
    /// SHA-256 of its recursively sorted canonical envelope bytes without a final LF.
    pub sha256: String,
}

/// Digest of one emitted HTML file, excluding the self-referential receipt.
#[derive(Clone, Serialize)]
pub struct OutputHash {
    /// Fixed or validated basename, never a private input path.
    pub file: String,
    /// SHA-256 of the exact emitted HTML bytes.
    pub sha256: String,
}

/// Evidence of a completed private export, not an assertion about a production response SLA.
#[derive(Clone, Serialize)]
pub struct ExportReceipt {
    /// Fixed receipt version one.
    pub format_version: u64,
    /// Count of all exported immutable versions.
    pub versions: u64,
    /// Injected start UTC second.
    pub started_at: i64,
    /// Injected end UTC second.
    pub ended_at: i64,
    /// Integer monotonic elapsed milliseconds.
    pub elapsed_ms: u64,
    /// Every canonical envelope digest in reference order.
    pub records: Vec<RecordHash>,
    /// Every HTML output digest in filename order.
    pub outputs: Vec<OutputHash>,
}

/// Encodes the same five HTML metacharacters as the existing policy renderer.
pub fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn document(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta \
            charset=\"utf-8\"><title>{}</title></head><body><article>{}</article></body></html>\n",
        escape_html(title),
        body,
    )
}

fn fields(value: &Value, out: &mut String) {
    match value {
        Value::Object(object) => {
            out.push_str("<dl>");
            for (label, value) in object {
                out.push_str(&format!("<dt>{}</dt><dd>", escape_html(label)));
                fields(value, out);
                out.push_str("</dd>");
            }
            out.push_str("</dl>");
        }
        Value::Array(values) => {
            out.push_str("<ol>");
            for value in values {
                out.push_str("<li>");
                fields(value, out);
                out.push_str("</li>");
            }
            out.push_str("</ol>");
        }
        Value::String(text) => out.push_str(&escape_html(text)),
        value => out.push_str(&escape_html(&value.to_string())),
    }
}

/// Renders every envelope field as labelled text, with no untrusted attributes or links.
pub fn render_record(record: &RecordEnvelope) -> Result<String> {
    let value = serde_json::to_value(record).map_err(|_| Error::InvalidInput)?;
    let mut body = format!(
        "<h1>Record {}</h1>",
        escape_html(&record.reference().to_string())
    );
    fields(&value, &mut body);
    Ok(document("Compliance record", &body))
}

/// Checks the aggregate export expansion budget before any filesystem mutation.
pub fn export_budget(max_records_bytes: u64) -> Result<u64> {
    max_records_bytes
        .checked_mul(8)
        .and_then(|bytes| bytes.checked_add(BoundKey::ReservedJournalBytes.spec().min))
        .ok_or(Error::Capacity)
}

struct Output {
    name: String,
    bytes: Vec<u8>,
}
struct Plan {
    outputs: Vec<Output>,
    receipt: ExportReceipt,
}

fn plan(view: &RecordView, maximum: u64, started_at: i64) -> Result<Plan> {
    let mut index = String::from("<h1>Compliance records</h1><ul>");
    let mut outputs = Vec::new();
    let mut receipt = ExportReceipt {
        format_version: 1,
        versions: 0,
        started_at,
        ended_at: i64::MIN,
        elapsed_ms: u64::MAX,
        records: Vec::new(),
        outputs: Vec::new(),
    };
    let mut total = 0u64;
    for record in view.records().values() {
        let reference = record.reference();
        let name = format!("{}-{}.html", reference.id, reference.version);
        index.push_str(&format!(
            "<li>{}: {}</li>",
            escape_html(&reference.to_string()),
            escape_html(&name)
        ));
        let bytes = render_record(record)?.into_bytes();
        total = bounds::reserve(total, bytes.len() as u64, maximum, 0)?;
        receipt.records.push(RecordHash {
            record_ref: reference,
            sha256: sha256(&[&canonical(record)?]),
        });
        outputs.push(Output { name, bytes });
    }
    index.push_str("</ul>");
    let bytes = document("Compliance records index", &index).into_bytes();
    total = bounds::reserve(total, bytes.len() as u64, maximum, 0)?;
    outputs.push(Output {
        name: "index.html".into(),
        bytes,
    });
    outputs.sort_by(|a, b| a.name.cmp(&b.name));
    receipt.versions = receipt.records.len() as u64;
    receipt.outputs = outputs
        .iter()
        .map(|output| OutputHash {
            file: output.name.clone(),
            sha256: sha256(&[&output.bytes]),
        })
        .collect();
    bounds::reserve(total, canonical(&receipt)?.len() as u64 + 1, maximum, 0)?;
    Ok(Plan { outputs, receipt })
}

fn write_new(path: &Path, bytes: &[u8], hooks: &dyn ComplianceHooks) -> Result<()> {
    let mut file =
        open_records(path, OpenMode::CreateNew, hooks).map_err(|_| Error::Unavailable)?;
    file.write_all(bytes).map_err(|_| Error::Unavailable)?;
    file.sync_all().map_err(|_| Error::Unavailable)?;
    disk::sync_parent(path).map_err(|_| Error::Unavailable)
}

/// Writes a new private export directory; interruptions retain a private failed attempt.
pub fn export(
    view: &RecordView,
    out: &Path,
    clock: &dyn Clock,
    hooks: &dyn ComplianceHooks,
) -> Result<ExportReceipt> {
    let began = Instant::now();
    let started_at = clock.utc().timestamp();
    clock::instant(started_at)?;
    let mut plan = plan(
        view,
        export_budget(BoundKey::MaxRecordsBytes.spec().max)?,
        started_at,
    )?;
    let out = disk::normalized(out).map_err(|_| Error::Unavailable)?;
    match fs::symlink_metadata(&out) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        _ => return Err(Error::Unavailable),
    }
    disk::private_parent(&out).map_err(|_| Error::Unavailable)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&out)
        .map_err(|_| Error::Unavailable)?;
    disk::sync_parent(&out).map_err(|_| Error::Unavailable)?;
    for output in plan.outputs {
        write_new(&out.join(output.name), &output.bytes, hooks)?;
    }
    plan.receipt.ended_at = clock.utc().timestamp();
    clock::instant(plan.receipt.ended_at)?;
    if plan.receipt.ended_at < started_at {
        return Err(Error::Unavailable);
    }
    plan.receipt.elapsed_ms =
        u64::try_from(began.elapsed().as_millis()).map_err(|_| Error::Capacity)?;
    let mut bytes = canonical(&plan.receipt)?;
    bytes.push(b'\n');
    write_new(&out.join("export-receipt.json"), &bytes, hooks)?;
    Ok(plan.receipt)
}
