//! Regression guard for unavailable contexts in workflow/job env, pinned uses, and runs-on presence.
//! This short, hand-maintained workflow is checked line by line, not as a security control.
//! Dotted and bracket contexts and same-line flow-map env blocks are checked.
//! Block scalars, quoted keys, and other exotic YAML forms are out of scope.
//! GitHub's parser is the authority: rejected workflows fail loudly with zero jobs in the run summary.
//! A YAML-parser dependency is unnecessary for this deliberately limited authoring guard.

use anyhow::{bail, Context, Result};
use std::{fs, path::Path};

fn forbidden_context(value: &str, forbidden: &[&str]) -> bool {
    value.split("${{").skip(1).any(|expression| {
        let expression = expression.split("}}").next().unwrap_or_default();
        expression
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '.')
            .any(|token| forbidden.iter().any(|context| token.starts_with(context)))
            || forbidden.iter().any(|context| {
                let name = context.trim_end_matches('.');
                expression.match_indices(name).any(|(start, _)| {
                    let boundary = expression[..start]
                        .chars()
                        .next_back()
                        .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '.');
                    boundary
                        && expression[start + name.len()..]
                            .trim_start()
                            .starts_with('[')
                })
            })
    })
}

fn pinned_action(value: &str) -> bool {
    value.rsplit_once('@').is_some_and(|(_, revision)| {
        revision.len() == 40
            && revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn finish_job(job: Option<(usize, &str, bool)>, errors: &mut Vec<String>) {
    if let Some((line, name, false)) = job {
        errors.push(format!("line {line}: job {name} is missing runs-on"));
    }
}

/// Reject workflow context misuse, action refs without a full SHA, and jobs without runners.
pub fn workflow_lint(path: &Path) -> Result<()> {
    let source =
        fs::read_to_string(path).with_context(|| format!("read workflow {}", path.display()))?;
    let mut errors = Vec::new();
    let mut workflow_env = false;
    let mut jobs = false;
    let mut job = None;
    let mut job_env = false;
    for (index, line) in source.lines().enumerate() {
        let number = index + 1;
        let text = line.trim_start();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        let indent = line.len() - text.len();
        let entry = text.strip_prefix("- ").unwrap_or(text);
        let (key, value) = entry.split_once(':').unwrap_or((entry, ""));
        let key = key.trim();
        let value = value.split(" #").next().unwrap_or_default().trim();
        let flow_map = key == "env" && value.starts_with('{');
        if indent == 0 {
            finish_job(job.take(), &mut errors);
            workflow_env = key == "env";
            jobs = key == "jobs";
            job_env = false;
        }
        if jobs && indent == 2 {
            finish_job(job.take(), &mut errors);
            job = Some((number, key, false));
            job_env = false;
        }
        if indent == 4 {
            if let Some((_, _, has_runner)) = &mut job {
                job_env = key == "env";
                if key == "runs-on" {
                    *has_runner = true;
                }
            }
        }
        if workflow_env
            && (indent > 0 || flow_map)
            && forbidden_context(
                text,
                &[
                    "runner.",
                    "env.",
                    "steps.",
                    "job.",
                    "matrix.",
                    "strategy.",
                    "needs.",
                ],
            )
        {
            errors.push(format!(
                "line {number}: unavailable context in workflow env"
            ));
        }
        if job_env
            && (indent > 4 || flow_map)
            && forbidden_context(text, &["runner.", "env.", "steps.", "job."])
        {
            errors.push(format!("line {number}: unavailable context in job env"));
        }
        if key == "uses" && !pinned_action(value.trim_matches(['\'', '"'])) {
            errors.push(format!(
                "line {number}: uses must end in @ plus 40 lowercase hex characters"
            ));
        }
    }
    finish_job(job, &mut errors);
    if !errors.is_empty() {
        bail!("{}:\n{}", path.display(), errors.join("\n"));
    }
    println!("workflow-lint: {} passed", path.display());
    Ok(())
}
