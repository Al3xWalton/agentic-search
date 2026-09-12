//! Renders the twelve stable policy sections from the same validated inputs used for ingestion.
//! Rendering is deterministic and never asserts publication or legal approval. It does not grant
//! production permission, enforce serving policy or verify deployed egress ownership.

#![deny(missing_docs)]

use super::{
    identity::build_user_agent,
    politeness::{
        HARD_MAX_HOST_CONCURRENCY, HARD_MIN_HOST_GAP_MS, MAX_ACCEPTED_CRAWL_DELAY_SECS,
        MAX_ROBOTS_CACHE_SECS, MIN_BLOCK_SECS, ROBOTS_FAILURE_RETRY_SECS,
    },
};
use crate::config::{ingestion::ValidatedPolicy, CrawlerConfig};
use anyhow::Context;
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

/// Atomically replaces rendered UTF-8 policy text, using a same-directory create_new temp file.
/// The parent must exist and canonicalize to a directory; out may be absent or a regular file,
/// but never a symlink (including dangling) or another file type. The replacement mode is 0o644.
/// Failed writes/renames remove the owned temp file; errors identify their step and path.
/// This helper does not publish the policy or confer legal approval.
pub fn write_rendered(out: &Path, text: &str) -> anyhow::Result<()> {
    check_output(out)?;
    let parent = out
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = parent
        .canonicalize()
        .with_context(|| format!("policy-render canonicalize parent {}", parent.display()))?;
    if !parent.is_dir() {
        return Err(anyhow::anyhow!(
            "policy-render parent is not a directory: {}",
            parent.display()
        ));
    }
    let name = out
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("policy-render missing filename: {}", out.display()))?;
    let destination = parent.join(name);
    check_output(&destination)?;
    let temp = parent.join(format!(".policy-render-{}.tmp", uuid::Uuid::new_v4()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&temp)
        .with_context(|| format!("policy-render create temp {}", temp.display()))?;
    let result = (|| -> anyhow::Result<()> {
        file.set_permissions(fs::Permissions::from_mode(0o644))
            .with_context(|| format!("policy-render set mode {}", temp.display()))?;
        file.write_all(text.as_bytes())
            .with_context(|| format!("policy-render write {}", temp.display()))?;
        file.sync_all()
            .with_context(|| format!("policy-render sync {}", temp.display()))?;
        check_output(&destination)?;
        fs::rename(&temp, &destination).with_context(|| {
            format!(
                "policy-render rename {} to {}",
                temp.display(),
                destination.display()
            )
        })?;
        Ok(())
    })();
    if let Err(error) = result {
        fs::remove_file(&temp)
            .with_context(|| format!("policy-render cleanup {} after {error:#}", temp.display()))?;
        return Err(error);
    }
    Ok(())
}
fn check_output(out: &Path) -> anyhow::Result<()> {
    match fs::symlink_metadata(out) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(anyhow::anyhow!(
                    "policy-render symlink refused: {}",
                    out.display()
                ));
            }
            if !out.is_file() {
                return Err(anyhow::anyhow!(
                    "policy-render non-regular output refused: {}",
                    out.display()
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("policy-render inspect {}", out.display()))
        }
    }
    Ok(())
}

/// Loads and validates the embedded crawler template without opening a store or making requests.
pub fn template() -> anyhow::Result<ValidatedPolicy> {
    let config: CrawlerConfig =
        toml::from_str(include_str!("../../../../configs/crawler/crawler.toml"))?;
    config.ingestion.validate()
}

fn pending<'a>(value: &'a Option<String>, placeholder: &'a str) -> &'a str {
    value.as_deref().unwrap_or(placeholder)
}

/// Returns deterministic UTF-8 Markdown with exactly one nonempty section P01 through P12.
/// Durations are seconds, milliseconds or days as labelled; configured bounds were validated.
pub fn render(policy: &ValidatedPolicy) -> String {
    let c = policy.get();
    let p = &c.policy_content;
    let source = crate::source_metadata::REPOSITORY;
    let mut out = format!("# AVA Search crawler policy\n\nBounded research sample only; production disabled; founder approvals pending.\n\nPolicy version: {}. Source: {}. Policy URL: {}.\n\nIdentity: {}\n\n", c.version, source, c.identity.policy_url, build_user_agent(&c.identity).expect("validated identity"));
    let sections = [
        ("P01 Controller identity", pending(&p.controller_identity, "[FOUNDER REQUIRED: controller identity]").to_owned()),
        ("P02 Contact", format!("Crawler contact: {}. Public issues are not a confidential rights channel; private controller contact is pending founder approval.", c.identity.contact)),
        ("P03 Purpose", "Building a search index for AVA from publicly accessible pages. No profiling, advertising, images, favicons or user-facing cached copies are enabled by this ingestion slice.".into()),
        ("P04 Lawful basis and LIA", format!("Intended basis: legitimate interests, subject to an approved DPIA and linked LIA. No completed assessment is asserted. {}. Production also requires linked Article 14 measures and a distributed host-ownership attestation.", pending(&p.lia_summary_url, "[FOUNDER REQUIRED: approved LIA summary URL]"))),
        ("P05 Data categories", "Public page text and metadata; exact operational URLs including queries; access, robots, directives and rights signals; bounded diagnostics and per-target outcomes. Credentials and fragments are removed from recorded URLs. [FOUNDER REQUIRED: confirm exact data categories]".into()),
        ("P06 Retention", format!("Maximum raw bodies: {} days from the original parse, without renewal on 304. Snippets: at most {} characters and any stricter publisher limit; news or paywalled content gets zero absent explicit permission. Query logs: at most {} days, IPv4 /{}, IPv6 /{}, rotating salt required: {}. Serving enforcement is owned by #588. User-facing cached copy: {}. Ledger and document metadata have no TTL in this slice; these diagnostic URLs remain operational records. Raw objects are removed on expiry, no-store, rights reservation or deletion signals; deletion failures fail the run.", c.retention.raw_body_max_age_days, c.retention.snippet_max_chars, c.retention.query_log_max_age_days, c.retention.query_ip_v4_prefix, c.retention.query_ip_v6_prefix, c.retention.query_rotating_salt_required, c.retention.cached_copy)),
        ("P07 Robots, directives and opting out", format!("AVASearchBot checks robots before requests and revalidates queued snapshots. Maximum usable robots: {} seconds (hard cap {MAX_ROBOTS_CACHE_SECS} seconds); unreachable robots deny access and retry no earlier than {ROBOTS_FAILURE_RETRY_SECS} seconds. 4xx robots permit parsing semantics while 401/403/429 still block the host. Gap: {} ms; concurrency: {} per host; hard ceiling: {HARD_MIN_HOST_GAP_MS} ms and {HARD_MAX_HOST_CONCURRENCY} connections. Publisher Crawl-delay raises the gap; above {MAX_ACCEPTED_CRAWL_DELAY_SECS} seconds the target is skipped. Access refusals and challenges block for at least {} seconds (floor {MIN_BLOCK_SECS} seconds). Retry-After and bounded backoff can extend deadlines. All applicable X-Robots-Tag and robots/AVASearchBot meta directives merge restrictively: noindex, nofollow, noarchive, nosnippet, noimageindex, max-snippet and unavailable_after. Invalid dates and exceeded directive limits are ineligible. Rights/TDM reservations and licence signals are stored; restricted bodies are not retained. Exclusions version: {}. Never-crawl matches are applied before DNS and robots; request a rule using the contact or pending private removal route. Conditional requests, redirects, feeds and sitemaps share identity, address checks, host limits and outcome accounting.", c.robots.cache_secs, c.politeness.gap_ms, c.politeness.max_concurrent_per_host, c.politeness.block_secs, c.exclusions.version)),
        ("P08 Egress verification", format!("Signed egress publication and DNS verification are pending follow-up A and deployment. {}. Once deployed, verify the configured trusted-key signature, validity period and inventory; forward-confirm reverse DNS against an AVA-controlled domain. Do not treat an unsigned or missing inventory as verified.", pending(&p.egress_file_url, "[FOUNDER REQUIRED: stable signed egress URL]"))),
        ("P09 Removal and delisting", format!("Request removal or delisting through {}. A public issue is not a private rights channel.", pending(&p.removal_url, "[FOUNDER REQUIRED: private removal/delisting route]"))),
        ("P10 Online Safety reports", format!("Online Safety reports: {}. No report route is asserted as operational by this source rendering.", pending(&p.osa_report_url, "[FOUNDER REQUIRED: OSA report route]"))),
        ("P11 Complaints to AVA and ICO", format!("You may complain to AVA using {}. Separately, you may complain to the ICO: {}.", pending(&p.complaints_url, "[FOUNDER REQUIRED: private controller complaints route]"), pending(&p.ico_url, "[FOUNDER REQUIRED: confirmed ICO complaints link]"))),
        ("P12 Public sources and Article 14 measures", format!("Sources are publicly accessible pages; public availability does not remove data-protection duties. Measures and notice rationale: {}. Production remains disabled until the selected founder-approved DPIA links the LIA and Article 14 measures for this policy version.", pending(&p.article14_measures, "[FOUNDER REQUIRED: approved Article 14 measures and notice rationale]"))),
    ];
    for (heading, content) in sections {
        out.push_str(&format!("## {heading}\n\n{content}\n\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_render_symlink_refused() {
        let root =
            std::path::PathBuf::from(std::env::var_os("STORY584_SCRATCH").expect("owned scratch"))
                .join(format!("policy-render-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let sentinel = root.join("sentinel");
        let out = root.join("policy.md");
        let text = render(&template().unwrap());
        fs::write(&sentinel, b"sentinel").unwrap();
        std::os::unix::fs::symlink(&sentinel, &out).unwrap();
        assert!(write_rendered(&out, &text).is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), b"sentinel");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
        fs::remove_file(&out).unwrap();
        std::os::unix::fs::symlink(root.join("absent"), &out).unwrap();
        assert!(write_rendered(&out, &text).is_err());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
        fs::remove_file(&out).unwrap();
        fs::create_dir(&out).unwrap();
        assert!(write_rendered(&out, &text).is_err());
        fs::remove_dir(&out).unwrap();
        fs::write(&out, b"replace me").unwrap();
        fs::set_permissions(&out, fs::Permissions::from_mode(0o600)).unwrap();
        write_rendered(&out, &text).unwrap();
        assert_eq!(fs::read_to_string(&out).unwrap(), text);
        assert_eq!(
            fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(fs::read(&sentinel).unwrap(), b"sentinel");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
        assert!(write_rendered(&root.join("missing/child"), &text).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
