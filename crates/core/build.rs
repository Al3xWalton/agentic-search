//! Embeds immutable source identity and renders the corresponding source offer.
//! Git failures remain usable unknown builds; failure to write the offer fails the build.

#![deny(missing_docs)]

#[path = "build_support/revision.rs"]
mod revision;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = std::path::PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").ok_or("missing manifest directory")?,
    );
    let root = manifest.join("../..").canonicalize()?;
    let environment = std::env::var("SOURCE_REVISION").ok();
    let selected = revision::resolve(&root, environment.as_deref());
    revision::emit_watches(&root);
    println!("cargo:rustc-env=AVA_SEARCH_REVISION={}", selected.revision);
    println!(
        "cargo:rustc-env=AVA_SEARCH_REVISION_SOURCE={}",
        selected.source
    );
    if selected.source == "unknown" {
        println!("cargo:warning=Source revision unknown; this build is not release-ready");
    }
    let template = std::fs::read_to_string(root.join("SOURCE_OFFER.md"))?;
    let repository = env!("CARGO_PKG_REPOSITORY");
    let source_url = if selected.source == "unknown" {
        repository.to_owned()
    } else {
        format!("{repository}/tree/{}", selected.revision)
    };
    let rendered = template
        .lines()
        .map(|line| {
            if line.starts_with("source_url=") {
                format!("source_url={source_url}")
            } else {
                line.replace("{revision}", &selected.revision)
                    .replace("{revision_source}", selected.source)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let out =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").ok_or("missing output directory")?);
    let temporary = out.join("SOURCE_OFFER.md.tmp");
    std::fs::write(&temporary, rendered)?;
    std::fs::rename(temporary, out.join("SOURCE_OFFER.md"))?;
    Ok(())
}
