//! Embeds immutable source identity and renders the corresponding source offer.
//! Git failures remain usable unknown builds; failure to write the offer fails the build.

#![deny(missing_docs)]

#[path = "build_support/revision.rs"]
mod revision;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = std::path::PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR")
            .ok_or("missing manifest directory")
            .map_err(|e| format!("read CARGO_MANIFEST_DIR: {e}"))?,
    );
    let root_path = manifest.join("../..");
    let root = root_path.canonicalize().map_err(|e| {
        format!(
            "canonicalize manifest root {}: {e} ({:?})",
            root_path.display(),
            e.kind()
        )
    })?;
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
    let template_path = root.join("SOURCE_OFFER.md");
    let template = std::fs::read_to_string(&template_path).map_err(|e| {
        format!(
            "read source-offer template {}: {e} ({:?})",
            template_path.display(),
            e.kind()
        )
    })?;
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
    let out = std::path::PathBuf::from(
        std::env::var_os("OUT_DIR")
            .ok_or("missing output directory")
            .map_err(|e| format!("read OUT_DIR for {}: {e}", root.display()))?,
    );
    let temporary = out.join("SOURCE_OFFER.md.tmp");
    std::fs::write(&temporary, rendered).map_err(|e| {
        format!(
            "write source offer {}: {e} ({:?})",
            temporary.display(),
            e.kind()
        )
    })?;
    let offer = out.join("SOURCE_OFFER.md");
    std::fs::rename(&temporary, &offer).map_err(|e| {
        format!(
            "rename source offer {} to {}: {e} ({:?})",
            temporary.display(),
            offer.display(),
            e.kind()
        )
    })?;
    Ok(())
}
