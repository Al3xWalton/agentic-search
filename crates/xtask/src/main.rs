//! Cargo entrypoint for repository guards and serial CI orchestration.

#![deny(missing_docs)]

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "Repository verification and pinned tooling")]
struct Cli {
    #[command(subcommand)]
    command: Task,
}

#[derive(Subcommand)]
enum Task {
    CrawlerUserAgent {
        #[arg(long)]
        root: Option<PathBuf>,
    },
    CrawlerDependencyDeny {
        #[arg(long)]
        root: Option<PathBuf>,
    },
    CrawlerPolicyCheck {
        file: PathBuf,
    },
    StrictClippyTouched {
        #[arg(long)]
        base: Option<String>,
    },
    ToolchainPin {
        #[arg(long)]
        root: Option<PathBuf>,
    },
    NoDeveloperPaths {
        #[arg(long)]
        root: Option<PathBuf>,
    },
    CheckNotices {
        #[arg(long)]
        root: Option<PathBuf>,
        #[arg(long)]
        baseline: Option<PathBuf>,
    },
    CheckSbom {
        file: PathBuf,
    },
    Sbom,
    SourceTree {
        destination: PathBuf,
        #[arg(long)]
        root: Option<PathBuf>,
    },
    Secrets {
        #[arg(long)]
        root: Option<PathBuf>,
        #[arg(long)]
        scanner: Option<PathBuf>,
    },
    InstallTools {
        #[arg(
            required_unless_present = "verify_archive",
            conflicts_with = "verify_archive"
        )]
        destination: Option<PathBuf>,
        #[arg(long, num_args = 2, value_names = ["FILE", "SHA256"])]
        verify_archive: Option<Vec<String>>,
    },
    CiAll,
    WorkflowLint {
        file: Option<PathBuf>,
    },
    Check,
    SourceOffer,
    Licenses,
    CiInit {
        /// Skip toolchain installation and version probes for directory-only initialization.
        #[arg(long)]
        no_toolchain: bool,
    },
    NativeDeps,
    NodeVersions,
}

fn execute(task: Task) -> Result<()> {
    let default_root = xtask::repository_root();
    match task {
        Task::CrawlerUserAgent { root } => {
            xtask::ingestion::crawler_user_agent(root.as_deref().unwrap_or(&default_root))
        }
        Task::CrawlerDependencyDeny { root } => {
            xtask::ingestion::crawler_dependency_deny(root.as_deref().unwrap_or(&default_root))
        }
        Task::CrawlerPolicyCheck { file } => xtask::ingestion::crawler_policy_check(&file),
        Task::StrictClippyTouched { base } => {
            xtask::ingestion::strict_clippy_touched(base.as_deref())
        }
        Task::ToolchainPin { root } => {
            println!(
                "{}",
                xtask::guards::toolchain_pin(root.as_deref().unwrap_or(&default_root))?
            );
            Ok(())
        }
        Task::NoDeveloperPaths { root } => xtask::ci::no_developer_paths(root.as_deref()),
        Task::CheckNotices { root, baseline } => {
            let baseline = baseline.or_else(|| root.as_ref().map(|root| root.join(".baseline")));
            xtask::guards::check_notices(
                root.as_deref().unwrap_or(&default_root),
                baseline.as_deref(),
            )
        }
        Task::CheckSbom { file } => xtask::guards::check_sbom(&file),
        Task::Sbom => xtask::artifacts::sbom(),
        Task::SourceTree { root, destination } => {
            xtask::source_tree::source_tree(root.as_deref().unwrap_or(&default_root), &destination)
        }
        Task::Secrets { root, scanner } => {
            xtask::artifacts::secrets(root.as_deref(), scanner.as_deref())
        }
        Task::InstallTools {
            destination,
            verify_archive,
        } => match verify_archive {
            Some(args) => xtask::install::verify_archive(std::path::Path::new(&args[0]), &args[1]),
            None => xtask::install::install_tools(&destination.expect("clap requires destination")),
        },
        Task::CiAll => xtask::ci::ci_all(),
        Task::WorkflowLint { file } => xtask::workflow::workflow_lint(
            &file.unwrap_or_else(|| default_root.join(".github/workflows/ci.yaml")),
        ),
        Task::Check => xtask::ci::check(),
        Task::SourceOffer => xtask::ci::source_offer(),
        Task::Licenses => xtask::artifacts::licenses(),
        Task::CiInit { no_toolchain } => xtask::ci::ci_init(no_toolchain),
        Task::NativeDeps => xtask::ci::native_deps(),
        Task::NodeVersions => xtask::ci::node_versions(),
    }
}

fn main() {
    if let Err(error) = execute(Cli::parse().command) {
        eprintln!("{error:#}");
        std::process::exit(xtask::exit_code(&error));
    }
}
