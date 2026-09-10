//! Export Git's current source inventory while retaining file modes and symlink text.

use anyhow::{bail, Context, Result};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs,
    os::unix::{ffi::OsStringExt, fs::symlink},
    path::{Component, Path},
    process::{Command, Output},
};

fn query(
    root: &Path,
    args: &[&str],
    command: &mut impl FnMut(&Path, &[&str]) -> Result<Output>,
) -> Result<Vec<u8>> {
    let output = command(root, args)?;
    if !output.status.success() {
        bail!("source-tree: git enumeration failed");
    }
    Ok(output.stdout)
}

fn export(
    root: &Path,
    destination: &Path,
    command: &mut impl FnMut(&Path, &[&str]) -> Result<Output>,
) -> Result<()> {
    let mut top = query(root, &["rev-parse", "--show-toplevel"], command)?;
    while top.last() == Some(&b'\n') {
        top.pop();
    }
    if Path::new(&OsString::from_vec(top)).canonicalize()? != root.canonicalize()? {
        bail!("source-tree: root does not own an initialized repository");
    }
    let entries = query(
        root,
        &[
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        command,
    )?;
    let stages = query(root, &["ls-files", "--stage", "-z"], command)?;
    let links: BTreeSet<_> = stages
        .split(|byte| *byte == 0)
        .filter(|row| row.starts_with(b"160000 "))
        .map(|row| {
            row.iter()
                .position(|byte| *byte == b'\t')
                .map(|i| &row[i + 1..])
                .context("source-tree: malformed gitlink")
        })
        .collect::<Result<_>>()?;
    let entries: BTreeSet<_> = entries
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .collect();
    for raw in entries {
        let name = OsString::from_vec(raw.to_vec());
        let relative = Path::new(&name);
        if relative.is_absolute()
            || relative
                .components()
                .any(|part| part == Component::ParentDir)
        {
            bail!("source-tree: invalid source path");
        }
        if relative
            .ancestors()
            .skip(1)
            .any(|parent| root.join(parent).is_symlink())
        {
            bail!("source-tree: source parent is a symlink");
        }
        let source = root.join(relative);
        let target = destination.join(relative);
        if links.contains(raw) {
            if !source.join(".git").exists() {
                bail!("source-tree: uninitialized submodule");
            }
            fs::create_dir_all(&target)?;
            export(&source, &target, command)?;
        } else if source.is_symlink() {
            fs::create_dir_all(target.parent().context("source-tree: missing parent")?)?;
            symlink(fs::read_link(source)?, target)?;
        } else if source.is_file() {
            fs::create_dir_all(target.parent().context("source-tree: missing parent")?)?;
            fs::copy(&source, &target)?;
            fs::set_permissions(target, fs::metadata(source)?.permissions())?;
        } else if source.exists() {
            bail!("source-tree: unreadable or unsupported source entry");
        }
        // Deleted tracked paths do not belong to the candidate tree.
    }
    Ok(())
}

/// Export tracked and authored files, recursively including initialized gitlinks.
pub fn source_tree(root: &Path, destination: &Path) -> Result<()> {
    source_tree_with(root, destination, |root, args| {
        Ok(Command::new("git").current_dir(root).args(args).output()?)
    })
}

/// Use a command seam to test enumeration failures without replacing Git or invoking a shell.
pub fn source_tree_with(
    root: &Path,
    destination: &Path,
    mut command: impl FnMut(&Path, &[&str]) -> Result<Output>,
) -> Result<()> {
    let root = root.canonicalize()?;
    let destination = crate::external_path(destination, &root)?;
    if destination.symlink_metadata().is_ok() {
        bail!("source-tree: destination must be new and external");
    }
    fs::create_dir_all(&destination)?;
    if let Err(error) = export(&root, &destination, &mut command) {
        fs::remove_dir_all(&destination)
            .context("source-tree: could not remove failed projection")?;
        return Err(error);
    }
    println!("source-tree: exported source");
    Ok(())
}
