use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use eyre::{Result, WrapErr};

pub(super) fn checkout(
    cache_root: &Path,
    binary: &str,
    repo: &str,
    git_ref: &str,
) -> Result<PathBuf> {
    validate_component(binary)?;
    eyre::ensure!(!git_ref.is_empty(), "source Git ref must not be empty");
    // A local clone URL is relative to the caller, not the cached checkout.
    let local_repo = if Path::new(repo).is_relative() && Path::new(repo).exists() {
        Some(
            fs::canonicalize(repo)?
                .into_os_string()
                .into_string()
                .map_err(|_| eyre::eyre!("local source repository path is not valid UTF-8"))?,
        )
    } else {
        None
    };
    let repo = local_repo.as_deref().unwrap_or(repo);
    fs::create_dir_all(cache_root).wrap_err("failed to create source cache root")?;
    eyre::ensure!(
        fs::symlink_metadata(cache_root)?.file_type().is_dir(),
        "source cache root is not a directory: {}",
        cache_root.display()
    );
    let parent = cache_directory(cache_root, binary, repo, git_ref);
    create_directory(&parent)?;
    let build_dir = parent.join("checkout");

    if create_directory(&build_dir)? {
        git(&build_dir, &["init", "--quiet"])?;
        git(&build_dir, &["remote", "add", "--", "origin", repo])?;
    } else {
        // Never let Git discover an ancestor repository or follow a foreign checkout.
        eyre::ensure!(
            fs::symlink_metadata(build_dir.join(".git"))?
                .file_type()
                .is_dir(),
            "source cache is not an owned Git checkout: {}",
            build_dir.display()
        );
        let top_level = git(&build_dir, &["rev-parse", "--show-toplevel"])?;
        eyre::ensure!(
            fs::canonicalize(top_level)? == fs::canonicalize(&build_dir)?,
            "source cache Git root does not match {}",
            build_dir.display()
        );
        let origin = git(&build_dir, &["config", "--get", "remote.origin.url"])?;
        eyre::ensure!(
            origin == repo,
            "source cache origin does not match requested repository {}",
            repo
        );
    }

    // Fetch accepts full commit IDs as well as branch and tag names. Stop on
    // failure so an old FETCH_HEAD can never select stale source for the build.
    git(
        &build_dir,
        &[
            "fetch",
            "--depth",
            "1",
            "--no-tags",
            "--",
            "origin",
            git_ref,
        ],
    )
    .wrap_err_with(|| format!("failed to fetch {} @ {}", repo, git_ref))?;
    git(
        &build_dir,
        &["checkout", "--detach", "--force", "FETCH_HEAD^{commit}"],
    )
    .wrap_err_with(|| format!("failed to check out {} @ {}", repo, git_ref))?;
    // Keep Cargo's build cache, but remove stale source and configuration inputs.
    git(&build_dir, &["clean", "-ffdx", "--exclude=/target/"])
        .wrap_err_with(|| format!("failed to clean source checkout for {} @ {}", repo, git_ref))?;
    Ok(build_dir)
}

fn cache_directory(cache_root: &Path, binary: &str, repo: &str, git_ref: &str) -> PathBuf {
    let mut key = DefaultHasher::new();
    (binary, repo, git_ref).hash(&mut key);
    cache_root.join(format!("source-{:016x}", key.finish()))
}

fn create_directory(path: &Path) -> Result<bool> {
    match fs::create_dir(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            eyre::ensure!(
                fs::symlink_metadata(path)?.file_type().is_dir(),
                "source cache path is not a directory: {}",
                path.display()
            );
            Ok(false)
        }
        Err(error) => Err(error).wrap_err_with(|| format!("failed to create {}", path.display())),
    }
}

fn git(directory: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(directory)
        .output()
        .wrap_err_with(|| format!("failed to run git {} in {}", args[0], directory.display()))?;
    eyre::ensure!(
        output.status.success(),
        "git {} failed in {}: {}",
        args[0],
        directory.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout.strip_suffix('\n').unwrap_or(&stdout).to_owned())
}

pub(super) fn sibling_symlink(build_dir: &Path, name: &str, target: &Path) -> Result<()> {
    validate_component(name)?;
    let link_path = build_dir
        .parent()
        .expect("checkout has a parent")
        .join(name);
    match fs::symlink_metadata(&link_path) {
        Ok(metadata) => eyre::ensure!(
            metadata.file_type().is_symlink() && fs::read_link(&link_path)? == target,
            "source dependency path already exists with a different target: {}",
            link_path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::os::unix::fs::symlink(target, &link_path).wrap_err_with(|| {
                format!(
                    "failed to symlink {} -> {}",
                    link_path.display(),
                    target.display()
                )
            })?;
        }
        Err(error) => return Err(error).wrap_err("failed to inspect source dependency path"),
    }
    Ok(())
}

fn validate_component(name: &str) -> Result<()> {
    eyre::ensure!(
        matches!(Path::new(name).components().next(), Some(Component::Normal(component)) if component == name),
        "source build path must be a single normal component: {:?}",
        name
    );
    Ok(())
}

#[cfg(test)]
mod tests;
