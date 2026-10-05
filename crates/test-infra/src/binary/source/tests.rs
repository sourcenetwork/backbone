use super::*;
use crate::TestRunDir;

struct Fixture {
    _directory: TestRunDir,
    repo: PathBuf,
    cache: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory =
            TestRunDir::new(&std::env::temp_dir(), "BACKBONE_SOURCE_TEST_KEEP").unwrap();
        let repo = directory.path().join("repo");
        fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "--quiet", "--initial-branch=main"]).unwrap();
        git(&repo, &["config", "user.name", "Source fixture"]).unwrap();
        git(&repo, &["config", "user.email", "fixture@example.invalid"]).unwrap();
        git(&repo, &["config", "commit.gpgsign", "false"]).unwrap();
        git(&repo, &["config", "tag.gpgSign", "false"]).unwrap();
        git(&repo, &["config", "core.hooksPath", "/dev/null"]).unwrap();
        Self {
            cache: directory.path().join("cache"),
            repo,
            _directory: directory,
        }
    }

    fn commit(&self, content: &str) -> String {
        fs::write(self.repo.join("source.txt"), content).unwrap();
        git(&self.repo, &["add", "source.txt"]).unwrap();
        git(&self.repo, &["commit", "--quiet", "-m", content]).unwrap();
        git(&self.repo, &["rev-parse", "HEAD"]).unwrap()
    }

    fn checkout(&self, git_ref: &str) -> Result<PathBuf> {
        checkout(&self.cache, "fixture", self.repo.to_str().unwrap(), git_ref)
    }

    fn cache_directory(&self, git_ref: &str) -> PathBuf {
        cache_directory(&self.cache, "fixture", self.repo.to_str().unwrap(), git_ref)
    }
}

fn assert_revision(checkout: &Path, expected: &str, content: &str) {
    assert_eq!(git(checkout, &["rev-parse", "HEAD"]).unwrap(), expected);
    assert_eq!(
        fs::read_to_string(checkout.join("source.txt")).unwrap(),
        content
    );
    assert_eq!(
        git(checkout, &["rev-parse", "--abbrev-ref", "HEAD"]).unwrap(),
        "HEAD"
    );
}

#[test]
fn checks_out_full_commit_in_fresh_and_cached_directories() {
    let fixture = Fixture::new();
    let pinned = fixture.commit("pinned source");
    fixture.commit("newer source");

    let checkout = fixture.checkout(&pinned).unwrap();
    assert_revision(&checkout, &pinned, "pinned source");
    fs::write(checkout.join("source.txt"), "dirty source").unwrap();
    assert_eq!(fixture.checkout(&pinned).unwrap(), checkout);
    assert_revision(&checkout, &pinned, "pinned source");
}

#[test]
fn refreshes_a_cached_branch_and_keeps_distinct_ref_names_separate() {
    let fixture = Fixture::new();
    fixture.commit("initial source");
    git(&fixture.repo, &["checkout", "-b", "feature/pin"]).unwrap();
    let first = fixture.commit("first branch source");
    git(&fixture.repo, &["branch", "feature_pin"]).unwrap();
    let checkout = fixture.checkout("feature/pin").unwrap();
    assert_revision(&checkout, &first, "first branch source");

    let latest = fixture.commit("latest branch source");
    assert_eq!(fixture.checkout("feature/pin").unwrap(), checkout);
    assert_revision(&checkout, &latest, "latest branch source");
    let other = fixture.checkout("feature_pin").unwrap();
    assert_ne!(checkout, other);
    assert_revision(&other, &first, "first branch source");
}

#[test]
fn checks_out_annotated_tags_and_refreshes_moved_tags() {
    let fixture = Fixture::new();
    let first = fixture.commit("tagged source");
    git(&fixture.repo, &["tag", "-a", "v1", "-m", "release", &first]).unwrap();
    let latest = fixture.commit("newer source");
    let checkout = fixture.checkout("v1").unwrap();
    assert_revision(&checkout, &first, "tagged source");

    git(
        &fixture.repo,
        &["tag", "-f", "-a", "v1", "-m", "release", &latest],
    )
    .unwrap();
    assert_eq!(fixture.checkout("v1").unwrap(), checkout);
    assert_revision(&checkout, &latest, "newer source");
}

#[test]
fn failed_fetch_does_not_reuse_fetch_head_or_reset_cached_source() {
    let fixture = Fixture::new();
    let first = fixture.commit("initial source");
    git(&fixture.repo, &["branch", "temporary"]).unwrap();
    let checkout = fixture.checkout("temporary").unwrap();
    assert!(checkout.join(".git/FETCH_HEAD").exists());
    fs::write(checkout.join("source.txt"), "untouched source").unwrap();
    git(&fixture.repo, &["branch", "-D", "temporary"]).unwrap();

    let error = fixture.checkout("temporary").unwrap_err();
    assert!(format!("{error:#}").contains("failed to fetch"));
    assert_revision(&checkout, &first, "untouched source");
}

#[test]
fn reports_checkout_failure_after_a_successful_fetch() {
    let fixture = Fixture::new();
    let first = fixture.commit("initial source");
    let checkout = fixture.checkout("main").unwrap();
    fixture.commit("latest source");
    fs::write(checkout.join(".git/index.lock"), "fixture lock").unwrap();

    let error = fixture.checkout("main").unwrap_err();
    assert!(format!("{error:#}").contains("failed to check out"));
    assert_revision(&checkout, &first, "initial source");
}

#[test]
fn separates_repositories_with_the_same_binary_and_ref() {
    let first = Fixture::new();
    let second = Fixture::new();
    let first_commit = first.commit("first repository");
    let second_commit = second.commit("second repository");
    let first_checkout = first.checkout("main").unwrap();
    let second_checkout = checkout(
        &first.cache,
        "fixture",
        second.repo.to_str().unwrap(),
        "main",
    )
    .unwrap();

    assert_ne!(first_checkout, second_checkout);
    assert_revision(&first_checkout, &first_commit, "first repository");
    assert_revision(&second_checkout, &second_commit, "second repository");
}

#[test]
fn rejects_unrelated_directories_and_mismatched_origins_without_changes() {
    let fixture = Fixture::new();
    fixture.commit("source");
    let foreign = fixture.cache_directory("main").join("checkout");
    fs::create_dir_all(&foreign).unwrap();
    fs::write(foreign.join("keep"), "unrelated content").unwrap();
    assert!(fixture.checkout("main").is_err());
    assert_eq!(
        fs::read_to_string(foreign.join("keep")).unwrap(),
        "unrelated content"
    );
    assert!(!foreign.join(".git").exists());

    let checkout = fixture.checkout("HEAD").unwrap();
    git(
        &checkout,
        &["remote", "set-url", "origin", "unrelated-repository"],
    )
    .unwrap();
    fs::write(checkout.join("source.txt"), "unrelated changes").unwrap();
    let error = fixture.checkout("HEAD").unwrap_err();
    assert!(format!("{error:#}").contains("origin does not match"));
    assert_eq!(
        fs::read_to_string(checkout.join("source.txt")).unwrap(),
        "unrelated changes"
    );
}

#[test]
fn rejects_symlinked_cache_directories_without_touching_the_target() {
    let fixture = Fixture::new();
    fixture.commit("source");
    let parent = fixture.cache_directory("main");
    fs::create_dir_all(&parent).unwrap();
    std::os::unix::fs::symlink(&fixture.repo, parent.join("checkout")).unwrap();
    assert!(fixture.checkout("main").is_err());
    assert_eq!(
        git(&fixture.repo, &["branch", "--show-current"]).unwrap(),
        "main"
    );
}

#[test]
fn keeps_dependency_links_inside_the_cache_and_rejects_foreign_paths() {
    let fixture = Fixture::new();
    fixture.commit("source");
    let checkout = fixture.checkout("main").unwrap();
    for name in ["..", "../outside", "/absolute", "checkout"] {
        assert!(sibling_symlink(&checkout, name, &fixture.repo).is_err());
    }
    sibling_symlink(&checkout, "backbone", &fixture.repo).unwrap();
    sibling_symlink(&checkout, "backbone", &fixture.repo).unwrap();
    assert_eq!(
        fs::read_link(checkout.parent().unwrap().join("backbone")).unwrap(),
        fixture.repo
    );
    assert!(sibling_symlink(&checkout, "backbone", &fixture.cache).is_err());
    assert!(checkout.join("source.txt").is_file());
}

#[test]
fn rejects_binary_path_traversal_and_keeps_ref_strings_out_of_paths() {
    let fixture = Fixture::new();
    fixture.commit("source");
    assert!(checkout(
        &fixture.cache,
        "../escape",
        fixture.repo.to_str().unwrap(),
        "main"
    )
    .is_err());
    assert!(fixture.checkout("..").is_err());
    assert_eq!(
        fixture.cache_directory("..").parent(),
        Some(fixture.cache.as_path())
    );
}

#[test]
fn resolves_relative_repository_paths_against_the_callers_directory() {
    let fixture = Fixture::new();
    let commit = fixture.commit("local source");
    let current_dir = std::env::current_dir().unwrap();
    let mut relative = PathBuf::new();
    for _ in current_dir.ancestors().skip(1) {
        relative.push("..");
    }
    relative.extend(fixture.repo.components().skip(1));

    let checkout = checkout(
        &fixture.cache,
        "fixture",
        relative.to_str().unwrap(),
        "main",
    )
    .unwrap();
    assert_revision(&checkout, &commit, "local source");
    assert_eq!(
        PathBuf::from(git(&checkout, &["config", "--get", "remote.origin.url"]).unwrap()),
        fs::canonicalize(&fixture.repo).unwrap()
    );
}

#[test]
fn removes_untracked_and_ignored_source_inputs_but_preserves_build_cache_and_siblings() {
    let fixture = Fixture::new();
    let commit = fixture.commit("source");
    let checkout = fixture.checkout("main").unwrap();
    fs::write(checkout.join(".git/info/exclude"), "ignored-input\n").unwrap();
    fs::write(checkout.join("ignored-input"), "stale ignored source").unwrap();
    fs::create_dir(checkout.join(".cargo")).unwrap();
    fs::write(checkout.join(".cargo/config.toml"), "stale configuration").unwrap();
    fs::create_dir(checkout.join("target")).unwrap();
    fs::write(checkout.join("target/keep"), "cached build").unwrap();
    sibling_symlink(&checkout, "backbone", &fixture.repo).unwrap();

    assert_eq!(fixture.checkout("main").unwrap(), checkout);
    assert_revision(&checkout, &commit, "source");
    assert!(!checkout.join("ignored-input").exists());
    assert!(!checkout.join(".cargo").exists());
    assert_eq!(
        fs::read_to_string(checkout.join("target/keep")).unwrap(),
        "cached build"
    );
    assert_eq!(
        fs::read_link(checkout.parent().unwrap().join("backbone")).unwrap(),
        fixture.repo
    );
    assert_eq!(
        fs::read_to_string(fixture.repo.join("source.txt")).unwrap(),
        "source"
    );
}
