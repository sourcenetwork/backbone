#!/usr/bin/env bash
set -euo pipefail

# Build and cache cross-repo binary dependencies for integration tests.
#
# Persistent local clones under ~/.sourcenetwork/src/ enable warm incremental
# builds. Finished binaries go into immutable commit-hash directories under
# ~/.sourcenetwork/bin/ with top-level symlinks for PATH consumption.
#
# Required env vars (set in ci.yml):
#   DEFRA_REF    — git ref for defradb.rs  (e.g. "main")
#   HUBD_REF     — git ref for hub.rs      (e.g. "main")
#   ORBIS_REF    — git ref for orbis-rs    (e.g. "jack/integration-testing")
#
# Optional:
#   GITHUB_PAT   — PAT for private repo access (used in git URLs)
#   CACHE_DIR    — override binary cache root (default: ~/.sourcenetwork/bin)
#   SRC_DIR      — override source clone root (default: ~/.sourcenetwork/src)
#   MAX_VERSIONS — versions to keep per component (default: 3)

CACHE_DIR="${CACHE_DIR:-$HOME/.sourcenetwork/bin}"
SRC_DIR="${SRC_DIR:-$HOME/.sourcenetwork/src}"
MAX_VERSIONS="${MAX_VERSIONS:-3}"

mkdir -p "$CACHE_DIR" "$SRC_DIR"

repo_url() {
    local repo=$1
    if [[ -n "${GITHUB_PAT:-}" ]]; then
        echo "https://${GITHUB_PAT}@github.com/sourcenetwork/${repo}.git"
    else
        echo "https://github.com/sourcenetwork/${repo}.git"
    fi
}

resolve_commit() {
    local repo=$1 ref=$2
    git ls-remote "$(repo_url "$repo")" "$ref" \
        | head -1 | cut -f1
}

ensure_clone() {
    local repo=$1 ref=$2 commit=$3
    local src="$SRC_DIR/$repo"
    local url
    url=$(repo_url "$repo")

    if [[ -d "$src/.git" ]]; then
        git -C "$src" remote set-url origin "$url"
        git -C "$src" fetch origin "$ref" --quiet
    else
        echo "  Cloning $repo..."
        git clone "$url" "$src" --quiet
    fi
    git -C "$src" checkout "$commit" --quiet --force
}

build_if_missing() {
    local repo=$1 ref=$2 commit=$3
    shift 3
    # Remaining args are "package:binary" or "package:binary:output" specs.
    # "output" is the filename in the cache dir (defaults to binary name).
    # Use "package:binary:output:features" to pass --features to cargo build.
    local cache_path="$CACHE_DIR/$repo/$commit"
    local src="$SRC_DIR/$repo"

    # Check if all binaries already exist
    local all_present=true
    for spec in "$@"; do
        IFS=: read -r _pkg binary output features <<< "$spec"
        output="${output:-$binary}"
        if [[ ! -x "$cache_path/$output" ]]; then
            all_present=false
            break
        fi
    done

    if $all_present; then
        echo "Cache hit: $repo@${commit:0:12}"
    else
        echo "Cache miss: $repo@${commit:0:12} — building..."
        ensure_clone "$repo" "$ref" "$commit"

        mkdir -p "$cache_path"
        for spec in "$@"; do
            IFS=: read -r package binary output features <<< "$spec"
            output="${output:-$binary}"
            local feat_args=()
            if [[ -n "${features:-}" ]]; then
                feat_args=(--features "$features")
            fi
            echo "  Building $output (cargo build -p $package ${feat_args[*]:-} --release)..."
            cargo build --manifest-path "$src/Cargo.toml" \
                -p "$package" "${feat_args[@]}" --release 2>&1 | tail -5
            cp "$src/target/release/$binary" "$cache_path/$output"
            chmod +x "$cache_path/$output"
        done
        echo "  Built: $repo@${commit:0:12}"
    fi

    # Update top-level symlinks
    for spec in "$@"; do
        IFS=: read -r _pkg binary output _features <<< "$spec"
        output="${output:-$binary}"
        ln -sf "$cache_path/$output" "$CACHE_DIR/$output"
    done
}

prune_old_versions() {
    local repo=$1
    local repo_dir="$CACHE_DIR/$repo"
    [[ -d "$repo_dir" ]] || return 0

    local count
    count=$(find "$repo_dir" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
    if (( count > MAX_VERSIONS )); then
        echo "Pruning $repo: $count versions (keeping $MAX_VERSIONS)"
        find "$repo_dir" -mindepth 1 -maxdepth 1 -type d -print0 \
            | xargs -0 ls -dt \
            | tail -n +"$((MAX_VERSIONS + 1))" \
            | xargs rm -rf
    fi
}

echo "=== Ensuring binary dependencies ==="

# Resolve commits
DEFRA_COMMIT=$(resolve_commit "defradb.rs" "$DEFRA_REF")
HUBD_COMMIT=$(resolve_commit "hub.rs" "$HUBD_REF")
ORBIS_COMMIT=$(resolve_commit "orbis-rs" "$ORBIS_REF")

echo "defradb.rs: $DEFRA_REF → ${DEFRA_COMMIT:0:12}"
echo "hub.rs:     $HUBD_REF → ${HUBD_COMMIT:0:12}"
echo "orbis-rs:   $ORBIS_REF → ${ORBIS_COMMIT:0:12}"

# Build missing binaries
# defra: standard binary + iroh variant (same repo/commit, different features)
build_if_missing "defradb.rs" "$DEFRA_REF" "$DEFRA_COMMIT" \
    "cli:defra" \
    "cli:defra:defra-iroh:iroh"
build_if_missing "hub.rs" "$HUBD_REF" "$HUBD_COMMIT" "hubd:hubd"
build_if_missing "orbis-rs" "$ORBIS_REF" "$ORBIS_COMMIT" "orbis-node:orbis-node" "cli-tool:cli-tool"

# Prune old versions
prune_old_versions "defradb.rs"
prune_old_versions "hub.rs"
prune_old_versions "orbis-rs"

# Verify all binaries are available
echo ""
echo "=== Binary versions ==="
for bin in defra defra-iroh hubd orbis-node cli-tool; do
    if [[ -x "$CACHE_DIR/$bin" ]]; then
        echo "  $bin: $(readlink "$CACHE_DIR/$bin")"
    else
        echo "  ERROR: $bin not found in $CACHE_DIR" >&2
        exit 1
    fi
done

echo ""
echo "Add to PATH: export PATH=\"$CACHE_DIR:\$PATH\""
