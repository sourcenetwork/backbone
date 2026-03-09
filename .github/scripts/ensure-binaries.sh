#!/usr/bin/env bash
set -euo pipefail

# Build and cache cross-repo binary dependencies for integration tests.
#
# Uses immutable commit-hash directories under ~/.sourcenetwork/bin/ so
# multiple concurrent jobs can safely share the cache. Top-level symlinks
# point to the active version.
#
# Required env vars (set in ci.yml):
#   DEFRA_REF    — git ref for defradb.rs  (e.g. "main")
#   HUBD_REF     — git ref for hub.rs      (e.g. "main")
#   ORBIS_REF    — git ref for orbis-rs    (e.g. "jack/integration-testing")
#
# Optional:
#   CACHE_DIR    — override cache root (default: ~/.sourcenetwork/bin)
#   MAX_VERSIONS — versions to keep per component (default: 3)

CACHE_DIR="${CACHE_DIR:-$HOME/.sourcenetwork/bin}"
MAX_VERSIONS="${MAX_VERSIONS:-3}"
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT

mkdir -p "$CACHE_DIR"

resolve_commit() {
    local repo=$1 ref=$2
    git ls-remote "https://github.com/sourcenetwork/${repo}.git" "$ref" \
        | head -1 | cut -f1
}

build_if_missing() {
    local repo=$1 ref=$2 commit=$3
    shift 3
    # Remaining args are "package:binary" pairs
    local cache_path="$CACHE_DIR/$repo/$commit"

    # Check if all binaries exist
    local all_present=true
    for spec in "$@"; do
        local binary="${spec#*:}"
        if [[ ! -x "$cache_path/$binary" ]]; then
            all_present=false
            break
        fi
    done

    if $all_present; then
        echo "Cache hit: $repo@${commit:0:12}"
    else
        echo "Cache miss: $repo@${commit:0:12} — building..."
        local src="$BUILD_DIR/$repo"
        git clone --depth 1 --branch "$ref" \
            "https://github.com/sourcenetwork/${repo}.git" "$src" 2>&1 | tail -1

        mkdir -p "$cache_path"
        for spec in "$@"; do
            local package="${spec%%:*}"
            local binary="${spec#*:}"
            echo "  Building $binary (cargo install -p $package)..."
            cargo install --git "https://github.com/sourcenetwork/${repo}.git" \
                --branch "$ref" \
                -p "$package" \
                --root "$cache_path" \
                --force 2>&1 | tail -5
            # cargo install puts binaries in $root/bin/
            if [[ -f "$cache_path/bin/$binary" ]]; then
                mv "$cache_path/bin/$binary" "$cache_path/$binary"
            fi
        done
        rm -rf "$cache_path/bin" "$cache_path/.crates.toml" "$cache_path/.crates2.json"
        echo "  Built: $repo@${commit:0:12}"
    fi

    # Update top-level symlinks
    for spec in "$@"; do
        local binary="${spec#*:}"
        ln -sf "$cache_path/$binary" "$CACHE_DIR/$binary"
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
build_if_missing "defradb.rs" "$DEFRA_REF" "$DEFRA_COMMIT" "cli:defra"
build_if_missing "hub.rs" "$HUBD_REF" "$HUBD_COMMIT" "hubd:hubd"
build_if_missing "orbis-rs" "$ORBIS_REF" "$ORBIS_COMMIT" "orbis-node:orbis-node" "cli-tool:cli-tool"

# Prune old versions
prune_old_versions "defradb.rs"
prune_old_versions "hub.rs"
prune_old_versions "orbis-rs"

# Verify all binaries are available
echo ""
echo "=== Binary versions ==="
for bin in defra hubd orbis-node cli-tool; do
    if [[ -x "$CACHE_DIR/$bin" ]]; then
        echo "  $bin: $(readlink "$CACHE_DIR/$bin")"
    else
        echo "  ERROR: $bin not found in $CACHE_DIR" >&2
        exit 1
    fi
done

echo ""
echo "Add to PATH: export PATH=\"$CACHE_DIR:\$PATH\""
