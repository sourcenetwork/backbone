#!/usr/bin/env bash
set -euo pipefail

# Build and cache cross-repo binary dependencies for integration tests.
#
# defra and hub.rs binaries are built by their own CI and cached on the
# studios. This script just verifies they exist (via symlinks).
#
# orbis-rs has no CI on the studios, so this script resolves the commit,
# clones/fetches into a persistent local checkout, and does an incremental
# cargo build --release.
#
# Required env vars (set in ci.yml):
#   ORBIS_REF    — git ref for orbis-rs    (e.g. "jack/integration-testing")
#
# Optional:
#   PRIVATE_REPO_PAT — PAT for private repo access (used in git URLs)
#   CACHE_DIR        — override binary cache root (default: ~/.sourcenetwork/bin)
#   SRC_DIR          — override source clone root (default: ~/.sourcenetwork/src)
#   MAX_VERSIONS     — versions to keep per component (default: 3)

CACHE_DIR="${CACHE_DIR:-$HOME/.sourcenetwork/bin}"
SRC_DIR="${SRC_DIR:-$HOME/.sourcenetwork/src}"
MAX_VERSIONS="${MAX_VERSIONS:-3}"

mkdir -p "$CACHE_DIR" "$SRC_DIR"

repo_url() {
    local repo=$1
    if [[ -n "${PRIVATE_REPO_PAT:-}" ]]; then
        echo "https://${PRIVATE_REPO_PAT}@github.com/sourcenetwork/${repo}.git"
    else
        echo "https://github.com/sourcenetwork/${repo}.git"
    fi
}

resolve_commit() {
    local repo=$1 ref=$2
    git ls-remote "$(repo_url "$repo")" "$ref" | head -1 | cut -f1
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
    local cache_path="$CACHE_DIR/$repo/$commit"
    local src="$SRC_DIR/$repo"

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
                -p "$package" ${feat_args[@]+"${feat_args[@]}"} --release 2>&1 | tail -5
            cp "$src/target/release/$binary" "$cache_path/$output"
            chmod +x "$cache_path/$output"
        done
        echo "  Built: $repo@${commit:0:12}"
    fi

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

# defra and hub.rs: binaries built by their own CI, just verify symlinks exist
echo "--- defra/hub.rs (pre-built by their CI) ---"
for bin in defra defra-iroh hubd; do
    if [[ -x "$CACHE_DIR/$bin" ]]; then
        echo "  $bin: $(readlink "$CACHE_DIR/$bin")"
    else
        echo "  ERROR: $bin not found in $CACHE_DIR" >&2
        echo "  defra and hub.rs CI must run first to populate the binary cache." >&2
        exit 1
    fi
done

# orbis-rs: no CI on studios, build here
echo "--- orbis-rs (built by ensure-binaries) ---"
ORBIS_COMMIT=$(resolve_commit "orbis-rs" "$ORBIS_REF")
echo "orbis-rs: $ORBIS_REF → ${ORBIS_COMMIT:0:12}"

build_if_missing "orbis-rs" "$ORBIS_REF" "$ORBIS_COMMIT" \
    "orbis-node:orbis-node" "cli-tool:cli-tool"

prune_old_versions "orbis-rs"

# Final verification
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
