#!/usr/bin/env bash
set -euo pipefail

# Download pre-built binary dependencies for integration tests.
#
# Reads pinned refs from backbone.toml (the single source of truth for
# dependency versions). Each component entry declares a repo and git ref
# (branch, tag, or commit SHA).
#
# defra and hub.rs binaries are downloaded as GitHub Actions artifacts
# from their CI workflows when the pinned commit has them. Those artifacts
# are only produced on a push to main, so a ref pinned to a branch still
# under review has none; that case falls back to a source build rather than
# failing, because a pinned branch is the normal state while a cross-repo
# change is in flight.
#
# orbis-rs has no CI artifact pipeline at all, so it is always built from
# source: resolve the commit, clone or fetch into a persistent local
# checkout, and do an incremental cargo build --release.
#
# Required:
#   backbone.toml    — in the repo root (or any ancestor directory)
#
# Optional env vars:
#   PRIVATE_REPO_PAT — PAT for private repo access (gh CLI and git URLs)
#   CACHE_DIR        — override binary cache root (default: ~/.sourcenetwork/bin)
#   SRC_DIR          — override source clone root (default: ~/.sourcenetwork/src)
#   MAX_VERSIONS     — versions to keep per component (default: 3)

CACHE_DIR="${CACHE_DIR:-$HOME/.sourcenetwork/bin}"
SRC_DIR="${SRC_DIR:-$HOME/.sourcenetwork/src}"
MAX_VERSIONS="${MAX_VERSIONS:-3}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MANIFEST="$REPO_ROOT/backbone.toml"

mkdir -p "$CACHE_DIR" "$SRC_DIR"

# gh CLI auth via PAT
export GH_TOKEN="${PRIVATE_REPO_PAT:-}"

if [[ ! -f "$MANIFEST" ]]; then
    echo "ERROR: backbone.toml not found at $MANIFEST" >&2
    exit 1
fi

# Parse a field from a [components.<name>] section in backbone.toml.
# Usage: manifest_get <component> <field>
manifest_get() {
    local component=$1 field=$2
    # Match the section, then find the field within it (before the next section)
    awk -v section="components.$component" -v key="$field" '
        $0 ~ "\\[" section "\\]" { found=1; next }
        found && /^\[/ { found=0 }
        found && $0 ~ "^" key " *= *\"" {
            gsub(/.*= *"/, ""); gsub(/".*/, ""); print; exit
        }
    ' "$MANIFEST"
}

repo_url() {
    local repo=$1
    if [[ -n "${PRIVATE_REPO_PAT:-}" ]]; then
        echo "https://${PRIVATE_REPO_PAT}@github.com/sourcenetwork/${repo}.git"
    else
        echo "https://github.com/sourcenetwork/${repo}.git"
    fi
}

# Extract the short repo name from a full URL.
# "https://github.com/sourcenetwork/defradb.rs" → "defradb.rs"
repo_name() {
    local url=$1
    basename "$url" .git
}

resolve_commit() {
    local repo=$1 ref=$2
    local commit
    commit=$(git ls-remote "$(repo_url "$repo")" "$ref" | head -1 | cut -f1)
    if [[ -n "$commit" ]]; then
        echo "$commit"
        return 0
    fi

    if [[ "$ref" =~ ^[0-9a-fA-F]{7,40}$ ]]; then
        echo "$ref"
        return 0
    fi

    echo "ERROR: could not resolve $repo ref '$ref'" >&2
    return 1
}

# Download a binary artifact from a GitHub Actions workflow run.
# Try to place $binary_name in the cache from a CI artifact. Returns non-zero
# without exiting when the commit has no successful run or that run published
# no matching artifact, so the caller can build from source instead.
download_artifact() {
    local repo=$1 commit=$2 artifact_name=$3 binary_name=$4

    local run_id
    run_id=$(gh run list -R "sourcenetwork/$repo" \
        --commit "$commit" --status success --workflow ci.yml \
        --limit 1 --json databaseId -q '.[0].databaseId')

    if [[ -z "$run_id" ]]; then
        echo "  no successful CI run for $repo@${commit:0:12}"
        return 1
    fi

    echo "  Downloading $artifact_name from run $run_id..."
    local tmp_dir
    tmp_dir=$(mktemp -d)
    if ! gh run download "$run_id" -R "sourcenetwork/$repo" \
        --name "$artifact_name" --dir "$tmp_dir" 2>/dev/null; then
        echo "  run $run_id published no $artifact_name"
        rm -rf "$tmp_dir"
        return 1
    fi

    local found
    found=$(find "$tmp_dir" -type f | head -1)
    if [[ -z "$found" ]]; then
        echo "  artifact $artifact_name was empty"
        rm -rf "$tmp_dir"
        return 1
    fi

    cp "$found" "$CACHE_DIR/$binary_name"
    chmod +x "$CACHE_DIR/$binary_name"
    rm -rf "$tmp_dir"
    echo "  $binary_name: ready (artifact)"
    return 0
}

# --- orbis-rs helper functions (source build, no CI artifacts) ---

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

    local features_fingerprint=""
    for spec in "$@"; do
        IFS=: read -r _pkg _binary _output features <<< "$spec"
        features_fingerprint="${features_fingerprint}${features:-default};"
    done

    local all_present=true
    for spec in "$@"; do
        IFS=: read -r _pkg binary output features <<< "$spec"
        output="${output:-$binary}"
        if [[ ! -x "$cache_path/$output" ]]; then
            all_present=false
            break
        fi
    done

    if $all_present && [[ -f "$cache_path/.features" ]]; then
        local cached_features
        cached_features=$(cat "$cache_path/.features")
        if [[ "$cached_features" != "$features_fingerprint" ]]; then
            echo "Features changed for $repo@${commit:0:12}, rebuilding..."
            all_present=false
            rm -rf "$cache_path"
        fi
    elif $all_present && [[ ! -f "$cache_path/.features" ]]; then
        echo "No features record for $repo@${commit:0:12}, rebuilding..."
        all_present=false
        rm -rf "$cache_path"
    fi

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
                feat_args=(--no-default-features --features "$features")
            fi
            echo "  Building $output (cargo build -p $package ${feat_args[*]:-} --release)..."
            cargo build --manifest-path "$src/Cargo.toml" \
                -p "$package" ${feat_args[@]+"${feat_args[@]}"} --release 2>&1 | tail -5
            cp "$src/target/release/$binary" "$cache_path/$output"
            chmod +x "$cache_path/$output"
        done
        echo "$features_fingerprint" > "$cache_path/.features"
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

echo "=== Reading dependency pins from backbone.toml ==="

# Read refs from backbone.toml
DEFRA_REPO=$(repo_name "$(manifest_get defra repo)")
DEFRA_REF=$(manifest_get defra ref)
HUBD_REPO=$(repo_name "$(manifest_get hubd repo)")
HUBD_REF=$(manifest_get hubd ref)
ORBIS_REPO=$(repo_name "$(manifest_get orbis-node repo)")
ORBIS_REF=$(manifest_get orbis-node ref)

for var in DEFRA_REPO DEFRA_REF HUBD_REPO HUBD_REF ORBIS_REPO ORBIS_REF; do
    if [[ -z "${!var}" ]]; then
        echo "ERROR: could not read $var from backbone.toml" >&2
        exit 1
    fi
    echo "  $var=${!var}"
done

# defra and hub.rs: prefer a CI artifact, build from source when the pinned
# commit has none. Their artifact jobs are gated on a push to main, so a ref
# pinned to a branch under review always takes the source path.
echo ""
echo "--- defra (artifact, else source) ---"
DEFRA_COMMIT=$(resolve_commit "$DEFRA_REPO" "$DEFRA_REF")
echo "$DEFRA_REPO: $DEFRA_REF → ${DEFRA_COMMIT:0:12}"
if ! download_artifact "$DEFRA_REPO" "$DEFRA_COMMIT" \
    "defra-iroh-aarch64-apple-darwin" "defra-iroh"; then
    echo "  Falling back to a source build."
    build_if_missing "$DEFRA_REPO" "$DEFRA_REF" "$DEFRA_COMMIT" \
        "cli:defra:defra-iroh:sourcehub,orbis,iroh"
    prune_old_versions "$DEFRA_REPO"
fi

echo ""
echo "--- hub.rs (artifact, else source) ---"
HUBD_COMMIT=$(resolve_commit "$HUBD_REPO" "$HUBD_REF")
echo "$HUBD_REPO: $HUBD_REF → ${HUBD_COMMIT:0:12}"
if ! download_artifact "$HUBD_REPO" "$HUBD_COMMIT" \
    "hubd-aarch64-apple-darwin" "hubd"; then
    echo "  Falling back to a source build."
    build_if_missing "$HUBD_REPO" "$HUBD_REF" "$HUBD_COMMIT" "hubd:hubd"
    prune_old_versions "$HUBD_REPO"
fi

# orbis-rs: no CI artifact pipeline, build from source
echo ""
echo "--- orbis-rs (built from source) ---"
ORBIS_COMMIT=$(resolve_commit "$ORBIS_REPO" "$ORBIS_REF")
echo "orbis-rs: $ORBIS_REF → ${ORBIS_COMMIT:0:12}"

build_if_missing "$ORBIS_REPO" "$ORBIS_REF" "$ORBIS_COMMIT" \
    "orbis-node:orbis-node::bls12-381,redb,bulletin-hubrs,iroh,authz-sourcehub" \
    "cli-tool:cli-tool"

prune_old_versions "$ORBIS_REPO"

# Final verification
echo ""
echo "=== Binary verification ==="
for bin in defra-iroh hubd orbis-node cli-tool; do
    if [[ -x "$CACHE_DIR/$bin" ]]; then
        echo "  $bin: OK"
    else
        echo "  ERROR: $bin not found in $CACHE_DIR" >&2
        exit 1
    fi
done
