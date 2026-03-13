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
#   DEFRA_REF    — git ref for defradb.rs  (e.g. "main" or a commit SHA)
#   HUBD_REF     — git ref for hub.rs      (e.g. "main" or a commit SHA)
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

    # Build a features fingerprint from all specs
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

    # Check features match (rebuild if features changed)
    if $all_present && [[ -f "$cache_path/.features" ]]; then
        local cached_features
        cached_features=$(cat "$cache_path/.features")
        if [[ "$cached_features" != "$features_fingerprint" ]]; then
            echo "Features changed for $repo@${commit:0:12}, rebuilding..."
            all_present=false
            rm -rf "$cache_path"
        fi
    elif $all_present && [[ ! -f "$cache_path/.features" ]]; then
        # Old cache without features file — rebuild
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

ensure_prebuilt_binary() {
    local repo=$1 ref=$2 binary=$3 output=${4:-$3}
    local commit cache_path

    commit=$(resolve_commit "$repo" "$ref")
    cache_path="$CACHE_DIR/$repo/$commit/$output"

    echo "$repo: $ref → ${commit:0:12}"
    if [[ ! -x "$cache_path" ]]; then
        echo "  ERROR: cached binary missing at $cache_path" >&2
        echo "  $repo CI must build and cache commit $commit first." >&2
        exit 1
    fi

    ln -sf "$cache_path" "$CACHE_DIR/$binary"
    echo "  $binary: $(readlink "$CACHE_DIR/$binary")"
}

echo "=== Ensuring binary dependencies ==="

# defra and hub.rs: binaries built by their own CI, relink to the exact
# commit requested by this workflow so runners do not drift.
echo "--- defra/hub.rs (pre-built by their CI) ---"
ensure_prebuilt_binary "defradb.rs" "$DEFRA_REF" "defra-iroh"
ensure_prebuilt_binary "hub.rs" "$HUBD_REF" "hubd"

# orbis-rs: no CI on studios, build here
echo "--- orbis-rs (built by ensure-binaries) ---"
ORBIS_COMMIT=$(resolve_commit "orbis-rs" "$ORBIS_REF")
echo "orbis-rs: $ORBIS_REF → ${ORBIS_COMMIT:0:12}"

build_if_missing "orbis-rs" "$ORBIS_REF" "$ORBIS_COMMIT" \
    "orbis-node:orbis-node::bls12-381,redb,bulletin-hubrs,iroh,authz-sourcehub" \
    "cli-tool:cli-tool"

prune_old_versions "orbis-rs"

# Final verification
echo ""
echo "=== Binary versions ==="
for bin in defra-iroh hubd orbis-node cli-tool; do
    if [[ -x "$CACHE_DIR/$bin" ]]; then
        echo "  $bin: $(readlink "$CACHE_DIR/$bin")"
    else
        echo "  ERROR: $bin not found in $CACHE_DIR" >&2
        exit 1
    fi
done
