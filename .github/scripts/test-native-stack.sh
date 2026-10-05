#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/backbone-native.XXXXXX")
cleanup() {
    local result=$?
    if [[ -n "${RUN:-}" ]]; then
        for repo in vera orbis; do
            if [[ -f "$WORK/$repo/Cargo.lock" ]]; then
                cp "$WORK/$repo/Cargo.lock" "$RUN/$repo-Cargo.lock" || result=1
            fi
        done
    fi
    rm -rf -- "$WORK" || result=1
    exit "$result"
}
trap cleanup EXIT
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/native-stack}"
mkdir -p "$CARGO_TARGET_DIR" "$ROOT/target/native-stack-runs" "$WORK/bin"
export CARGO_TARGET_DIR="$(cd "$CARGO_TARGET_DIR" && pwd)"
RUN=$(mktemp -d "$ROOT/target/native-stack-runs/release.XXXXXX")
if [[ -n "${GITHUB_ENV:-}" ]]; then
    echo "NATIVE_STACK_EVIDENCE=$RUN" >> "$GITHUB_ENV"
fi

# Use repository release profiles and native host binaries, without inherited
# profiling, sanitizer, or development-profile compiler overrides.
while IFS= read -r variable; do
    case "$variable" in
        CARGO_PROFILE_*|CARGO_TARGET_*_RUSTFLAGS) unset "$variable" ;;
    esac
done < <(compgen -e)
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS \
    CARGO_INCREMENTAL CARGO_BUILD_INCREMENTAL CARGO_BUILD_TARGET

ref_for() {
    awk -v section="[components.$1]" '
        $0 == section { found=1; next }
        found && /^\[/ { exit }
        found && /^ref = / { split($0, parts, "\""); print parts[2]; exit }
    ' "$ROOT/backbone.toml"
}

checkout() {
    local repo=$1 ref=$2 destination=$3
    [[ "$ref" =~ ^[0-9a-f]{40}$ ]] || { echo "Expected immutable revision for $repo" >&2; return 1; }
    git init -q "$destination"
    git -C "$destination" fetch -q --depth 1 "https://github.com/sourcenetwork/$repo.git" "$ref"
    git -C "$destination" checkout -q --detach FETCH_HEAD
    [[ $(git -C "$destination" rev-parse HEAD) == "$ref" ]]
}

vera_ref=$(ref_for verad)
orbis_ref=$(ref_for orbis-node)
defra_ref=$(ref_for defra)
checkout vera.rs "$vera_ref" "$WORK/vera"
checkout orbis-rs "$orbis_ref" "$WORK/orbis"
# Check every existing inline git declaration, not just the presence of one pin.
check_fixture_pin() {
    local repo=$1 revision=$2
    [[ "$revision" =~ ^[0-9a-f]{40}$ ]] || { echo "Expected immutable revision for $repo" >&2; return 1; }
    if ! awk -v dependency="git = \"https://github.com/sourcenetwork/$repo\"" \
        -v revision="rev = \"$revision\"" '
        index($0, dependency) { found=1; if (!index($0, revision)) mismatch=1 }
        END { exit !found || mismatch }
    ' "$WORK/orbis/bin/orbis-node/Cargo.toml"; then
        echo "Orbis fixture dependencies do not match the $repo release pin" >&2
        return 1
    fi
}
check_fixture_pin vera.rs "$vera_ref"
check_fixture_pin defradb.rs "$defra_ref"

export RUST_LOG=info
export RUST_BACKTRACE=1
export VERA_E2E_DIR="$RUN/clusters"
export VERA_E2E_KEEP=1
# Qualify production Argon2id defaults, even on a runner used for cheaper unit tests.
unset ORBIS_LOCAL_STORAGE_KDF_M_COST_KIB ORBIS_LOCAL_STORAGE_KDF_T_COST
{
    echo "backbone=$(git -C "$ROOT" rev-parse HEAD)"
    echo "vera=$vera_ref orbis=$orbis_ref defra=$defra_ref"
    echo "profile=release orbis_features=native,redb,iroh,bls12-381 default_features=false"
    echo "kdf=production-defaults (262144 KiB, 3 iterations)"
    rustc +1.98.0 --version --verbose
} | tee "$RUN/provenance.log"

cargo +1.98.0 build --release --locked --manifest-path "$WORK/vera/Cargo.toml" \
    -p verad --bin verad 2>&1 | tee "$RUN/build-verad.log"
cp "$CARGO_TARGET_DIR/release/verad" "$WORK/bin/verad"
export VERAD_BINARY="$WORK/bin/verad"
# Exercise this PR's proof client, including through Defra and Orbis consumers.
patch="patch.'https://github.com/sourcenetwork/backbone.git'.acp-light-client.path='$ROOT/crates/acp-light-client'"
native=(--manifest-path "$WORK/orbis/Cargo.toml" --config "$patch" -p orbis-node
    --no-default-features --features native,redb,iroh,bls12-381)
# The local override changes the disposable lockfile. Stage the production binary
# before test dev-dependencies can enable additional features in Cargo's output.
cargo +1.98.0 build --release "${native[@]}" --bin orbis-node \
    2>&1 | tee "$RUN/build-orbis.log"
cp "$CARGO_TARGET_DIR/release/orbis-node" "$WORK/bin/orbis-node"
export ORBIS_NODE_BINARY="$WORK/bin/orbis-node"
cargo +1.98.0 tree --locked "${native[@]}" --color never --edges normal,build \
    --prefix none > "$RUN/native-dependencies.log"
if grep -E '^(cosmrs|tendermint(-rpc|-config|-proto)?|cosmos-sdk-proto) v' "$RUN/native-dependencies.log"; then
    echo "Native node includes Cosmos transport dependencies" >&2
    exit 1
fi
shasum -a 256 "$VERAD_BINARY" "$ORBIS_NODE_BINARY" "$WORK/vera/Cargo.lock" \
    "$WORK/orbis/Cargo.lock" | tee -a "$RUN/provenance.log"

cargo +1.98.0 test --release --locked "${native[@]}" --test native_startup --no-run \
    2>&1 | tee "$RUN/build-tests.log"
cargo +1.98.0 test --release --locked "${native[@]}" --test native_startup \
    -- --ignored --list | tee "$RUN/scenarios.log"
for scenario in native_startup_registers_and_preserves_identity_on_restart native_defra_signing native_distributed_threshold_workflows; do
    grep -Fx "$scenario: test" "$RUN/scenarios.log" >/dev/null
    cargo +1.98.0 test --release --locked "${native[@]}" --test native_startup \
        "$scenario" -- --ignored --exact --test-threads=1 --nocapture \
        2>&1 | tee "$RUN/$scenario.log"
done
