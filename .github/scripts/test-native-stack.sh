#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/backbone-native.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/native-stack}"

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

checkout vera.rs "$(ref_for verad)" "$WORK/vera"
checkout orbis-rs "$(ref_for orbis-node)" "$WORK/orbis"
# Defra is linked into the native signing fixture; require the declared release pin.
grep -F "rev = \"$(ref_for defra)\"" "$WORK/orbis/bin/orbis-node/Cargo.toml" >/dev/null

cargo +1.98.0 build --locked --manifest-path "$WORK/vera/Cargo.toml" -p verad
export VERAD_BINARY="$CARGO_TARGET_DIR/debug/verad"
export RUST_LOG=info
export RUST_BACKTRACE=1
export VERA_E2E_DIR="$ROOT/target/native-stack-runs"
export VERA_E2E_KEEP=1
# Exercise this PR's proof client, including through Defra and Orbis consumers.
patch="patch.'https://github.com/sourcenetwork/backbone.git'.acp-light-client.path='$ROOT/crates/acp-light-client'"
# The local path override changes source identities in the disposable lockfile.
cargo +1.98.0 test --manifest-path "$WORK/orbis/Cargo.toml" --config "$patch" \
    -p orbis-node --features native --test native_startup --no-run
for scenario in native_startup_registers_and_preserves_identity_on_restart native_defra_signing native_distributed_threshold_workflows; do
    cargo +1.98.0 test --locked --manifest-path "$WORK/orbis/Cargo.toml" --config "$patch" \
        -p orbis-node --features native --test native_startup "$scenario" -- --ignored --exact
done
