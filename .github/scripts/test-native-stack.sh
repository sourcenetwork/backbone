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
mkdir -p "$CARGO_TARGET_DIR" "$ROOT/target/native-stack-runs"
export CARGO_TARGET_DIR="$(cd "$CARGO_TARGET_DIR" && pwd)"
RUN=$(mktemp -d "$ROOT/target/native-stack-runs/release.XXXXXX")
if [[ -n "${GITHUB_ENV:-}" ]]; then
    echo "NATIVE_STACK_EVIDENCE=$RUN" >> "$GITHUB_ENV"
fi

# Use normal runtime images and release-profile fixtures without inherited
# profiling, sanitizer, or development-profile compiler overrides.
while IFS= read -r variable; do
    case "$variable" in
        CARGO_PROFILE_*|CARGO_TARGET_*_RUSTFLAGS) unset "$variable" ;;
    esac
done < <(compgen -e)
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS \
    CARGO_INCREMENTAL CARGO_BUILD_INCREMENTAL CARGO_BUILD_TARGET \
    VERAD_BINARY ORBIS_NODE_BINARY ORBIS_NATIVE_DIAGNOSTIC_IMAGE

field_for() {
    awk -v section="[$1]" -v field="$2" '
        $0 == section { found=1; next }
        found && /^\[/ { exit }
        found && $1 == field && $2 == "=" { split($0, parts, "\""); print parts[2]; exit }
    ' "$ROOT/backbone.toml"
}

ref_for() { field_for "components.$1" ref; }

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

export RUST_LOG=info,vera_node::tx_gossip=trace
export RUST_BACKTRACE=1
export VERA_E2E_KEEP=1
# Qualify production Argon2id defaults, even on a runner used for cheaper unit tests.
unset ORBIS_LOCAL_STORAGE_KDF_M_COST_KIB ORBIS_LOCAL_STORAGE_KDF_T_COST
{
    echo "backbone=$(git -C "$ROOT" rev-parse HEAD)"
    echo "vera=$vera_ref orbis=$orbis_ref defra=$defra_ref"
    echo "profile=release curves=bls12-381,jubjub default_features=false"
    echo "kdf=production-defaults (262144 KiB, 3 iterations)"
    rustc +1.98.0 --version --verbose
} | tee "$RUN/provenance.log"

# Bind the runtime's proof client to the candidate's actual source.
proof_ref=$(awk '/^acp-light-client = / { split($0, parts, "rev = \""); split(parts[2], rev, "\""); print rev[1] }' \
    "$WORK/orbis/bin/orbis-node/Cargo.toml")
[[ "$proof_ref" =~ ^[0-9a-f]{40}$ ]] || { echo "Missing immutable Orbis proof-client revision" >&2; exit 1; }
git -C "$ROOT" fetch -q --depth 1 https://github.com/sourcenetwork/backbone.git "$proof_ref"
if [[ -n $(git -C "$ROOT" status --porcelain --untracked-files=no) ]] ||
    ! git -C "$ROOT" diff --quiet --no-ext-diff --no-textconv "$proof_ref" HEAD -- Cargo.toml crates/acp-light-client; then
    echo "Update Orbis's proof-client pin and runtime images to qualify the changed SDK" >&2
    exit 1
fi
orbis_runtime=$(field_for qualification orbis_runtime_ref)
orbis_build=$(field_for qualification orbis_image_revision)
[[ "$orbis_runtime" =~ ^[0-9a-f]{40}$ && "$orbis_build" =~ ^[0-9a-f]{40}$ ]] || {
    echo "Record qualified Orbis runtime and image build revisions in backbone.toml" >&2; exit 1;
}
for revision in "$orbis_runtime" "$orbis_build"; do
    git -C "$WORK/orbis" fetch -q --depth 1 https://github.com/sourcenetwork/orbis-rs.git "$revision"
done
ORBIS_NATIVE_VERA_IMAGE=$(field_for qualification vera_image)
export ORBIS_NATIVE_VERA_IMAGE
python3 "$ROOT/.github/scripts/native-image-evidence.py" --role vera \
    --image "$ORBIS_NATIVE_VERA_IMAGE" --image-id "$(field_for qualification vera_image_id)" \
    --source "$vera_ref" --checkout "$WORK/vera" --output "$RUN/image-vera.json"
for curve in bls12-381 jubjub; do
    key=${curve//-/_}
    python3 "$ROOT/.github/scripts/native-image-evidence.py" --role orbis --curve "$curve" \
        --image "$(field_for qualification "orbis_image_$key")" \
        --image-id "$(field_for qualification "orbis_image_id_$key")" \
        --source "$orbis_build" --runtime-source "$orbis_runtime" \
        --checkout "$WORK/orbis" --output "$RUN/image-$curve.json"
done
# The fixture links the same proof-client source selected by the normal images.
patch="patch.'https://github.com/sourcenetwork/backbone.git'.acp-light-client.path='$ROOT/crates/acp-light-client'"
for curve in bls12-381 jubjub; do
    native=(--manifest-path "$WORK/orbis/Cargo.toml" --config "$patch" -p orbis-node
        --no-default-features --features "native,redb,iroh,$curve")
    echo "curve=$curve profile=release orbis_features=native,redb,iroh,$curve default_features=false" \
        | tee "$RUN/provenance-$curve.log"
    key=${curve//-/_}
    ORBIS_NATIVE_IMAGE=$(field_for qualification "orbis_image_$key")
    export ORBIS_NATIVE_IMAGE
    # The path override updates only the disposable consumer lockfile.
    cargo +1.98.0 tree "${native[@]}" --color never --edges normal,build \
        --prefix none > "$RUN/native-dependencies-$curve.log"
    if grep -E '^(cosmrs|tendermint(-rpc|-config|-proto)?|cosmos-sdk-proto) v|^(reqwest v0\.11\.|h2 v0\.3\.|rustls v0\.21\.)' "$RUN/native-dependencies-$curve.log"; then
        echo "Native $curve node includes legacy transport dependencies" >&2
        exit 1
    fi
    shasum -a 256 "$WORK/vera/Cargo.lock" "$WORK/orbis/Cargo.lock" \
        "$RUN/image-vera.json" "$RUN/image-$curve.json" | tee -a "$RUN/provenance-$curve.log"

    cargo +1.98.0 test --release --locked "${native[@]}" --test native_startup --no-run \
        2>&1 | tee "$RUN/build-tests-$curve.log"
    cargo +1.98.0 test --release --locked "${native[@]}" --test native_startup \
        -- --list | tee "$RUN/scenarios-$curve.log"
    scenarios=(native_startup_registers_and_preserves_identity_on_restart)
    if [[ $curve == bls12-381 ]]; then
        scenarios+=(native_defra_signing)
    fi
    scenarios+=(native_distributed_threshold_workflows native_pet_threshold_workflows)
    for scenario in "${scenarios[@]}"; do
        grep -Fx "$scenario: test" "$RUN/scenarios-$curve.log" >/dev/null
        NATIVE_STACK_CURVE="$curve" bash "$ROOT/.github/scripts/run-native-scenario.sh" "$RUN" "$scenario" \
            cargo +1.98.0 test --release --locked "${native[@]}" --test native_startup \
            "$scenario" -- --exact --test-threads=1 --nocapture
    done
done
