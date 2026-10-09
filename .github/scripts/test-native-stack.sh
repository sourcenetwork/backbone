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

# Use repository release profiles and pinned runtime images, without inherited
# profiling, sanitizer, or development-profile compiler overrides.
while IFS= read -r variable; do
    case "$variable" in
        CARGO_PROFILE_*|CARGO_TARGET_*_RUSTFLAGS) unset "$variable" ;;
    esac
done < <(compgen -e)
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS \
    CARGO_INCREMENTAL CARGO_BUILD_INCREMENTAL CARGO_BUILD_TARGET \
    VERAD_BINARY ORBIS_NODE_BINARY ORBIS_NATIVE_IMAGE ORBIS_NATIVE_VERA_IMAGE \
    ORBIS_NATIVE_DIAGNOSTIC_IMAGE

ref_for() {
    awk -v section="[${2:-components}.$1]" '
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
fixture_ref=$(ref_for orbis-fixture qualification)
defra_ref=$(ref_for defra)
checkout vera.rs "$vera_ref" "$WORK/vera"
checkout orbis-rs "$fixture_ref" "$WORK/orbis"
# Fixture changes must not change the runtime selected by the release manifest.
git -C "$WORK/orbis" fetch -q --depth 1 https://github.com/sourcenetwork/orbis-rs.git "$orbis_ref"
git -C "$WORK/orbis" diff --name-only "$orbis_ref" HEAD > "$RUN/fixture-changes.log"
while IFS= read -r path; do
    case "$path" in
        .github/workflows/rust.yml|scripts/qualify-native-restart.py|\
        crates/test-support/src/container.rs|crates/test-support/src/lib.rs|\
        crates/test-support/src/native_network.rs|crates/test-support/src/network/native.rs|\
        bin/orbis-node/tests/native_startup.rs|bin/orbis-node/tests/support/native_pet.rs|\
        bin/orbis-node/tests/support/native_pet/document.rs|\
        bin/orbis-node/tests/support/native_pet/member_replacement.rs|\
        bin/orbis-node/tests/support/native_pet/scheduled_refresh.rs|\
        docker/docker-compose-native-integration-test.yml) ;;
        *) echo "Orbis fixture changes runtime source: $path" >&2; exit 1 ;;
    esac
done < "$RUN/fixture-changes.log"
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
    echo "vera=$vera_ref orbis=$orbis_ref fixture=$fixture_ref defra=$defra_ref"
    echo "profile=release curves=bls12-381,jubjub default_features=false"
    echo "kdf=production-defaults (262144 KiB, 3 iterations)"
    rustc +1.98.0 --version --verbose
} | tee "$RUN/provenance.log"

verify_image_label() {
    local image=$1 label=$2 expected=$3
    [[ $(docker image inspect --format "{{ index .Config.Labels \"$label\" }}" "$image") == "$expected" ]] || {
        echo "Native runtime image label mismatch: $label" >&2
        return 1
    }
}

# The Compose fixture uses image IDs, so qualify those exact runtimes.
[[ $(cat "$WORK/orbis/docker/NATIVE_VERA_REF") == "$vera_ref" ]]
vera_image="ghcr.io/sourcenetwork/orbis-rs/vera-native:$orbis_ref"
docker pull "$vera_image"
verify_image_label "$vera_image" org.opencontainers.image.revision "$vera_ref"
export ORBIS_NATIVE_VERA_IMAGE=$(docker image inspect --format '{{.Id}}' "$vera_image")

# Match the released proof client and its inherited workspace dependencies.
client_ref=$(awk '/acp-light-client = / && /github.com\/sourcenetwork\/backbone.git/ {
    if (match($0, /rev = "[0-9a-f]+"/)) print substr($0, RSTART + 7, RLENGTH - 8)
}' "$WORK/orbis/bin/orbis-node/Cargo.toml")
[[ "$client_ref" =~ ^[0-9a-f]{40}$ ]]
if ! git -C "$ROOT" cat-file -e "$client_ref^{commit}" 2>/dev/null; then
    git -C "$ROOT" fetch --depth 1 origin "$client_ref"
fi
git -C "$ROOT" diff --exit-code --quiet HEAD -- Cargo.toml crates/acp-light-client
[[ $(git -C "$ROOT" rev-parse "$client_ref:crates/acp-light-client") == \
   $(git -C "$ROOT" rev-parse 'HEAD:crates/acp-light-client') ]]
git -C "$ROOT" diff --exit-code "$client_ref" HEAD -- Cargo.toml

for curve in bls12-381 jubjub; do
    native=(--manifest-path "$WORK/orbis/Cargo.toml" -p orbis-node
        --no-default-features --features "native,redb,iroh,$curve")
    image="ghcr.io/sourcenetwork/orbis-rs/node-integration:$orbis_ref-native-$curve"
    docker pull "$image"
    verify_image_label "$image" org.opencontainers.image.revision "$orbis_ref"
    verify_image_label "$image" io.sourcenetwork.orbis.backend native
    verify_image_label "$image" io.sourcenetwork.orbis.curve "$curve"
    verify_image_label "$image" io.sourcenetwork.orbis.integration-features false
    export ORBIS_NATIVE_IMAGE=$(docker image inspect --format '{{.Id}}' "$image")
    echo "curve=$curve profile=release orbis_features=native,redb,iroh,$curve default_features=false" \
        | tee "$RUN/provenance-$curve.log"
    printf 'vera_image=%s orbis_image=%s\n' "$ORBIS_NATIVE_VERA_IMAGE" "$ORBIS_NATIVE_IMAGE" \
        | tee -a "$RUN/provenance-$curve.log"
    cargo +1.98.0 tree --locked "${native[@]}" --color never --edges normal,build \
        --prefix none > "$RUN/native-dependencies-$curve.log"
    if grep -E '^(cosmrs|tendermint(-rpc|-config|-proto)?|cosmos-sdk-proto) v' "$RUN/native-dependencies-$curve.log"; then
        echo "Native $curve node includes Cosmos transport dependencies" >&2
        exit 1
    fi
    shasum -a 256 "$WORK/vera/Cargo.lock" "$WORK/orbis/Cargo.lock" \
        | tee -a "$RUN/provenance-$curve.log"

    cargo +1.98.0 test --release --locked "${native[@]}" --test native_startup --no-run \
        2>&1 | tee "$RUN/build-tests-$curve.log"
    cargo +1.98.0 test --release --locked "${native[@]}" --test native_startup \
        -- --list | tee "$RUN/scenarios-$curve.log"
    cargo +1.98.0 test --release --locked "${native[@]}" --test native_startup \
        -- --ignored --list > "$RUN/ignored-scenarios-$curve.log"
    scenarios=(native_startup_registers_and_preserves_identity_on_restart)
    if [[ $curve == bls12-381 ]]; then
        scenarios+=(native_defra_signing)
    fi
    scenarios+=(native_distributed_threshold_workflows native_pet_threshold_workflows
        native_pet_member_replacement native_pet_scheduled_refresh_after_restart)
    for scenario in "${scenarios[@]}"; do
        grep -Fx "$scenario: test" "$RUN/scenarios-$curve.log" >/dev/null
        if grep -Fx "$scenario: test" "$RUN/ignored-scenarios-$curve.log" >/dev/null; then
            echo "Required native scenario remains ignored: $scenario" >&2
            exit 1
        fi
        NATIVE_STACK_CURVE="$curve" bash "$ROOT/.github/scripts/run-native-scenario.sh" "$RUN" "$scenario" \
            cargo +1.98.0 test --release --locked "${native[@]}" --test native_startup \
            "$scenario" -- --exact --test-threads=1 --nocapture
    done
done
