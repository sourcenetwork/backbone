#!/usr/bin/env bash
set -euo pipefail

case "${RESOLVE_LOCKFILE:-false}" in
    true)
        cargo update -p alloy-primitives -p alloy-rlp
        cargo metadata --locked --format-version 1 --filter-platform x86_64-unknown-linux-gnu >/dev/null
        ;;
    false)
        cargo test --locked -p acp-light-client
        cargo clippy --locked -p acp-light-client --all-targets -- -D warnings
        ;;
    *) echo 'Invalid lockfile resolution option' >&2; exit 2 ;;
esac
