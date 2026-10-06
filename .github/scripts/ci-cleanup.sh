#!/usr/bin/env bash
set +x
set -euo pipefail

if [[ -n "${PRIVATE_REPO_PAT:-}" ]]; then
    git config --global --remove-section "url.https://${PRIVATE_REPO_PAT}@github.com/sourcenetwork/" 2>/dev/null || true
fi
git checkout -- .
git clean -fd
