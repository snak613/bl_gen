#!/usr/bin/env bash

set -euxo pipefail

GITHUB_TOKEN="${1:-}"
TARGET_DIR="${2:-}"
CACHE_DIR="${3:-}"


if [ -z "$(git status --porcelain)" ]; then
    echo "[+] No files were changed"
else
    echo "[+] Files were changed! Pushing changes..."
    exit 1
    git pull
    git add $TARGET_DIR $CACHE_DIR
    git remote set-url origin https://x-access-token:${GITHUB_TOKEN}@github.com/$GITHUB_REPOSITORY
    git config --local user.email "41898282+github-actions[bot]@users.noreply.github.com"
    git config --local user.name "GitHub Actions"
    git commit -m "[Github Action] Automated lists update."
    git push
fi
