#!/usr/bin/env bash

set -euxo pipefail

GITHUB_TOKEN="${1:-}"
TARGET_DIR="${2:-}"

if [ -z "$TARGET_DIR" ]; then
  echo "Error: Target directory not provided."
  exit 1
fi


if [ -z "$(git status --porcelain $TARGET_DIR)" ]; then
    echo "[+] No files were changed"
else
    echo "[+] Files were changed! Pushing changes..."
    git pull
    git add $TARGET_DIR
    git remote set-url origin https://x-access-token:${GITHUB_TOKEN}@github.com/$GITHUB_REPOSITORY
    git config --local user.email "41898282+github-actions[bot]@users.noreply.github.com"
    git config --local user.name "GitHub Actions"
    git commit -m "[Github Action] Automated lists update."
    git push
fi