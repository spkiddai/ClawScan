#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/release.sh vX.Y.Z [--skip-tests]

Creates and pushes an annotated release tag for the current main branch.
The GitHub Actions release workflow will publish the GitHub Release.

Environment variables:
  REMOTE=origin   Git remote to push to
  BRANCH=main     Branch that must be checked out and in sync
EOF
}

REMOTE="${REMOTE:-origin}"
BRANCH="${BRANCH:-main}"
SKIP_TESTS=0
VERSION=""

while (($# > 0)); do
  case "$1" in
    --skip-tests)
      SKIP_TESTS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      if [[ -n "$VERSION" ]]; then
        echo "error: unexpected argument: $1" >&2
        usage >&2
        exit 1
      fi
      VERSION="$1"
      shift
      ;;
  esac
done

if [[ -z "$VERSION" ]]; then
  echo "error: version is required" >&2
  usage >&2
  exit 1
fi

if [[ ! "$VERSION" =~ ^v[0-9]+(\.[0-9]+){2}([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "error: version must look like v0.1.0 or v0.1.0-rc.1" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "$REPO_ROOT"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: missing required command: $1" >&2
    exit 1
  fi
}

require_cmd git
require_cmd go

current_branch="$(git branch --show-current)"
if [[ "$current_branch" != "$BRANCH" ]]; then
  echo "error: current branch is '$current_branch', expected '$BRANCH'" >&2
  exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "error: working tree is not clean" >&2
  exit 1
fi

echo "Fetching $REMOTE..."
git fetch --prune --tags "$REMOTE"

local_head="$(git rev-parse HEAD)"
remote_head="$(git rev-parse "$REMOTE/$BRANCH")"
if [[ "$local_head" != "$remote_head" ]]; then
  echo "error: local $BRANCH is not in sync with $REMOTE/$BRANCH" >&2
  echo "local:  $local_head" >&2
  echo "remote: $remote_head" >&2
  exit 1
fi

if git rev-parse -q --verify "refs/tags/$VERSION" >/dev/null; then
  echo "error: tag $VERSION already exists" >&2
  exit 1
fi

if [[ "$SKIP_TESTS" -eq 0 ]]; then
  echo "Running tests..."
  go test ./...
fi

echo "Creating tag $VERSION..."
git tag -a "$VERSION" -m "$VERSION"

echo "Pushing tag $VERSION to $REMOTE..."
git push "$REMOTE" "$VERSION"

cat <<EOF
Release tag pushed successfully.

GitHub Actions should now run the release workflow for:
  $VERSION
EOF
