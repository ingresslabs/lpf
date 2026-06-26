#!/bin/bash
set -euo pipefail

REPO="ingresslabs/lpf"
GIT_REMOTE="${GIT_REMOTE:-origin}"
GIT_LAB_REMOTE="${GIT_LAB_REMOTE:-lab}"

echo "=== lpf auto-release ==="

VERSION=$(grep -m1 '^## ' CHANGELOG.md | sed 's/^## //' | cut -d' ' -f1)

if [ -z "${VERSION}" ]; then
  echo "ERROR: could not extract version from CHANGELOG.md"
  exit 1
fi

TAG="v${VERSION}"
echo "Version: ${VERSION}  Tag: ${TAG}"

if git rev-parse "${TAG}" >/dev/null 2>&1; then
  echo "Tag ${TAG} already exists, checking for new commits..."
  COMMITS_SINCE=$(git rev-list --count "${TAG}..HEAD")
  if [ "${COMMITS_SINCE}" -eq 0 ]; then
    echo "No new commits since ${TAG}, nothing to do."
    exit 0
  fi
  echo "ERROR: tag ${TAG} exists but there are ${COMMITS_SINCE} new commits since."
  echo "Bump the version in CHANGELOG.md first."
  exit 1
fi

LAST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
if [ -n "${LAST_TAG}" ]; then
  COMMITS_SINCE=$(git rev-list --count "${LAST_TAG}..HEAD")
  if [ "${COMMITS_SINCE}" -eq 0 ]; then
    echo "No new commits since ${LAST_TAG}, nothing to do."
    exit 0
  fi
  echo "Commits since ${LAST_TAG}: ${COMMITS_SINCE}"
fi

git config user.email "jenkins@lpf.ci"
git config user.name "Jenkins CI"

git tag -a "${TAG}" -m "Release ${TAG}"
echo "Tag ${TAG} created."

echo "Pushing tag to ${GIT_REMOTE}..."
git push "${GIT_REMOTE}" "${TAG}"

if git remote get-url "${GIT_LAB_REMOTE}" >/dev/null 2>&1; then
  echo "Pushing tag to ${GIT_LAB_REMOTE}..."
  git push "${GIT_LAB_REMOTE}" "${TAG}" || echo "(lab push skipped)"
fi

echo "Waiting for GitHub Actions release workflow to finish..."
for i in $(seq 1 30); do
  sleep 20
  STATUS=$(gh run list --repo "${REPO}" --workflow release.yml --limit 1 --json status --jq '.[0].status' 2>/dev/null || echo "")
  if [ "${STATUS}" = "completed" ]; then
    CONCLUSION=$(gh run list --repo "${REPO}" --workflow release.yml --limit 1 --json conclusion --jq '.[0].conclusion' 2>/dev/null || echo "")
    echo "Release workflow finished: ${CONCLUSION}"
    break
  fi
  echo "  waiting... (${i}/30)"
done

echo "Cleaning up old GitHub Releases (keeping only latest)..."
RELEASE_COUNT=$(gh release list --repo "${REPO}" --limit 100 --json tagName --jq 'length' 2>/dev/null || echo "0")
if [ "${RELEASE_COUNT}" -gt 1 ]; then
  gh release list --repo "${REPO}" --limit 100 --json tagName --jq '.[1:][].tagName' | while read -r old_tag; do
    echo "  deleting release: ${old_tag}"
    gh release delete "${old_tag}" --repo "${REPO}" --yes
  done
  echo "Old releases cleaned. Only latest remains."
else
  echo "  ${RELEASE_COUNT} release(s) found, nothing to clean."
fi

echo "=== auto-release complete: ${TAG} ==="
