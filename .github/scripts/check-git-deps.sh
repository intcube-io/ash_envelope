#!/usr/bin/env bash
#
# Guard for git-sourced dependencies in mix.lock.
#
# AshEnvelope tracks ash_storage from an unmerged branch on a third-party fork
# (ash-project/ash_storage#44). mix.lock pins an exact SHA, so builds are
# reproducible — but the branch that SHA came from can be force-pushed, renamed,
# or deleted out from under us, and it can advance without anyone noticing.
#
# This checks, for every git dep in mix.lock:
#
#   1. the branch still exists on the remote          -> hard failure
#   2. the locked SHA is still reachable from it      -> hard failure
#   3. whether the branch tip has moved past the lock -> warning only
#
# (1) and (2) are real breakage: the build cannot be reproduced. (3) is just
# staleness — it must not fail CI, or every upstream push would block unrelated
# pull requests.
#
# Usage: .github/scripts/check-git-deps.sh [path/to/mix.lock]

set -euo pipefail

LOCKFILE="${1:-mix.lock}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

failed=0
drifted=0
checked=0

# GitHub Actions annotations; harmless no-ops in a local shell.
warn() { echo "::warning::$*"; }
fail() { echo "::error::$*"; }

summary() {
  [ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "$*" >>"$GITHUB_STEP_SUMMARY"
  return 0
}

summary "## Git dependency pins"
summary ""

while IFS= read -r line; do
  name=$(sed -E 's/^[[:space:]]*"([^"]+)".*/\1/' <<<"$line")
  url=$(sed -E 's/.*\{:git, "([^"]+)".*/\1/' <<<"$line")
  sha=$(sed -E 's/.*\{:git, "[^"]+", "([0-9a-f]+)".*/\1/' <<<"$line")

  # A git dep may be pinned by branch, tag, or ref. Only branch pins can drift.
  if [[ "$line" =~ branch:\ \"([^\"]+)\" ]]; then
    branch="${BASH_REMATCH[1]}"
  else
    echo "→ $name: not a branch pin, skipping drift check"
    summary "- \`$name\` — pinned by tag/ref, no drift possible"
    continue
  fi

  checked=$((checked + 1))
  echo "→ $name: $url @ $branch"
  echo "  locked: $sha"

  tip=$(git ls-remote "$url" "refs/heads/$branch" 2>/dev/null | cut -f1)

  if [ -z "$tip" ]; then
    fail "$name: branch '$branch' no longer exists at $url — the pin cannot be resolved."
    summary "- ❌ \`$name\` — branch \`$branch\` is **gone** from the remote"
    failed=1
    continue
  fi

  echo "  tip:    $tip"

  # Shallow-ish clone: we need commit topology to test ancestry, but no blobs.
  clone="$WORKDIR/$name"
  if ! git clone --quiet --filter=blob:none --branch "$branch" "$url" "$clone" 2>/dev/null; then
    fail "$name: could not clone $url ($branch)."
    summary "- ❌ \`$name\` — clone failed"
    failed=1
    continue
  fi

  if ! git -C "$clone" cat-file -e "${sha}^{commit}" 2>/dev/null; then
    fail "$name: locked commit $sha is not present on '$branch' (force-pushed or rebased away)."
    summary "- ❌ \`$name\` — locked commit \`${sha:0:8}\` **no longer exists** on \`$branch\`"
    failed=1
    continue
  fi

  if ! git -C "$clone" merge-base --is-ancestor "$sha" HEAD 2>/dev/null; then
    fail "$name: locked commit $sha exists but is not an ancestor of '$branch' — the branch was rewritten."
    summary "- ❌ \`$name\` — locked commit \`${sha:0:8}\` is **not on** \`$branch\` anymore"
    failed=1
    continue
  fi

  if [ "$tip" != "$sha" ]; then
    behind=$(git -C "$clone" rev-list --count "${sha}..HEAD")
    warn "$name: pin is $behind commit(s) behind '$branch' (locked ${sha:0:8}, tip ${tip:0:8}). Not a failure — bump when ready."
    summary "- ⚠️ \`$name\` — **$behind commit(s) behind** \`$branch\` (locked \`${sha:0:8}\`, tip \`${tip:0:8}\`)"
    drifted=$((drifted + 1))
  else
    echo "  ✓ up to date with branch tip"
    summary "- ✅ \`$name\` — at \`$branch\` tip (\`${sha:0:8}\`)"
  fi
done < <(grep ':git,' "$LOCKFILE")

echo
if [ "$checked" -eq 0 ]; then
  echo "No branch-pinned git dependencies in $LOCKFILE."
fi

if [ "$failed" -ne 0 ]; then
  echo "FAILED: at least one git pin can no longer be resolved."
  exit 1
fi

if [ "$drifted" -ne 0 ]; then
  echo "OK (with $drifted stale pin(s)) — all locked commits still resolve."
else
  echo "OK — all git pins resolve and are current."
fi
