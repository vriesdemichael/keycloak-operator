#!/usr/bin/env bash
# Check if the current branch has diverged from its remote tracking branch.
# This typically happens when someone rebases the branch remotely (e.g., via GitHub UI
# or the auto-rebase workflow) while you have local commits.
#
# Exit codes:
#   0 - Branch is in sync or ahead (safe to commit)
#   1 - Branch has diverged (needs manual fix before committing)

set -euo pipefail

# Get current branch name
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)

if [[ "$BRANCH" == "HEAD" ]]; then
    # Detached HEAD state - skip check
    exit 0
fi

if [[ "$BRANCH" == "main" ]]; then
    # On main branch - skip divergence check
    exit 0
fi

# Check if branch has a remote tracking branch
UPSTREAM=$(git rev-parse --abbrev-ref --symbolic-full-name "@{u}" 2>/dev/null) || {
    # No upstream configured - that's fine, skip check
    exit 0
}

# Fetch latest from remote (silently)
git fetch --quiet 2>/dev/null || true

# Count commits ahead and behind
AHEAD=$(git rev-list --count "@{u}..HEAD" 2>/dev/null) || AHEAD=0
BEHIND=$(git rev-list --count "HEAD..@{u}" 2>/dev/null) || BEHIND=0

if [[ "$BEHIND" -gt 0 && "$AHEAD" -gt 0 ]]; then
    echo "❌ Branch '$BRANCH' has DIVERGED from its remote!"
    echo ""
    echo "   Local:  $AHEAD commit(s) ahead"
    echo "   Remote: $BEHIND commit(s) ahead"
    echo ""
    echo "This usually happens when the branch was rebased remotely"
    echo "(e.g., by the auto-rebase workflow or GitHub UI)."
    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ HOW TO FIX:                                                 │"
    echo "├─────────────────────────────────────────────────────────────┤"
    echo "│                                                             │"
    echo "│ If you have NO local uncommitted changes you want to keep: │"
    echo "│                                                             │"
    echo "│   git fetch origin                                          │"
    echo "│   git reset --hard origin/$BRANCH                          │"
    echo "│                                                             │"
    echo "│ If you have LOCAL CHANGES to preserve:                      │"
    echo "│                                                             │"
    echo "│   git stash                        # Save your changes      │"
    echo "│   git fetch origin                                          │"
    echo "│   git reset --hard origin/$BRANCH  # Sync with remote      │"
    echo "│   git stash pop                    # Restore your changes   │"
    echo "│                                                             │"
    echo "│ If you have LOCAL COMMITS to preserve (cherry-pick):        │"
    echo "│                                                             │"
    echo "│   git log --oneline -5             # Note your commit SHAs  │"
    echo "│   git fetch origin                                          │"
    echo "│   git reset --hard origin/$BRANCH  # Sync with remote      │"
    echo "│   git cherry-pick <sha1> <sha2>    # Re-apply your commits  │"
    echo "│                                                             │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    exit 1
fi

if [[ "$BEHIND" -gt 0 ]]; then
    echo "⚠️  Branch '$BRANCH' is $BEHIND commit(s) behind remote."
    echo "   Consider running: git pull --rebase"
    echo ""
    # Don't fail - just warn. Being behind is less problematic.
fi

exit 0
