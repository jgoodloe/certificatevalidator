#!/usr/bin/env sh
# Create a labeled alert issue assigned to the repo owner, or comment on
# the already-open one so repeated runs don't spam new issues.
# Usage: alert.sh <label> <title> <body-file>
# Requires: gh CLI with GH_TOKEN; GH_REPO or a checkout with origin set.
set -eu
label="$1"; title="$2"; body="$3"
owner="${GITHUB_REPOSITORY_OWNER:?set GITHUB_REPOSITORY_OWNER}"

num=$(gh issue list --label "$label" --state open --json number --jq '.[0].number // empty')
if [ -n "$num" ]; then
    gh issue comment "$num" --body-file "$body"
    echo "Commented on existing alert issue #$num"
else
    gh issue create --title "$title" --label "$label" \
        --assignee "$owner" --body-file "$body"
fi
