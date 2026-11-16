#!/usr/bin/env bash
# Append one audited run to the evidence branch using fast-forward pushes only.
set -euo pipefail

report=$(cd "$1" && pwd)
remote=$(git remote get-url origin)
branch=interop-evidence
ref="refs/heads/$branch"
path="runs/${GITHUB_RUN_ID}/attempt-${GITHUB_RUN_ATTEMPT}"
# Keep the Actions checkout credentials and take the same append-only path
# on the first publication, on retries, and if another writer advances the ref.
for attempt in 1 2 3 4 5; do
  if git ls-remote --exit-code "$remote" "$ref" >/dev/null; then
    git fetch --depth=1 --no-tags origin "$ref"
    git switch --detach FETCH_HEAD
  else
    status=$?
    [[ "$status" == 2 ]] || exit "$status"
    git switch --orphan "$branch-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-$attempt"
  fi

  if [[ -d "$path" ]]; then
    diff -qr "$report" "$path"
    exit 0
  fi
  mkdir -p "$path"
  cp "$report"/{results.csv.gz,summary.json,summary.md,provenance.json} "$path/"
  git add -- "$path"
  git -c user.name='github-actions[bot]' -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
    commit -m "Record WIMSE matrix evidence for run $GITHUB_RUN_ID attempt $GITHUB_RUN_ATTEMPT"
  if git push origin "HEAD:$ref"; then exit 0; fi
  sleep "$attempt"
done
echo "Unable to append evidence after five fast-forward push attempts" >&2
exit 1
