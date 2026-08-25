#!/usr/bin/env bash
# Enforce the repository's single-author publication policy.
set -Eeuo pipefail

repo="$(git rev-parse --show-toplevel)"
cd "$repo"

revision="${1:-HEAD}"
expected_email="sorenplanck@tutamail.com"
policy_baseline="${DOM_AUTHORSHIP_BASELINE:-87ec29415f4ef07c2b41ca6e31f45e3be95a0875}"
failures=0

if ! git merge-base --is-ancestor "$policy_baseline" "$revision"; then
  echo "authorship policy baseline is not an ancestor of $revision: $policy_baseline" >&2
  exit 1
fi

revision_range="${policy_baseline}..${revision}"

while IFS=$'\t' read -r commit author_name author_email committer_name committer_email parents; do
  if [[ "$author_email" != "$expected_email" ]]; then
    echo "$commit has an unauthorized author email: $author_email" >&2
    failures=$((failures + 1))
  fi
  if [[ "$author_name" != "Soren Planck" && "$author_name" != "sorenplanck" ]]; then
    echo "$commit has an unauthorized author name: $author_name" >&2
    failures=$((failures + 1))
  fi
  # A merge performed through the GitHub web interface is committed by the
  # host identity "GitHub <noreply@github.com>". When the merge's author is
  # the single policy author, that committer identity belongs to the hosting
  # platform, not to a second contributor, so it does not breach the policy.
  # The allowance is limited to merge commits: an ordinary commit with the
  # host committer identity still fails.
  if [[ "$committer_email" == "noreply@github.com" && "$committer_name" == "GitHub" \
        && "$author_email" == "$expected_email" && "$parents" == *" "* ]]; then
    continue
  fi
  if [[ "$committer_email" != "$expected_email" ]]; then
    echo "$commit has an unauthorized committer email: $committer_email" >&2
    failures=$((failures + 1))
  fi
  if [[ "$committer_name" != "Soren Planck" && "$committer_name" != "sorenplanck" ]]; then
    echo "$commit has an unauthorized committer name: $committer_name" >&2
    failures=$((failures + 1))
  fi
done < <(git log "$revision_range" --format=$'%H\t%an\t%ae\t%cn\t%ce\t%P')

# A here-string, not a pipeline. `grep -q` exits at the first match, which
# kills a piped producer with SIGPIPE, and `set -o pipefail` then reports that
# 141 as the pipeline's status — so a MATCH reads as NO MATCH and the ban
# silently stops being enforced. It only fires once the log exceeds the pipe
# buffer, and this range is already 58 KB against 64 KB.
commit_bodies="$(git log "$revision_range" --format='%B')"
if grep -Eiq '^Co-authored-by:' <<<"$commit_bodies"; then
  echo "co-author trailers are forbidden by the single-author policy" >&2
  failures=$((failures + 1))
fi

if [[ $failures -ne 0 ]]; then
  echo "AUTHORSHIP = FAIL ($failures violation(s))" >&2
  exit 1
fi

echo "AUTHORSHIP = PASS (Soren Planck is the sole author and committer after $policy_baseline)"
