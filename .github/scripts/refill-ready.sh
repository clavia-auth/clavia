#!/usr/bin/env bash
# Keeps the Ready column of the Clavia board (https://github.com/orgs/clavia-auth/projects/1)
# stocked: when it holds fewer than READY_TARGET items, the next ones move up from Backlog.
#
# "Next" is the order the ticket-pick skill uses (.claude/skills/ticket-pick/SKILL.md):
#   1. the earliest milestone (0.1 before 0.2…; no milestone last),
#   2. priority (P0 first; none last),
#   3. Security and Bug before Feature and Task,
#   4. the smallest size, then the lowest number.
# Never moved: a closed issue, a pull request, an issue labelled needs-design, an issue that
# says "Depends on #N" (or another repository's issue) while N is open, and a "Release …"
# issue while its milestone has other open issues in any repository on the board.
#
# It only fills Ready; it never takes anything out of In progress. The WIP limit of In progress
# is the ticket-* skills' to keep, and the board's column limit shows it.
#
# Needs GH_TOKEN with Projects read and write on the organisation (the PROJECT_TOKEN secret).
# DRY_RUN=1 prints what it would move and moves nothing; ITEMS_FILE reads the board's items
# from a file instead of the board, with DRY_RUN, for testing: `{items: [{id, status, priority,
# size, content: {type, repository, number}}]}`, the shape of `gh project item-list`.
#
# GitHub's GraphQL API allows the token's user 5,000 points an hour, shared with everything else
# acting as them. `gh project item-list` asks for every field of every item, hundreds of points a
# run; the board is read here with the four fields this script uses, a page of 100 at a time.
set -euo pipefail

OWNER=clavia-auth
PROJECT=1
READY_TARGET=${READY_TARGET:-5}
DRY_RUN=${DRY_RUN:-0}

summary() { echo "$*"; [ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "$*" >>"$GITHUB_STEP_SUMMARY"; return 0; }

if [ -n "${ITEMS_FILE:-}" ]; then
  items=$(cat "$ITEMS_FILE")
else
  # shellcheck disable=SC2016 # $owner, $number and $endCursor are GraphQL variables.
  items=$(gh api graphql --paginate -F number="$PROJECT" -f owner="$OWNER" -f query='
    query($owner: String!, $number: Int!, $endCursor: String) {
      organization(login: $owner) {
        projectV2(number: $number) {
          items(first: 100, after: $endCursor) {
            pageInfo { hasNextPage endCursor }
            nodes {
              id
              status: fieldValueByName(name: "Status") { ... on ProjectV2ItemFieldSingleSelectValue { name } }
              priority: fieldValueByName(name: "Priority") { ... on ProjectV2ItemFieldSingleSelectValue { name } }
              size: fieldValueByName(name: "Size") { ... on ProjectV2ItemFieldSingleSelectValue { name } }
              content {
                __typename
                ... on Issue { number repository { nameWithOwner } }
                ... on PullRequest { number repository { nameWithOwner } }
              }
            }
          }
        }
      }
    }' --jq '.data.organization.projectV2.items.nodes[]
      | {id, status: .status.name, priority: .priority.name, size: .size.name,
         content: {type: .content.__typename, repository: .content.repository.nameWithOwner,
                   number: .content.number}}' | jq -s '{items: .}')
fi
count() { jq --arg s "$1" '[.items[] | select(.status == $s)] | length' <<<"$items"; }
ready=$(count Ready)
in_progress=$(count "In progress")
in_review=$(count "In review")
summary "Board: Ready $ready, In progress $in_progress, In review $in_review (Ready target $READY_TARGET)."

wanted=$((READY_TARGET - ready))
if [ "$wanted" -le 0 ]; then
  summary "Ready is full; nothing moved."
  exit 0
fi

# Open issues still to do in a milestone, across the repositories on the board, by milestone title.
declare -A open_in_milestone=()
for repo in clavia clavia-dashboard authzen-php clavia-js-core clavia-js-next clavia-js-effect; do
  while IFS=$'\t' read -r title open; do
    [ -n "$title" ] || continue
    open_in_milestone["$title"]=$(( ${open_in_milestone["$title"]:-0} + open ))
  done < <(gh api "repos/$OWNER/$repo/milestones?state=open&per_page=100" --jq '.[] | "\(.title)\t\(.open_issues)"')
done

is_open() { # owner/repo number
  [ "$(gh api "repos/$1/issues/$2" --jq .state 2>/dev/null || echo closed)" = open ]
}

# One line per eligible Backlog issue: sort key, then the item id and its reference.
candidates=""
while IFS=$'\t' read -r item_id repo number priority size; do
  issue=$(gh api "repos/$repo/issues/$number")
  read -r state is_pr design type milestone < <(jq -r '[.state, (has("pull_request")|tostring),
      ([.labels[].name] | index("needs-design") != null | tostring),
      (.type.name // "-"), ((.milestone.title // "-") | gsub(" "; " "))] | @tsv' <<<"$issue")
  milestone=${milestone//$' '/ }
  [ "$state" = open ] && [ "$is_pr" = false ] && [ "$design" = false ] || continue

  title=$(jq -r .title <<<"$issue")
  if [[ $title == Release\ * ]] && [ "${open_in_milestone["$milestone"]:-0}" -gt 1 ]; then
    continue
  fi

  blocked=false
  while read -r dep; do
    [ -n "$dep" ] || continue
    dep_repo=${dep%#*}; dep_number=${dep#*#}
    [ "$dep_repo" = "" ] && dep_repo=$repo
    [[ $dep_repo == */* ]] || dep_repo="$OWNER/$dep_repo"
    if is_open "$dep_repo" "$dep_number"; then blocked=true; break; fi
  done < <(jq -r '.body // ""' <<<"$issue" \
    | grep -oiE 'depends on ([a-z0-9._/-]+)?#[0-9]+' | sed -E 's/^[Dd]epends on //' || true)
  $blocked && continue

  # Sort key: milestone version (no milestone last), priority, type, size, number.
  version=$(grep -oE '^[0-9]+(\.[0-9]+)*' <<<"$milestone" || true)
  m_key=$( [ -n "$version" ] && awk -F. '{printf "%04d%04d%04d", $1, $2, $3}' <<<"$version" || echo 999999999999)
  case $priority in P0) p=0 ;; P1) p=1 ;; P2) p=2 ;; P3) p=3 ;; *) p=9 ;; esac
  case $type in Security) t=0 ;; Bug) t=1 ;; Feature) t=2 ;; Task) t=3 ;; *) t=9 ;; esac
  case $size in XS) s=0 ;; S) s=1 ;; M) s=2 ;; L) s=3 ;; XL) s=4 ;; *) s=9 ;; esac
  candidates+="$m_key$p$t$s$(printf %06d "$number")"$'\t'"$item_id"$'\t'"${repo#*/}#$number $title"$'\n'
done < <(jq -r '.items[] | select(.status == "Backlog" and .content.type == "Issue")
    | [.id, .content.repository, (.content.number | tostring), (.priority // "-"), (.size // "-")] | @tsv' <<<"$items")

chosen=$(printf '%s' "$candidates" | sort | head -n "$wanted")
if [ -z "$chosen" ]; then
  summary "Ready is short of $wanted, but nothing in Backlog can start: triage or design is needed."
  exit 0
fi

if [ "$DRY_RUN" != 1 ]; then
  # The project's id and its Status field with the Ready option, in one query.
  # shellcheck disable=SC2016 # GraphQL variables.
  read -r project_id status_field ready_option < <(gh api graphql -F number="$PROJECT" -f owner="$OWNER" -f query='
    query($owner: String!, $number: Int!) {
      organization(login: $owner) {
        projectV2(number: $number) {
          id
          field(name: "Status") { ... on ProjectV2SingleSelectField { id options { id name } } }
        }
      }
    }' --jq '.data.organization.projectV2
      | "\(.id) \(.field.id) \(.field.options[] | select(.name == "Ready") | .id)"')
fi

while IFS=$'\t' read -r _ item_id label; do
  if [ "$DRY_RUN" = 1 ]; then
    summary "- would move to Ready: $label"
  else
    gh project item-edit --id "$item_id" --project-id "$project_id" \
      --field-id "$status_field" --single-select-option-id "$ready_option" >/dev/null
    summary "- moved to Ready: $label"
  fi
done <<<"$chosen"
