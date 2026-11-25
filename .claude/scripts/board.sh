#!/usr/bin/env bash
# The Clavia project board (https://github.com/orgs/clavia-auth/projects/1) from the shell,
# for the ticket-* skills.
#
#   board.sh show                       open items: Status, Priority, Size, repository#number, title
#   board.sh status <url> <Status>      Backlog | Ready | In progress | In review | Done
#   board.sh set <url> <Field> <Value>  Priority P0–P3, Size XS–XL, Area …
#
# <url> is an issue's or a pull request's html_url; an item not on the board yet is added.
# Needs a gh login with the project scope (gh auth refresh -s project). Where the board cannot
# be reached (no scope, or a sandbox without GraphQL) it says so and exits 3: callers carry on,
# because the board's own workflows move items when a pull request is linked and merged.
#
# GitHub's GraphQL API allows 5,000 points an hour, and 2,000 a minute: a batch of updates hits the
# second long before the first. So the project's id and fields are fetched in one query and cached
# for ten minutes, `show` asks for the three fields it prints and nothing else, and a call refused
# for rate limiting is retried after a pause before the board is given up on.
set -euo pipefail

OWNER=clavia-auth
PROJECT=1
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/clavia-board"
CACHE="$CACHE_DIR/project-$OWNER-$PROJECT.json"
CACHE_SECONDS=600

unreachable() {
  echo "board: the project board cannot be reached from here ($1); leaving it to its workflows" >&2
  exit 3
}

# Run a gh command; when GitHub refuses it for rate limiting, wait 20 s, then 40 s, and try again.
# Its output goes to stdout; anything else it says, to stderr, once it has given up.
retrying() {
  local err attempt
  err=$(mktemp)
  for attempt in 1 2 3; do
    if "$@" 2>"$err"; then
      rm -f "$err"
      return 0
    fi
    grep -qi 'rate limit' "$err" || break
    [ "$attempt" -lt 3 ] && sleep $((attempt * 20))
  done
  if grep -qi 'rate limit' "$err"; then
    rm -f "$err"
    unreachable "GitHub's rate limit, still refused after a minute"
  fi
  cat "$err" >&2
  rm -f "$err"
  return 1
}

# Seconds since the cache was written; a large number when there is none.
cache_age() {
  if [ -f "$CACHE" ]; then
    echo $(($(date +%s) - $(stat -f %m "$CACHE" 2>/dev/null || stat -c %Y "$CACHE")))
  else
    echo 999999
  fi
}

# The project's node id and its single-select fields with their options, from the cache while it is
# fresh: {id, fields: [{id, name, options: [{id, name}]}]}.
project() {
  local refresh=${1:-}
  if [ -z "$refresh" ] && [ "$(cache_age)" -lt "$CACHE_SECONDS" ]; then
    cat "$CACHE"
    return
  fi
  local json
  # shellcheck disable=SC2016 # $owner and $number are GraphQL variables, not the shell's.
  json=$(retrying gh api graphql -F number="$PROJECT" -f owner="$OWNER" -f query='
    query($owner: String!, $number: Int!) {
      organization(login: $owner) {
        projectV2(number: $number) {
          id
          fields(first: 50) {
            nodes { ... on ProjectV2SingleSelectField { id name options { id name } } }
          }
        }
      }
    }' --jq '.data.organization.projectV2 | {id, fields: [.fields.nodes[] | select(.id)]}') \
    || unreachable "the project could not be read"
  [ -n "$json" ] && [ "$json" != "null" ] || unreachable "no project $PROJECT under $OWNER"
  mkdir -p "$CACHE_DIR"
  printf '%s\n' "$json" >"$CACHE"
  printf '%s\n' "$json"
}

ids() { # project json, field, option → "field-id option-id", or nothing
  jq -r --arg f "$2" --arg o "$3" \
    '.fields[] | select(.name==$f) as $field | $field.options[] | select(.name==$o) | "\($field.id) \(.id)"' <<<"$1"
}

set_option() { # url, field, option
  local url=$1 field=$2 option=$3 json pair fid oid item
  json=$(project)
  pair=$(ids "$json" "$field" "$option")
  if [ -z "$pair" ] && [ "$(cache_age)" -ge 60 ]; then
    # A field or an option added since the cache was written: read the project once more, unless
    # it was read within the minute (a typo must not cost a query every time).
    json=$(project refresh)
    pair=$(ids "$json" "$field" "$option")
  fi
  if [ -z "$pair" ]; then
    jq -e --arg f "$field" '.fields[] | select(.name==$f)' <<<"$json" >/dev/null \
      || { echo "board: no field named $field" >&2; exit 2; }
    echo "board: $field has no option $option" >&2
    exit 2
  fi
  read -r fid oid <<<"$pair"
  # Adding an item already on the board returns the item it is.
  item=$(retrying gh project item-add "$PROJECT" --owner "$OWNER" --url "$url" --format json --jq .id) \
    || unreachable "the item could not be added"
  retrying gh project item-edit --id "$item" --project-id "$(jq -r .id <<<"$json")" --field-id "$fid" \
    --single-select-option-id "$oid" >/dev/null || unreachable "the field could not be set"
  echo "board: $field → $option ($url)"
}

show() {
  # Three field values and the content's title per item, 100 items a page: a few points a page,
  # where `gh project item-list` asks for every field of every item.
  # shellcheck disable=SC2016 # GraphQL variables, not the shell's.
  retrying gh api graphql --paginate -F number="$PROJECT" -f owner="$OWNER" -f query='
    query($owner: String!, $number: Int!, $endCursor: String) {
      organization(login: $owner) {
        projectV2(number: $number) {
          items(first: 100, after: $endCursor) {
            pageInfo { hasNextPage endCursor }
            nodes {
              status: fieldValueByName(name: "Status") { ... on ProjectV2ItemFieldSingleSelectValue { name } }
              priority: fieldValueByName(name: "Priority") { ... on ProjectV2ItemFieldSingleSelectValue { name } }
              size: fieldValueByName(name: "Size") { ... on ProjectV2ItemFieldSingleSelectValue { name } }
              content {
                ... on Issue { number title repository { name } }
                ... on PullRequest { number title repository { name } }
                ... on DraftIssue { title }
              }
            }
          }
        }
      }
    }' --jq '.data.organization.projectV2.items.nodes[]
      | select((.status.name // "") != "Done")
      | [(.status.name // "-"), (.priority.name // "-"), (.size.name // "-"),
         ((.content.repository.name // "") + "#" + ((.content.number // 0) | tostring)),
         (.content.title // "")] | @tsv' \
    | awk '!seen[$0]++' | sort -t$'\t' -k1,1 -k2,2
}

case "${1:-}" in
  show) [ $# -eq 1 ] || { echo "usage: board.sh show" >&2; exit 2; }
    show || unreachable "the items could not be listed" ;;
  status) [ $# -eq 3 ] || { echo "usage: board.sh status <url> <Status>" >&2; exit 2; }
    set_option "$2" Status "$3" ;;
  set) [ $# -eq 4 ] || { echo "usage: board.sh set <url> <Field> <Value>" >&2; exit 2; }
    set_option "$2" "$3" "$4" ;;
  *) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
