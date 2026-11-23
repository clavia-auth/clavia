#!/usr/bin/env bash
# Places one built release into a checkout of the gh-pages branch:
#
#   docs/site/publish.sh <version> <built-site> <pages-dir>
#
# <built-site> holds what docs/site/build.sh made: `v<version>/` (the release's own directory) and
# `root/` (the same release, for the site's root). The release's directory is replaced whole; the
# root becomes this release only when it is the newest stable one; versions.json lists every
# release published, newest first, for the page's release picker. The Docs workflow commits the
# result.
set -euo pipefail

version="${1:?version}"
built="${2:?built site}"
pages="${3:?pages directory}"

[[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "Not a release: ${version}" >&2; exit 1; }

touch "${pages}/.nojekyll"
rm -rf "${pages:?}/v${version}"
cp -R "${built}/v${version}" "${pages}/v${version}"

releases() {
  local dir
  for dir in "${pages}"/v[0-9]*/; do
    [ -d "${dir}" ] && basename "${dir}" | sed 's/^v//'
  done | sort -V -r
}
latest=$(releases | grep -v -- - | head -n 1 || true)
if [ "${version}" = "${latest}" ]; then
  cp "${built}/root/"* "${pages}/"
fi
releases | jq -R . | jq -s --arg latest "${latest}" '{latest: $latest, versions: .}' > "${pages}/versions.json"
