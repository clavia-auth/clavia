#!/usr/bin/env bash
# Builds one release of the Management API reference, and its guides, into a directory:
#
#   docs/site/build.sh <release> <management-api.yaml> <out-dir> [root] [guides-dir]
#
# <release> is the server release shown on the page (0.3.0, or `dev` for a preview); [root] is the
# path from <out-dir> to the site's root, where versions.json and the icon live ("" for the root
# itself, "../" for /vX.Y.Z/). [guides-dir] holds the release's guides (docs/guides): README.md lists
# them in order, and each becomes <out-dir>/guides/<name>.html beside its Markdown. Without it (a
# release from before the guides), the reference is built alone and links to none.
#
# Nothing is installed or compiled: the pages load Scalar, marked and DOMPurify, pinned, from
# jsDelivr. The Docs workflow runs this; to preview locally:
#
#   docs/site/build.sh dev docs/openapi/management-api.yaml /tmp/clavia-docs "" docs/guides \
#     && php -S localhost:8080 -t /tmp/clavia-docs
set -euo pipefail

release="${1:?release}"
spec="${2:?path to management-api.yaml}"
out="${3:?output directory}"
root="${4:-}"
guides="${5:-}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[[ "${release}" =~ ^([0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?|dev)$ ]] || { echo "Not a release: ${release}" >&2; exit 1; }
[[ "${root}" =~ ^(\.\./)*$ ]] || { echo "Not a path to the root: ${root}" >&2; exit 1; }
[ -z "${guides}" ] || [ -f "${guides}/README.md" ] || { echo "No README.md in ${guides}" >&2; exit 1; }

# Fills a template's {{NAME}} placeholders from NAME=value arguments, values taken literally (through
# the environment: awk would read escapes in a -v value).
fill() {
  local template="$1" pair names=""
  shift
  for pair in "$@"; do
    export "FILL_${pair%%=*}=${pair#*=}"
    names+="${pair%%=*} "
  done
  FILL_NAMES="${names}" awk '
    BEGIN { count = split(ENVIRON["FILL_NAMES"], names, " ") }
    {
      for (i = 1; i <= count; i++) {
        key = "{{" names[i] "}}"
        value = ENVIRON["FILL_" names[i]]
        out = ""
        rest = $0
        while ((at = index(rest, key)) > 0) {
          out = out substr(rest, 1, at - 1) value
          rest = substr(rest, at + length(key))
        }
        $0 = out rest
      }
      print
    }' "${template}"
}

mkdir -p "${out}"
if [ -n "${guides}" ]; then
  fill "${here}/index.html" "RELEASE=${release}" "ROOT=${root}" > "${out}/index.html"
else
  # No guides for this release: the lines that link to them go.
  grep -v 'data-guides' "${here}/index.html" | fill /dev/stdin "RELEASE=${release}" "ROOT=${root}" > "${out}/index.html"
fi
cp "${spec}" "${out}/management-api.yaml"
cp "${here}/../../public/auth/static/clavia-icon.svg" "${out}/clavia-icon.svg"

[ -n "${guides}" ] || exit 0

# The guides, in the order README.md lists them ("1. [Title](name.md): …"), the index first.
pages=("index|Overview|README")
while IFS='|' read -r name title; do
  [ -f "${guides}/${name}.md" ] || { echo "README.md lists ${name}.md, which does not exist" >&2; exit 1; }
  pages+=("${name}|${title}|${name}")
done < <(sed -nE 's/^[0-9]+\. \[([^]]+)\]\(([a-z0-9-]+)\.md\).*/\2|\1/p' "${guides}/README.md")

mkdir -p "${out}/guides"
for page in "${pages[@]}"; do
  IFS='|' read -r name title source <<< "${page}"
  nav=""
  for other in "${pages[@]}"; do
    IFS='|' read -r other_name other_title _ <<< "${other}"
    href="${other_name}.html"
    [ "${other_name}" = index ] && href="./"
    current=""
    [ "${other_name}" = "${name}" ] && current=' aria-current="page"'
    nav+="        <li><a href=\"${href}\"${current}>${other_title}</a></li>"$'\n'
  done
  cp "${guides}/${source}.md" "${out}/guides/${name}.md"
  fill "${here}/guide.html" "RELEASE=${release}" "ROOT=${root}../" "SLUG=${name}" "TITLE=${title}" \
    "NAV=${nav%$'\n'}" > "${out}/guides/${name}.html"
done
