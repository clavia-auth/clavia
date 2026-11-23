#!/usr/bin/env bash
# Builds one release of the Management API reference into a directory:
#
#   docs/site/build.sh <release> <management-api.yaml> <out-dir> [root]
#
# <release> is the server release shown on the page (0.3.0, or `dev` for a preview); [root] is the
# path from <out-dir> to the site's root, where versions.json and the icon live ("" for the root
# itself, "../" for /vX.Y.Z/). Nothing is installed or compiled: the page loads Scalar, pinned, from
# jsDelivr. The Docs workflow runs this; to preview locally:
#
#   docs/site/build.sh dev docs/openapi/management-api.yaml /tmp/clavia-docs && php -S localhost:8080 -t /tmp/clavia-docs
set -euo pipefail

release="${1:?release}"
spec="${2:?path to management-api.yaml}"
out="${3:?output directory}"
root="${4:-}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[[ "${release}" =~ ^([0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?|dev)$ ]] || { echo "Not a release: ${release}" >&2; exit 1; }
[[ "${root}" =~ ^(\.\./)*$ ]] || { echo "Not a path to the root: ${root}" >&2; exit 1; }

mkdir -p "${out}"
sed -e "s|{{RELEASE}}|${release}|g" -e "s|{{ROOT}}|${root}|g" "${here}/index.html" > "${out}/index.html"
cp "${spec}" "${out}/management-api.yaml"
cp "${here}/../../public/auth/static/clavia-icon.svg" "${out}/clavia-icon.svg"
