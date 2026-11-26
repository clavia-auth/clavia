#!/usr/bin/env bash
# Starts the end-to-end stack (compose.yaml) and seeds it:
#
#   test/e2e/up.sh
#
# Needs Docker and mkcert. Makes a certificate for *.clavia.test with mkcert's CA (it does not install
# the CA anywhere: the callers trust it, see test/e2e/verify.sh), the production Caddyfile with that
# certificate in its two https sites, starts everything and waits until it is healthy, then runs
# `seed-dev`. Safe to run again.
#
# The stack publishes ports 80 and 443 on 127.0.0.1: stop the development stack (`make down`) first, or
# move this one with CLAVIA_E2E_HTTP_PORT and CLAVIA_E2E_HTTPS_PORT.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "${here}/../.." && pwd)"
work="${here}/.work"
domain="clavia.test"
compose=(docker compose -f "${here}/compose.yaml")

command -v mkcert >/dev/null || { echo "mkcert is needed: https://github.com/FiloSottile/mkcert" >&2; exit 1; }

mkdir -p "${work}/certs"
if [[ ! -f "${work}/certs/${domain}.pem" ]]; then
  mkcert -cert-file "${work}/certs/${domain}.pem" -key-file "${work}/certs/${domain}-key.pem" \
    "${domain}" "*.${domain}" >/dev/null 2>&1
fi

# The CA the certificate comes from, for the callers that trust it (verify.sh, the Behat suite).
cp "$(mkcert -CAROOT)/rootCA.pem" "${work}/rootCA.pem"

# The production Caddyfile, with this certificate in the two https sites and nothing else changed:
# its rules are what is tested.
sed -E 's#^(\{\$CLAVIA_CADDY_SCHEME:https\}://(auth|management)\.\{\$CLAVIA_ROOT_DOMAIN\} \{)$#\1\
	tls /etc/caddy/certs/{$CLAVIA_ROOT_DOMAIN}.pem /etc/caddy/certs/{$CLAVIA_ROOT_DOMAIN}-key.pem#' \
  "${root}/deploy/helm/clavia/files/Caddyfile" >"${work}/Caddyfile"
if [[ "$(grep -c '^	tls /etc/caddy/certs/' "${work}/Caddyfile")" != 2 ]]; then
  echo "The production Caddyfile no longer has the two https sites this script adds a certificate to." >&2
  exit 1
fi

"${compose[@]}" up -d --build --wait
"${compose[@]}" exec -T php php bin/clavia seed-dev >"${work}/seed.txt"

echo "Up: https://auth.${domain} and https://management.${domain} (127.0.0.1)."
for name in auth management; do
  if ! getent hosts "${name}.${domain}" >/dev/null 2>&1 && ! dscacheutil -q host -a name "${name}.${domain}" 2>/dev/null | grep -q ip_address; then
    echo "Note: ${name}.${domain} does not resolve here; a browser needs '127.0.0.1 ${name}.${domain}' in /etc/hosts." >&2
  fi
done
