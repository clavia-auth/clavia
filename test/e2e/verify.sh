#!/usr/bin/env bash
# Checks the running end-to-end stack from outside, over HTTPS, as a caller would:
#
#   test/e2e/verify.sh
#
# Discovery answers, the two hosts keep to their own surfaces, and the internal listener is published
# nowhere. It trusts mkcert's CA for these calls only, and needs no /etc/hosts entry: curl is told
# where the names are. CLAVIA_E2E_HTTPS_PORT says where Caddy listens if it is not 443.
set -euo pipefail

domain="clavia.test"
port="${CLAVIA_E2E_HTTPS_PORT:-443}"
ca="$(mkcert -CAROOT)/rootCA.pem"
failed=0

# status <host> <path> prints "<status> <redirect target or ->".
get() {
  curl -s -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 10 --cacert "${ca}" \
    --resolve "$1.${domain}:${port}:127.0.0.1" -H "Host: $1.${domain}" "https://$1.${domain}:${port}$2"
}

expect() { # <description> <actual> <expected pattern>
  if [[ "$2" =~ $3 ]]; then
    echo "ok   $1"
  else
    echo "FAIL $1: got '$2', wanted /$3/"
    failed=1
  fi
}

discovery="$(curl -s --max-time 10 --cacert "${ca}" --resolve "auth.${domain}:${port}:127.0.0.1" -H "Host: auth.${domain}" \
  "https://auth.${domain}:${port}/.well-known/openid-configuration")"
expect "discovery names the issuer" "${discovery}" '"issuer":"https://auth\.clavia\.test"'

# auth.* serves the OAuth and sign-in surfaces; the machine planes are management.*'s.
expect "auth.* refuses the Management API" "$(get auth /api/v1/users)" '^404 '
expect "auth.* refuses SCIM" "$(get auth /scim/v2/Users)" '^404 '
expect "auth.* does not serve metrics" "$(get auth /metrics)" '^404 '

# management.* serves the Management API and SCIM (a 401: they reached the application, which wants
# a token), the dashboard, and sends anything else to the dashboard without reaching PHP.
expect "management.* reaches the Management API" "$(get management /api/v1/users)" '^401 '
expect "management.* reaches SCIM" "$(get management /scim/v2/Users)" '^401 '
expect "management.* does not serve metrics" "$(get management /metrics)" '^404 '
for path in /oauth2/token /auth/login /.well-known/openid-configuration; do
  expect "management.* sends ${path} to the dashboard" "$(get management "${path}")" "^302 https://management\\.clavia\\.test(:[0-9]+)?/dashboard\$"
done

# The internal listener (probes, metrics) is on 8081 inside the network, and published nowhere.
if curl -s -o /dev/null --max-time 3 http://127.0.0.1:8081/healthz; then
  echo "FAIL the internal listener answers on 127.0.0.1:8081"
  failed=1
else
  echo "ok   the internal listener is not published"
fi

exit "${failed}"
