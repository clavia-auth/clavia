#!/usr/bin/env bash
# Checks that the running end-to-end stack answers, from outside and over HTTPS, before a suite is
# pointed at it:
#
#   test/e2e/verify.sh
#
# Discovery names the issuer, which proves Caddy, TLS, PHP-FPM, the database and the seed are all in
# place. What each host must and must not serve is the Behat suite's (`composer e2e`), not this
# script's. It trusts the CA `up.sh` leaves in test/e2e/.work for this call only, and needs no
# /etc/hosts entry: curl is told where the name is. CLAVIA_E2E_HTTPS_PORT says where Caddy listens if
# it is not 443.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
port="${CLAVIA_E2E_HTTPS_PORT:-443}"

discovery="$(curl -sS --max-time 10 --cacert "${here}/.work/rootCA.pem" \
  --connect-to "auth.clavia.test:443:127.0.0.1:${port}" \
  https://auth.clavia.test/.well-known/openid-configuration)"

if [[ "${discovery}" =~ \"issuer\":\"https://auth\.clavia\.test\" ]]; then
  echo "ok   discovery names the issuer"
else
  echo "FAIL discovery does not name the issuer: ${discovery:0:200}"
  exit 1
fi
