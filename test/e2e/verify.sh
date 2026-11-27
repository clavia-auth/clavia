#!/usr/bin/env bash
# Checks that the running end-to-end stack answers, from outside and over HTTPS, before a suite is
# pointed at it:
#
#   test/e2e/verify.sh
#
# Discovery names the issuer, which proves Caddy, TLS, PHP-FPM, the database and the seed are all in
# place. With CLAVIA_E2E_DASHBOARD=1 it also checks the dashboard. What each host must and must not serve is the Behat suite's (`composer e2e`), not this
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

# With the dashboard in the stack: it answers at /dashboard, and a visitor with no session is sent to sign
# in through Clavia, which proves it reached Clavia's discovery over TLS (its settings are read on first use).
if [[ -n "${CLAVIA_E2E_DASHBOARD:-}" ]]; then
  dashboard() {
    curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 20 --cacert "${here}/.work/rootCA.pem" \
      --connect-to "management.clavia.test:443:127.0.0.1:${port}" "https://management.clavia.test/dashboard$1"
  }
  # The first request is the one that reads the settings: allow the server a moment to be up.
  for _ in $(seq 1 30); do
    signed_out="$(dashboard /signed-out || true)"
    [[ "${signed_out}" == 200* ]] && break
    sleep 2
  done
  [[ "${signed_out}" == 200* ]] || { echo "FAIL the dashboard does not answer at /dashboard/signed-out: ${signed_out}"; exit 1; }
  echo "ok   the dashboard answers"

  sign_in="$(dashboard /auth/sign-in)"
  if [[ "${sign_in}" =~ ^303\ https://auth\.clavia\.test/oauth2/authorize\? ]]; then
    echo "ok   the dashboard sends a visitor to sign in through Clavia"
  else
    echo "FAIL /dashboard/auth/sign-in: ${sign_in:0:200}"
    exit 1
  fi
fi

# With the receiver: it answers on the port it is published on.
if [[ -n "${CLAVIA_E2E_RECEIVER:-}" ]]; then
  if curl -sS -o /dev/null --max-time 10 "http://127.0.0.1:${CLAVIA_E2E_RECEIVER_PORT:-8026}/healthz"; then
    echo "ok   the webhook receiver answers"
  else
    echo "FAIL the webhook receiver does not answer"
    exit 1
  fi
fi
