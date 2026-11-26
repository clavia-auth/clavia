#!/usr/bin/env bash
# The OpenID Foundation conformance plans against the end-to-end stack, compared with the baseline:
#
#   conformance/run.sh            # exits 1 when an outcome differs from conformance/baseline.json
#   CLAVIA_E2E_COMPOSE_OVERRIDE=conformance/compose.yaml test/e2e/down.sh    # afterwards
#
# The steps of conformance/README.md as a script: the suite built at the release the README names, the
# stack started with the suite beside it (conformance/compose.yaml), the seeded account given a profile and
# the suite's clients registered (provision.py), both plans run, and every module's outcome compared with
# baseline.json (compare.py). Needs Docker, mkcert, Java 17 with Maven, Python 3, and the stack's names
# resolving to 127.0.0.1 (auth., management. and suite.clavia.test). What the run leaves is in
# conformance/.work/report: the outcomes, the differences, and the suite's HTML export of each plan.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "${here}/.." && pwd)"
work="${here}/.work"
domain="clavia.test"
version="${CLAVIA_CONFORMANCE_VERSION:-5.1.36}"
suite="https://suite.${domain}:${CLAVIA_CONFORMANCE_PORT:-8443}"
ca="${root}/test/e2e/.work/rootCA.pem"
basic='oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]'
config='oidcc-config-certification-test-plan'

mkdir -p "${work}/report"

# 1. The suite, built once at its release; the jar is kept between runs.
if [[ ! -f "${work}/suite/target/fapi-test-suite.jar" ]]; then
  rm -rf "${work}/suite"
  git clone --quiet --depth 1 --branch "release-v${version}" \
    https://gitlab.com/openid/conformance-suite.git "${work}/suite"
  (cd "${work}/suite" && mvn -B -q -DskipTests clean package)
fi

# 2. The stack, with the suite and its TLS front beside it.
cat >"${work}/Caddyfile" <<CADDY
https://suite.${domain}:8443 {
	tls /etc/caddy/certs/${domain}.pem /etc/caddy/certs/${domain}-key.pem
	reverse_proxy oidf-server:8080
}
CADDY
CLAVIA_E2E_COMPOSE_OVERRIDE="${here}/compose.yaml" "${root}/test/e2e/up.sh"

echo "Waiting for the suite at ${suite}..."
for _ in $(seq 1 90); do
  curl --silent --fail --cacert "${ca}" --output /dev/null "${suite}/" && break
  sleep 2
done
curl --silent --fail --cacert "${ca}" --output /dev/null "${suite}/" \
  || { echo "The suite did not answer at ${suite}." >&2; exit 1; }

# 3. The seeded machine client, as seed-dev printed it, registers the suite's clients.
credentials="$(grep -o -- "-u '[^']*'" "${root}/test/e2e/.work/seed.txt" | head -1 | sed -E "s/^-u '(.*)'$/\1/")"
[[ "${credentials}" == *:* ]] || { echo "No machine client in the seed output." >&2; exit 1; }
python3 "${here}/provision.py" --domain "${domain}" --suite "${suite}" \
  --m2m-id "${credentials%%:*}" --m2m-secret "${credentials#*:}" \
  --email "dev@${domain}" --password devpassword --ca "${ca}" --profile >"${work}/plan.json"

# 4. Both plans. The suite's script exits non-zero for the deliberate failure, among others: the
# comparison with the baseline decides, not that exit code.
python3 -m pip install --quiet --disable-pip-version-check -r "${work}/suite/scripts/requirements.txt" 2>/dev/null \
  || python3 -m pip install --quiet --disable-pip-version-check requests
(
  cd "${work}/suite/scripts"
  CONFORMANCE_SERVER="${suite}/" CONFORMANCE_SERVER_MTLS="https://suite.${domain}:8444/" CONFORMANCE_DEV_MODE=1 \
    REQUESTS_CA_BUNDLE="${ca}" python3 run-test-plan.py --no-parallel \
    "${basic}" "${work}/plan.json" "${config}" "${work}/plan.json"
) || echo "run-test-plan.py exited with $?; the baseline decides."

# 5. Every module's outcome against the baseline.
python3 "${here}/compare.py" --suite "${suite}" --ca "${ca}" --baseline "${here}/baseline.json" \
  --out "${work}/report"
