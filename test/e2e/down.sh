#!/usr/bin/env bash
# Stops the end-to-end stack and forgets its data: test/e2e/down.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose=(docker compose -f "${here}/compose.yaml")
# The compose file up.sh merged in, if any, so its services go too.
if [[ -n "${CLAVIA_E2E_COMPOSE_OVERRIDE:-}" ]]; then
  compose+=(-f "${CLAVIA_E2E_COMPOSE_OVERRIDE}")
fi
"${compose[@]}" --profile dashboard --profile receiver down --volumes --remove-orphans
rm -rf "${here}/.work"
