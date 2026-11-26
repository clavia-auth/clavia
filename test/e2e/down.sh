#!/usr/bin/env bash
# Stops the end-to-end stack and forgets its data: test/e2e/down.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
docker compose -f "${here}/compose.yaml" down --volumes --remove-orphans
rm -rf "${here}/.work"
