#!/bin/sh
# Clavia's scheduled commands, for Compose (compose.yaml's `scheduler`): a container has no cron,
# so this loop is one. On a host with cron, or in Kubernetes (the Helm chart's CronJobs), schedule
# the same commands there instead:
#
#   * * * * *   bin/clavia jobs:run              queued bulk jobs on the users (imports, exports)
#   * * * * *   bin/clavia webhooks:deliver      webhook deliveries due, within a 50-second budget
#   * * * * *   bin/clavia fga:sync              identity changes OpenFGA has not taken yet
#   0 3 * * *   bin/clavia audit:purge           audit events past CLAVIA_AUDIT_RETENTION_DAYS
#   15 3 * * *  bin/clavia clients:purge-unused  self-registered clients never used
#
# Every command exits when done, and each is safe to run twice at once (jobs, deliveries and identity
# changes are claimed with FOR UPDATE SKIP LOCKED), so a slow minute only delays the next. Times are UTC.

set -u

run() {
    php bin/clavia "$@" || echo "scheduler: bin/clavia $* failed" >&2
}

# Stop at once on `docker compose stop`, even in the middle of a sleep.
trap 'exit 0' TERM INT

while true; do
    sleep $((60 - $(date +%s) % 60)) &
    wait $!
    # The minute this round is for, read before anything runs so a slow round skips no daily task.
    minute=$(date -u +%H%M)
    run jobs:run
    run webhooks:deliver
    run fga:sync
    [ "$minute" = "0300" ] && run audit:purge
    [ "$minute" = "0315" ] && run clients:purge-unused
done
