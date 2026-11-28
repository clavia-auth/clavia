#!/bin/sh
# What deploy/compose/scheduler.sh runs once a minute, every two seconds, so a scenario that waits for a
# webhook delivery or a job does not wait a minute for it. The daily purges are left out: a stack lives for
# minutes.
trap 'exit 0' TERM INT

while true; do
    php bin/clavia jobs:run || echo "scheduler: jobs:run failed" >&2
    php bin/clavia webhooks:deliver || echo "scheduler: webhooks:deliver failed" >&2
    php bin/clavia fga:sync || echo "scheduler: fga:sync failed" >&2
    sleep 2
done
