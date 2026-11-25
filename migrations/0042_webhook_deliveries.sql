-- The webhook outbox (#119, docs/design/webhooks.md §4): one row per audit event per enabled endpoint
-- listening to it, written in the event's own transaction. `webhooks:deliver` claims endpoints
-- (`delivering_until`), so one worker sends an endpoint's deliveries at a time. Nothing of a
-- receiver's answer is kept but its status, the time it took and a failure category; nothing of the
-- payload at all: it is the audit row, rendered when sent. A purged audit event, or a deleted
-- endpoint, takes its deliveries with it.
ALTER TABLE webhook_endpoints ADD COLUMN delivering_until timestamptz;

CREATE TABLE webhook_deliveries (
    id                uuid PRIMARY KEY,
    endpoint_id       uuid NOT NULL REFERENCES webhook_endpoints (id) ON DELETE CASCADE,
    audit_event_id    uuid NOT NULL REFERENCES audit_events (id) ON DELETE CASCADE,
    status            varchar(16) NOT NULL CHECK (status IN ('pending', 'succeeded', 'abandoned')),
    attempts          integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at   timestamptz NOT NULL,
    last_status_code  integer,
    last_duration_ms  integer,
    last_failure      varchar(16),
    created_at        timestamptz NOT NULL,
    ended_at          timestamptz,
    CONSTRAINT ck_webhook_deliveries_ended CHECK ((status = 'pending') = (ended_at IS NULL))
);

CREATE INDEX webhook_deliveries_due_idx ON webhook_deliveries (endpoint_id, created_at) WHERE status = 'pending';
CREATE INDEX webhook_deliveries_ended_idx ON webhook_deliveries (ended_at) WHERE ended_at IS NOT NULL;
