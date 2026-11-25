-- Webhook endpoints (#118, docs/design/webhooks.md): https URLs that will receive the audit events
-- they subscribe to. Their secrets are sealed with CLAVIA_SECRET_ENCRYPTION_KEY
-- (`webhook:<id>:secret` as associated data), never hashed: they are read back to sign. The previous
-- secret signs beside the new one until `previous_secret_until`, a day after a rotation.
CREATE TABLE webhook_endpoints (
    id                       uuid PRIMARY KEY,
    url                      varchar(2048) NOT NULL,
    description              varchar(480) NOT NULL DEFAULT '',
    -- `["*"]`, or the audit event types it wants.
    events                   jsonb NOT NULL,
    is_enabled               boolean NOT NULL DEFAULT true,
    secret_sealed            text NOT NULL,
    previous_secret_sealed   text,
    previous_secret_until    timestamptz,
    created_at               timestamptz NOT NULL,
    updated_at               timestamptz NOT NULL,
    CONSTRAINT ck_webhook_endpoints_events CHECK (jsonb_typeof(events) = 'array' AND jsonb_array_length(events) > 0),
    CONSTRAINT ck_webhook_endpoints_previous CHECK ((previous_secret_sealed IS NULL) = (previous_secret_until IS NULL))
);
