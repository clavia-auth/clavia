-- Operating webhooks (#120, docs/design/webhooks.md §5.3, §5.4).
--
-- An endpoint remembers since when every delivery to it has failed (`failing_since`, cleared by a
-- success), so the worker switches off one dead for five days, and why it is off
-- (`disabled_reason`: an operator, or failing). A delivery keeps the type of its event, so the log
-- reads without the audit row, which may since have been purged.
ALTER TABLE webhook_endpoints
    ADD COLUMN failing_since timestamptz,
    ADD COLUMN disabled_reason varchar(16) CHECK (disabled_reason IN ('operator', 'failing'));

UPDATE webhook_endpoints SET disabled_reason = 'operator' WHERE NOT is_enabled;

ALTER TABLE webhook_endpoints
    ADD CONSTRAINT ck_webhook_endpoints_disabled_reason CHECK (is_enabled = (disabled_reason IS NULL));

ALTER TABLE webhook_deliveries ADD COLUMN event_type varchar(64);

UPDATE webhook_deliveries d SET event_type = a.type FROM audit_events a WHERE a.id = d.audit_event_id;

ALTER TABLE webhook_deliveries ALTER COLUMN event_type SET NOT NULL;

CREATE INDEX webhook_deliveries_log_idx ON webhook_deliveries (endpoint_id, created_at DESC, id DESC);
