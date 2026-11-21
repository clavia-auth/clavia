-- The audit trail (Phase E): what happened, when, who did it, to what, and from where.
--
-- Append-only. A row is never updated — a trigger refuses it, whatever the role — and is
-- deleted only by `clavia audit:purge`, past CLAVIA_AUDIT_RETENTION_DAYS. No foreign keys:
-- the account, client or role an event names may be deleted, and its trail must stay.
CREATE TABLE audit_events (
    id              uuid PRIMARY KEY,
    type            varchar(64) NOT NULL,
    occurred_at     timestamptz NOT NULL,
    outcome         varchar(16) NOT NULL,
    -- Who: a person (through an application or not), an application, the console, nobody known.
    actor_kind      varchar(16) NOT NULL,
    actor_user_id   uuid,
    actor_client_id varchar(64),
    -- What it was about.
    target_type     varchar(32),
    target_id       varchar(255),
    -- Short, flat, never a credential (checked by the domain before it gets here).
    details         jsonb NOT NULL DEFAULT '{}',
    client_address  varchar(64),
    user_agent      varchar(512),

    CONSTRAINT ck_audit_events_outcome CHECK (outcome IN ('success', 'failure')),
    CONSTRAINT ck_audit_events_actor CHECK (
        (actor_kind = 'person' AND actor_user_id IS NOT NULL)
        OR (actor_kind = 'application' AND actor_user_id IS NULL AND actor_client_id IS NOT NULL)
        OR (actor_kind IN ('system', 'anonymous') AND actor_user_id IS NULL)
    ),
    CONSTRAINT ck_audit_events_target CHECK ((target_type IS NULL) = (target_id IS NULL)),
    CONSTRAINT ck_audit_events_details CHECK (jsonb_typeof(details) = 'object')
);

-- Newest first, and newest first within each way the trail is read.
CREATE INDEX ix_audit_events_occurred_at ON audit_events (occurred_at DESC, id DESC);
CREATE INDEX ix_audit_events_target ON audit_events (target_type, target_id, occurred_at DESC);
CREATE INDEX ix_audit_events_actor_user ON audit_events (actor_user_id, occurred_at DESC)
    WHERE actor_user_id IS NOT NULL;
CREATE INDEX ix_audit_events_actor_client ON audit_events (actor_client_id, occurred_at DESC)
    WHERE actor_client_id IS NOT NULL;
CREATE INDEX ix_audit_events_type ON audit_events (type, occurred_at DESC);

CREATE FUNCTION audit_events_are_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit events are never changed' USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER tr_audit_events_append_only
    BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_are_append_only();
