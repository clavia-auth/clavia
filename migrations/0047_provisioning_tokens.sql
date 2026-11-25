-- Provisioning tokens (docs/design/scim-provisioning.md §2, §4): what lets a directory reach
-- /scim/v2, issued by an operator for one connection, good until a date, revocable.
CREATE TABLE provisioning_tokens (
    id                  uuid PRIMARY KEY,
    -- SHA-256 of the token, hexadecimal. The token itself is never stored.
    token_hash          char(64) NOT NULL,
    -- Where every account the token creates, reads or changes lives; its tokens go with it.
    connection          varchar(32) NOT NULL REFERENCES connections (name) ON DELETE CASCADE,
    description         varchar(120) NOT NULL CHECK (description <> ''),
    created_at          timestamptz NOT NULL,
    expires_at          timestamptz NOT NULL CHECK (expires_at > created_at),
    revoked_at          timestamptz,
    subject_attribute   varchar(16) NOT NULL CHECK (subject_attribute IN ('externalId', 'userName')),
    addresses_trusted   boolean NOT NULL,
    delete_deactivates  boolean NOT NULL,
    CONSTRAINT provisioning_tokens_token_hash_key UNIQUE (token_hash)
);

CREATE INDEX provisioning_tokens_created_at_idx ON provisioning_tokens (created_at DESC, id);
CREATE INDEX provisioning_tokens_connection_idx ON provisioning_tokens (connection, created_at DESC);

-- A directory acting through its token is a fifth kind of actor, named by the token. No foreign
-- key, as for the other actors: a revoked or deleted token's trail stays.
ALTER TABLE audit_events ADD COLUMN actor_provisioning_token_id uuid;
ALTER TABLE audit_events DROP CONSTRAINT ck_audit_events_actor;
ALTER TABLE audit_events ADD CONSTRAINT ck_audit_events_actor CHECK (
    (actor_kind = 'person' AND actor_user_id IS NOT NULL AND actor_provisioning_token_id IS NULL)
    OR (actor_kind = 'application' AND actor_user_id IS NULL AND actor_client_id IS NOT NULL
        AND actor_provisioning_token_id IS NULL)
    OR (actor_kind = 'provisioning' AND actor_user_id IS NULL AND actor_client_id IS NULL
        AND actor_provisioning_token_id IS NOT NULL)
    OR (actor_kind IN ('system', 'anonymous') AND actor_user_id IS NULL AND actor_provisioning_token_id IS NULL)
);
