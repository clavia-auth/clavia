-- Application ownership and consent (Step 12).
--
-- Ownership needs no column: it is written into the client id, which starts with `tpc_`
-- for a third-party application and is letters and digits only otherwise.

-- Whether a first-party application asking for this API's permissions on a person's
-- behalf may do without the consent screen: the operator runs both, so signing in is the
-- consent. A third-party application asks whatever this says. On by default, so an API
-- registered before consent existed keeps behaving as it did; always on for a system API,
-- which no third-party application can reach.
ALTER TABLE resource_servers ADD COLUMN allow_skipping_consent boolean NOT NULL DEFAULT true;
ALTER TABLE resource_servers
    ADD CONSTRAINT ck_resource_servers_system_skips_consent CHECK (allow_skipping_consent OR NOT is_system);

-- What a person agreed, on the consent screen, to let an application do as them on an
-- API. One row per (person, application, API); the API is null for a request that named
-- none. Every link is a foreign key, so deleting the account, the application or the API
-- takes the consent along.
CREATE TABLE user_consents (
    user_id             uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id           varchar(64) NOT NULL REFERENCES oauth2_clients (client_id) ON DELETE CASCADE,
    resource_server_id  varchar(19) REFERENCES resource_servers (id) ON DELETE CASCADE,
    -- Everything agreed to, OIDC scopes included, space-separated (RFC 6749 §3.3).
    scope               text NOT NULL,
    granted_at          timestamptz NOT NULL,
    -- When the scope last widened.
    updated_at          timestamptz NOT NULL,

    -- A null API is one value here, not a new one each time: one "no API" consent per
    -- person and application.
    CONSTRAINT uq_user_consents UNIQUE NULLS NOT DISTINCT (user_id, client_id, resource_server_id)
);

-- The cascades from `oauth2_clients` and `resource_servers` look rows up by those keys.
CREATE INDEX ix_user_consents_client_id ON user_consents (client_id);
CREATE INDEX ix_user_consents_resource_server_id ON user_consents (resource_server_id);
