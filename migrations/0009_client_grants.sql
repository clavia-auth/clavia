-- What a client may request from an API as itself — the authorization decision of the
-- Client Credentials grant (RFC 6749 §4.4), where nobody stands behind the request who
-- could have consented to less.
--
-- Written from the shell only. An HTTP endpoint that wrote these would let its caller
-- widen its own access.

CREATE TABLE client_grants (
    client_id           varchar(64) NOT NULL REFERENCES oauth2_clients (client_id) ON DELETE CASCADE,
    resource_server_id  varchar(19) NOT NULL REFERENCES resource_servers (id) ON DELETE CASCADE,
    -- Scope values, a JSON array of strings. Intersected with the API's permissions at
    -- issuance rather than trusted, so a permission withdrawn from the API takes effect
    -- on the next token — which is also why this is not a foreign key onto permissions.
    scopes              jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at          timestamptz NOT NULL,

    -- One grant per client per API: two would be two answers, and the wider would win.
    PRIMARY KEY (client_id, resource_server_id),
    CONSTRAINT ck_client_grants_scopes CHECK (jsonb_typeof(scopes) = 'array')
);

CREATE INDEX ix_client_grants_resource_server_id ON client_grants (resource_server_id);
