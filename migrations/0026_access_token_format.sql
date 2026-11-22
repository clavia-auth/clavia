-- The form of the access tokens issued for an API: `opaque`, looked up by introspection,
-- or `jwt`, an RFC 9068 token the API validates on its own. Opaque by default, so every
-- API registered before the choice existed keeps receiving what it already handles.
ALTER TABLE resource_servers
    ADD COLUMN access_token_format text NOT NULL DEFAULT 'opaque'
        CONSTRAINT ck_resource_servers_access_token_format CHECK (access_token_format IN ('opaque', 'jwt'));
