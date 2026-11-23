-- Clients that registered themselves (RFC 7591; docs/design/dynamic-client-registration.md):
-- the registration access token that lets one manage its registration (RFC 7592), by its
-- digest, and the initial access token it came through. An operator's client has no row, so
-- the configuration endpoint can never reach it.
CREATE TABLE client_registrations (
    client_id               varchar(64) PRIMARY KEY REFERENCES oauth2_clients (client_id) ON DELETE CASCADE,
    -- SHA-256 of the registration access token, hexadecimal. The token itself is never stored.
    access_token_hash       char(64) NOT NULL,
    -- Kept when the initial access token is purged: a client outlives the token it came through.
    initial_access_token_id uuid REFERENCES initial_access_tokens (id) ON DELETE SET NULL,
    registered_at           timestamptz NOT NULL,
    CONSTRAINT client_registrations_access_token_hash_key UNIQUE (access_token_hash)
);
