-- Single-use authorization codes (RFC 6749 §4.1.2), bound to a client, a user, a
-- redirect URI and a PKCE challenge (RFC 7636).
--
-- In PostgreSQL rather than Redis even though they live a minute: single use needs a
-- row that can be locked, and replay detection needs the spent row to outlive the code.

CREATE TABLE oauth2_authorization_codes (
    id                     uuid PRIMARY KEY,
    -- SHA-256 of the code, hexadecimal. The code itself is never stored.
    code_hash              char(64) NOT NULL,
    client_id              varchar(64) NOT NULL REFERENCES oauth2_clients (client_id) ON DELETE CASCADE,
    user_id                uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- The redirect_uri of the authorization request; the token request must present
    -- the same one (RFC 6749 §4.1.3).
    redirect_uri           varchar(2048) NOT NULL,
    -- The scope granted, space-delimited (RFC 6749 §3.3).
    scope                  text NOT NULL DEFAULT '',
    code_challenge         varchar(128) NOT NULL,
    -- Always S256 — `plain` is refused — but stored rather than assumed, so the row
    -- states what it was checked against.
    code_challenge_method  varchar(16) NOT NULL,
    expires_at             timestamptz NOT NULL,
    -- Set the moment the code is redeemed. A second redemption attempt is a replay.
    -- The row is kept: deleting it would make a replay indistinguishable from a typo.
    used_at                timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT uq_oauth2_authorization_codes_code_hash UNIQUE (code_hash),
    CONSTRAINT ck_oauth2_authorization_codes_method CHECK (code_challenge_method = 'S256')
);

CREATE INDEX ix_oauth2_authorization_codes_client_id ON oauth2_authorization_codes (client_id);
CREATE INDEX ix_oauth2_authorization_codes_user_id ON oauth2_authorization_codes (user_id);
