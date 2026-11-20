-- Issued access tokens (RFC 6750). Opaque: looked up by digest, which is what lets
-- every surface that accepts a token honour revocation the instant it happens.

CREATE TABLE oauth2_access_tokens (
    id                     uuid PRIMARY KEY,
    -- SHA-256 of the token, hexadecimal. The token itself is never stored.
    token_hash             char(64) NOT NULL,
    client_id              varchar(64) NOT NULL REFERENCES oauth2_clients (client_id) ON DELETE CASCADE,
    -- NULL for a machine acting as itself (client credentials): such a token has no
    -- subject, and every surface that answers questions about a person must refuse it.
    user_id                uuid REFERENCES users (id) ON DELETE CASCADE,
    -- Which code minted this token, so a replayed code can revoke everything it
    -- produced (RFC 6749 §4.1.2).
    authorization_code_id  uuid REFERENCES oauth2_authorization_codes (id) ON DELETE SET NULL,
    token_type             varchar(32) NOT NULL DEFAULT 'Bearer',
    scope                  text NOT NULL DEFAULT '',
    issued_at              timestamptz NOT NULL DEFAULT now(),
    expires_at             timestamptz NOT NULL,
    revoked_at             timestamptz,

    CONSTRAINT uq_oauth2_access_tokens_token_hash UNIQUE (token_hash)
);

CREATE INDEX ix_oauth2_access_tokens_client_id ON oauth2_access_tokens (client_id);
CREATE INDEX ix_oauth2_access_tokens_user_id ON oauth2_access_tokens (user_id);
CREATE INDEX ix_oauth2_access_tokens_authorization_code_id ON oauth2_access_tokens (authorization_code_id);
