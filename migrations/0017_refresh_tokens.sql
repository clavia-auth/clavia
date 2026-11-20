-- Refresh tokens (Step 11, RFC 6749 §6), rotated on every use.
--
-- A spent token is kept, marked `used_at`: presented again, it is a replay, and the
-- family it names is revoked with every access token it minted (RFC 6749 §10.4).

CREATE TABLE oauth2_refresh_tokens (
    id                     uuid PRIMARY KEY,
    -- SHA-256 of the token, hexadecimal. The token itself is never stored.
    token_hash             char(64) NOT NULL,
    -- The first token of the chain; its own id for that first token. Not a foreign key:
    -- the family is a label every descendant carries, whatever became of the first.
    family_id              uuid NOT NULL,
    client_id              varchar(64) NOT NULL REFERENCES oauth2_clients (client_id) ON DELETE CASCADE,
    -- Always a person: a client acting as itself gets no refresh token (RFC 6749 §4.4.3).
    user_id                uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- The code the family started from, so a replayed code revokes the session it bought.
    authorization_code_id  uuid REFERENCES oauth2_authorization_codes (id) ON DELETE SET NULL,
    -- The ceiling: what a refresh may ask for. Narrowed again at every issuance.
    scope                  text NOT NULL DEFAULT '',
    -- The API the family's access tokens are for. A refresh cannot retarget it.
    audience               varchar(255),
    issued_at              timestamptz NOT NULL,
    -- The idle limit, or the family's deadline when that comes first.
    expires_at             timestamptz NOT NULL,
    -- Fixed at sign-in and copied down the chain.
    family_expires_at      timestamptz NOT NULL,
    -- Set by the one refresh that spent the token, under a row lock.
    used_at                timestamptz,
    revoked_at             timestamptz,

    CONSTRAINT uq_oauth2_refresh_tokens_token_hash UNIQUE (token_hash),
    CONSTRAINT ck_oauth2_refresh_tokens_deadlines CHECK (expires_at <= family_expires_at)
);

CREATE INDEX ix_oauth2_refresh_tokens_family_id ON oauth2_refresh_tokens (family_id);
CREATE INDEX ix_oauth2_refresh_tokens_authorization_code_id ON oauth2_refresh_tokens (authorization_code_id);
CREATE INDEX ix_oauth2_refresh_tokens_client_id ON oauth2_refresh_tokens (client_id);
CREATE INDEX ix_oauth2_refresh_tokens_user_id ON oauth2_refresh_tokens (user_id);

-- The family an access token came with or from, so revoking the family revokes it.
ALTER TABLE oauth2_access_tokens ADD COLUMN refresh_family_id uuid;
CREATE INDEX ix_oauth2_access_tokens_refresh_family_id ON oauth2_access_tokens (refresh_family_id);
