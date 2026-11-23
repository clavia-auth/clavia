-- Initial access tokens (RFC 7591 §3; docs/design/dynamic-client-registration.md): what lets
-- software register itself as a client, issued by an operator, good for a number of
-- registrations until a date, revocable.
CREATE TABLE initial_access_tokens (
    id          uuid PRIMARY KEY,
    -- SHA-256 of the token, hexadecimal. The token itself is never stored.
    token_hash  char(64) NOT NULL,
    description varchar(120) NOT NULL CHECK (description <> ''),
    created_at  timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL CHECK (expires_at > created_at),
    max_uses    integer NOT NULL CHECK (max_uses BETWEEN 1 AND 1000),
    -- Spent by one conditional UPDATE per registration, never past max_uses.
    uses        integer NOT NULL DEFAULT 0 CHECK (uses >= 0 AND uses <= max_uses),
    revoked_at  timestamptz,
    CONSTRAINT initial_access_tokens_token_hash_key UNIQUE (token_hash)
);

CREATE INDEX initial_access_tokens_created_at_idx ON initial_access_tokens (created_at DESC, id);
