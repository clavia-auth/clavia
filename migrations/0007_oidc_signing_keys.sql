-- Keys of the `postgres` signing backend: the only backend whose private keys this
-- server holds itself. The cloud backends keep theirs in the provider and need no row.
--
-- One key is active and signs every new token; retired keys stay published in the JWKS
-- until every token they signed has expired, then drop out of it. Rows are kept after
-- that, so `clavia keys:list` can still say which key a stored token named.

CREATE TABLE oidc_signing_keys (
    -- The RFC 7638 thumbprint of the public key: 43 base64url characters for SHA-256.
    kid                    varchar(64) PRIMARY KEY,
    algorithm              varchar(16) NOT NULL,
    -- The private key (PKCS #8 PEM), sealed with AES-256-GCM under
    -- CLAVIA_SECRET_ENCRYPTION_KEY, with the kid as associated data: a ciphertext
    -- copied onto another row does not decrypt. Never stored in the clear.
    private_key_encrypted  text NOT NULL,
    -- The public half, exactly as published in the JWKS. Rendered from here, never
    -- re-derived from the private key.
    public_jwk             jsonb NOT NULL,
    status                 varchar(16) NOT NULL,
    created_at             timestamptz NOT NULL,
    retired_at             timestamptz,
    -- When a retired key leaves the JWKS.
    published_until        timestamptz,

    CONSTRAINT ck_oidc_signing_keys_algorithm CHECK (algorithm IN ('RS256')),
    CONSTRAINT ck_oidc_signing_keys_status CHECK (status IN ('active', 'retired')),
    CONSTRAINT ck_oidc_signing_keys_retirement CHECK (
        (status = 'active' AND retired_at IS NULL AND published_until IS NULL)
        OR (status = 'retired' AND retired_at IS NOT NULL AND published_until IS NOT NULL)
    )
);

-- At most one active key: with a single signer there is never a question of which
-- key a fresh token used, and two concurrent rotations cannot both succeed.
CREATE UNIQUE INDEX uq_oidc_signing_keys_one_active ON oidc_signing_keys ((true)) WHERE status = 'active';
