-- Second factors (Step 7): TOTP authenticators and the recovery codes issued with them.
--
-- A factor is keyed (user, type): one of each kind per account, which is also what a
-- sign-in looks up. Its seed is the one credential this server must read back — it
-- computes the expected code — so it is sealed (AES-256-GCM, the account in the
-- associated data), never hashed. Recovery codes are only ever compared, so they are
-- SHA-256 digests, keyed (user, digest).

CREATE TABLE mfa_factors (
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    type            varchar(16) NOT NULL,
    secret_encrypted text NOT NULL,
    -- Null while pending: a factor enforces nothing until one code from it was accepted.
    confirmed_at    timestamptz,
    -- The TOTP time step of the last code accepted. Any step at or before it is refused,
    -- which is what makes a code single-use.
    last_used_step  bigint,
    created_at      timestamptz NOT NULL,

    PRIMARY KEY (user_id, type),
    CONSTRAINT ck_mfa_factors_type CHECK (type IN ('totp')),
    CONSTRAINT ck_mfa_factors_confirmation CHECK (confirmed_at IS NULL OR last_used_step IS NOT NULL)
);

CREATE TABLE mfa_recovery_codes (
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash   char(64) NOT NULL,
    -- Set by the one conditional UPDATE that spends the code.
    used_at     timestamptz,
    created_at  timestamptz NOT NULL,

    PRIMARY KEY (user_id, code_hash)
);
