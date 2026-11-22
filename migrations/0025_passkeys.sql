-- Passkeys: WebAuthn credentials registered on an account (docs/design/passkeys.md §7).
--
-- The credential id and the public key are bytes; they are not secrets, so nothing here goes
-- through the secret cipher. A credential belongs to one passkey and one account: the unique
-- constraint is what decides, not a check made before the insert. A passkey goes with its
-- account.
CREATE TABLE passkeys (
    id              uuid PRIMARY KEY,
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id   bytea NOT NULL,
    public_key      bytea NOT NULL,
    -- A COSE algorithm identifier: -8 EdDSA, -7 ES256, -257 RS256.
    algorithm       integer NOT NULL,
    sign_count      bigint NOT NULL DEFAULT 0,
    transports      jsonb NOT NULL DEFAULT '[]',
    aaguid          uuid,
    backup_eligible boolean NOT NULL,
    backed_up       boolean NOT NULL,
    name            text NOT NULL,
    created_at      timestamptz NOT NULL,
    last_used_at    timestamptz,
    CONSTRAINT uq_passkeys_credential_id UNIQUE (credential_id),
    CONSTRAINT ck_passkeys_credential_id_length CHECK (octet_length(credential_id) BETWEEN 16 AND 1023),
    CONSTRAINT ck_passkeys_sign_count CHECK (sign_count >= 0),
    CONSTRAINT ck_passkeys_name_length CHECK (char_length(name) BETWEEN 1 AND 64),
    -- A passkey cannot be backed up without being eligible for backup (WebAuthn Level 3 §6.1.3).
    CONSTRAINT ck_passkeys_backup CHECK (backup_eligible OR NOT backed_up)
);

CREATE INDEX ix_passkeys_user_id ON passkeys (user_id);
