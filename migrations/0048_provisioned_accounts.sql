-- Accounts directories provision through SCIM (docs/design/scim-provisioning.md §4): the userName
-- and externalId a directory knows a person by, beside the account itself, which goes with them.
CREATE TABLE provisioned_accounts (
    user_id                 uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    connection              varchar(32) NOT NULL REFERENCES connections (name),
    -- As the directory sent it, and case-folded: userName is unique ignoring case (RFC 7643 §4.1.1).
    user_name               varchar(255) NOT NULL CHECK (user_name <> ''),
    user_name_key           varchar(255) NOT NULL,
    -- Unique exactly (RFC 7643 §3.1: caseExact).
    external_id             varchar(255) CHECK (external_id <> ''),
    -- The token that made the account; no foreign key, so a revoked token's accounts stay.
    provisioning_token_id   uuid NOT NULL,
    created_at              timestamptz NOT NULL,
    updated_at              timestamptz NOT NULL,
    CONSTRAINT provisioned_accounts_user_name_key UNIQUE (connection, user_name_key),
    CONSTRAINT provisioned_accounts_external_id_key UNIQUE (connection, external_id)
);

-- A directory pages through its accounts oldest first.
CREATE INDEX provisioned_accounts_connection_idx ON provisioned_accounts (connection, created_at, user_id);

-- An enterprise connection may let in only the people a directory provisioned (§2).
ALTER TABLE connections ADD COLUMN require_provisioning boolean NOT NULL DEFAULT false;
