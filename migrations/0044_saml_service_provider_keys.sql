-- This server's keys as a SAML service provider (#123, docs/design/saml-connections.md §4, §5.1).
--
-- A pair per rotation step: a signing key and an encryption key, each RSA with a self-signed
-- certificate (DER, base64). With the `postgres` backend the private half is sealed with the secret
-- encryption key, `saml-sp:<kid>` as associated data; a remote backend (slice 3) leaves it null.
-- At most one current and one next key per usage; retired keys stay until their overlap is over,
-- a retired encryption key still decrypting.
CREATE TABLE saml_service_provider_keys (
    kid                    varchar(64) PRIMARY KEY,
    usage                  varchar(16) NOT NULL CHECK (usage IN ('signing', 'encryption')),
    status                 varchar(16) NOT NULL CHECK (status IN ('next', 'current', 'retired')),
    certificate            text NOT NULL,
    private_key_encrypted  text,
    valid_until            timestamptz NOT NULL,
    created_at             timestamptz NOT NULL,
    promoted_at            timestamptz,
    retired_at             timestamptz,
    CONSTRAINT ck_saml_sp_keys_retired CHECK ((status = 'retired') = (retired_at IS NOT NULL)),
    CONSTRAINT ck_saml_sp_keys_promoted CHECK (status = 'next' OR promoted_at IS NOT NULL)
);

CREATE UNIQUE INDEX saml_sp_keys_one_current ON saml_service_provider_keys (usage) WHERE status = 'current';
CREATE UNIQUE INDEX saml_sp_keys_one_next ON saml_service_provider_keys (usage) WHERE status = 'next';
