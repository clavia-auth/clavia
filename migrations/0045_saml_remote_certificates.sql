-- Certificates of the SAML service provider's keys when they live in a KMS (#124,
-- docs/design/saml-connections.md §5.1): built once through the KMS, kept by the key's reference
-- (never published), so listing the keys and serving the metadata never call the KMS. A reference
-- names one immutable key version, so its certificate never goes stale. Nothing private is kept.
CREATE TABLE saml_remote_certificates (
    reference    text PRIMARY KEY,
    kid          varchar(64) NOT NULL,
    usage        varchar(16) NOT NULL CHECK (usage IN ('signing', 'encryption')),
    certificate  text NOT NULL,
    valid_until  timestamptz NOT NULL,
    created_at   timestamptz NOT NULL
);
