-- External identities (Step 8): Clavia accounts linked to accounts at an external
-- identity provider (Google, GitHub).
--
-- The key is (provider, subject) — the identifier the provider promises not to
-- reassign — never the email address, which is kept only to show operators what the
-- provider reported when the link was made. A subject belongs to one account; an
-- account may hold several identities. The provider is a name until connections exist
-- (Step 13), which will make it a foreign key.

CREATE TABLE external_identities (
    provider    varchar(32) NOT NULL,
    subject     varchar(255) NOT NULL,
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    email       varchar(320),
    linked_at   timestamptz NOT NULL,

    CONSTRAINT pk_external_identities PRIMARY KEY (provider, subject),
    CONSTRAINT ck_external_identities_provider CHECK (provider ~ '^[a-z][a-z0-9-]{0,31}$')
);

CREATE INDEX ix_external_identities_user ON external_identities (user_id);
