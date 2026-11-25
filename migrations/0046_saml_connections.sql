-- SAML connections (#125, docs/design/saml-connections.md §4): an identity provider registered from
-- its metadata. Its entity ID, its HTTP-Redirect single sign-on URL, its one to three signing
-- certificates (PEM, with the expiry they state, never enforced), the URL its metadata is read again
-- from (none when it was given as a document), and the connection's options. A SAML connection, and
-- only one, has the first four.
ALTER TABLE connections
    ADD COLUMN saml_entity_id text,
    ADD COLUMN saml_sso_url text,
    ADD COLUMN saml_certificates jsonb,
    ADD COLUMN saml_metadata_url text,
    ADD COLUMN saml_options jsonb;

ALTER TABLE connections DROP CONSTRAINT ck_connections_strategy;
ALTER TABLE connections
    ADD CONSTRAINT ck_connections_strategy
        CHECK (strategy IN ('database', 'social', 'oidc', 'passwordless', 'saml'));

ALTER TABLE connections
    ADD CONSTRAINT ck_connections_saml CHECK (
        (strategy = 'saml') = (
            saml_entity_id IS NOT NULL AND saml_sso_url IS NOT NULL
            AND saml_certificates IS NOT NULL AND saml_options IS NOT NULL
        )
        AND (strategy = 'saml' OR saml_metadata_url IS NULL)
    );
