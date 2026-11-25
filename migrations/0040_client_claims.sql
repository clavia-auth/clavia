-- Custom claims of an application (#116, docs/design/custom-claims.md): the mappings its ID tokens
-- and userinfo answers carry, as a list of {name, source, value?, in}. Validated by the
-- application (at most 20, names unique and never reserved, first-party clients only); `[]` when
-- none.
ALTER TABLE oauth2_clients ADD COLUMN claims jsonb NOT NULL DEFAULT '[]';
ALTER TABLE oauth2_clients ADD CONSTRAINT ck_oauth2_clients_claims_list CHECK (jsonb_typeof(claims) = 'array');
