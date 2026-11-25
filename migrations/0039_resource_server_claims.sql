-- Custom claims of an API (#115, docs/design/custom-claims.md): the mappings its access tokens
-- and introspection carry, as a list of {name, source, value?}. Validated by the application
-- (at most 20, names unique and never reserved); `[]` when none.
ALTER TABLE resource_servers ADD COLUMN claims jsonb NOT NULL DEFAULT '[]';
ALTER TABLE resource_servers ADD CONSTRAINT ck_resource_servers_claims_list CHECK (jsonb_typeof(claims) = 'array');
