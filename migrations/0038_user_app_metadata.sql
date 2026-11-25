-- Application metadata on accounts (#114, docs/design/custom-claims.md): a JSON object only
-- operators write, which claim mappings copy into tokens. Bounded by the application (16 KiB,
-- five levels); `{}` when nothing is kept.
ALTER TABLE users ADD COLUMN app_metadata jsonb NOT NULL DEFAULT '{}';
ALTER TABLE users ADD CONSTRAINT ck_users_app_metadata_object CHECK (jsonb_typeof(app_metadata) = 'object');
