-- How the person signed in, kept on every token issued on their behalf, so an access token —
-- refreshed ones included — can report its `acr` and `auth_time` (RFC 9470 §6), as the code it
-- came from does. A token issued before this migration knows neither, and reports neither.
ALTER TABLE oauth2_access_tokens
    ADD COLUMN auth_time timestamptz NULL,
    ADD COLUMN amr jsonb NOT NULL DEFAULT '[]';

ALTER TABLE oauth2_refresh_tokens
    ADD COLUMN auth_time timestamptz NULL,
    ADD COLUMN amr jsonb NOT NULL DEFAULT '[]';
