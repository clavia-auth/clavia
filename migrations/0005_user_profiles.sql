-- The standard claims of the OIDC `profile` scope (OIDC Core §5.1, §5.4).
--
-- Every column is nullable and NULL means "unknown": an unset claim is left out of the
-- ID token and the userinfo response, never sent as null or as an empty string.

ALTER TABLE users
    ADD COLUMN name         varchar(255),
    ADD COLUMN given_name   varchar(255),
    ADD COLUMN family_name  varchar(255),
    ADD COLUMN nickname     varchar(255),
    -- An absolute http(s) URL.
    ADD COLUMN picture      varchar(2048),
    -- A BCP 47 language tag: `en-US`.
    ADD COLUMN locale       varchar(35);
