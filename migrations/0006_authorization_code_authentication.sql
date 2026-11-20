-- What an ID token minted from a code must report (OIDC Core §2, §3.1.2.1), captured
-- when the code is issued: the session that approved it may be gone by the time the
-- code is redeemed.

ALTER TABLE oauth2_authorization_codes
    -- The `nonce` of an OpenID Connect request, returned verbatim in the ID token.
    ADD COLUMN nonce      varchar(512),
    -- When the person authenticated (`auth_time`). NULL when nothing authenticated
    -- anyone — the development auto-login — and the claim is then left out.
    ADD COLUMN auth_time  timestamptz,
    -- How they authenticated: RFC 8176 `amr` values, as a JSON array of strings.
    ADD COLUMN amr        jsonb NOT NULL DEFAULT '[]'::jsonb;
