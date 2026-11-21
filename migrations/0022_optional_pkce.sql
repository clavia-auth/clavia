-- PKCE exemption (Step 20): a confidential client may be relieved of PKCE for OpenID
-- Connect requests that carry a `nonce` (OAuth 2.1 §7.5.1). Every client requires it
-- unless an operator says otherwise, and a public client can never be relieved of it.
ALTER TABLE oauth2_clients
    ADD COLUMN require_pkce boolean NOT NULL DEFAULT true,
    ADD CONSTRAINT ck_oauth2_clients_require_pkce
        CHECK (require_pkce OR client_type = 'confidential');

-- A code issued without PKCE has no challenge; it is bound by its nonce instead. The
-- challenge and its method come together, and a code has one or the other binding.
ALTER TABLE oauth2_authorization_codes
    ALTER COLUMN code_challenge DROP NOT NULL,
    ALTER COLUMN code_challenge_method DROP NOT NULL,
    DROP CONSTRAINT ck_oauth2_authorization_codes_method,
    ADD CONSTRAINT ck_oauth2_authorization_codes_method CHECK (
        (code_challenge IS NULL AND code_challenge_method IS NULL AND nonce IS NOT NULL)
        OR (code_challenge IS NOT NULL AND code_challenge_method = 'S256')
    );
