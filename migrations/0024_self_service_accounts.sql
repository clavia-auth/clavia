-- Self-service accounts: a pool may let people create their own account, and may require
-- an account to prove its address before it signs in with a password.
-- See docs/design/self-service-accounts.md.

ALTER TABLE connections
    -- People may create their own account in this pool, from the sign-up page.
    ADD COLUMN allow_sign_up boolean NOT NULL DEFAULT false,
    -- An unverified account in this pool cannot sign in with its password until it follows
    -- the verification link it is sent.
    ADD COLUMN require_verified_email boolean NOT NULL DEFAULT false,
    -- Both are about accounts with passwords: pools only.
    ADD CONSTRAINT ck_connections_self_service CHECK (
        strategy = 'database' OR (NOT allow_sign_up AND NOT require_verified_email)
    );
