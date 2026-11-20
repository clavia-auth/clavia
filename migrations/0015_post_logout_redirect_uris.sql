-- RP-Initiated Logout (Step 9): where a sign-out an application starts may send the
-- browser back. OpenID Connect RP-Initiated Logout 1.0 §3.1: a post_logout_redirect_uri
-- must have been registered, and is matched exactly — like a redirect URI, and kept
-- apart from them, because a page to land on after signing out is not an endpoint
-- that accepts authorization responses.

ALTER TABLE oauth2_clients
    ADD COLUMN post_logout_redirect_uris jsonb NOT NULL DEFAULT '[]',
    ADD CONSTRAINT ck_oauth2_clients_post_logout_redirect_uris
        CHECK (jsonb_typeof(post_logout_redirect_uris) = 'array');
