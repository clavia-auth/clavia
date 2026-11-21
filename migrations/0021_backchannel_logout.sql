-- Back-channel logout (Step 17): telling applications that a session they signed in
-- through has ended (OpenID Connect Back-Channel Logout 1.0).

-- The session that approved a code: its `sid`, which the ID token minted from the code
-- carries, so the application can tie a later logout token to this sign-in. NULL when no
-- session stood behind the approval (the development auto-login).
ALTER TABLE oauth2_authorization_codes
    ADD COLUMN sid varchar(64);

-- Where a client wants to be told (§2.2), and whether it needs the session named. This
-- server posts there on its own account: https, no fragment, and never at its own
-- network — the last checked again at every send.
ALTER TABLE oauth2_clients
    ADD COLUMN backchannel_logout_uri varchar(2048),
    ADD COLUMN backchannel_logout_session_required boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT ck_oauth2_clients_backchannel_logout_uri
        CHECK (backchannel_logout_uri IS NULL OR (
            backchannel_logout_uri LIKE 'https://%' AND position('#' IN backchannel_logout_uri) = 0
        ));
