-- The DPoP key an authorization code must be redeemed with (`dpop_jkt`, RFC 9449 §10), and the one
-- a public client's refresh family is bound to (§5): RFC 7638 SHA-256 thumbprints, base64url. Null
-- for anything not bound, as everything issued before this migration is.
ALTER TABLE oauth2_authorization_codes
    ADD COLUMN dpop_jkt varchar(43) NULL;

ALTER TABLE oauth2_refresh_tokens
    ADD COLUMN dpop_jkt varchar(43) NULL;
