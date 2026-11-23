-- The DPoP key an access token is bound to (RFC 9449 §6): the RFC 7638 SHA-256 thumbprint of the
-- public key, base64url. Null for a bearer token, as every token issued before this migration is.
ALTER TABLE oauth2_access_tokens
    ADD COLUMN dpop_jkt varchar(43) NULL;
