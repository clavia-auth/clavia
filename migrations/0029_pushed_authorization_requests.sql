-- Whether a client's authorization requests must be pushed first (RFC 9126 §6,
-- `require_pushed_authorization_requests`) and reach the authorization endpoint by reference.
-- Off by default: a client may push its requests either way.
ALTER TABLE oauth2_clients
    ADD COLUMN require_pushed_authorization_requests boolean NOT NULL DEFAULT false;
