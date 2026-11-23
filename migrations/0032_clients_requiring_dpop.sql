-- A client may be required to bind every token it is issued to a DPoP key (RFC 9449 §5.2,
-- `dpop_bound_access_tokens` in the Management API): a token request without a proof is refused.
ALTER TABLE oauth2_clients
    ADD COLUMN require_dpop boolean NOT NULL DEFAULT false;
