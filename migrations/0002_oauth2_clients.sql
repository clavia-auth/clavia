-- Client applications registered with this authorization server (RFC 6749 §2).
--
-- There is deliberately no scope column: a client holds no scope of its own. What may
-- be requested is decided by the API named in `audience` and by what the user (or, for
-- a machine, its client grant) holds there.

CREATE TABLE oauth2_clients (
    -- The public identifier the client presents, and the primary key. Generated, not
    -- chosen, and immutable; there is no surrogate id to map to.
    client_id                   varchar(64) PRIMARY KEY,
    -- bcrypt. NULL for a public client, which by definition has no secret.
    client_secret_hash          varchar(255),
    name                        varchar(120) NOT NULL DEFAULT '',
    client_type                 varchar(16) NOT NULL,
    -- Matched exactly against the redirect_uri of every authorization request.
    redirect_uris               jsonb NOT NULL DEFAULT '[]',
    -- Which grants the client may use at the token endpoint. Opt-in, never implied.
    grant_types                 jsonb NOT NULL DEFAULT '[]',
    -- Which response_type values it may use at the authorization endpoint.
    response_types              jsonb NOT NULL DEFAULT '[]',
    -- The one way this client proves itself: none, client_secret_basic, client_secret_post.
    token_endpoint_auth_method  varchar(32) NOT NULL DEFAULT 'none',
    created_at                  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT ck_oauth2_clients_type CHECK (client_type IN ('public', 'confidential')),
    CONSTRAINT ck_oauth2_clients_redirect_uris CHECK (jsonb_typeof(redirect_uris) = 'array'),
    CONSTRAINT ck_oauth2_clients_grant_types CHECK (jsonb_typeof(grant_types) = 'array'),
    CONSTRAINT ck_oauth2_clients_response_types CHECK (jsonb_typeof(response_types) = 'array'),
    -- RFC 6749 §2.1: the type is whether the client can keep a secret.
    CONSTRAINT ck_oauth2_clients_secret CHECK (
        (client_type = 'public' AND client_secret_hash IS NULL AND token_endpoint_auth_method = 'none')
        OR (client_type = 'confidential' AND client_secret_hash IS NOT NULL AND token_endpoint_auth_method <> 'none')
    )
);

CREATE INDEX ix_oauth2_clients_name ON oauth2_clients (name);
