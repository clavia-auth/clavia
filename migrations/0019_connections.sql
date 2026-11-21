-- Connections (Step 13): the ways to sign in, which applications may use each, and the
-- pool or provider every account belongs to.

CREATE TABLE connections (
    -- The natural key, and permanent: accounts, sessions and linked identities record
    -- it, and it is part of the callback URL registered at an external provider.
    name                          varchar(32) PRIMARY KEY,
    display_name                  varchar(120) NOT NULL,
    strategy                      varchar(16) NOT NULL,
    -- The global switch: off means off for every application.
    is_enabled                    boolean NOT NULL DEFAULT true,
    -- A domain connection: open to every third-party application, the only kind they get.
    -- A first-party application goes by its own list in client_connections.
    is_domain_connection          boolean NOT NULL DEFAULT false,
    -- OpenID Connect providers only. The endpoints are what discovery said when the
    -- connection was registered or its issuer changed.
    oidc_issuer                   varchar(2048),
    oidc_client_id                varchar(255),
    -- AES-GCM under CLAVIA_SECRET_ENCRYPTION_KEY, bound to the connection's name.
    oidc_client_secret_encrypted  text,
    oidc_scope                    varchar(512),
    oidc_authorization_endpoint   varchar(2048),
    oidc_token_endpoint           varchar(2048),
    oidc_jwks_uri                 varchar(2048),
    created_at                    timestamptz NOT NULL,

    CONSTRAINT ck_connections_name CHECK (name ~ '^[a-z][a-z0-9-]{0,31}$'),
    CONSTRAINT ck_connections_strategy CHECK (strategy IN ('database', 'social', 'oidc')),
    -- An OIDC connection, and only one, has every OIDC setting.
    CONSTRAINT ck_connections_oidc CHECK (
        (strategy = 'oidc') = (
            oidc_issuer IS NOT NULL AND oidc_client_id IS NOT NULL
            AND oidc_client_secret_encrypted IS NOT NULL AND oidc_scope IS NOT NULL
            AND oidc_authorization_endpoint IS NOT NULL AND oidc_token_endpoint IS NOT NULL
            AND oidc_jwks_uri IS NOT NULL
        )
        AND (strategy = 'oidc' OR (
            oidc_issuer IS NULL AND oidc_client_id IS NULL AND oidc_client_secret_encrypted IS NULL
            AND oidc_scope IS NULL AND oidc_authorization_endpoint IS NULL
            AND oidc_token_endpoint IS NULL AND oidc_jwks_uri IS NULL
        ))
    )
);

-- The built-in connections: the default pool, where accounts were before connections
-- existed — a domain connection, so third-party applications keep signing people in
-- with a password — and the social providers the code implements, which work once the
-- deployment sets their credentials.
INSERT INTO connections (name, display_name, strategy, is_enabled, is_domain_connection, created_at) VALUES
    ('password', 'Username-Password', 'database', true, true, now()),
    ('google', 'Google', 'social', true, false, now()),
    ('github', 'GitHub', 'social', true, false, now());

-- Every account belongs to one connection. The accounts that exist were created in the
-- default pool, or by an external provider: an account with no password and a linked
-- identity belongs to the provider it was first linked through.
ALTER TABLE users ADD COLUMN connection varchar(32);
UPDATE users SET connection = coalesce(
    CASE WHEN password_hash IS NULL THEN (
        SELECT provider FROM external_identities
        WHERE external_identities.user_id = users.id
        ORDER BY linked_at, provider
        LIMIT 1
    ) END,
    'password'
);
ALTER TABLE users ALTER COLUMN connection SET NOT NULL;
ALTER TABLE users
    ADD CONSTRAINT fk_users_connection FOREIGN KEY (connection) REFERENCES connections (name);

-- An address is unique within a connection, not across them: the same person may be a
-- customer in one pool and an employee in another, as two accounts.
ALTER TABLE users DROP CONSTRAINT uq_users_email;
ALTER TABLE users ADD CONSTRAINT uq_users_connection_email UNIQUE (connection, email);

-- A linked identity names the connection it signs in through. Deleting a connection is
-- refused while an identity is linked through it, as while an account belongs to it.
ALTER TABLE external_identities DROP CONSTRAINT ck_external_identities_provider;
ALTER TABLE external_identities
    ADD CONSTRAINT fk_external_identities_provider FOREIGN KEY (provider) REFERENCES connections (name);

-- Which applications may sign people in through which connections. A third-party
-- application lists none: it gets the domain connections.
CREATE TABLE client_connections (
    client_id        varchar(64) NOT NULL REFERENCES oauth2_clients (client_id) ON DELETE CASCADE,
    connection_name  varchar(32) NOT NULL REFERENCES connections (name) ON DELETE CASCADE,

    PRIMARY KEY (client_id, connection_name)
);

CREATE INDEX ix_client_connections_connection ON client_connections (connection_name);

-- The first-party applications that exist keep offering every way to sign in they did.
INSERT INTO client_connections (client_id, connection_name)
SELECT oauth2_clients.client_id, connections.name
FROM oauth2_clients CROSS JOIN connections
WHERE oauth2_clients.client_id NOT LIKE 'tpc\_%';
