-- The APIs this server issues tokens for (RFC 6749 §1.1 "resource server"; Auth0's
-- "APIs"), and the permissions each defines.
--
-- Registering an API is what makes a scope mean anything: `read:users` on two APIs are
-- two permissions spelled the same, which is why every resource server checks `aud`
-- before it looks at `scope`.

CREATE TABLE resource_servers (
    -- `rs_` and 16 letters and digits. A surrogate key by choice: the identifier is a
    -- URI, right as an audience and unwieldy as a key repeated on every permission and
    -- grant (and, later, as a path segment of the Management API).
    id          varchar(19) PRIMARY KEY,
    -- The `audience` a client names and the `aud` its token carries. Immutable.
    identifier  varchar(255) NOT NULL,
    name        varchar(120) NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL,

    CONSTRAINT uq_resource_servers_identifier UNIQUE (identifier)
);

CREATE TABLE permissions (
    resource_server_id  varchar(19) NOT NULL REFERENCES resource_servers (id) ON DELETE CASCADE,
    -- A scope token (RFC 6749 §3.3).
    value               varchar(128) NOT NULL,
    description         text NOT NULL DEFAULT '',

    -- A permission *is* a value on an API: there is no surrogate id to point at instead.
    PRIMARY KEY (resource_server_id, value)
);
