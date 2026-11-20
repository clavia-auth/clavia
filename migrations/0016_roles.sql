-- Role-based access control (Step 10): roles, the permissions they grant, who holds them,
-- and which APIs narrow a person's token to what their roles grant.
--
-- Every link is a foreign key onto the row it names, so nothing here can outlive what it
-- points at: a permission an API stops defining leaves every role that granted it, and a
-- deleted role or account takes its assignments with it.

-- Whether a token issued on a person's behalf carries only what their roles grant on the
-- API, and is refused to somebody who holds nothing there. Machine clients are governed by
-- their client grants either way. A system API always enforces roles: without them every
-- permission it defines would go to anybody who can sign in.
ALTER TABLE resource_servers ADD COLUMN enforce_policies boolean NOT NULL DEFAULT false;
UPDATE resource_servers SET enforce_policies = true WHERE is_system;
ALTER TABLE resource_servers
    ADD CONSTRAINT ck_resource_servers_system_enforces_policies CHECK (enforce_policies OR NOT is_system);

CREATE TABLE roles (
    -- `rol_` and 16 letters and digits. Not the name: operators rename roles, and the
    -- assignments and URLs that point at one must not follow a typo fix.
    id          varchar(20) PRIMARY KEY,
    name        varchar(64) NOT NULL,
    description text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL,

    CONSTRAINT uq_roles_name UNIQUE (name)
);

CREATE TABLE role_permissions (
    role_id             varchar(20) NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    resource_server_id  varchar(19) NOT NULL,
    value               varchar(128) NOT NULL,

    PRIMARY KEY (role_id, resource_server_id, value),
    -- The permission row itself, not a copy of its spelling.
    CONSTRAINT fk_role_permissions_permission FOREIGN KEY (resource_server_id, value)
        REFERENCES permissions (resource_server_id, value) ON DELETE CASCADE
);

-- The cascade from `permissions` looks rows up by the permission.
CREATE INDEX ix_role_permissions_permission ON role_permissions (resource_server_id, value);

CREATE TABLE user_roles (
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id     varchar(20) NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    assigned_at timestamptz NOT NULL,

    PRIMARY KEY (user_id, role_id)
);

-- A role's holders, most recently assigned first.
CREATE INDEX ix_user_roles_role ON user_roles (role_id, assigned_at DESC, user_id);
