-- SCIM groups, and the roles they grant (docs/design/scim-provisioning.md §2, §5.5).

-- A role a directory's group may grant. It never holds a permission on a system API (the Management
-- API): a directory's token must never make anyone an administrator of this server. The domain
-- refuses it; so does the database, whichever row is written first.
ALTER TABLE roles ADD COLUMN provisionable boolean NOT NULL DEFAULT false;

-- Checked after each row that could break the rule: a permission granted, a role made
-- provisionable. Constraint triggers, so they see the row as written.
CREATE FUNCTION provisionable_role_check(checked_role varchar) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM roles
        JOIN role_permissions ON role_permissions.role_id = roles.id
        JOIN resource_servers ON resource_servers.id = role_permissions.resource_server_id
        WHERE roles.id = checked_role AND roles.provisionable AND resource_servers.is_system
    ) THEN
        RAISE EXCEPTION 'a provisionable role holds no permission on a system API'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'ck_provisionable_roles_no_system_api';
    END IF;
END;
$$;

CREATE FUNCTION role_permissions_provisionable_check() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM provisionable_role_check(NEW.role_id);
    RETURN NULL;
END;
$$;

CREATE FUNCTION roles_provisionable_check() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM provisionable_role_check(NEW.id);
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER tr_role_permissions_provisionable
    AFTER INSERT OR UPDATE ON role_permissions
    FOR EACH ROW EXECUTE FUNCTION role_permissions_provisionable_check();

CREATE CONSTRAINT TRIGGER tr_roles_provisionable
    AFTER INSERT OR UPDATE OF provisionable ON roles
    FOR EACH ROW EXECUTE FUNCTION roles_provisionable_check();

-- Whether an operator gave the role, or only a directory's group did: a group takes away only
-- what it gave, so a role granted by hand stays.
ALTER TABLE user_roles ADD COLUMN by_hand boolean NOT NULL DEFAULT true;
CREATE INDEX ix_user_roles_through_groups ON user_roles (user_id) WHERE NOT by_hand;

-- A directory's groups, per connection, and their members: accounts of the same connection.
CREATE TABLE scim_groups (
    id                      uuid PRIMARY KEY,
    connection              varchar(32) NOT NULL REFERENCES connections (name) ON DELETE CASCADE,
    display_name            varchar(255) NOT NULL CHECK (display_name <> ''),
    -- Case-folded: a group's name is unique in its connection ignoring case.
    display_name_key        varchar(255) NOT NULL,
    external_id             varchar(255) CHECK (external_id <> ''),
    provisioning_token_id   uuid NOT NULL,
    created_at              timestamptz NOT NULL,
    updated_at              timestamptz NOT NULL,
    CONSTRAINT scim_groups_display_name_key UNIQUE (connection, display_name_key),
    CONSTRAINT scim_groups_external_id_key UNIQUE (connection, external_id)
);

CREATE INDEX scim_groups_connection_idx ON scim_groups (connection, created_at, id);
CREATE INDEX scim_groups_display_name_idx ON scim_groups (display_name);

CREATE TABLE scim_group_members (
    group_id    uuid NOT NULL REFERENCES scim_groups (id) ON DELETE CASCADE,
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX scim_group_members_user_idx ON scim_group_members (user_id);
