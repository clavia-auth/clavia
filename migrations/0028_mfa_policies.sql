-- Whether an application, or an API, takes people in on one factor (docs/design/mfa-policies.md):
-- `optional`, what the request asks with `acr_values` and nothing more, or `required`, more than
-- one factor. Optional by default, so nothing registered before changes.
ALTER TABLE oauth2_clients
    ADD COLUMN mfa_policy text NOT NULL DEFAULT 'optional'
        CONSTRAINT ck_oauth2_clients_mfa_policy CHECK (mfa_policy IN ('optional', 'required'));

ALTER TABLE resource_servers
    ADD COLUMN mfa_policy text NOT NULL DEFAULT 'optional'
        CONSTRAINT ck_resource_servers_mfa_policy CHECK (mfa_policy IN ('optional', 'required'));
