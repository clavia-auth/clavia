-- Fine-grained authorization on an API (#136, docs/design/fine-grained-authorization.md §4): its store
-- in OpenFGA, the model in force there, whether it is on, whether a denial says its kind, and the
-- clients that speak for it.
--
-- Nothing of the relationship graph is kept here: it lives in OpenFGA's own database. The model is
-- configuration, kept as the JSON text the operator wrote (OpenFGA's form, schema 1.1), so it is read
-- back without asking the engine. Either all four are set or none is; a system API has none.

ALTER TABLE resource_servers
    ADD COLUMN authorization_enabled        boolean NOT NULL DEFAULT false,
    ADD COLUMN fga_store_id                 text
        CONSTRAINT ck_resource_servers_fga_store_id CHECK (fga_store_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    ADD COLUMN fga_model_id                 text
        CONSTRAINT ck_resource_servers_fga_model_id CHECK (fga_model_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    ADD COLUMN authorization_model          text
        CONSTRAINT ck_resource_servers_authorization_model CHECK (authorization_model IS JSON OBJECT),
    ADD COLUMN authorization_denial_reasons boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT ck_resource_servers_authorization_whole CHECK (
        (fga_store_id IS NULL) = (fga_model_id IS NULL)
        AND (fga_store_id IS NULL) = (authorization_model IS NULL)
        AND (fga_store_id IS NOT NULL OR NOT authorization_enabled)
    ),
    ADD CONSTRAINT ck_resource_servers_authorization_not_system CHECK (NOT (is_system AND fga_store_id IS NOT NULL));

-- A client speaks for one API at most: the primary key is the client. It goes with the client, and with
-- the API.
CREATE TABLE authorization_clients (
    client_id          varchar(64) PRIMARY KEY REFERENCES oauth2_clients (client_id) ON DELETE CASCADE,
    resource_server_id varchar(19) NOT NULL REFERENCES resource_servers (id) ON DELETE CASCADE,
    position           smallint    NOT NULL
);

CREATE INDEX ix_authorization_clients_resource_server ON authorization_clients (resource_server_id);
