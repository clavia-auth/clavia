-- APIs this server itself depends on — the Management API. Their permissions are the
-- server's to define and they cannot be deleted: either would revoke the credentials
-- needed to undo the mistake. Set only by provisioning on the machine
-- (`clavia management-api:register`), never over HTTP.

ALTER TABLE resource_servers ADD COLUMN is_system boolean NOT NULL DEFAULT false;
