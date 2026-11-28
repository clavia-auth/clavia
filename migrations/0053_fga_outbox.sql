-- The identity feed's outbox (#137, docs/design/fine-grained-authorization.md §5.4): what Clavia still
-- has to bring into step in an API's store in OpenFGA, written in the transaction of the change.
--
-- A row names a subject, never tuples: `user:<id>` (the roles a person holds there), `role:<id>` (a
-- role's members), `client:<id>` (a deleted application's relationships) or `*` (every role's members,
-- as a resync writes them). The sender reads Clavia as it is when it sends, so a row sent late, twice
-- or out of order still leaves the store as Clavia says. One row per API and subject: queuing it again
-- moves `generation` on, and a worker settles a row only at the generation it claimed. Nothing of the
-- graph is kept here.

CREATE TABLE fga_outbox (
    id                 bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    resource_server_id varchar(19) NOT NULL REFERENCES resource_servers (id) ON DELETE CASCADE,
    subject            varchar(80) NOT NULL
        CONSTRAINT ck_fga_outbox_subject CHECK (subject = '*' OR subject ~ '^(user|role|client):.+$'),
    generation         integer     NOT NULL DEFAULT 1 CHECK (generation > 0),
    attempts           integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at    timestamptz NOT NULL,
    claimed_until      timestamptz,
    created_at         timestamptz NOT NULL,
    CONSTRAINT uq_fga_outbox_subject UNIQUE (resource_server_id, subject)
);

CREATE INDEX ix_fga_outbox_due ON fga_outbox (next_attempt_at);
