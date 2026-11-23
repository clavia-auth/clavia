-- Bulk jobs on the users (#19): queued by the Management API, run by `clavia jobs:run`. An import
-- holds its NDJSON input (password hashes included) only until it finishes; then only the report
-- remains, until `jobs:run` purges the job.
CREATE TABLE user_jobs (
    id                      uuid PRIMARY KEY,
    kind                    varchar(32) NOT NULL CHECK (kind IN ('users_import')),
    status                  varchar(16) NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    connection              varchar(32) NOT NULL REFERENCES connections (name) ON DELETE CASCADE,
    -- Who asked, so the accounts it makes are recorded as theirs in the audit trail.
    requested_by_kind       varchar(16) NOT NULL,
    requested_by_user_id    uuid,
    requested_by_client_id  varchar(64),
    created_at              timestamptz NOT NULL,
    started_at              timestamptz,
    finished_at             timestamptz,
    input                   text,
    total                   integer NOT NULL DEFAULT 0,
    created                 integer NOT NULL DEFAULT 0,
    failed                  integer NOT NULL DEFAULT 0,
    errors                  jsonb NOT NULL DEFAULT '[]',
    failure                 text,
    -- A finished job keeps no input: it may hold password hashes.
    CHECK (status IN ('queued', 'running') OR input IS NULL)
);

-- The queue: the oldest queued job first.
CREATE INDEX user_jobs_queued_idx ON user_jobs (created_at) WHERE status = 'queued';
