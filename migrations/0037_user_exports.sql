-- Exports of the accounts of a connection (#19), run by `clavia jobs:run` like an import. The output,
-- NDJSON with no password hash, is kept apart from the job: a job's status is read often, and its
-- output only when downloaded. It goes with the job, when `jobs:run` purges it.
ALTER TABLE user_jobs DROP CONSTRAINT user_jobs_kind_check;
ALTER TABLE user_jobs ADD CONSTRAINT user_jobs_kind_check CHECK (kind IN ('users_import', 'users_export'));
-- An export reads the directory: it is never given an input.
ALTER TABLE user_jobs ADD CONSTRAINT user_jobs_export_has_no_input CHECK (kind = 'users_import' OR input IS NULL);

CREATE TABLE user_job_outputs (
    job_id   uuid PRIMARY KEY REFERENCES user_jobs (id) ON DELETE CASCADE,
    content  text NOT NULL
);
