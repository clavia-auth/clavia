-- Passwordless sign-in (Step 16): the built-in `email` connection, whose accounts are
-- proven by access to a mailbox — a one-time code or a sign-in link sent by email.

ALTER TABLE connections DROP CONSTRAINT ck_connections_strategy;
ALTER TABLE connections
    ADD CONSTRAINT ck_connections_strategy CHECK (strategy IN ('database', 'social', 'oidc', 'passwordless'));

-- Switched on, but usable only while the deployment can send mail (CLAVIA_EMAIL_BACKEND
-- other than 'none'), and not a domain connection: a stranger's application is not
-- handed a way to create accounts from nothing but an address.
--
-- No application is given it: those that exist keep exactly the ways in they had, and an
-- operator turns it on for the ones that want it. Applications registered from now on
-- get every connection, this one included.
INSERT INTO connections (name, display_name, strategy, is_enabled, is_domain_connection, created_at)
VALUES ('email', 'Email', 'passwordless', true, false, now());
