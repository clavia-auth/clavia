-- When a self-registered client was first issued a token (docs/design/
-- dynamic-client-registration.md §5.4). Null until then: `clients:purge-unused` deletes a client
-- still unused past CLAVIA_CLIENT_REGISTRATION_UNUSED_LIFETIME.
ALTER TABLE client_registrations
    ADD COLUMN first_used_at timestamptz;

-- The purge's question: unused registrations, oldest first.
CREATE INDEX client_registrations_unused_idx ON client_registrations (registered_at)
    WHERE first_used_at IS NULL;
