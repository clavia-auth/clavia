-- Where a client starts a sign-in of its own (#219): `initiate_login_uri`, OpenID Connect Dynamic Client
-- Registration 1.0 §2. A person whose sign-in request expired is sent there to start again. An https URL,
-- as InitiateLoginUri keeps it; null when the client registered none.

ALTER TABLE oauth2_clients
    ADD COLUMN initiate_login_uri text
        CONSTRAINT ck_oauth2_clients_initiate_login_uri CHECK (initiate_login_uri LIKE 'https://%');
