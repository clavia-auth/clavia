-- Branding per application (#25): its accent colour and its logo on the sign-in pages.
--
-- The colour is six hexadecimal digits in lower case, as AccentColor keeps it: it is written into a
-- stylesheet, so the database refuses anything else too. The logo is the image itself, PNG, JPEG or
-- WebP and at most 256 KiB (ClientLogo), served from this server's origin; its version, a digest of the
-- content, is what the pages name it by, read without the image. It goes with its application.

ALTER TABLE oauth2_clients
    ADD COLUMN accent_color text
        CONSTRAINT ck_oauth2_clients_accent_color CHECK (accent_color ~ '^#[0-9a-f]{6}$');

CREATE TABLE client_logos (
    client_id  varchar(64) PRIMARY KEY REFERENCES oauth2_clients (client_id) ON DELETE CASCADE,
    media_type text        NOT NULL CONSTRAINT ck_client_logos_media_type
                               CHECK (media_type IN ('image/png', 'image/jpeg', 'image/webp')),
    content    bytea       NOT NULL CONSTRAINT ck_client_logos_size CHECK (octet_length(content) <= 262144),
    version    text        NOT NULL CONSTRAINT ck_client_logos_version CHECK (version ~ '^[0-9a-f]{16}$')
);
