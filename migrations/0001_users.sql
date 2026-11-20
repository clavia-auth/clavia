-- End users: the resource owners (RFC 6749 §1.1) and the subjects of ID tokens.

CREATE TABLE users (
    -- The OIDC `sub`: stable and opaque. Never the email address — emails change
    -- hands, and OIDC Core §2 requires `sub` never to be reassigned.
    id              uuid PRIMARY KEY,
    email           varchar(320) NOT NULL,
    -- Whether the address was confirmed to belong to this person (the `email_verified`
    -- claim). Set by whatever proved it, never by the value simply being present.
    email_verified  boolean NOT NULL DEFAULT false,
    -- bcrypt. NULL for an account that only ever signs in through an external
    -- provider: it has nothing to verify, which is a failed sign-in, not an empty
    -- password matching an empty hash.
    password_hash   varchar(255),
    -- Re-checked wherever a token could be minted, not only at login.
    is_active       boolean NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT uq_users_email UNIQUE (email)
);
