-- The API an authorization request named in `audience`: the permissions of that API
-- were what the scope was checked against, and the token minted from the code carries
-- it as its `aud`. NULL when the request named no API (only OIDC scopes then).

ALTER TABLE oauth2_authorization_codes ADD COLUMN audience varchar(255);
