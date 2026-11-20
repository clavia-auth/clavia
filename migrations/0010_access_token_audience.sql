-- The API an access token is for: its `aud`. Set when the client named one — always
-- for a token a client obtained as itself — and checked by a resource server before
-- it looks at the scope.
--
-- The identifier itself rather than a reference to the API: a token keeps saying what
-- it was issued for even if the API is later removed.

ALTER TABLE oauth2_access_tokens ADD COLUMN audience varchar(255);
