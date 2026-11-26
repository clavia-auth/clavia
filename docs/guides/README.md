# Management API guides

Short guides to read before the [reference](../openapi/management-api.yaml). Each one is written for
someone calling the API of their own Clavia deployment. The examples use `example.com`; put your
own `CLAVIA_ROOT_DOMAIN` in its place.

1. [Getting a token](getting-a-token.md): a machine client, or a person signing in.
2. [Scopes and roles](scopes-and-roles.md): what a token may do, and who decides.
3. [Errors](errors.md): problem documents, bearer refusals, and stepping up.
4. [Paging and search](paging-and-search.md): reading a list.
5. [DPoP-bound tokens](dpop.md): tokens a stolen copy of is useless.
6. [Registering clients](registering-clients.md): letting others register their applications.

Two hosts are involved in each guide:

- `auth.example.com` issues tokens (`/oauth2/token`, `/oauth2/authorize`, `/oauth2/register`).
- `management.example.com` serves the Management API, under `/api/v1/`.
