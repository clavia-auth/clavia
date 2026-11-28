# Management API guides

Short guides to read before the references: the [Management API's](../openapi/management-api.yaml),
and the [authorization server's](../openapi/authorization-server.yaml), where tokens come from. Each one is written for
someone calling the API of their own Clavia deployment. The examples use `example.com`; put your
own `CLAVIA_ROOT_DOMAIN` in its place.

1. [Getting a token](getting-a-token.md): a machine client, or a person signing in.
2. [Scopes and roles](scopes-and-roles.md): what a token may do, and who decides.
3. [Errors](errors.md): problem documents, bearer refusals, and stepping up.
4. [Paging and search](paging-and-search.md): reading a list.
5. [DPoP-bound tokens](dpop.md): tokens a stolen copy of is useless.
6. [Registering clients](registering-clients.md): letting others register their applications.
7. [Fine-grained authorization](fine-grained-authorization.md): asking an API's decisions, and keeping its relationships.

Two hosts are involved in each guide:

- `auth.example.com` issues tokens (`/oauth2/token`, `/oauth2/authorize`, `/oauth2/register`): the
  [authorization server's reference](../openapi/authorization-server.yaml) describes each of its endpoints.
- `management.example.com` serves the Management API, under `/api/v1/`: its
  [reference](../openapi/management-api.yaml). It also serves the Authorization API, under
  `/access/v1/`, when the deployment has fine-grained authorization: its
  [reference](../openapi/authorization-api.yaml).
