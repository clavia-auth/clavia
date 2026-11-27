# Errors

A refusal comes in one of two shapes:
- **A problem about the token** (missing, unusable, short of a scope, from too weak a sign-in) is an
  [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750#section-3) bearer refusal: a `WWW-Authenticate`
  header, and a small JSON body.
- **Any other problem** (the request, the resource) is an
  [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem document, `application/problem+json`.

Branch on the status code first, then on `error` (a bearer refusal) or `status` and `errors`
(a problem document). The human-readable texts may change; the codes won't.

No error repeats a secret or a value it refused. No error is cacheable.

## Bearer refusals

| Status | `error` | Meaning | What to do |
|---|---|---|---|
| `401` | none | No token, or not in the `Authorization` header | Send one |
| `401` | `invalid_token` | Unknown, expired, revoked, for another API, or its subject deactivated | Get a new token |
| `401` | `insufficient_user_authentication` | A person's token from too weak a sign-in | [Step up](#stepping-up) |
| `401` | `invalid_dpop_proof` | A DPoP-bound token whose proof is missing or wrong | See [DPoP](dpop.md) |
| `403` | `insufficient_scope` | The token lacks the operation's scope, named in `scope` | Ask for a token with it, or a wider grant |

The header says the same as the body, and names the realm, which is the Management API's identifier:

```http
HTTP/2 403
Content-Type: application/json
WWW-Authenticate: Bearer realm="https://management.example.com/api/v1/", error="insufficient_scope",
  error_description="The access token does not carry the 'read:roles' scope.", scope="read:roles"

{"error":"insufficient_scope","error_description":"The access token does not carry the 'read:roles' scope."}
```

With no token at all, the body is an empty object, `{}`, and the challenge carries no `error`.

`invalid_token` is deliberately one answer for every reason a token is unusable. Expired or issued
for another API, the remedy is the same: a new token.

### Stepping up

When the Management API's MFA policy is `required`, a person's token must come from a sign-in with a
second factor. A token from a password alone is refused, and the challenge says what to ask for,
following [RFC 9470](https://www.rfc-editor.org/rfc/rfc9470#section-3):

```http
HTTP/2 401
WWW-Authenticate: Bearer realm="https://management.example.com/api/v1/",
  error="insufficient_user_authentication",
  error_description="The Management API requires a stronger sign-in.",
  acr_values="http://schemas.openid.net/pape/policies/2007/06/multi-factor"
```

The application sends the person back to `/oauth2/authorize` with that `acr_values`. A person who
has a second factor is asked for it. One who hasn't, and whose address is verified, is asked to
enrol one on the way. Anyone else is refused (`unmet_authentication_requirements`, at the
application's redirect URI). The new code yields a token that passes.

This check comes **before** the scope check, so a person may need to step up before learning that a
scope is missing. Machine tokens are never asked: there's nobody to step up.

## Problem documents

```json
{
  "type": "about:blank",
  "title": "Unprocessable Content",
  "status": 422,
  "detail": "The request does not satisfy the API's contract.",
  "errors": [
    {"parameter": "per_page", "detail": "Must be less than or equal to 100."},
    {"parameter": "bogus", "detail": "Is not a parameter of this operation."}
  ]
}
```

`errors` lists every violation found, up to fifty, so one round trip shows them all. Each entry
points at its place:
- `pointer`, a JSON Pointer into the body (`/email`; `""` for the body itself);
- or `parameter`, the query or path parameter's name.

The value at fault is never repeated.

| Status | When |
|---|---|
| `400` | The request can't be read: unreadable JSON, a parameter sent twice, a value that isn't UTF-8 |
| `404` | No such resource (`"detail": "No such user."`) |
| `409` | A conflict with what exists: a name already taken, a system API not to be deleted, a job not finished |
| `415` | A body that is not `application/json` |
| `422` | The contract or a rule refuses it: an unknown field, a value out of range, an unknown permission |
| `429` | A limit was reached, such as the mail sent to one address; nothing was done, so try later |
| `503` | Something the operation needs can't be reached, such as mail for a password link |

**The contract is strict.** A field or query parameter the reference doesn't describe is refused,
not ignored (`"Is not allowed."`, `"Is not a parameter of this operation."`). A typo therefore
fails loudly instead of being dropped. Values are taken exactly as typed: `"02"` is not an integer,
and `"true"` is not a boolean.

A path the API doesn't have is a plain `404` (`{"detail": "Not Found"}`), not a problem document.

An unexpected failure is a bare `500` with an `X-Error-Reference` header. The server's log has the
details under that reference; quote it when you report the problem.
