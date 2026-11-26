# DPoP-bound tokens

A bearer token works for whoever holds it: copied from a log or a proxy, it works just as well for
the thief. [DPoP (RFC 9449)](https://www.rfc-editor.org/rfc/rfc9449) binds a token to a key pair
your client keeps. Each request then carries a fresh **proof**, signed with the private key, and a
token without its proof is refused. The Management API checks the binding on every call.

DPoP is optional, and off for a client unless it asks. A client registered with
`dpop_bound_access_tokens: true` must use it: a token request without a proof is then refused.

## The proof

A proof is a small JWT, made for one request, sent in the `DPoP` header. Its header names the
public key:

```json
{"typ": "dpop+jwt", "alg": "ES256", "jwk": {"kty": "EC", "crv": "P-256", "x": "…", "y": "…"}}
```

Its claims say which request it is for:

| Claim | Value |
|---|---|
| `jti` | A random identifier, never reused: a proof is good once |
| `htm` | The request's method: `POST`, `GET` |
| `htu` | The URL, without query or fragment: `https://management.example.com/api/v1/users` |
| `iat` | Now, in seconds. A proof older than a minute (`CLAVIA_DPOP_PROOF_LIFETIME`) is refused |
| `nonce` | The server's nonce, at the token endpoint only (below) |
| `ath` | With a token, the base64url SHA-256 of the access token |

Keys may be `ES256`, `EdDSA` or `RS256`. Keep the private key in memory or in a key store, never
inside the proof (a proof carrying a private member is refused). Any JOSE library can make these;
generate one key per client instance and keep it as long as its tokens.

## Getting a bound token

At the token endpoint the server also asks for its own nonce, so a proof can't be made in advance.
The first request, with a proof but no nonce, is refused:

```http
POST /oauth2/token HTTP/1.1
Host: auth.example.com
Authorization: Basic …
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIs…   (htm POST, htu https://auth.example.com/oauth2/token)

grant_type=client_credentials&audience=https://management.example.com/api/v1/
```

```http
HTTP/2 400
DPoP-Nonce: 8Kp2…

{"error":"use_dpop_nonce","error_description":"The DPoP proof must carry the server's nonce."}
```

Make a new proof with that `nonce` claim, and send the request again:

```json
{"access_token": "…", "token_type": "DPoP", "expires_in": 3600, "scope": "read:users read:clients"}
```

`token_type: DPoP` says the token is bound. Each answer to a request with a proof carries the next
`DPoP-Nonce`: keep the latest one for your next request. The nonce changes every five minutes
(`CLAVIA_DPOP_NONCE_LIFETIME`), and the previous one is still accepted for as long again. A
`use_dpop_nonce` can come at any time: retry once with the nonce it carries.

## Calling the API

Send the token under the **`DPoP`** scheme, not `Bearer`, with a new proof naming it in `ath`:

```bash
curl -s https://management.example.com/api/v1/users \
  -H "Authorization: DPoP $TOKEN" \
  -H "DPoP: $PROOF"     # htm GET, htu …/api/v1/users, ath = SHA-256 of $TOKEN, a fresh jti
```

The Management API asks for no nonce: the proof's age and its single use are enough. What it
refuses, all as `401`:

| Sent | `error` |
|---|---|
| A bound token as `Bearer` | `invalid_token`: "The access token is bound to a key: present it with DPoP." |
| A bearer token as `DPoP` | `invalid_token` |
| No proof, a proof from another key, without `ath`, for another URL or method, too old | `invalid_dpop_proof` |
| A proof sent a second time | `invalid_dpop_proof` |

A refusal under the DPoP scheme is challenged in that scheme, with the algorithms accepted:

```http
WWW-Authenticate: DPoP realm="https://management.example.com/api/v1/", error="invalid_dpop_proof",
  error_description="The DPoP proof is not valid for this request.", algs="ES256 EdDSA RS256"
```

The reason a proof was refused is logged on the server, never told to the caller.
