# Design: DPoP, sender-constrained tokens

**Status:** agreed · **Date:** 2026-11-23 · **Issue:** clavia-auth/clavia#11 ·
**Specifications:** RFC 9449 (OAuth 2.0 Demonstrating Proof of Possession), RFC 7638 (JWK
thumbprint), RFC 7800 (`cnf`), RFC 9068 (JWT access tokens), RFC 7662 (introspection),
RFC 9126 (pushed authorization requests), OAuth 2.1 §1.4.3 (sender-constrained tokens)

## 1. Summary

Every access token Clavia issues today is a bearer token: whoever holds it can use it. A token
copied from a log, a proxy, a browser's storage or a compromised resource server works for the
thief exactly as for its owner, until it expires. A refresh token of a public client is worse:
it lives for days.

DPoP (RFC 9449) binds a token to a key the client holds. The client sends, with each request, a
short signed JWT — a *proof* — made with its private key for that one request (method, URL,
time, and the token's hash). The server records the key's thumbprint in the token (`cnf.jkt`)
and refuses the token without a fresh proof from the same key. A stolen token is then useless
without the private key, which a well-built client keeps non-extractable (WebCrypto, a platform
keystore).

### Goals

- Bind access tokens to a DPoP key at the token endpoint, for every grant, and refresh tokens of
  public clients (§5).
- Bind authorization codes to the key the client will use (`dpop_jkt`, §10), including through
  PAR (§10.1).
- Check proofs as §4.3 says, with replay protection (§11.1) and server-provided nonces (§8).
- Accept DPoP-bound tokens at this server's own protected resources — userinfo and the
  Management API — and refuse them presented as bearer tokens (§7.2).
- `cnf.jkt` in JWT access tokens and introspection (§6), `dpop_signing_alg_values_supported` in
  discovery (§5.1), and a per-client "DPoP required" (`dpop_bound_access_tokens`, §5.2).

### Not in scope

- mTLS-bound tokens (RFC 8705): a different binding, for a deployment with client certificates.
- Resource-server-provided nonces at this server's own resources (§9): question 2.
- DPoP for the dashboard: it is a confidential backend client whose tokens never reach a browser;
  it can adopt DPoP later through the per-client setting.

## 2. Decisions

| Topic | Decision | Why (the alternatives rejected) |
|---|---|---|
| Opt-in or required | **Opt-in per request, required per client** (`dpop_bound_access_tokens`, off by default) | A client that sends a proof gets a bound token; one that does not gets a bearer token, as today. RFC 9449 §5.2 defines the client metadata. Requiring DPoP server-wide would break every existing client on upgrade |
| Algorithms | `ES256`, `EdDSA` (Ed25519), `RS256`, `PS256` | What WebCrypto, platform keystores and the common libraries make. No `none`, no MAC (§4.2: asymmetric only). The list is what discovery advertises and the verifier accepts, from one place |
| Who checks a proof | The **signature, `typ`, `alg` and `jwk`** in a secondary adapter (`DpopProofVerifier`, on `web-token/jwt-library`); **everything about the request** — method, URL, time, replay, nonce, token hash, key binding — in the application | The adapter only knows JOSE. Which request a proof is for is a protocol decision (rule 5 of the hexagon) |
| `htu` | Compared with the URL **this server says** the endpoint is at — the issuer, or the Management API's host, plus the route's path — never with the request's `Host` | CLAUDE.md: the host never comes from a header. §4.3 compares scheme, authority and path, without query or fragment, after RFC 3986 normalisation |
| Proof age | `iat` within `CLAVIA_DPOP_PROOF_LIFETIME` in the past (60 s) and 5 s in the future | §11.1 leaves the window to the server; a proof is made for one request and sent at once |
| Replay | A `jti` is accepted once per key, in Redis, for the proof lifetime and the skew (`DpopReplayCache`, `SET NX`) | §11.1. A proof outside the window is refused by its age, so the cache never needs to be longer |
| Server nonces | **At the token endpoint and PAR, always**: a proof without the current nonce is answered `use_dpop_nonce` with a `DPoP-Nonce` header (§8) | A nonce limits a proof to a time the server chose, which defeats pre-generated proofs (§11.2): an attacker with brief access to the client (XSS) could otherwise sign proofs for later. Every client library that supports DPoP retries on `use_dpop_nonce`. One round trip per client every nonce window |
| Nonce form | A random value per window (`CLAVIA_DPOP_NONCE_LIFETIME`, 5 min) in Redis; the current and the previous one are accepted | No key to derive or rotate, and a nonce issued just before the window turns still works |
| Binding of access tokens | The access token records the key's RFC 7638 thumbprint (`dpop_jkt`), as JWT `cnf.jkt` and in introspection; `token_type` is `DPoP` | §6.1, §6.2, §5 |
| Binding of refresh tokens | **Public clients**: the family records the thumbprint; a refresh needs a proof from the same key. **Confidential clients**: not bound; a refresh may present any key, and the new access token is bound to it | §5: a public client's refresh token MUST be bound; a confidential one is bound to the client's authentication |
| Binding of codes | `dpop_jkt` at `/oauth2/authorize` (and in a pushed request) binds the code; redeeming it needs a proof from that key. A DPoP header at `/oauth2/par` binds the pushed request to its key | §10, §10.1: stops a stolen code from being redeemed with the thief's key |
| Downgrade | A bound token presented as `Bearer` is `invalid_token` | §7.2: otherwise binding is optional for the thief |
| Revocation | No proof needed | RFC 9449 does not apply DPoP to revocation; giving a token back should stay easy |

## 3. Settings

| Setting | Default | Range | Why |
|---|---|---|---|
| `CLAVIA_DPOP_PROOF_LIFETIME` | 60 | 5–300 s | How old a proof's `iat` may be (§11.1), and how long its `jti` is remembered |
| `CLAVIA_DPOP_NONCE_LIFETIME` | 300 | 30–3600 s | How long a server nonce is current; the previous one stays valid as long again |

No switch: DPoP is per request and per client.

## 4. Model

### Domain

- `Domain\OAuth2\Dpop\JwkThumbprint` (value object): the RFC 7638 SHA-256 thumbprint, base64url,
  43 characters. `equals()`.
- `Domain\OAuth2\Dpop\DpopProof` (value object): what a verified proof says — `thumbprint`,
  `method`, `url`, `issuedAt`, `jti`, `?accessTokenHash`, `?nonce`.
- `Domain\OAuth2\Dpop\ProofRequirement`: the request a proof must be for (method, URL, the access
  token when there is one, the nonce when one is required), with
  `check(DpopProof, DateTimeImmutable $now, int $lifetime): ?DpopRefusal` — every §4.3 rule that
  is not cryptography, in one place.
- `AccessToken` gains `?JwkThumbprint $dpopJkt`; `RefreshToken` (the family) and
  `AuthorizationCode` gain the same. `AccessToken::tokenType()` is `DPoP` when bound.
- `Client` gains `bool $requiresDpop` (`dpop_bound_access_tokens`).
- `AccessTokenClaims` adds `cnf: {jkt}` for a bound token.

### Application

- Port `DpopProofVerifier`: `verify(string $proof, list<SigningAlgorithm> $allowed): ?DpopProof` —
  `typ` `dpop+jwt`, an allowed `alg`, a public `jwk` and no private member, a valid signature by
  that `jwk`, the required claims present. Null for anything else.
- Port `DpopReplayCache`: `claim(JwkThumbprint, string $jti, int $ttl): bool`.
- Port `DpopNonces`: `current(): string`, `isCurrent(string): bool`.
- `OAuth2\Dpop\ReadDpopProof`: the one door. Given the `DPoP` header(s), the request and what is
  required, it verifies, checks, claims the `jti`, and returns the proof's thumbprint, or the
  refusal (`invalid_dpop_proof` or `use_dpop_nonce`).
- `TokenRequest` gains `?string $dpopProof` and the endpoint's URL; `IssueToken` reads the proof
  once and hands the thumbprint to the grant, which binds what it issues.
- `Authorize` and `PushAuthorizationRequest` read `dpop_jkt` (and PAR's DPoP header) and carry it
  on the code.
- `AuthenticateManagementCaller` and `UserInfo` take the credentials as scheme, token and proof.

### Adapters

- `Signing\Jose\JoseDpopProofVerifier`: the JWS parsed with `web-token/jwt-library`, verified with
  the embedded `jwk`, its algorithm checked against both the header and the key type.
- `Redis\RedisDpopReplayCache` (`dpop-jti:<digest of jkt and jti>`), `Redis\RedisDpopNonces`.
- `Http\Shared\AccessTokenCredentials` replaces `BearerCredentials`: `Bearer` or `DPoP`, one
  `Authorization` header, at most one `DPoP` header (§4.3: more than one is refused).

### Migrations

- `oauth2_access_tokens`, `oauth2_refresh_tokens`, `oauth2_authorization_codes`:
  `dpop_jkt varchar(43) NULL`.
- `oauth2_clients`: `require_dpop boolean NOT NULL DEFAULT false`.

## 5. Flows

### 5.1 A proof, checked (§4.3)

For a request with a `DPoP` header:

1. Exactly one `DPoP` header, else `invalid_dpop_proof`.
2. The adapter verifies it as a JWS (see `DpopProofVerifier`); anything wrong is `invalid_dpop_proof`.
3. `htm` is the request's method; `htu` is the endpoint's URL as this server knows it.
4. `iat` is within the proof lifetime, and at most 5 s ahead.
5. Where a nonce is required: `nonce` is current, or the answer is `use_dpop_nonce` with a
   fresh `DPoP-Nonce`.
6. Where an access token is presented: `ath` is the base64url SHA-256 of it, and the token's
   `cnf.jkt` is the proof's thumbprint.
7. The `jti` is claimed for that key; a second use is `invalid_dpop_proof`.

Every refusal is logged with its reason; the answer names none (`invalid_dpop_proof`, one
description).

### 5.2 The token endpoint (§5)

1. Client authentication and the grant's checks, as today.
2. A `DPoP` header is read (5.1, nonce required). A client with `dpop_bound_access_tokens`
   sending none is `invalid_dpop_proof`.
3. **Authorization code**: a code bound to a key (`dpop_jkt`) needs a proof from that key;
   otherwise `invalid_grant`, and the code is spent, as for a wrong verifier.
4. **Refresh**: a bound family (public client) needs a proof from its key, else `invalid_grant`,
   and the token is not spent (a wrong proof is not a replay).
5. Whatever is issued with a proof is bound: the access token (`token_type: DPoP`), the refresh
   family of a public client, from the first token on.
6. **Device code**, **client credentials**: the same binding of the access token.
7. Every answer of the token endpoint carries the current `DPoP-Nonce` (§8), so a client can
   use it on its next request without a failed round trip.

### 5.3 The authorization endpoint and PAR (§10)

- `dpop_jkt` is validated (43 base64url characters) with the other parameters, and carried on
  the code. Unknown to a client that does not use DPoP: it is optional.
- `/oauth2/par` with a `DPoP` header (nonce required, `htu` the PAR endpoint): the proof's
  thumbprint becomes the pushed request's `dpop_jkt`; a `dpop_jkt` parameter that disagrees is
  `invalid_dpop_proof`.

### 5.4 This server's protected resources (§7)

`/oidc/userinfo` and `/api/v1/*`:

- `Authorization: DPoP <token>` with a proof (`ath`, `htm`, `htu`; no nonce, question 2): the
  token must be bound to the proof's key.
- `Authorization: Bearer <token>` for a bound token: `invalid_token` (§7.2).
- A refusal of a DPoP request is `401` with `WWW-Authenticate: DPoP error="…",
  algs="ES256 EdDSA RS256 PS256"` (§7.1); a bearer one keeps its `Bearer` challenge.
- The Management API's step-up check (#63) is unchanged: it looks at the token.

### 5.5 Introspection (§6.2)

An active bound token answers `token_type: DPoP` and `cnf: {jkt}`. Introspection itself needs no
proof: the caller is the resource server, authenticated by its secret.

## 6. Interfaces

- **Discovery**: `dpop_signing_alg_values_supported` (`ProviderMetadata`, `OidcTest`).
- **Token endpoint and PAR**: the `DPoP` request header; `DPoP-Nonce` on every answer;
  `invalid_dpop_proof` and `use_dpop_nonce` (400).
- **Authorization endpoint**: the `dpop_jkt` parameter.
- **Userinfo, Management API**: the `DPoP` scheme and header; the `DPoP` challenge.
- **Management API document**: clients gain `dpop_bound_access_tokens` (read, create, update);
  the `401` description names the `DPoP` scheme. `ManagementApiMiddleware` reads
  `AccessTokenCredentials`.
- **JWT access tokens**: `cnf.jkt`. **Introspection**: `cnf.jkt`, `token_type`.
- **Dashboard** (clavia-dashboard): the client setting. A separate issue.

## 7. Security rules

- **A bound token never works without a fresh proof from its key**, at every surface of this
  server that accepts tokens, and never as a bearer token.
- **The URL a proof names is the one this server knows**, never one read from the request's
  `Host` or a forwarded header.
- **A proof is used once** (`jti` per key) and is short-lived; at the token endpoint it carries a
  nonce this server chose, so it cannot have been made in advance.
- **No private key in a proof**: a `jwk` carrying a private member is refused, not trusted.
- **Asymmetric algorithms only**, the key's type matching the algorithm: a proof claiming `HS256`
  with the public key as a secret finds nothing to verify with.
- **A wrong proof spends what a wrong guess spends**: a code (as a wrong verifier does), never a
  refresh token (a wrong proof is not a replay).
- **The refusal says nothing useful**: one `invalid_dpop_proof`, the reason in the log.

## 8. Tests

- **Unit**: `JwkThumbprint` against RFC 7638 §3.1's example; `ProofRequirement` over every §4.3
  rule (method, URL normalisation, age, future, nonce, `ath`, key mismatch); the proof verifier's
  contract (`DpopProofVerifierContract`) with proofs signed by real ES256, EdDSA, RS256 and PS256
  keys, and refusals for `none`, `HS256`, a private `jwk`, a wrong `typ`, a wrong signature.
- **Contracts**: the replay cache and the nonces, against Redis and their doubles; the token,
  code and refresh repositories keep `dpop_jkt`.
- **Acceptance** (`DpopTest`), with a test client that makes proofs:
  - a token request with a proof gets `token_type: DPoP`, and `cnf.jkt` in the JWT and in
    introspection; one without gets a bearer token;
  - `use_dpop_nonce` first, then success with the nonce; `DPoP-Nonce` on every answer;
  - a replayed proof, an old one, one for another URL or method: `invalid_dpop_proof`;
  - a code bound with `dpop_jkt` refuses another key, and is spent;
  - a public client's refresh needs its key; a confidential client's does not;
  - userinfo and the Management API take `DPoP`, refuse a bound token as `Bearer`, and answer the
    `DPoP` challenge;
  - a client with `dpop_bound_access_tokens` is refused a bearer token;
  - PAR binds the pushed request to the proof's key.

## 9. Slices

1. **Proofs at the token endpoint.** The verifier port and adapter, `ProofRequirement`, the replay
   cache, server nonces, `ReadDpopProof`; binding access tokens for every grant (migration),
   `token_type: DPoP`, `cnf.jkt` in JWT access tokens and introspection, `DPoP-Nonce`, discovery.
   *Done when* a client sending proofs gets bound access tokens that introspect with `cnf.jkt`,
   and every §4.3 refusal is covered.
2. **Codes and refresh tokens.** `dpop_jkt` at the authorization endpoint and PAR, PAR's DPoP
   header; codes bound; public clients' refresh families bound. *Done when* a stolen code or
   public refresh token is useless with another key.
3. **This server's resources.** `AccessTokenCredentials`; userinfo and the Management API accept
   DPoP, refuse a bound token as bearer, and challenge with `DPoP`. *Done when* a bound token works
   only with its proof at both.
4. **Required per client.** `dpop_bound_access_tokens` on clients (migration, Management API,
   OpenAPI). *Done when* such a client is refused a token without a proof.
5. **Dashboard** (clavia-dashboard): the client setting. *Done when* an operator can require DPoP
   of an application.

## 10. Open questions

1. **Server nonces at the token endpoint always** (§2)? *Recommendation:* yes. It costs one round
   trip per nonce window, every DPoP library handles it, and it is the only defence against
   proofs made in advance by an attacker who briefly ran code in the client.
2. **Nonces at this server's own resources** (§9)? *Recommendation:* not now. The proof's age and
   the `jti` cache bound replay there; a nonce would add a round trip to every Management API
   client, the dashboard included. It can be added per resource later without changing tokens.
3. **The algorithm list** (§2)? *Recommendation:* `ES256`, `EdDSA`, `RS256`, `PS256`. ES256 is what
   browsers make by default; the others cover platform keystores and older libraries.

## 11. As built

What the slices settled differently from the sections above, so the code and this document agree.

- **No PS256** (§2, question 3). `web-token/jwt-library` implements RSA-PSS in pure PHP, at about a
  second of CPU per verification, and a proof's signature is checked before anything else: anyone
  could make the token endpoint burn a second per request with forged PS256 proofs. ES256, EdDSA
  and RS256 go through OpenSSL or libsodium and cost a millisecond. RS256 covers RSA keys.
- **`DPoP-Nonce` on every answer to a request that carried a proof** (§5.2 step 7), and with
  `use_dpop_nonce`: a client without DPoP has no use for it.

