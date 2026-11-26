# Design: An OpenAPI document for the authorization server's endpoints

**Status:** agreed · **Date:** 2026-11-26 · **Issue:** clavia-auth/clavia#93 (part of #94) ·
**Specifications:** RFC 6749 (§3.1, §3.2, §4, §5), RFC 7009 (revocation), RFC 7591 and 7592 (client
registration and management), RFC 7662 (introspection), RFC 8414 and OpenID Connect Discovery 1.0
(metadata), RFC 8628 (device authorization), RFC 9126 (PAR), RFC 9449 (DPoP), OpenID Connect Core 1.0
(§3.1.2, §5.3), RP-Initiated Logout 1.0, OpenAPI 3.0.3

## 1. Summary

The Management API is a contract (`docs/openapi/management-api.yaml`) that every request and every
acceptance-test response is checked against, and it is published as a reference site. The
authorization server's own endpoints (`/oauth2/*`, `/oidc/*`, `/.well-known/*`) have no document:
a developer integrating an application reads RFCs plus `CLAUDE.md`, and the reference site stops at
the API that administers Clavia, not the one that signs people in.

This design adds a **second document, `docs/openapi/authorization-server.yaml`**, kept true the way
the first is, and published beside it.

### Goals

- Every endpoint an application or API calls on `auth.{domain}` is described: its parameters, its
  bodies, every response it can give, and the refusals, with examples, in the same hand as the
  Management API's reference.
- The document cannot drift: the acceptance suite already exercises these endpoints, and from now on
  checks what they answered against the document, and a unit test checks that the document and the
  routes name the same operations.
- The published site shows both documents.

### Not in scope

- **What the RFCs already say.** The document states what Clavia accepts and answers and links the
  RFC section; it does not restate PKCE verification, DPoP proof rules or the grant flows (§2, "What
  is left to the RFCs").
- **`/auth/*`**: sign-in, second factor, consent, device approval. These are pages for a person's
  browser, authenticated by a session cookie, not an API: nothing calls them.
- **`/scim/v2/*`**: SCIM is its own specification (RFC 7644) and the directory vendors document the
  client side; it may become a third document later.
- **Enforcing the document at runtime.** Unlike the Management API's middleware, these handlers keep
  answering in RFC 6749's own shapes. The document describes them; it does not gate them (§2).
- Client libraries and code generation from the document.

## 2. Decisions

| Topic | Decision | Why (alternatives rejected) |
|---|---|---|
| Whether | Yes: a document for the endpoints that are an API (token, PAR, introspection, revocation, device code, registration, userinfo, JWKS, discovery, authorize, end session) | The issue asks "whether". Three of them (token, introspection, device code) are what most integrators call first, and nothing but prose describes their refusals or their headers. Leaving it to the RFCs alone loses what is Clavia's: which client authentication methods, which grants, which errors, which limits |
| One document or two | A second file, `authorization-server.yaml`, with its own `info`, tags and `components` | The two APIs differ in host, authentication (client credentials vs bearer with scopes), body encoding and error format. One document would need two `servers`, two sets of security schemes and a tag list mixing both; Scalar renders several sources natively |
| Request bodies | Teach the validator `application/x-www-form-urlencoded`: the body is decoded into a map of strings and checked against an `object` schema whose properties are `type: string` | Today the validator refuses any non-JSON media type unless the schema is opaque `{type: string, format: binary}`. Describing the token request as opaque bytes would make the reference useless (no fields) and test nothing. A form is as simple as a query string, which the validator already decodes (`QueryString`, `ParameterDecoder`); the same code is reused. Rejected: a JSON schema pretending the body is JSON (a lie in the reference and in the example `curl`) |
| Repeated form parameters | The decoder reports a parameter sent twice, as the query-string decoder does | RFC 6749 §3.1 forbids repeats and the handlers refuse them; the document and the handlers agree |
| One token request or one per grant | One operation, `POST /oauth2/token`, with a request schema that is a `oneOf` over four named schemas, one per `grant_type` (authorization code, refresh token, client credentials, device code), sharing the client authentication fields | A reader looks up "client credentials", not "token". Scalar renders `oneOf` with the discriminating `grant_type` constant. Rejected: one flat schema with every field optional (does not say which are required for which grant); one operation per grant (the path is the same, OpenAPI cannot express it) |
| Client authentication | `components/securitySchemes`: `clientSecretBasic` (HTTP basic), plus prose for `client_secret_post` and `none` (a body field, which OpenAPI security schemes cannot express). Each operation's `security` lists the schemes it accepts. `security` here is **descriptive**: nothing in the pipeline reads it | The Management API's `security` names the scope and the middleware enforces it ("there is no second list"). Here the rule lives in the use cases (`AUTH_METHODS` constants, `token_endpoint_auth_method` per client). A test pins the two together (§8) so the description cannot diverge |
| Refusals | One shared `OAuthError` schema (`error`, `error_description`, `error_uri`?) with the enum of codes each endpoint can give, as component responses (`invalid_client` 401 with `WWW-Authenticate`, `invalid_grant`, `invalid_request`, `temporarily_unavailable` 429 with `Retry-After`) | RFC 6749 §5.2 is the format; the document says which codes appear where, which the RFC leaves loose. Not RFC 9457: clients parse §5.2 |
| Headers | `Cache-Control: no-store` and `Pragma: no-cache` on token, PAR, device and introspection responses, `WWW-Authenticate`, `Retry-After`, `DPoP-Nonce` where applicable are declared on the responses; the response validator already checks declared headers | These are part of the contract (RFC 6749 §5.1) and the sort of thing that regresses silently |
| Redirects and pages | `/oauth2/authorize` and `/oidc/logout` are described with their query or form parameters and their responses as: `302` (a `Location` whose query is described in the text: `code`, `state`, `iss`, or the error), `200` and `4xx` as `text/html` with an opaque body. The redirect's `Location` is checked for presence, not parsed | A redirect target is the client's, and the HTML is the sign-in UI: neither is API. The parameters, the refusals that are redirected and the ones that are shown (RFC 6749 §4.1.2.1) are exactly what an integrator needs |
| Registration | `/oauth2/register` and `/oauth2/register/{client_id}` are described as they are: JSON in and out (RFC 7591/7592), with `registration_access_token` as a bearer scheme | These need no validator change |
| Hosts | `servers: https://auth.{domain}` with the `domain` variable, as the site gives for the Management API | The two hosts' separation is a security property (`CLAUDE.md`, Hosts); the reference shows it |
| Versioning | `info.version` is the document's own (`1`); the release is on the site. The paths are the protocol's and carry no version | As for the Management API |
| Keeping it true | Three tests (§8): responses of the existing acceptance suite checked against the document; the document and the routes name the same operations; discovery metadata and the document agree on grants, methods and algorithms | Same principle as `ManagementFixtures::api()`: the suite that already proves behaviour proves the document, at no new cost per test |

### What is left to the RFCs

The reference says "as RFC X §Y" with a link, and nothing more, for: the authorization code flow's
steps and PKCE verification, the DPoP proof's checks and nonce rules, device-flow polling intervals
(only the `slow_down` response is shown), the claims of an ID token or a JWT access token (RFC 9068;
the configured claims are discovery's `claims_supported` and the custom claims design), the contents
of the logout token sent to back-channel endpoints, and the wording of `error_description` (free text,
never contractual).

## 3. Settings

None. The document is served by nothing: it is a file in the repository, published with the site.

## 4. Model

No domain change. Three additions to the code that already reads OpenAPI:

- **`FormBody` in `Adapter\Primary\Http\OpenApi`** (`Validation/`): decodes `application/x-www-form-urlencoded`
  with the code `QueryString` uses, refuses a repeated parameter, and hands `SchemaValidator` an
  `object` of strings. `DocumentReader::content()` accepts the media type when its schema is an
  `object` whose properties are strings (or `oneOf`s of such objects), and keeps refusing any other
  non-JSON media type, so the validator stays strict about what it does not understand.
- **`RequestValidator` / `ResponseValidator`** read `FormBody` for requests; responses are unchanged
  (all JSON or opaque), and the HTML ones are opaque bytes.
- **A test-side `AuthorizationServerContract`** (`test/Support`), the sibling of the loader the
  Management fixtures use, loading the second document once.

## 5. Flows

Documenting is not a flow, but the *use* of the document in tests has one, per request that reaches
`auth.{domain}`:

1. The acceptance harness sends the request as today.
2. If the path matches an operation of the document (the router matches `/oauth2/register/{client_id}`
   as a template), the response is validated against that operation's responses by status and
   media type: `OperationNotFound` is not an error for an unrouted path (a 404 test), and a status
   the document does not list **fails the test**, with the violations listed.
3. A request that a test sends *well-formed on purpose* through `OAuth2Fixtures` (a helper
   `form()`) is also validated against the operation's request body, so an example in the document
   is a request that works. A request a test sends *malformed on purpose* skips this step: it is
   there to prove the refusal, and the refusal's response is still checked in step 2.

Refusals the document must list, per endpoint: the codes of RFC 6749 §5.2 for the token endpoint; `invalid_client` and
`429` for the four client-authenticating endpoints (`CLAUDE.md`, Client authentication); `use_dpop_nonce`
where a nonce is required; for authorize, the two ways of refusing (shown to the person, or redirected);
for userinfo, the RFC 6750 challenges.

## 6. Interfaces

- **`docs/openapi/authorization-server.yaml`**: operations, tags with `x-displayName` (Authorize, Token,
  Introspection and revocation, Devices, Registration, Discovery and keys, UserInfo, Sessions), shared
  components and examples named in `components/examples`, one cast as in the Management API (Ada, Acme
  Reports, the Reports API).
- **Examples**, all validated by an extended `ManagementExamplesTest`-style test; secrets say they are not real.
- **`docs/site/`**: `index.html` configures Scalar with two sources (`sources: [{title, url}]`), and
  `build.sh` takes a second document and copies it beside the first, as it takes the guides since #98.
  The Docs workflow takes the document from the tag, as it takes the Management API's and the guides: a
  release from before it is built with one source, as a release from before the guides is built without
  them. Each release folder holds what its tag had; the release picker is unchanged. A server entry per
  document (`auth.{domain}`, `management.{domain}`). Scalar stays the one pinned script, with its SRI
  hash, so the page loads nothing new.
- **The guides** (`docs/guides`, #98) link the new reference where they send the reader to the RFCs
  for the token endpoint (Getting a token, DPoP-bound tokens, Registering clients), and
  `ManagementGuidesTest` learns to check an operation they name against either document.
- **Dashboard impact: none.** `contract/management-api.yaml` stays the Management API's copy. Later,
  and optionally, the dashboard's Endpoints page can link each endpoint to its entry in the reference.
- **`CLAUDE.md`** gains a paragraph beside "Management API" saying the second document exists, is
  descriptive, and how it is checked; **`docs/RELEASING.md`**'s site table mentions it.

## 7. Security rules

- **The document describes, it never gates.** Nothing at runtime reads it, so a mistake in it cannot
  change what the server accepts or refuses. It is not an enforcement point and must not become one
  without a design: RFC 6749 refusals have their own shapes and ordering (client authentication
  before the grant), and a generic validator running first would answer a malformed request before
  the server has authenticated the client, and with its own error shape instead of RFC 6749's.
- **No example holds a real secret**, a token that verifies, or a key: every value says it is not real,
  as in the Management API's document, and `ManagementExamplesTest`'s check is extended to this one.
- **No refusal repeats the value at fault** (the existing invariant): the examples show messages that
  name the parameter, never its value.
- **The reference does not widen the surface**: operations with no route are caught by the coverage
  test, so the document cannot advertise an endpoint that is not there, and a route with no operation
  fails the same test, so an endpoint cannot be added undocumented.
- **The validator stays strict**: form support accepts only what it can enforce, repeated parameters
  and unknown media types stay refused at load.

## 8. Tests

| Test | Proves |
|---|---|
| `FormBodyTest` (Unit, OpenApi) | decoding, a repeated parameter, an empty value, percent-decoding errors, a body that is not a form, and that the reader refuses a form schema it cannot enforce |
| `OpenApiDocumentationTest` (Unit/Documentation; was `ManagementDocumentationTest`, now run over both documents) | the document loads; each `summary` is a short label and each tag has `x-displayName` |
| `OpenApiExamplesTest` (likewise, was `ManagementExamplesTest`) | every example validates against its schema, a form's as the object of strings it is |
| `AuthorizationServerCoverageTest` | the routes under `/oauth2`, `/oidc` and `/.well-known` and the document's operations are the same set (method and path); `/auth/*` and the Management API's paths are excluded by name |
| Harness hook (`AcceptanceTestCase`) | every existing acceptance response from a documented operation conforms: the suite is the proof, and the first run lists the mismatches to fix (in the document, or in a handler if the handler is wrong) |
| `DiscoveryAgreesWithDocumentTest` | `grant_types_supported`, `token_endpoint_auth_methods_supported`, `code_challenge_methods_supported` and `dpop_signing_alg_values_supported` of discovery equal the enums of the document |
| `ApiReferencePageTest` (extended) | the site page loads both documents |

## 9. Slices

1. **The validator learns forms.** `FormBody`, the reader accepting a form schema, tests.
   *Done when* a document with a form-encoded request body loads, a conforming request passes, a
   repeated parameter and an unsupported schema are refused, and the Management API's document
   validates as before.
2. **Token, PAR, introspection, revocation, device code.** The document with these operations, the
   shared refusals and headers, examples, the examples test, the documentation test, and the harness
   hook limited to them. *Done when* the existing acceptance suite passes with the hook on, any
   mismatch fixed on the right side, and the coverage test lists the other routes as pending.
3. **Registration, userinfo, JWKS, discovery, authorize, end session.** The rest, the coverage test
   without exceptions, the discovery agreement test. *Done when* every route is an operation and the
   suite is green with the hook on for every documented path.
4. **The site.** Scalar with two sources, `build.sh` and the Docs workflow taking the document from the
   tag (a release without it keeps one source), the page test (two sources, the SRI hash unchanged), the
   guides' links to the new reference and their test; `CLAUDE.md` and `RELEASING.md` updated. *Done
   when* a preview shows both references, the guides link the authorization server's operations, and
   the Docs workflow builds a release folder with both documents, and one without for an older tag.

## 10. Open questions

1. **Do `authorize` and `end session` belong?** They are browser redirects, not calls, and their value
   is the parameter and refusal tables. *Recommendation: yes*, as in §2: integrators look for them in
   the reference first, and the coverage test is simpler with no exceptions.
2. **Is a validator change acceptable for this?** The alternative is documenting forms as opaque bytes,
   which keeps the validator untouched but leaves the token endpoint's request without fields.
   *Recommendation: extend the validator*; the change is small (a form is a query string in the body)
   and it keeps "refused at load what it cannot enforce".
3. **Which milestone?** The parent #94 has no milestone and the issue has none: the slices are
   independent of the product's features. *Recommendation:* 0.5. The Management API's slices (#95 to
   #98) have all merged, so the site is settled and this adds to it; #94 then closes with 0.5's
   release, which publishes both.
4. **Should SCIM get its own document, in the same series?** *Recommendation: not now*; open an issue
   when a directory vendor asks for it, since its client side is documented by RFC 7644 and the
   vendors.
