# Design: SAML 2.0 enterprise connections

**Status:** proposed · **Date:** 2026-11-24 · **Issue:** clavia-auth/clavia#20 ·
**Specifications:** SAML 2.0 Core (§2.3.3 assertions, §2.5 conditions, §3.2.2 responses, §3.4
`AuthnRequest`), Bindings (§3.4 HTTP-Redirect with DEFLATE, §3.5 HTTP-POST), Profiles (§4.1 Web
Browser SSO: §4.1.4.2 and §4.1.4.3 the response's usage and processing rules, §4.1.4.5 POST-specific
processing), Metadata (§2.4
`SPSSODescriptor` and `IDPSSODescriptor`), XML Signature 1.1 and its Best Practices (W3C Note,
2013), RFC 6931 (algorithm identifiers), the OASIS SAML V2.0 Security and Privacy Considerations

## 1. Summary

Companies sign their staff in with Entra ID, Okta, Google Workspace, ADFS or Keycloak, and many of
those deployments speak SAML, not OpenID Connect. Today Clavia accepts Google, GitHub and any
OpenID Connect provider; an application whose customers use a SAML identity provider cannot sign
them in.

This design adds **SAML connections**: an operator registers an identity provider from its
metadata, and people sign in there, through the same path as every other external sign-in:
`ResolveExternalAccount`, then `CompleteFirstFactor`, so a second factor, sessions, consent and
roles all work as they do.

### Goals

- Service-provider-initiated Web Browser SSO: an `AuthnRequest` by HTTP-Redirect, a `Response` by
  HTTP-POST.
- An identity provider registered from its metadata (a document or a URL), refreshed on demand.
- A service-provider metadata document per connection, for the identity provider's administrator.
- Signatures validated by a maintained library, with every check of the Web Browser SSO profile
  applied, and replays refused.

### Not in scope

- **Identity-provider-initiated SSO** (an unsolicited response): refused (§2).
- **Encrypted assertions**, **signed `AuthnRequest`s**, **Single Logout**, **artifact binding**,
  **ECP**: each needs a service-provider key or a back channel. §10 says when they would come.
- **Choosing the connection by email domain** (home realm discovery): the login page shows a
  button per connection, as for OpenID Connect providers. A domain-routing design can come later
  for every external kind at once.
- **Trusting the identity provider's authentication context** (`AuthnContextClassRef`) as a second
  factor: an external sign-in is one factor (`amr` `ext`), as it is for OpenID Connect.
- **Federations and multi-entity metadata** (eduGAIN): one connection, one identity provider.

## 2. Decisions

| Topic | Decision | Why (alternatives rejected) |
|---|---|---|
| Library | **`simplesamlphp/saml2`** (v6.3 today; v7 as soon as it is stable, which requires PHP 8.5 as Clavia does) with `simplesamlphp/xml-security`, behind one port | XML signature handling is where SAML implementations break (signature wrapping, comments in text nodes, canonicalisation). This library is the core of SimpleSAMLphp, run by national research federations at scale, with a typed object model and schema validation. `onelogin/php-saml` is simpler but leans on `xmlseclibs` and an array-shaped API; writing our own on `DOMDocument` would repeat every mistake the advisories list. Behind a port, a change of library touches one adapter (§10, question 1) |
| Who starts | **Only Clavia** (SP-initiated). A response must answer an `AuthnRequest` this server sent (`InResponseTo`), for this browser, once | An unsolicited response carries no proof the browser asked for it: it is a login CSRF by design, and it can be replayed by whoever saw it. The SAML profile allows it; the OASIS security considerations warn against it |
| The browser binding | The response arrives by a **cross-site POST, which carries no `SameSite=Lax` cookie**. The assertion consumer service (ACS) therefore keeps the POSTed response under a fresh one-time handle (60 s, Redis) and answers `303` to `GET /auth/saml/{connection}/complete?h=…`, where the cookies come back and all the checks run | The external sign-in pairs `state` with the `clavia_external_state` cookie, and the session cookie is `Lax`: neither rides the IdP's POST. Making them `SameSite=None` would weaken every other page. The 303 to a GET restores both without a script, which the sign-in origin's CSP forbids anyway |
| `RelayState` | The opaque handle of the pending sign-in (as `state` is for OpenID Connect), compared with the browser's cookie in constant time, claimed with `GETDEL` | The same pairing as every external sign-in. It never carries a URL: the post-sign-in target stays server-side |
| What is signed | The **assertion** must be signed by a certificate of the connection; a signed response containing an unsigned assertion is refused | The assertion is what we act on. Accepting a signature on the envelope alone opens the door to a second, unsigned assertion beside the signed one, which is how wrapping attacks start. Entra ID, Okta, ADFS and Keycloak all sign assertions |
| Which keys | The **certificates named by the connection** (up to three, for rollover), compared by key, never a key carried in the message, never a chain to a CA; their validity dates are ignored | SAML metadata pins keys, and a certificate in the signature (`KeyInfo`) proves nothing. Identity providers ship self-signed certificates whose dates mean nothing; expiry would break sign-in at a date the IdP's administrator never meant |
| Algorithms | RSA-SHA256/384/512 and ECDSA-SHA256/384/512, exclusive canonicalisation; **SHA-1 refused** (signature and digest) | RFC 6931 and the XML Signature Best Practices deprecate SHA-1. ADFS and Entra default to SHA-256; an IdP still on SHA-1 is told to change |
| The checks | Every check of SAML Profiles §4.1.4.2, §4.1.4.3 and §4.1.4.5 (`Destination`, `Issuer`, `InResponseTo`, `Status` success, `Audience`, the bearer `SubjectConfirmation`'s `Recipient`, `NotOnOrAfter` and `InResponseTo`, `NotBefore` and `NotOnOrAfter` of the conditions, `AuthnStatement` present), with **60 s of clock skew**; exactly **one assertion** | The profile lists them; a missed one is a known attack (a response for another service provider, an old response). Several assertions in one response is legal and never needed: refusing it removes the wrapping attacks that pick a different one |
| Replay | The assertion's `ID` is claimed once per connection in Redis until its `NotOnOrAfter` (plus the skew), beside the one-time `InResponseTo` | Profiles §4.1.4.5 asks for it. `InResponseTo` alone already makes a captured response useless to another browser; the assertion cache covers the same browser posting twice |
| Who the person is | `(connection, subject)`: the subject is the **persistent `NameID`** by default, or an attribute the operator names (Entra's `objectidentifier`, ADFS's `objectGUID`). Never the address | As for every external identity. A transient `NameID` changes at every sign-in and is refused when it is the subject; an email `NameID` is an address, which can change hands |
| The address | From the `NameID` (email format) or a named attribute; **verified only when the operator says the IdP verifies it** (`email_verified: trusted`, off by default) | SAML has no `email_verified`. Linking to an existing account by address (`CLAVIA_SOCIAL_AUTO_LINK`) needs a verified address; an enterprise IdP usually owns its domain, but that is the operator's statement to make, not ours |
| Profile | Attribute names mapped per connection (`name`, `given_name`, `family_name`), with the common defaults for Entra, Okta and ADFS offered by the dashboard | Every IdP names attributes differently (`http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname`, `firstName`…); a mapping is data, not code |
| Metadata in | The operator gives the IdP's **metadata document** or its **URL**; Clavia reads the entity ID, the HTTP-Redirect SSO URL and the signing certificates, and stores them. `POST …/refresh-metadata` reads the URL again | As OpenID Connect discovery is read at registration. A refresh on every sign-in would put the IdP's metadata host in the sign-in's path; an operator rotating a certificate refreshes, or the IdP publishes the next one ahead (up to three kept) |
| Metadata out | `GET /auth/saml/{connection}/metadata`: an `EntityDescriptor` with the entity ID, the ACS (HTTP-POST), `AuthnRequestsSigned="false"`, `WantAssertionsSigned="true"`, the `NameIDFormat` wanted | What every IdP's administrator asks for first. Public, unsigned (nothing secret in it), cached for an hour |
| Entity ID | `https://auth.{domain}/auth/saml/{connection}`, one per connection | One per connection, because two connections can be two tenants of the same IdP, which refuses two applications with one entity ID |
| XML safety | Parsed with external entities and network access off (`LIBXML_NONET`, no `DOCTYPE` accepted), at most **256 KiB** of response and **1 MiB** of metadata | XXE and entity expansion are the classic XML attacks; a SAML message never needs a `DOCTYPE` |

## 3. Settings

None new. `CLAVIA_SOCIAL_AUTO_LINK` applies to SAML connections as to every external one (only with
a trusted address). `CLAVIA_OUTBOUND_ALLOW_PRIVATE_ADDRESSES` applies to metadata URLs. Clock skew,
sizes and lifetimes are constants.

## 4. Model

### Domain

- `ConnectionStrategy::Saml`, external (`isExternal()`).
- `SamlSettings` (value object): IdP entity ID, SSO URL (https), 1 to 3 signing certificates (PEM,
  the public key read once to refuse anything that is not RSA ≥ 2048 or EC P-256/384/521), metadata
  URL or none, subject source (`name_id` or an attribute name), `NameIDFormat` requested, address
  source and whether it is trusted, profile attribute names.
- `SamlRequestId` (value object): `_` and 32 random bytes in hex, as the schema's `ID` type needs.
- `PendingExternalSignIn` gains the SAML request id beside (instead of) the code verifier and nonce.
- `AssertedIdentity` is unchanged: what the adapter hands back is the same as an OpenID Connect
  provider's.

### Application

- `BeginSamlSignIn`: the pending sign-in (handle, request id, target, client, login state), the
  redirect URL from the port.
- `ReceiveSamlResponse` (the ACS): size and form checks only; keeps the response under a one-time
  handle; returns the handle.
- `CompleteSamlSignIn` (the GET): cookie and `RelayState`, the pending sign-in claimed, the response
  claimed, `SamlServiceProvider::consume()` with what is expected, the assertion id claimed in the
  replay cache, then `ResolveExternalAccount` and `CompleteFirstFactor` as for OpenID Connect. Every
  refusal is an `ExternalSignInFailure` (one page, the reason logged), and `SignInRefused` is
  dispatched as today.
- `RegisterSamlConnection`, `RefreshSamlMetadata` (Management API), `DescribeSamlServiceProvider`
  (the metadata out).
- Ports: `SamlServiceProvider` (`authnRequestUrl()`, `consume()`, `readMetadata()`,
  `serviceProviderMetadata()`), `SamlResponseStore` (the ACS handle), `SamlAssertionReplayCache`.
  `SamlServiceProvider` has one adapter (`Adapter\Secondary\IdentityProvider\Saml\SimpleSamlServiceProvider`);
  its contract is run against responses a test identity provider signs (§8).

### Migrations

`connections` gains the SAML columns beside the OpenID Connect ones (`saml_entity_id`,
`saml_sso_url`, `saml_certificates jsonb`, `saml_metadata_url`, `saml_options jsonb`), and the
strategy check takes `saml`.

## 5. Flows

### 5.1 Registering

`POST /api/v1/connections` with `strategy: saml` and either `saml.metadata_url` (fetched through
`OutboundUrlPolicy`) or `saml.metadata` (the XML), plus the mapping options. The metadata is parsed
safely (§2), and must hold exactly one `IDPSSODescriptor` supporting SAML 2.0, an HTTP-Redirect SSO
service on https, and at least one signing key. Each failure is a `422` naming the field. The answer
includes the service provider's entity ID, ACS URL and metadata URL, which the operator gives the IdP.
`POST /api/v1/connections/{name}/refresh-metadata` reads the URL again and replaces the endpoint and
the certificates, which the trail records as a change of fields.

### 5.2 Signing in

1. The login page shows the connection's button, where the application enables it (as today).
2. `GET /auth/saml/{connection}`: `BeginSamlSignIn` opens the pending sign-in (handle, request id,
   ten minutes), sets `clavia_external_state` to the handle, and redirects to the IdP's SSO URL with
   `SAMLRequest` (deflated `AuthnRequest`: `ID`, `IssueInstant`, `Destination`, the ACS URL, the
   entity ID, `NameIDPolicy`) and `RelayState` = the handle.
3. The person signs in at the IdP, which POSTs `SAMLResponse` and `RelayState` to
   `POST /auth/saml/{connection}/acs`. No CSRF token: this POST comes from the IdP's page, and it
   changes nothing but a short-lived handle.
4. The ACS checks the sizes and the base64, keeps `{response, RelayState}` under a new one-time
   handle (60 s), and answers `303` to `GET /auth/saml/{connection}/complete?h=…`.
5. `CompleteSamlSignIn`, now with the browser's cookies:
   1. the stored response claimed (`GETDEL`), or "expired";
   2. its `RelayState` equal to the `clavia_external_state` cookie (constant time), or "started in
      another browser";
   3. the pending sign-in claimed, for this connection, or "expired";
   4. the application still allows the connection, or "not available";
   5. `consume()`: XML parsed safely; one assertion; the signature (§2's keys and algorithms); then
      every check of §2 against the pending request id, the ACS URL, the entity IDs and now; any
      failure is "the provider failed", with the category logged (`signature`, `audience`,
      `expired`, `in_response_to`, `status`, `subject`, `xml`);
   6. the assertion id claimed in the replay cache, or "expired";
   7. `ResolveExternalAccount` with `(connection, subject)`, the address and whether it is trusted,
      the profile; then `CompleteFirstFactor` (`amr` `ext`).
6. A failure shows the external sign-in's error page; the IdP's `StatusMessage` is never shown.

### 5.3 Metadata out

`GET /auth/saml/{connection}/metadata` for an enabled SAML connection: the `EntityDescriptor` of §2,
`application/samlmetadata+xml`, `Cache-Control: public, max-age=3600`. Unknown or disabled: `404`.

## 6. Interfaces

- **Routes** on `auth.{domain}`: `GET /auth/saml/{connection}`, `POST /auth/saml/{connection}/acs`,
  `GET /auth/saml/{connection}/complete`, `GET /auth/saml/{connection}/metadata`. The ACS is the one
  `/auth/*` POST without a CSRF token, named as such in CLAUDE.md.
- **Management API**: `strategy: saml` on connections with a `saml` object (the settings of §4, the
  certificates' fingerprints and expiry shown read-only); `POST /connections/{name}/refresh-metadata`
  (`update:connections`); the service provider's entity ID, ACS and metadata URLs in the answer.
- **Login page**: the connection's button, its display name.
- **Dashboard** (clavia-dashboard): a SAML form (metadata URL or upload, the mappings with presets
  for Entra ID, Okta, ADFS and Google Workspace), the values to give the IdP with copy buttons, the
  certificates with their fingerprints, and a refresh button.

## 7. Security rules

- **No unsolicited response**: `InResponseTo` must name a request this server sent, for this
  browser, once.
- **No signature wrapping**: exactly one assertion; the assertion itself signed; the library hands
  back only the element its signature covers; the checks read that element and nothing else.
- **No foreign key**: only the connection's certificates verify, compared by key; `KeyInfo` in the
  message is ignored.
- **No weak algorithm**: SHA-1 refused for signatures and digests.
- **No XXE**: no `DOCTYPE`, no network, sizes bounded, for responses and for metadata.
- **No replay**: the pending sign-in and the ACS handle are single-use; the assertion id is claimed
  until it expires.
- **No response for someone else**: `Destination`, `Recipient` and `Audience` must be this
  connection's own, and `Issuer` the IdP's entity ID.
- **No SSRF**: a metadata URL goes through `OutboundUrlPolicy`, at registration and at refresh.
- **No echo**: nothing the IdP sends (status messages, attribute values) reaches a page or the log;
  the log keeps a category.
- **No address-based identity**: the subject is the persistent `NameID` or a stable attribute; a
  transient one is refused; an address links only when the operator trusts the IdP for it.
- **No open redirect**: `RelayState` is an opaque handle; the target stays server-side.

## 8. Tests

- **A test identity provider** in `test/Support` that builds and signs responses with real keys
  (RSA and EC), so the adapter's contract checks genuine XML signatures, as the passkey verifier's
  does with genuine CBOR. A double for the use cases answers what it is told.
- The adapter's contract: a valid response accepted; then each refusal, one test each: unsigned
  assertion, signed response with an unsigned assertion, a wrapped second assertion, a signature by
  another key, `KeyInfo` with an attacker's certificate, SHA-1, a comment inside the `NameID`, a
  `DOCTYPE`, a wrong `Destination`, `Recipient`, `Audience`, `Issuer` or `InResponseTo`, expired and
  not-yet-valid conditions (with the skew at its edge), a failed `Status`, two assertions, a
  transient `NameID` as the subject, oversized input.
- Metadata: Entra ID, Okta, ADFS and Keycloak documents (public samples) read; one with a
  `DOCTYPE`, one without a signing key, one with only HTTP-POST SSO, refused.
- Acceptance, through the real routes: a sign-in end to end (begin, the IdP's POST, the 303, the
  session), with a second factor; the ACS POST without cookies; another browser's `RelayState`; a
  replayed response; a disabled connection; the service provider metadata; registration from a
  document and from a URL (with a private address refused).

## 9. Slices

1. **The port and its adapter.** `simplesamlphp/saml2` added (deptrac's Vendor layer), the
   `SamlServiceProvider` port, `SimpleSamlServiceProvider`, the test identity provider, the contract
   with every refusal of §8. *Done when* the contract passes against genuine signed responses,
   attacks included, with nothing wired to a route yet.
2. **SAML connections.** `ConnectionStrategy::Saml`, `SamlSettings`, the migration, the Management
   API (registration from metadata, refresh), the service provider metadata route. *Done when* an
   operator can register an IdP from its metadata or URL and hand it this server's metadata.
3. **Signing in.** The pending sign-in, the four routes, the ACS handle and the 303, the replay
   cache, `ResolveExternalAccount` with the trusted-address rule, the login page button, the
   refusals and their trail. *Done when* a person signs in through a SAML IdP end to end, with a
   second factor where they have one, and every refusal of §5.2 is covered.
4. **Dashboard** (clavia-dashboard): the SAML connection form, presets, the values for the IdP, the
   certificates and refresh. *Done when* an operator can set up a SAML connection without the API.

## 10. Open questions

1. **The library** (§2)? *Recommendation:* `simplesamlphp/saml2`, on v6.3 now and v7 when it is
   stable. It is a new dependency with its own XML security library; the first slice proves it with
   the attack fixtures before anything depends on it, and `onelogin/php-saml` remains the fallback
   behind the same port.
2. **Encrypted assertions**? Some IdPs encrypt by default. *Recommendation:* not in this design.
   Decrypting needs a service-provider private key; it should be a key of the signing backend
   (KMS) rather than one more extractable key, which needs its own design. Until then, the
   dashboard tells the operator to turn encryption off at the IdP, and an encrypted assertion is
   refused with that reason logged.
3. **Signed `AuthnRequest`s**? *Recommendation:* not now. They prove the request comes from this
   service provider, which the IdP rarely requires; they need the same service-provider key as
   question 2, and would come with it.
4. **Refreshing metadata automatically** (a daily command)? *Recommendation:* on demand first; a
   `connections:refresh-saml-metadata` command can follow when an operator has missed a
   certificate rotation once.
