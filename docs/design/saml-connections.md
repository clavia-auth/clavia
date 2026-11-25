# Design: SAML 2.0 enterprise connections

**Status:** agreed · **Date:** 2026-11-24 · **Issue:** clavia-auth/clavia#20 ·
**Specifications:** SAML 2.0 Core (§2.3.3 assertions, §2.3.4 encrypted assertions, §2.5
conditions, §3.2.2 responses, §3.4 `AuthnRequest`), Bindings (§3.4 HTTP-Redirect with DEFLATE and
§3.4.4.1 its signature, §3.5 HTTP-POST), Profiles (§4.1 Web Browser SSO: §4.1.4.2 and §4.1.4.3 the
response's usage and processing rules, §4.1.4.5 POST-specific processing), Metadata (§2.4
`SPSSODescriptor`, `IDPSSODescriptor` and `KeyDescriptor`), XML Signature 1.1, XML Encryption 1.1
(§5.4 key transport, §5.2 block encryption), the XML Signature Best Practices (W3C Note, 2013),
RFC 6931 (algorithm identifiers), RFC 5280 (§4.1 the certificate), the OASIS SAML V2.0 Security and
Privacy Considerations

**Revised** before agreement: the service provider's own keys are part of this design (§2 "Keys of
our own", §4, §9), so encrypted assertions and signed requests ship with it rather than after it.

## 1. Summary

Companies sign their staff in with Entra ID, Okta, Google Workspace, ADFS or Keycloak, and many of
those deployments speak SAML, not OpenID Connect. Today Clavia accepts Google, GitHub and any
OpenID Connect provider; an application whose customers use a SAML identity provider cannot sign
them in.

This design adds **SAML connections**: an operator registers an identity provider from its
metadata, and people sign in there, through the same path as every other external sign-in:
`ResolveExternalAccount`, then `CompleteFirstFactor`, so a second factor, sessions, consent and
roles all work as they do. And it gives Clavia, as a **service provider, keys of its own**: one to
sign its requests, one to decrypt the assertions sent to it, kept like the token signing keys, in
PostgreSQL sealed or in a KMS that never lets them out.

### Goals

- Service-provider-initiated Web Browser SSO: an `AuthnRequest` by HTTP-Redirect, signed; a
  `Response` by HTTP-POST, its assertion signed and, where the IdP does it, encrypted.
- An identity provider registered from its metadata (a document or a URL), refreshed on demand.
- A service-provider metadata document per connection, with this server's certificates.
- Service-provider keys behind a port with the backends of the token signing keys (`postgres`,
  `aws-kms`, `gcp-kms`, `azure-key-vault`), generated, rotated and listed from the shell.
- Signatures validated and assertions decrypted by a maintained library, with every check of the
  Web Browser SSO profile applied, and replays refused.

### Not in scope

- **Identity-provider-initiated SSO** (an unsolicited response): refused (§2).
- **Single Logout**, **artifact binding**, **ECP**: other profiles, each a design of its own.
- **Choosing the connection by email domain** (home realm discovery): the login page shows a
  button per connection, as for OpenID Connect providers.
- **Trusting the identity provider's authentication context** (`AuthnContextClassRef`) as a second
  factor: an external sign-in is one factor (`amr` `ext`), as it is for OpenID Connect.
- **Federations and multi-entity metadata** (eduGAIN): one connection, one identity provider.
- **Certificates from a CA** for the service provider: self-signed, which is what SAML metadata
  expects (keys are pinned, not chained).

## 2. Decisions

| Topic | Decision | Why (alternatives rejected) |
|---|---|---|
| Library | **`simplesamlphp/saml2`** (v6.3 today; v7 as soon as it is stable, which requires PHP 8.5 as Clavia does) with `simplesamlphp/xml-security`, behind one port | XML signature handling is where SAML implementations break (signature wrapping, comments in text nodes, canonicalisation). This library is the core of SimpleSAMLphp, run by national research federations at scale, with a typed object model and schema validation. `onelogin/php-saml` is simpler but leans on `xmlseclibs` and an array-shaped API; writing our own on `DOMDocument` would repeat every mistake the advisories list. Behind a port, a change of library touches one adapter (§10, question 1) |
| Who starts | **Only Clavia** (SP-initiated). A response must answer an `AuthnRequest` this server sent (`InResponseTo`), for this browser, once | An unsolicited response carries no proof the browser asked for it: it is a login CSRF by design, and it can be replayed by whoever saw it. The SAML profile allows it; the OASIS security considerations warn against it |
| The browser binding | The response arrives by a **cross-site POST, which carries no `SameSite=Lax` cookie**. The assertion consumer service (ACS) therefore keeps the POSTed response under a fresh one-time handle (60 s, Redis) and answers `303` to `GET /auth/saml/{connection}/complete?h=…`, where the cookies come back and all the checks run | The external sign-in pairs `state` with the `clavia_external_state` cookie, and the session cookie is `Lax`: neither rides the IdP's POST. Making them `SameSite=None` would weaken every other page. The 303 to a GET restores both without a script, which the sign-in origin's CSP forbids anyway |
| `RelayState` | The opaque handle of the pending sign-in (as `state` is for OpenID Connect), compared with the browser's cookie in constant time, claimed with `GETDEL` | The same pairing as every external sign-in. It never carries a URL: the post-sign-in target stays server-side |
| What is signed | The **assertion** must be signed by a certificate of the connection; a signed response containing an unsigned assertion is refused. An encrypted assertion is decrypted first, and its signature checked inside (sign, then encrypt) | The assertion is what we act on. Accepting a signature on the envelope alone opens the door to a second, unsigned assertion beside the signed one, which is how wrapping attacks start. Entra ID, Okta, ADFS and Keycloak all sign assertions |
| Which keys verify | The **certificates named by the connection** (up to three, for rollover), compared by key, never a key carried in the message, never a chain to a CA; their validity dates are ignored | SAML metadata pins keys, and a certificate in the signature (`KeyInfo`) proves nothing. Identity providers ship self-signed certificates whose dates mean nothing; expiry would break sign-in at a date the IdP's administrator never meant |
| Signature algorithms | RSA-SHA256/384/512, exclusive canonicalisation; **SHA-1 refused** (signature and digest); **no ECDSA** (§11) | RFC 6931 and the XML Signature Best Practices deprecate SHA-1. ADFS and Entra default to SHA-256; an IdP still on SHA-1 is told to change. The library cannot read an ECDSA signature, and the identity providers in scope sign with RSA |
| **Keys of our own** | **Two service-provider keys**, both RSA 3072: a **signing** key and an **encryption** key, each with a self-signed X.509 certificate published in the metadata (`KeyDescriptor use="signing"` and `use="encryption"`). One pair for the deployment, shared by every SAML connection | Two, because a KMS key has one usage (AWS KMS `SIGN_VERIFY` or `ENCRYPT_DECRYPT`, GCP's purposes, Azure's key operations), and because one key for both is what the cryptographic guidance warns against. RSA, because XML Encryption key transport is RSA-OAEP everywhere IdPs implement it. One pair for the deployment, because the IdP pins the certificate, and a pair per connection would multiply rotations without separating anything: the entity IDs already differ per connection (§10, question 2) |
| Where they live | **Behind a port, `ServiceProviderKeys`**, with the token signing backends: `postgres` (generated here, sealed with `SecretCipher`, `saml-sp:<kid>` as associated data, extractable, so a warning in production as for token keys), or a **remote key** in AWS KMS, Google Cloud KMS or Azure Key Vault named by reference. The port signs and decrypts; it never returns a private key | The same reasoning as `TokenSigner`: an interface that hands out a private key excludes every non-extractable backend, which are the ones worth having. Exactly one class reads a private key per backend: its own `sign()` and `decrypt()` |
| What the key decrypts | Only the **content-encryption key** (the `EncryptedKey`, tens of bytes, RSA-OAEP); the assertion itself is decrypted in PHP with that AES key, which exists in memory for the time of one response | A KMS decrypts small payloads; XML Encryption is hybrid by design. The content key is single-use and per message: holding it in memory exposes one assertion, never the private key |
| Encryption algorithms | Key transport **RSA-OAEP** (`rsa-oaep-mgf1p`, and XML Enc 1.1 `rsa-oaep` with SHA-256), **never RSA PKCS#1 v1.5** (`rsa-1_5`); content **AES-128/256-GCM** preferred, **AES-128/256-CBC** accepted (ADFS's default, and common elsewhere) under the rules of §7 | PKCS#1 v1.5 key transport is open to Bleichenbacher's attack. CBC is open to padding oracles (Jager and Somorovsky, 2011) when failures are told apart; refusing it would refuse ADFS's default and many older deployments. The metadata advertises GCM first, and a connection can require it (§10, question 3) |
| Signing requests | `AuthnRequest`s are **signed** (Bindings §3.4.4.1: RSA-SHA256 over `SAMLRequest`, `RelayState` and `SigAlg`, the query string as sent) whenever a signing key exists; the metadata says `AuthnRequestsSigned="true"`. Per connection it can be turned off for an IdP that chokes on it | The IdP learns the request comes from this service provider, which some (Keycloak's "client signature required", Shibboleth) demand. The signature covers the redirect's query, a digest the remote backends sign as they sign tokens |
| Certificates | Built by Clavia: a minimal **TBSCertificate** (RFC 5280 §4.1) encoded by hand, signed by the signing key through the port (`sha256WithRSAEncryption`); the encryption key's certificate is signed by the signing key too, since an encryption-only KMS key cannot sign. Subject `CN=<entity ID host> SAML SP`, ten years of validity, a random serial | A certificate is what metadata carries, and building one needs a signature from the key, which a KMS key gives only through its API. A library would want the private key; a hand-built DER is a few dozen lines, as the compact JWS is assembled by hand. IdPs pin the key and ignore the dates and the issuer |
| Rotation | `saml-keys:rotate` introduces the **next** pair (published beside the current in the metadata), then, after `CLAVIA_SAML_KEY_OVERLAP_DAYS`, **promotes** it: requests are signed with the new key, and assertions encrypted to either key still decrypt until the old one is **retired** | An IdP picks up a new certificate when it reads the metadata, which is rarely at once. Publishing first and switching later is the rollover Shibboleth documents for service providers |
| The checks | Every check of SAML Profiles §4.1.4.2, §4.1.4.3 and §4.1.4.5 (`Destination`, `Issuer`, `InResponseTo`, `Status` success, `Audience`, the bearer `SubjectConfirmation`'s `Recipient`, `NotOnOrAfter` and `InResponseTo`, `NotBefore` and `NotOnOrAfter` of the conditions, `AuthnStatement` present), with **60 s of clock skew**; exactly **one assertion**, plain or encrypted | The profile lists them; a missed one is a known attack (a response for another service provider, an old response). Several assertions in one response is legal and never needed: refusing it removes the wrapping attacks that pick a different one |
| Replay | The assertion's `ID` is claimed once per connection in Redis until its `NotOnOrAfter` (plus the skew), beside the one-time `InResponseTo` | Profiles §4.1.4.5 asks for it. `InResponseTo` alone already makes a captured response useless to another browser; the assertion cache covers the same browser posting twice |
| Who the person is | `(connection, subject)`: the subject is the **persistent `NameID`** by default, or an attribute the operator names (Entra's `objectidentifier`, ADFS's `objectGUID`). Never the address | As for every external identity. A transient `NameID` changes at every sign-in and is refused when it is the subject; an email `NameID` is an address, which can change hands |
| The address | From the `NameID` (email format) or a named attribute; **verified only when the operator says the IdP verifies it** (`email_verified: trusted`, off by default) | SAML has no `email_verified`. Linking to an existing account by address (`CLAVIA_SOCIAL_AUTO_LINK`) needs a verified address; an enterprise IdP usually owns its domain, but that is the operator's statement to make, not ours |
| Profile | Attribute names mapped per connection (`name`, `given_name`, `family_name`), with the common defaults for Entra, Okta and ADFS offered by the dashboard | Every IdP names attributes differently; a mapping is data, not code |
| Metadata in | The operator gives the IdP's **metadata document** or its **URL**; Clavia reads the entity ID, the HTTP-Redirect SSO URL and the signing certificates, and stores them. `POST …/refresh-metadata` reads the URL again | As OpenID Connect discovery is read at registration. A refresh on every sign-in would put the IdP's metadata host in the sign-in's path |
| Metadata out | `GET /auth/saml/{connection}/metadata`: an `EntityDescriptor` with the entity ID, the ACS (HTTP-POST), the signing and encryption certificates (current and next), `AuthnRequestsSigned`, `WantAssertionsSigned="true"`, the encryption methods in order of preference, the `NameIDFormat` wanted | What every IdP's administrator asks for first. Public (nothing secret in it), cached for an hour |
| Entity ID | `https://auth.{domain}/auth/saml/{connection}`, one per connection | Two connections can be two tenants of the same IdP, which refuses two applications with one entity ID |
| XML safety | Parsed with external entities and network access off (`LIBXML_NONET`, no `DOCTYPE` accepted), at most **256 KiB** of response and **1 MiB** of metadata | XXE and entity expansion are the classic XML attacks; a SAML message never needs a `DOCTYPE` |

## 3. Settings

| Setting | Default | Range | Why |
|---|---|---|---|
| `CLAVIA_SAML_KEY_BACKEND` | `postgres` | `postgres`, `aws-kms`, `gcp-kms`, `azure-key-vault` | Where the service provider's keys live; the same choice as `CLAVIA_SIGNING_BACKEND`, kept apart because the keys and their usages differ |
| `CLAVIA_SAML_SIGNING_KEY_REF` | none | a key version reference | With a remote backend: the signing key (asymmetric sign, RSA 3072 or 4096) |
| `CLAVIA_SAML_ENCRYPTION_KEY_REF` | none | a key version reference | With a remote backend: the encryption key (asymmetric decrypt, RSA-OAEP) |
| `CLAVIA_SAML_NEXT_SIGNING_KEY_REF`, `CLAVIA_SAML_NEXT_ENCRYPTION_KEY_REF` | none | references | With a remote backend: the pair published ahead of a rotation |
| `CLAVIA_SAML_RETIRED_ENCRYPTION_KEY_REFS` | none | references | Decrypt with these still, until IdPs have moved |
| `CLAVIA_SAML_KEY_OVERLAP_DAYS` | `14` | 1–90 | How long a next pair is published before it is promoted (`postgres`) |

With a remote backend, rotation is the operator's: a new key version is named as the next, then as
the current, then the old one listed as retired, as for token keys. `bin/clavia` refuses a remote
backend without both references (exit 78). `CLAVIA_SOCIAL_AUTO_LINK` and
`CLAVIA_OUTBOUND_ALLOW_PRIVATE_ADDRESSES` apply as they do elsewhere.

## 4. Model

### Domain

- `ConnectionStrategy::Saml`, external (`isExternal()`).
- `SamlSettings` (value object): IdP entity ID, SSO URL (https), 1 to 3 signing certificates (PEM,
  read once to refuse anything that is not RSA ≥ 2048), metadata URL or none,
  subject source (`name_id` or an attribute name), `NameIDFormat` requested, address source and
  whether it is trusted, profile attribute names, `sign_requests` (on), `require_encryption` and
  `require_gcm` (on: changed from off in slice 6, §11).
- `SamlRequestId` (value object): `_` and 32 random bytes in hex, as the schema's `ID` type needs.
- `ServiceProviderKey` (value object): `kid` (the RFC 7638 thumbprint of its public key), usage
  (`signing` or `encryption`), status (`next`, `current`, `retired`), the certificate (DER), created.
  `ServiceProviderKeySet`: at most one current and one next per usage, enforced by the database too.
- `PendingExternalSignIn` gains the SAML request id beside (instead of) the code verifier and nonce.
- `AssertedIdentity` is unchanged.

### Application

- Ports:
  - `ServiceProviderKeys`: `certificates(): ServiceProviderKeySet` (what metadata publishes),
    `sign(kid, string $data): string` (RSASSA-PKCS1-v1_5 over SHA-256, the digest computed here and
    handed to a remote key), `decryptKey(kid, string $encryptedKey, OaepParameters): string` (the
    content key only). Implemented by `PostgresServiceProviderKeys` and `RemoteServiceProviderKeys`
    (over the AWS, GCP and Azure clients the token signers already use, extended with `decrypt`);
  - `ServiceProviderKeyStore` (`postgres` only): generate, introduce, promote, retire, sealed;
  - `SamlServiceProvider`: `authnRequestUrl()` (signing through `ServiceProviderKeys`),
    `consume()` (decrypting through it), `readMetadata()`, `serviceProviderMetadata()`;
  - `SamlResponseStore` (the ACS handle), `SamlAssertionReplayCache`.
- `SelfSignedCertificate` (adapter-side, `Signing\X509`): the TBSCertificate's DER, signed through
  the port, checked with OpenSSL before it is stored.
- `GenerateServiceProviderKeys`, `RotateServiceProviderKeys` (`saml-keys:generate`, `saml-keys:rotate`,
  `saml-keys:list`), refusing a remote backend as `keys:rotate` does.
- `BeginSamlSignIn`, `ReceiveSamlResponse` (the ACS), `CompleteSamlSignIn` (the GET), as in §5.
- `RegisterSamlConnection`, `RefreshSamlMetadata`, `DescribeSamlServiceProvider`.

### Migrations

- `saml_service_provider_keys`: `kid`, `usage`, `status`, `certificate` (DER, base64),
  `private_key_encrypted` (sealed, `postgres` only, null for a remote reference), timestamps; one
  `current` and one `next` per usage (partial unique indexes).
- `connections`: `saml_entity_id`, `saml_sso_url`, `saml_certificates jsonb`, `saml_metadata_url`,
  `saml_options jsonb`; the strategy check takes `saml`.

## 5. Flows

### 5.1 Keys

1. `bin/clavia saml-keys:generate` (`postgres`): two RSA 3072 keys, their certificates (§2), stored
   sealed as `current`. Refused when a current pair exists, and with a remote backend.
2. `bin/clavia saml-keys:rotate`: with no next pair, introduces one (published, not used); with a
   next pair older than the overlap, promotes it (signing switches, the old encryption key retired
   but still decrypting); a retired key older than the overlap is deleted.
3. With a remote backend, the references name the keys; their certificates are built once (signed
   through the KMS) and cached in PostgreSQL by `kid`, so the metadata never calls the KMS.
4. Nothing generates a key on first use: a SAML sign-in without keys still works unsigned and
   unencrypted, and the connection's registration says so (a warning in the answer).

### 5.2 Registering a connection

`POST /api/v1/connections` with `strategy: saml` and either `saml.metadata_url` (fetched through
`OutboundUrlPolicy`) or `saml.metadata` (the XML), plus the mapping options. The metadata must hold
exactly one `IDPSSODescriptor` supporting SAML 2.0, an HTTP-Redirect SSO service on https, and at
least one signing key; each failure is a `422` naming the field. The answer includes the service
provider's entity ID, ACS URL and metadata URL. `POST /api/v1/connections/{name}/refresh-metadata`
reads the URL again.

### 5.3 Signing in

1. The login page shows the connection's button, where the application enables it.
2. `GET /auth/saml/{connection}`: `BeginSamlSignIn` opens the pending sign-in (handle, request id,
   ten minutes), sets `clavia_external_state` to the handle, and redirects to the IdP's SSO URL with
   `SAMLRequest` (deflated `AuthnRequest`), `RelayState` = the handle, and, when signing, `SigAlg`
   and `Signature` over the three as sent.
3. The IdP POSTs `SAMLResponse` and `RelayState` to `POST /auth/saml/{connection}/acs`. No CSRF
   token: this POST comes from the IdP's page, and it changes nothing but a short-lived handle.
4. The ACS checks the sizes and the base64, keeps `{response, RelayState}` under a new one-time
   handle (60 s), and answers `303` to `GET /auth/saml/{connection}/complete?h=…`.
5. `CompleteSamlSignIn`, now with the browser's cookies:
   1. the stored response claimed (`GETDEL`), or "expired";
   2. its `RelayState` equal to the `clavia_external_state` cookie (constant time), or "started in
      another browser";
   3. the pending sign-in claimed, for this connection, or "expired";
   4. the application still allows the connection, or "not available";
   5. `consume()`: XML parsed safely; one assertion, plain or encrypted; an encrypted one decrypted
      (§2's algorithms; the content key through `ServiceProviderKeys::decryptKey()` with the key its
      `KeyInfo` names, or each current and retired encryption key in turn); `require_encryption`
      and `require_gcm` honoured; the signature (§2's keys and algorithms); then every check of §2;
      any failure is "the provider failed", with the category logged (`decryption`, `signature`,
      `audience`, `expired`, `in_response_to`, `status`, `subject`, `xml`);
   6. the assertion id claimed in the replay cache, or "expired";
   7. `ResolveExternalAccount` with `(connection, subject)`, the address and whether it is trusted,
      the profile; then `CompleteFirstFactor` (`amr` `ext`).
6. A failure shows the external sign-in's error page; the IdP's `StatusMessage` is never shown.

### 5.4 Metadata out

`GET /auth/saml/{connection}/metadata` for an enabled SAML connection: the `EntityDescriptor` of §2,
`application/samlmetadata+xml`, `Cache-Control: public, max-age=3600`. Unknown or disabled: `404`.

## 6. Interfaces

- **Routes** on `auth.{domain}`: `GET /auth/saml/{connection}`, `POST /auth/saml/{connection}/acs`,
  `GET /auth/saml/{connection}/complete`, `GET /auth/saml/{connection}/metadata`. The ACS is the one
  `/auth/*` POST without a CSRF token, named as such in CLAUDE.md.
- **Console**: `saml-keys:generate`, `saml-keys:rotate`, `saml-keys:list` (kid, usage, status,
  certificate fingerprint and expiry; never key material).
- **Management API**:
  - `strategy: saml` on connections with a `saml` object (the settings of §4, the IdP certificates'
    fingerprints and expiry read-only); `POST /connections/{name}/refresh-metadata`
    (`update:connections`); the service provider's entity ID, ACS and metadata URLs in the answer;
  - `GET /api/v1/saml-keys` (`read:signing_keys`): the service provider's certificates and their
    place in the rotation, as `GET /api/v1/signing-keys` does for token keys; `POST
    /api/v1/saml-keys/rotate` (`create:signing_keys`), `409` with a remote backend.
- **Login page**: the connection's button, its display name.
- **Dashboard** (clavia-dashboard): a SAML form (metadata URL or upload, the mappings with presets
  for Entra ID, Okta, ADFS and Google Workspace, the signing and encryption options), the values to
  give the IdP with copy buttons, the certificates with their fingerprints, refresh; and the service
  provider keys beside the signing keys.

## 7. Security rules

- **No private key leaves its backend.** The port signs and decrypts; with `postgres`, the key is
  read only inside `sign()` and `decryptKey()`, sealed at rest with the `kid` as associated data;
  with a KMS, it never exists here. Nothing logs or returns key material.
- **One key, one usage**: the signing key never decrypts, the encryption key never signs a request
  (it signs nothing at all; its certificate is signed by the signing key).
- **No weak key transport**: RSA PKCS#1 v1.5 (`rsa-1_5`) refused; RSA-OAEP only.
- **No padding oracle**: every decryption or padding failure, every signature failure and every
  check failure is the same answer, the same page, the same status, after the same steps (the
  pending sign-in and the stored response are spent before decryption is tried, so a failure
  cannot be retried with the same handle); SAML failures count toward the sign-in throttle per
  client address; a connection can require GCM.
- **No unsolicited response**: `InResponseTo` must name a request this server sent, for this
  browser, once.
- **No signature wrapping**: exactly one assertion; the assertion itself signed; the library hands
  back only the element its signature covers; the checks read that element and nothing else.
- **No foreign key**: only the connection's certificates verify, compared by key; `KeyInfo` in the
  message is ignored for verification.
- **No weak signature**: SHA-1 refused for signatures and digests.
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

- **A test identity provider** in `test/Support` that builds, signs and encrypts responses with real
  keys (RSA for signatures, and EC to prove it is refused; RSA-OAEP with AES-GCM and AES-CBC for encryption), so the
  adapter's contract checks genuine XML, as the passkey verifier's does with genuine CBOR. A double
  for the use cases answers what it is told.
- `ServiceProviderKeys`: a contract run by the `postgres` backend and by the remote one over each
  KMS client's mocked transport (as the token signers' are): signing verifies with the published
  certificate; a content key encrypted to the published certificate decrypts; a retired key still
  decrypts; no method returns key material. `SelfSignedCertificate`: the DER parsed by OpenSSL, the
  signature verified, a known answer pinned.
- The SAML adapter's contract: a valid response accepted, plain and encrypted (GCM and CBC, OAEP
  with SHA-1 and SHA-256); then each refusal, one test each: unsigned assertion, signed response
  with an unsigned assertion, a wrapped second assertion, a signature by another key, `KeyInfo`
  with an attacker's certificate, SHA-1, `rsa-1_5` key transport, a tampered CBC ciphertext and a
  tampered GCM tag (the same refusal as a bad signature), a content key for another certificate,
  CBC when GCM is required, a plain assertion when encryption is required, a comment inside the
  `NameID`, a `DOCTYPE`, a wrong `Destination`, `Recipient`, `Audience`, `Issuer` or
  `InResponseTo`, expired and not-yet-valid conditions (with the skew at its edge), a failed
  `Status`, two assertions, a transient `NameID` as the subject, oversized input.
- A signed `AuthnRequest` verified against the published certificate as an IdP would (the query
  string as sent, Bindings §3.4.4.1).
- Metadata: Entra ID, Okta, ADFS and Keycloak documents (public samples) read; one with a
  `DOCTYPE`, one without a signing key, one with only HTTP-POST SSO, refused. Our own metadata
  validated against the SAML metadata schema.
- Acceptance, through the real routes: a sign-in end to end with an encrypted assertion and a signed
  request (begin, the IdP's POST, the 303, the session), with a second factor; the ACS POST without
  cookies; another browser's `RelayState`; a replayed response; a disabled connection; the service
  provider metadata through a rotation (next published, then promoted, then the old encryption key
  still decrypting); registration from a document and from a URL (a private address refused).

## 9. Slices

1. **The SAML port and its adapter.** `simplesamlphp/saml2` added (deptrac's Vendor layer), the
   `SamlServiceProvider` port, `SimpleSamlServiceProvider`, the test identity provider, the contract
   for plain assertions with every refusal of §8 that does not involve our keys. *Done when* the
   contract passes against genuine signed responses, attacks included, with nothing wired to a route.
2. **Service provider keys, in PostgreSQL.** `ServiceProviderKeys` and `ServiceProviderKeyStore`, the
   `postgres` backend, `SelfSignedCertificate`, the migration, the settings, `saml-keys:generate`,
   `rotate` and `list`, `GET /api/v1/saml-keys` and its rotation. *Done when* a deployment has a
   signing and an encryption key, sealed, with verifiable certificates, rotated through next,
   current and retired, and no method returns key material.
3. **Service provider keys in a KMS.** `RemoteServiceProviderKeys` over AWS KMS, Google Cloud KMS and
   Azure Key Vault (signing a digest, decrypting with RSA-OAEP), certificates built through the KMS
   and cached, the references and their validation at boot. *Done when* the keys contract passes for
   each backend over its mocked transport, and a misconfigured reference stops `bin/clavia` (78).
4. **SAML connections.** `ConnectionStrategy::Saml`, `SamlSettings`, the migration, the Management
   API (registration from metadata, refresh), the service provider metadata route with our
   certificates. *Done when* an operator can register an IdP from its metadata or URL and hand it
   this server's metadata.
5. **Signing in.** The pending sign-in, the four routes, the ACS handle and the 303, the replay
   cache, `ResolveExternalAccount` with the trusted-address rule, the login page button, the
   refusals and their trail, with plain assertions and unsigned requests. *Done when* a person signs
   in through a SAML IdP end to end, with a second factor where they have one, and every refusal of
   §5.3 is covered.
6. **Signed requests and encrypted assertions.** `AuthnRequest`s signed through the port; encrypted
   assertions decrypted through it; `require_encryption` and `require_gcm`; the encryption refusals
   of §8 and the uniform failure of §7. *Done when* a sign-in works with an IdP that requires signed
   requests and one that encrypts (GCM and CBC), with keys in PostgreSQL and in a mocked KMS, and
   every failure looks the same from outside.
7. **Dashboard** (clavia-dashboard): the SAML connection form, presets, the values for the IdP, the
   certificates and refresh, and the service provider keys. *Done when* an operator can set up a
   SAML connection and see the keys without the API.

## 10. Open questions

1. **The library** (§2)? *Recommendation:* `simplesamlphp/saml2`, on v6.3 now and v7 when it is
   stable. The first slice proves it with the attack fixtures before anything depends on it, and
   `onelogin/php-saml` remains the fallback behind the same port. Its decryption must accept a
   content key we decrypted through the port; slice 1 checks this, and the adapter decrypts the
   `EncryptedKey` itself if it does not.
2. **One key pair for the deployment, or one per connection** (§2)? *Recommendation:* one for the
   deployment. A pair per connection gives no isolation an operator can use (every connection runs
   in the same server), and multiplies the certificates IdP administrators must track.
3. **Accept AES-CBC** (§2, §7)? *Settled in slice 6: not by default* (§11). The recommendation was
   yes, by default, with uniform failures and the per-connection `require_gcm`. ADFS encrypts with AES-256-CBC by default, and older deployments of
   other IdPs do too; refusing it would make encryption unusable with them, which is worse than the oracle the rules of §7 close.
4. **Refreshing metadata automatically** (a daily command)? *Recommendation:* on demand first; a
   `connections:refresh-saml-metadata` command can follow when an operator has missed a
   certificate rotation once.

## 11. As built

What slice 1 (#122) settled, so later slices start from it.

- **Library: `simplesamlphp/saml2` v6.3.5 with `xml-security` 2.3.2** (v7 is still a release
  candidate). It needs PHP's `bcmath` (for `xml-common`), now in the image. Its Composer plugin
  (`composer-xmlprovider-installer`, which links each package's element registry) is denied: the
  library parses and verifies without it.
- **No ECDSA.** The library's object model refuses an ECDSA `SignatureMethod` (2.3 and 3.1 alike),
  so an EC-signed assertion cannot even be read; verifying ECDSA ourselves would mean doing the
  canonicalisation and reference checks the library is here to do. Entra ID, Okta, ADFS, Google
  Workspace and Keycloak sign SAML with RSA. An EC certificate is refused at registration, and the
  contract proves an EC-signed response is refused, not crashed on.
- **`verify()` is always handed a key.** Called without one, the library verifies with the
  certificate in the message's `KeyInfo`, which proves nothing. The adapter builds a verifier per
  certificate of the connection and never calls it bare.
- **The assertion is verified on its own document.** The library digests from the document root,
  which inside a response is the `Response`; the adapter imports the one assertion into a document
  of its own first (exclusive canonicalisation gives the same bytes), and reads only the assertion
  the library rebuilds from the signed bytes.
- **The signature's shape is the adapter's to check**: the library takes any transform, XPath
  included, and digests the last of several references. The adapter requires one reference to the
  assertion's `ID`, enveloped-signature then exclusive canonicalisation without comments, and a
  SHA-256, 384 or 512 digest.
- **No comment and no processing instruction anywhere in a response**, and exactly one
  `saml:Assertion` in the whole document: simpler than tracking which text node a reader takes.
- **Question 1 answered: yes.** A block-cipher decryptor given to `EncryptedAssertion::decrypt()` is
  used directly (`EncryptedElementTrait::decryptData()`), so slice 6 reads the `EncryptedKey`,
  decrypts the content key through `ServiceProviderKeys::decryptKey()`, and hands the library an AES
  decryptor (`EncryptionAlgorithmFactory`, `SymmetricKey`) with it. AES-CBC and AES-GCM are both
  there; only the first `EncryptedKey` of an assertion is kept.

What slice 2 (#123) settled:

- **`CLAVIA_SAML_KEY_BACKEND` takes `postgres` alone** until slice 3 brings the KMS backends with
  their references: naming one now refuses to boot (exit 78), rather than running with no keys.
- **No production warning yet** for `postgres` SAML keys: every deployment would see it, SAML or
  not. It belongs with slice 4, when a SAML connection exists to make the keys matter.
- **A rotation with no keys makes the first pair** (`generated`), as `keys:rotate` does for token
  keys, so the Management API needs no generate operation; `saml-keys:generate` remains for the
  shell, and refuses when a pair exists.
- **Retired keys are deleted by the next rotation** once retired for the overlap, not by a job of
  their own.
- **OAEP's MGF1 follows its digest** (`OaepDigest`): PHP's OpenSSL sets both at once. XML Encryption
  1.1 lets them differ (SHA-256 with MGF1-SHA-1); slice 6 decides what to do with that combination.
- **The certificate builder lives in `Signing\X509`**, beside the token signers, and takes a signing
  closure: the `postgres` store hands it the key it just made; a KMS backend will hand it its API.

What slice 3 (#124) settled:

- **Decryption is an interface of its own** (`RemoteDecryptionKey`, one class per provider), beside
  the token signers' `RemoteSigningKey` rather than added to it: an operator's own signing backend
  class implements that interface, and would break. Signing reuses the token signers' keys as they
  are (RSASSA-PKCS1-v1_5 over a SHA-256 digest is what RS256 already asks of them).
- **Only the three built-in providers** hold SAML keys; an operator's own class
  (`CLAVIA_SIGNING_BACKEND` may name one) is not offered for SAML.
- **Cloud KMS fixes the OAEP digest per key version** (`RSA_DECRYPT_OAEP_<bits>_SHA1` or `_SHA256`):
  a content key wrapped with the other is refused before Cloud KMS is asked. AWS KMS and Key Vault take
  either.
- **Certificates are cached in `saml_remote_certificates`**, by reference, the first one written kept:
  a reference names one immutable key version, so its certificate never goes stale. A retired
  encryption key's certificate is signed by the current signing key.
- **References are checked when the settings load** (`Bootstrap\SamlKeyReferences`), in each
  provider's form, so a bad one stops `bin/clavia` (78) without a provider called.

What slice 4 (#125) settled:

- **A registered SAML connection is not `configured` yet**: nobody can sign in through one before
  slice 5, so the login page offers no button for it.
- **Keycloak's metadata is an `EntitiesDescriptor` holding one entity**, and is read as that entity;
  an aggregate of several (a federation) is still refused.
- **A refusal names its field** with a pointer (`/saml/metadata`, `/saml/metadata_url`, `/saml` for an
  option), never the document's content.
- **The certificates keep their stated expiry** (read when the metadata is) beside their SHA-256, for
  the operator; neither is enforced, since the key is what is pinned.
- **Refreshing a connection registered from a document is `409`**: it has no URL to read again.
  Changing a connection's SAML options or re-registering its metadata by `PATCH` is not built yet.
- **This server's metadata advertises its encryption methods** in order (AES-GCM, then AES-CBC, then
  RSA-OAEP key transport), and `AuthnRequestsSigned` only when the connection signs and a signing key
  exists.

What slice 5 (#126) settled:

- **An address the operator does not trust still makes an account** for a new subject: unverified,
  in the SAML connection, matched against no other account (`User::registerFromAssertion()`,
  `ResolveExternalAccount`'s `unverifiedAddress`). The assertion vouches for the subject, which is
  the identity; requiring a verified address would make an untrusted connection sign nobody in. No
  address at all is still refused.
- **The pending sign-in keeps its OpenID Connect fields** (a verifier, a nonce, unused) beside the
  SAML request id: one store, one shape, rather than two kinds of pending sign-in.
- **The replay cache is keyed by connection and assertion id**, kept until the assertion's own end
  plus the skew. Its method is `claimAssertion()`, apart from the parked responses' `claim()`.
- **The profile attributes** (`name_attribute` and the others) are stored but not yet copied onto the
  account: `ResolveExternalAccount` sets no profile for any external sign-in today.

What slice 6 (#127) settled:

- **The port signs and decrypts through closures the application hands it**: `authnRequestUrl()`
  takes a signer over `ServiceProviderKeys::sign()`, `consume()` a `ContentKeyDecrypter` over
  `decryptKey()`. The two ports never call each other.
- **RSA-OAEP takes one digest for the OAEP hash and MGF1** (PHP's OpenSSL): `rsa-oaep-mgf1p`, 1.1's
  `rsa-oaep` with SHA-1 and its default MGF, or with SHA-256 and `mgf1sha256`. SHA-256 with MGF1-SHA-1
  is refused rather than tried.
- **The content key is decrypted, then AES runs on the library's own backend** (`Alg\Encryption\AES`),
  as question 1 found it could; the decrypted assertion is then verified exactly as a plain one.
- **The throttle is the sign-in throttle's, per client address**: every SAML refusal counts, and once
  it is reached the parked response is spent and nothing is read.
- **Without keys a request goes unsigned** and an encrypted assertion is refused (`decryption`): the
  connection's registration already warned.
- **GCM is required by default** (`require_gcm` on), reversing question 3's recommendation. Accepting
  AES-CBC exposes more than CBC: XML Encryption does not authenticate the algorithm an assertion names,
  so a GCM ciphertext relabelled as CBC falls to the same padding oracle (Jager, Schwenk and
  Somorovsky, 2013). An operator turns it off, knowingly, for an identity provider that encrypts with
  CBC (ADFS by default); the uniform failures and the throttle still stand there.

