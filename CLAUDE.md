# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

Clavia is an open-source OAuth 2.1 / OpenID Connect authorization server — an Auth0 equivalent
covering OAuth2 flows, interactive login/logout with MFA, and a Management API. The bar is
unchanged from the Python project: *"The code and architecture need to be perfectly coded and
documented."* Spec conformance and public-API documentation are part of "done".

**Engineering direction (overrides everything below it).** This project owes nothing to FastAPI or
Python. Where a restriction, convention or choice below exists only because the Python server did
it that way — a response shape, a JSON encoding flag, an error body, a token format, a library
workaround, a test layout — it is **not binding**. Write standard, clean, robust, state-of-the-art
PHP 8+: idiomatic PSR-based code, well-maintained libraries used as they are meant to be used
(e.g. Diactoros `JsonResponse` rather than a hand-rolled equivalent), modern language features,
strict types, and the platform's own defaults. Choose by what is correct, secure and maintainable
in PHP, never by what the Python server emitted. Only the OAuth 2.1 / OIDC / RFC requirements and
the security invariants are fixed. Whatever a section below says about Python parity, "frozen"
contracts or `docs/DEVIATIONS.md` yields to this paragraph; where code still mirrors Python for no
other reason, replace it when you touch it, and inject collaborators by interface where that
helps (e.g. a response factory), not as concrete classes.

**This repository is the PHP 8.5 port of Clavia.** The reference implementation is the Python
project at `../Clavia Python/clavia` (FastAPI + Authlib + SQLAlchemy; ~10k lines of source, 21
test files, 404 tests, 31 commits). It is feature-complete for everything below except audit logs
and multi-tenancy.

## Current state

**Steps 0 to 15 are done: the foundations, Authorization Code + PKCE, the login page with
browser sessions, OpenID Connect (ID tokens, discovery, JWKS, userinfo), Client
Credentials for machine clients holding a grant on an API, the Management API with
audiences in the user's flow, two-factor authentication (TOTP and recovery codes),
signing in with Google or GitHub, RP-Initiated Logout, roles (RBAC), rotating refresh
tokens, application ownership with the consent screen, and connections — pools of accounts,
the social providers and operator-registered OpenID Connect providers, enabled per
application — token introspection and revocation, and device authorization; the dashboard is in `frontend/`.**
The application answers `GET /healthz`,
`GET|POST /oauth2/authorize`, `POST /oauth2/token`, `POST /oauth2/introspect`, `POST /oauth2/revoke`,
`POST /oauth2/device/code`, `GET|POST /auth/device`,
`GET /.well-known/openid-configuration`,
`GET /.well-known/oauth-authorization-server`, `GET /oidc/jwks.json`, `GET|POST /oidc/userinfo`,
`GET|POST /oidc/logout`,
`GET|POST /auth/login`, `GET|POST /auth/mfa`, `GET|POST /auth/mfa/enroll`,
`POST /auth/mfa/enroll/confirm`, `POST /auth/mfa/disable`, `GET /auth/social/{provider}` and
its `/callback`, `GET|POST /auth/consent`, `POST /auth/logout`,
`POST /auth/theme` and the Management API under `/api/v1/` (users with their second factor,
roles, effective permissions, consents and linked identities, clients with secret rotation
and their connections, resource servers, roles and their holders, connections): a person can
sign in with a password in one of the pools an application enables, or through Google, GitHub
or an OpenID Connect provider an operator registered — and, once they have turned it on, a code from their authenticator app or a
recovery code — complete the flow in a browser, naming an API in `audience` if the client
wants its permissions — on an API that enforces roles, only what their roles grant there —
and the client gets an RS256 ID token it can verify against the published
JWKS; a machine client gets a subject-less token for an API it holds a grant on, and with one
for the Management API it administers the deployment, as a person holding a role there does. Update this section at the
end of every step (what exists, where it lives, which conventions it established).

What exists:

- **Skeleton**: `public/index.php` → `config/container.php` (laminas-servicemanager) →
  `config/pipeline.php` → `config/routes.php`. The pipeline is `ErrorHandler` → routing →
  405 → dispatch → 404. There is no implicit `HEAD` or `OPTIONS`: a route answers the methods
  it lists and nothing else.
- **Settings** (`src/Configuration`): `Settings` is a readonly class whose constructor
  parameters *are* the `CLAVIA_*` variables (`rootDomain` ⇄ `CLAVIA_ROOT_DOMAIN`);
  `Settings::fromEnvironment()` coerces, bounds-checks (`#[Range]`) and cross-checks them, with
  every validator of the Python `config.py`. `bin/clavia config` prints them from the class.
- **Composition root** (`src/Bootstrap`): `ConfigProvider` maps every service to a factory in
  `Bootstrap\Container`; `EnvironmentVariables` merges the process environment over `.env`.
- **Local infrastructure**: `docker-compose.yml` (Caddy, `php` = PHP-FPM 8.5, Postgres :5433,
  `db-test` :5434, Redis), `docker/php/`, the ported `Caddyfile`, `Makefile`, `setup-ssl.sh`.
- **QA**: `composer check` = PHPCS (PSR-12, 120 columns) + Psalm level 1 + deptrac + PHPUnit.
  `.github/workflows/ci.yml` runs it, with PostgreSQL and Redis as services.
- **Shared kernel** (`src/Domain/Shared`): the `Clock` and `RandomSource` ports; `Digest`
  (SHA-256, the at-rest form of codes and tokens); `SecretGenerator` (43-character tokens,
  alphanumeric ids, `rs_…`/`rol_…` prefixed ids); `Scope`/`ScopeSet` (RFC 6749 §3.3, with the
  narrowing operations); `Audience`; `Url` (kept byte for byte, compared exactly); `InvalidValue`.
- **Technical ports** (`src/Application/Port`): `TransactionManager`, `PasswordHasher`,
  `SecretCipher`, `SchemaMigrator` and their exceptions. One use case so far:
  `Application\Secrets\GenerateEncryptionKey`.
- **Secondary adapters** (`src/Adapter/Secondary`): `System\SystemClock`/`SystemRandomSource`;
  `Crypto\BcryptPasswordHasher` (cost 12) and `Crypto\AesGcmSecretCipher`;
  `Persistence\PhpDb\Database` (the one door to PostgreSQL), `PostgresUrl`,
  `PhpDbTransactionManager`; `Persistence\Migrations\SqlFileMigrator`; `Redis\RedisConnection`
  and `Redis\Keys`.
- **Console**: `clavia db:migrate`, `clavia db:status`, `clavia secrets:generate-key`,
  `clavia seed-dev`, `clavia authorize-url`, `clavia keys:generate|rotate|list`,
  `clavia clients:create-m2m`, `clavia clients:grant`, `clavia management-api:register|scopes`.
- **Test kit** (`test/Support`): `Fake\*` (one in-memory double per port), `Contract\*`
  (traits run against both the double and the real adapter), `TestEnvironment`, `TestStorage`,
  `IntegrationTestCase`, `AcceptanceTestCase` (`get`/`post`/`locationQuery`, a cookie jar,
  `freezeClock()`, an active signing key installed before every test), `OAuth2Fixtures`
  (users, clients, PKCE pairs and whole flows), `LoginFixtures` (`submitLogin`, login-state
  handles), `OidcFixtures` (`completeFlow`, `verifiedIdToken` — checked against the JWKS
  fetched over HTTP), `MachineFixtures` (a machine client, an API, a grant,
  `requestMachineToken`), `ManagementFixtures` (the Management API, `adminToken()`, `api()` —
  every response checked against the OpenAPI document), `TestSigningKeys` (RSA keys generated
  once per run), `Clients` (ready-made registrations for unit tests).
- **Authorization Code + PKCE** (Step 2):
  - `Domain\Identity` — `User`, `UserId`, `UserRepository`. `Domain\Client` — `Client`
    (`client_id` is the key; type, auth method and secret must agree), `ClientId`, the
    `ClientType` / `ClientAuthMethod` / `GrantType` / `ResponseType` enums, `ClientRepository`.
    `Domain\OAuth2` — `OAuth2Error` + `ErrorCode`, `CodeChallenge` / `CodeVerifier` (S256
    only), `AuthorizationCode` (`redeem()` returns a `Redemption`), `AccessToken`, their ids
    and repositories. `Domain\Authentication\LoginState`. `Domain\Shared\UuidId` is the base
    of every UUID identifier.
  - `Application\OAuth2\Authorize\Authorize` (returns `CodeIssued`, `RequestRefused` or
    `LoginRequired`; throws `OAuth2Error` when it must not redirect),
    `ClientAuthentication\ClientAuthenticator`, `Token\IssueToken` (dispatches to a `Grant`)
    and `Token\AuthorizationCodeGrant`; `RequestParameters` (keeps repetitions);
    `Authentication\DevelopmentAutoLogin`; `Development\SeedDevelopmentData` and
    `BuildAuthorizationUrl`; the `LoginStateStore` port.
  - `Adapter\Secondary\Persistence\PhpDb\PhpDb{User,Client,AuthorizationCode,AccessToken}Repository`,
    `Timestamp`; `Adapter\Secondary\Redis\RedisLoginStateStore`.
  - `Adapter\Primary\Http\OAuth2\{AuthorizeHandler,TokenHandler,OAuth2Responder}`,
    `Adapter\Primary\Http\Shared\RequestParameterReader`, `Adapter\Primary\Cli\{SeedDevelopmentData,AuthorizeUrl}Command`.
  - Migrations `0001_users` … `0004_oauth2_access_tokens`.
- **Login page and sessions** (Step 3):
  - `Domain\Authentication` — `Session` (absolute and idle lifetimes, `sid`, `methods`),
    `AuthenticationMethod` (RFC 8176 `amr` values), `LocalPath` (the only shape a post-sign-in
    `Location` may take).
  - `Application\Authentication` — `Sessions` (establish with rotation, resolve with sliding,
    end), `LoginThrottle`, `ResolveEndUser` (session, then the development auto-login),
    `SignIn\SignInWithPassword` (`SignedIn | CredentialsRejected`), `SignOut`,
    `LoginPage\DescribeLoginPage`; ports `SessionStore` and `AttemptCounter`;
    `PasswordHasher::simulateVerification()`; `ClientRepository::registersRedirectOrigin()`
    and `Client::redirectOrigins()`.
  - `Adapter\Secondary\Redis\{RedisSessionStore,RedisAttemptCounter}`.
  - `Adapter\Primary\Http\Auth\{LoginPageHandler,LoginHandler,LogoutHandler,ThemeHandler}`,
    `AuthPageResponder` + `AuthPage` + `LoginPages` (view models), `AuthCookies`, `CsrfToken`;
    `Adapter\Primary\Http\Shared\{RequestCookies,SetCookie}`. `AuthorizeHandler` now
    resolves the end user from the session cookie.
  - `templates/` — `layout/page.phtml`, `auth/login.phtml`, `error/page.phtml`,
    `partial/{alert,csrf,field}.phtml`, rendered by laminas-view through
    `mezzio/mezzio-laminasviewrenderer`.
- **OpenID Connect** (Step 4):
  - `Domain\Oidc` — `SigningKey` (active → retired, published until its grace ends),
    `SigningKeyStatus`, `SigningAlgorithm` (RS256; its hash and `halfHash()` for `at_hash`),
    `PublicJwk` (public members only, `kid` = RFC 7638 thumbprint), `Nonce`, `OidcScope`,
    `IdentityClaims` (what a scope releases — shared by the ID token and userinfo),
    `IdTokenClaims`. `Domain\Identity\Profile` (the `profile` claims) on `User`;
    `Domain\Authentication\AuthenticationContext` (`auth_time`, `amr`) captured on the
    `AuthorizationCode` with its `nonce`. `Domain\OAuth2\BearerTokenError` +
    `BearerErrorCode` (RFC 6750 §3.1). `Domain\Shared\Base64Url`.
  - `Application\Oidc` — `CompactJws` (the JWS assembled by hand), `IdTokenIssuer`,
    `Discovery\ProviderMetadata`, `Keys\{GenerateSigningKey,RotateSigningKey,ListSigningKeys,PublishSigningKeys}`,
    `UserInfo\ReadUserInfo`. Ports `TokenSigner` (+ `SigningKeyReference`,
    `NoActiveSigningKey`, `SigningFailed`), `SigningKeyStore`, `NonceRegistry`.
    `AuthorizationCodeGrant` mints the ID token in the redemption's transaction;
    `Authorize` checks the nonce before login and spends it with the code;
    `IssueToken::supportedGrantTypes()|supportedAuthMethods()` feed discovery.
  - `Adapter\Secondary\Signing\Postgres\{PostgresTokenSigner,PostgresSigningKeyStore,SigningKeyRow}`;
    `Redis\RedisNonceRegistry`; `Persistence\PhpDb\Jsonb`.
  - `Adapter\Primary\Http\Oidc\{DiscoveryHandler,JwksHandler,UserInfoHandler}`,
    `Http\Shared\{BearerCredentials,BearerChallenger}`; `Cli\{GenerateSigningKey,RotateSigningKey,ListSigningKeys}Command`.
    `seed-dev` creates a signing key when none is active. `Bootstrap\SigningBackend` refuses
    every backend but `postgres` by name.
  - Migrations `0005_user_profiles`, `0006_authorization_code_authentication`,
    `0007_oidc_signing_keys` (a partial unique index allows one active key).
- **Client Credentials** (Step 5):
  - `Domain\ResourceServer` — `ResourceServer` (an API: `rs_…` id, its `Audience`
    identifier, its permissions), `ResourceServerId`, `Permission`, `ClientGrant`
    (`grantableOn()`: the grant narrowed to what the API still defines), their repositories.
    `GrantType::ClientCredentials`; `ErrorCode::InvalidTarget` (RFC 8707) and `AccessDenied`;
    `AccessToken::issueToClient()` and `AccessToken::$audience`.
  - `Application\OAuth2\Token\ClientCredentialsGrant` (registered in `IssueTokenFactory`,
    so discovery lists it); `Application\Clients\RegisterMachineClient`.
  - `Adapter\Secondary\Persistence\PhpDb\{PhpDbResourceServerRepository,PhpDbClientGrantRepository}`;
    `Adapter\Primary\Cli\CreateMachineClientCommand`.
  - Migrations `0008_resource_servers` (with `permissions`), `0009_client_grants`,
    `0010_access_token_audience`.
- **Management API and audiences** (Step 6):
  - `Domain\Shared` — `PageRequest` (page ≥ 1, 1–100 per page, a literal search of at most
    200 characters) and `Page<T>`; `AlreadyExists` (thrown by a repository on a unique
    violation). `Domain\Identity\PasswordPolicy` (≥ 8 characters, ≤ 72 bytes, the hash's
    limit); `User::changeEmail()` (a new address is unverified), `recordEmailVerification()`,
    `changePassword()`. `Client::reconfigure()` / `withSecretHash()` and the coherence rules
    (the `code` response type and the `authorization_code` grant come together and need a
    redirect URI; `client_credentials` needs a confidential client). `ResourceServer::$isSystem`
    with `renamed()`, `withPermissions()`, `asSystem()`, `assertDeletable()` and
    `SystemApiProtected`. Every repository of the three gains `delete()` and `page()`.
    `AuthorizationCode::$audience`.
  - `Application\Management` — `ManagementPermission` (the twelve scopes), `NotFound`,
    `Conflict`; `Caller\{AuthenticateManagementCaller,ManagementCaller}`; per resource a
    `ReadX` query (`page()`, `one()`) and one use case per change: `Users\{CreateUser,UpdateUser,DeleteUser}`,
    `Clients\{RegisterClient,UpdateClient,RotateClientSecret,DeleteClient}`,
    `ResourceServers\{RegisterResourceServer,UpdateResourceServer,DeleteResourceServer}`;
    `Provisioning\{RegisterManagementApi,GrantClientAccess}` (shell only).
    `Development\SeedManagementAccess`. `Authorize` resolves `audience` and
    `AuthorizationCodeGrant` re-checks it at redemption.
  - `Adapter\Primary\Http\OpenApi` — the OpenAPI 3.0 document model and validator (see
    below the conventions).
  - `Adapter\Primary\Http\Management` — `ManagementContract` (the OpenAPI document:
    operation lookup, required permission, request and response validation),
    `ManagementApiMiddleware` (the front door of every `/api/v1/*` route), `ManagementRequest`,
    `JsonObject`, `Paging`, `UserFields`, `ResourceServerFields`, `ContractViolation`, `Problem`,
    `ManagementResponder`, `ManagementViews`, and seven handlers (`UsersHandler`,
    `UserHandler`, `ClientsHandler`, `ClientHandler`, `RotateClientSecretHandler`,
    `ResourceServersHandler`, `ResourceServerHandler`). `Cli\{RegisterManagementApi,ListManagementScopes,GrantClientAccess}Command`.
  - `Adapter\Secondary\Persistence\PhpDb\{Constraint,Search}`.
  - `docs/openapi/management-api.yaml` (OpenAPI 3.0.3). Migrations
    `0011_system_resource_servers`, `0012_authorization_code_audience`.
- **Multi-factor authentication** (Step 7):
  - `Domain\Authentication\Mfa` — `Totp` (RFC 6238/4226: SHA-1, six digits, thirty seconds,
    one step either side, every step compared in constant time, single-use by time step),
    `TotpSecret` (160 random bits; at least 128 accepted), `Base32` (RFC 4648),
    `RecoveryCode` (`xxxx-xxxx-xxxx`, looked up by the SHA-256 of the normalised code),
    `MfaFactor` (pending → confirmed, `accept()` records the step) with
    `FactorAlreadyConfirmed`, and the `MfaFactorRepository` / `RecoveryCodeRepository`
    interfaces. `Domain\Authentication\MfaChallenge` (the parked first factor) and
    `AuthenticationMethod::{OneTimePassword, MultipleFactors, combined()}`.
  - `Application\Authentication\Mfa` — `TotpSeeds` (sealing through `SecretCipher`, the
    provisioning URI), `DescribeMfa`, `BeginTotpEnrollment`, `ResumeTotpEnrollment`,
    `ConfirmTotpEnrollment`, `DisableMfa`, `CompleteSecondFactor` (with `SecondFactorAttempt`
    and the outcomes `SignedIn`, `SecondFactorRejected`, `ChallengeGone`),
    `DescribeSecondFactorPage`. `SignInWithPassword` returns `SecondFactorRequired` for an
    account with a confirmed factor; `RequireSignIn` parks a page behind the login;
    `ResolveEndUser::bySession()`. Port `MfaChallengeStore`. Management:
    `Users\{ManagedUser,ResetUserMfa}`.
  - `Adapter\Primary\Http\Auth\{MfaChallengeHandler,MfaSettingsHandler,MfaPages,QrCodeSvg,ClientAddress}`;
    `Management\UserMfaHandler` (`DELETE /api/v1/users/{user_id}/mfa`) and `mfa_enrolled` on
    every user the API returns. Templates `auth/mfa-{challenge,settings,setup,codes}` and
    `partial/code-field`.
  - `Adapter\Secondary\Persistence\PhpDb\{PhpDbMfaFactorRepository,PhpDbRecoveryCodeRepository}`,
    `Adapter\Secondary\Redis\RedisMfaChallengeStore`. Migration `0013_mfa`.
  - `bacon/bacon-qr-code` draws the QR code; its namespace joins deptrac's `Vendor` layer.
- **Social login** (Step 8):
  - `Domain\Identity` — `ProviderName` (the slug in URLs and keys), `AssertedIdentity` (what a
    provider says: subject, address, whether it vouches for it), `ExternalIdentity` (an account
    linked by `(provider, subject)`) and `ExternalIdentityRepository`;
    `User::registerFromProvider()`; `UserRepository::matchingEmail()` (ignoring case).
    `Domain\Authentication\PendingExternalSignIn` and `AuthenticationMethod::External` (`ext`).
  - `Application\Authentication\External` — `BeginExternalSignIn`, `CompleteExternalSignIn`
    (with `ExternalCallback`, `ExternalSignInRefused` + `ExternalSignInFailure`),
    `ResolveExternalAccount` (the linking rules), `ExternalCallbackUrl`, `ExternalProviderOption`.
    `SignIn\CompleteFirstFactor`: what follows any first factor — a session, or the second-factor
    challenge — used by the password and by external sign-in alike. Ports `IdentityProvider`,
    `IdentityProviders`, `IdentityProviderFailed`, `ExternalSignInStore`. `DescribeLoginPage`
    lists the configured providers.
  - `Adapter\Secondary\IdentityProvider\{GoogleIdentityProvider,GitHubIdentityProvider,AuthorizationCodeExchange,ProviderHttp,ConfiguredIdentityProviders}`;
    `Persistence\PhpDb\PhpDbExternalIdentityRepository`; `Redis\RedisExternalSignInStore`.
    Migration `0014_external_identities`.
  - `Adapter\Primary\Http\Auth\{ExternalSignInHandler,ExternalSignInCallbackHandler,ExternalSignInMessages}`;
    the provider links on the login page.
  - `guzzlehttp/guzzle` is the PSR-18 client (`Bootstrap\Container\HttpClientFactory`); its
    namespace joins deptrac's `Vendor` layer.
- **RP-Initiated Logout and the dashboard** (Step 9):
  - `Domain\Client\Client::$postLogoutRedirectUris` and `hasPostLogoutRedirectUri()` (exact
    match, no fragment).
  - `Application\Oidc\Logout\{EndSession,EndSessionRequest,SignedOut,SignOutConfirmationNeeded}`;
    port `SignatureVerifier`; `ProviderMetadata::END_SESSION_ENDPOINT`.
    `Development\{SeedDashboardClient,SeededDashboard}`.
  - `Adapter\Secondary\Signing\Jose\JoseSignatureVerifier`; `Adapter\Primary\Http\Oidc\EndSessionHandler`
    and `templates/auth/logout-confirm.phtml`; `post_logout_redirect_uris` in the Management API.
  - Migration `0015_post_logout_redirect_uris`. `frontend/` (the React dashboard).
- **The dashboard follows the contract** (after Step 11): `frontend/src/api/types.ts` holds
  the shapes `docs/openapi/management-api.yaml` defines and nothing else; the pages, fields
  and calls for what does not exist yet (connections, consents, sessions, linked identities,
  third-party clients, back-channel logout, the device grant, revocation at sign-out) were
  removed, and come back with their step. Errors are read as problem details (RFC 9457).
- **Roles** (Step 10):
  - `Domain\Rbac\{Role,RoleId,GrantedPermission,RoleRepository}`: a role grants permissions
    named `(API id, value)`, possibly across APIs; the repository also holds the assignments
    (`assign`, `unassign`, `replaceRolesOf`, `rolesOf`, `holders`) and answers the one question
    issuance asks, `permissionsHeld(user, API)`. `ResourceServer::$enforcePolicies` and
    `enforcingPolicies()` (refused off for a system API: `SystemApiProtected::policies()`).
  - `Application\Management\Roles\{ReadRoles,CreateRole,UpdateRole,DeleteRole,RoleAssignments,ReadRoleHolders,ReadEffectivePermissions,RolePermissions}`
    with `NewRole`, `RoleChanges`, `PermissionReference`, `DescribedRole`, `DescribedPermission`,
    `EffectivePermission`; `Provisioning\{EnsureRole,AssignRole}` for the shell and `seed-dev`.
    `ManagementPermission` gains `read|create|update|delete:roles`. `ReadUsers::describeAll()`.
  - `Authorize` refuses `access_denied` to somebody holding nothing on an API that enforces
    roles; `AuthorizationCodeGrant` narrows the API's permissions to what they hold at
    redemption (`invalid_grant` if that is now nothing).
  - `Adapter\Secondary\Persistence\PhpDb\PhpDbRoleRepository`; `PhpDbResourceServerRepository`
    reconciles permission rows instead of replacing them. Migration `0016_roles`
    (`roles`, `role_permissions` with a composite foreign key onto `permissions`, `user_roles`,
    `resource_servers.enforce_policies`).
  - `Adapter\Primary\Http\Management\{RolesHandler,RoleHandler,RoleUsersHandler,UserRolesHandler,UserPermissionsHandler,RoleFields}`;
    `ManagementResponder::jsonList()`; `enforce_policies` on resource servers.
    `Adapter\Primary\Cli\{CreateRoleCommand,AssignRoleCommand,ListRolesCommand}`
    (`roles:create|assign|list`). `seed-dev` gives the development user an `Administrator` role
    holding every management permission.
- **Refresh tokens** (Step 11):
  - `Domain\OAuth2\{RefreshToken,RefreshTokenId,Refresh,RefreshTokenRepository}`: a family
    started at code redemption (`startFamily`), each successor `succeededBy` the token it
    replaces, `examine()` before `spend()`; `GrantType::RefreshToken`, which a client may only
    hold beside `authorization_code`. `AccessToken::$refreshFamilyId`, `issueFromRefresh()`,
    `revoked()`; `AccessTokenRepository::revokeFamily()`.
  - `Application\OAuth2\Token\RefreshTokenGrant`; `UserScope` — what a token issued on a
    person's behalf may carry now, shared by both user grants (it took over
    `AuthorizationCodeGrant`'s narrowing). `IssuedToken::$refreshToken`.
  - `Adapter\Secondary\Persistence\PhpDb\PhpDbRefreshTokenRepository`. Migration
    `0017_refresh_tokens` (and `oauth2_access_tokens.refresh_family_id`).
  - `refresh_token` in the token response, discovery and the Management API's `GrantType`;
    the dashboard is seeded with it.
- **Ownership and consent** (Step 12):
  - `Domain\Client\Ownership`, read from the id: `ClientId::THIRD_PARTY_PREFIX` (`tpc_`),
    `ClientId::generate($secrets, $ownership)`, `Client::isFirstParty()`.
    `ResourceServer::$allowSkippingConsent` and `allowingConsentSkip()` (refused off for a
    system API: `SystemApiProtected::consent()`).
  - `Domain\Consent\{UserConsent,ConsentRepository,ConsentPolicy,PendingConsent}`;
    `Domain\OAuth2\Prompt` (`none`, `consent`); `ErrorCode::LoginRequired|ConsentRequired`.
  - `Authorize` refuses a third-party application a system API (`access_denied`, before
    sign-in), answers `prompt=none` with `login_required`/`consent_required`, and puts a
    request needing consent on hold (`ConsentRequired`). `AuthorizationRequest::resumption()`
    rebuilds the request as a `GET` from its parameters; `RequestParameters::with()` and
    `toQueryString()`.
  - `Application\OAuth2\Consent\{HeldConsents,DescribeConsent,DecideConsent}` with
    `ConsentScreen`, `ConsentedApi`, `ScopeLine`, `ConsentGiven`; `Port\ConsentStateStore`.
    `Management\Users\{ReadConsents,WithdrawConsent,DescribedConsent}`. `ClientCredentialsGrant`
    and `GrantClientAccess` keep third-party machines off system APIs.
  - `Adapter\Secondary\Redis\RedisConsentStateStore`, `PhpDb\PhpDbConsentRepository`;
    migration `0018_consent` (`user_consents`, `resource_servers.allow_skipping_consent`).
  - `Adapter\Primary\Http\Auth\{ConsentHandler,ConsentPages}`, `templates/auth/consent.phtml`
    and `consent-expired.phtml`; `Management\UserConsentsHandler`; `is_first_party` on
    clients and `allow_skipping_consent` on APIs in the Management API;
    `clients:create-m2m --third-party`. The dashboard shows ownership, the API switch and a
    user's authorized applications again.
- **Passwordless sign-in and mail** (Step 16):
  - `ConnectionStrategy::Passwordless` and the built-in `email` connection
    (`ConnectionName::email()`, `Connection::isPasswordless()`); `isExternal()` is social or
    OIDC only. Migration `0020_passwordless` seeds it — on, not a domain connection, given to
    no existing application.
  - `Domain\Authentication\{PasswordlessChallenge,PasswordlessMode,OneTimeCode}`: the
    code's digest is bound to the browser's handle; `PasswordlessChallenge::address()`
    normalizes an address (trimmed, lower-cased).
  - `Port\{Mailer,OutgoingMail,MailUnavailable,MailOutbox,PasswordlessChallengeStore}`;
    `Adapter\Secondary\Mail\{OutboxMailer,SmtpMailer,NoMailer}` (Symfony Mailer's ESMTP
    transport, STARTTLS required unless switched off, SMTPS on 465, 15-second timeout),
    `Redis\{RedisMailOutbox,RedisPasswordlessChallengeStore}`; `MailerFactory` picks by
    `CLAVIA_EMAIL_BACKEND`, and the settings refuse `smtp` without a host.
    `Settings::emailSender()`.
  - `ConnectionAccess` takes the `Mailer`: the passwordless connection is configured, hence
    usable, only while mail can be sent. `SignInMethods::$email`.
  - `Application\Authentication\Passwordless\{StartPasswordlessSignIn,AnswerPasswordlessCode,
    FollowPasswordlessLink,FinishPasswordlessSignIn,DescribePasswordlessChallenge,
    PasswordlessSendLimit,SignInMail}` with their outcomes (`PasswordlessCodeSent`,
    `PasswordlessLinkSent`, `PasswordlessCodeRejected`, `PasswordlessRefused` +
    `PasswordlessFailure`, `PasswordlessPrompt`).
  - `Adapter\Primary\Http\Auth\{PasswordlessStartHandler,PasswordlessCodeHandler,
    PasswordlessLinkHandler,PasswordlessPages}`, `templates/auth/passwordless-{code,link}.phtml`,
    the email form on the login page, the `clavia_passwordless` cookie;
    `AuthPageResponder::page()` sets extra cookies. CLI `mail:outbox`.
- **Device authorization** (Step 15):
  - `Domain\OAuth2\{DeviceAuthorization,DevicePoll,DeviceDecision,UserCode}`;
    `GrantType::DeviceCode` (`actsForAPerson()`: a refresh token needs the code or the device
    grant; the device grant is refused to third parties); `ErrorCode::AuthorizationPending|
    SlowDown|ExpiredToken`. `AccessToken::issueForUser()`, `RefreshToken::startFamilyFor()`,
    `IdTokenIssuer::issueFor()` — issuance without an authorization code.
  - `Port\DeviceAuthorizationStore` (`open` refuses a user code already live, `consume` wins
    once); `Redis\RedisDeviceAuthorizationStore`.
  - `Application\OAuth2\ReadRequestedAccess` + `RequestedAccess`: `scope` and `audience`,
    shared by `Authorize` and `Device\RequestDeviceAuthorization`. `Token\DeviceCodeGrant`.
    `Device\{PendingDeviceRequests,DescribeDeviceRequest,DecideDeviceRequest}` with
    `DeviceReview`, `DeviceDecided`, `DeviceSignInRequired`. `Consent\ScopeDescriptions`, the
    words the consent screen and the device page share. `RequireSignIn` takes the client the
    sign-in is for.
  - `Adapter\Primary\Http\OAuth2\DeviceAuthorizationHandler`,
    `Auth\{DeviceHandler,DevicePages}`, `templates/auth/device.phtml`;
    `device_authorization_endpoint` in discovery. The dashboard registers device clients.
- **Introspection and revocation** (Step 14):
  - `Application\OAuth2\TokenManagement\{IntrospectToken,TokenIntrospection,RevokeToken,
    IssuedTokens,PresentedToken,TokenTypeHint}`; `ErrorCode::UnsupportedTokenType`;
    `AccessTokenRepository::revoke()`. Each use case names the client authentication methods
    it accepts (`AUTH_METHODS`), which discovery advertises.
  - `Adapter\Primary\Http\OAuth2\{IntrospectionHandler,RevocationHandler}`,
    `OAuth2Responder::done()`; `introspection_endpoint`, `revocation_endpoint` and their
    `…_auth_methods_supported` in both metadata documents.
  - The dashboard hands its refresh token back at sign-out (a beacon to `/oauth2/revoke`).
- **Connections** (Step 13):
  - `Domain\Connection\{ConnectionName,ConnectionStrategy,Connection,OidcSettings,
    ConnectionRepository,BuiltInConnection}` (`ProviderName` became `ConnectionName`;
    `ConnectionName::defaultPool()` is `password`). `User::$connection`, set by `register(…,
    $pool)` and `registerFromProvider(…, $connection)`; `UserRepository::findByEmail($pool,
    …)`, `matchingEmail($email, $connections)`, `countIn()`. `Session::$connection` and
    `MfaChallenge::$connection`; `PendingExternalSignIn::$nonce`. `Client::$connections`,
    `withConnections()`, `enables()` (refused for a third party).
    `ExternalIdentityRepository::ofUser()`, `unlink()`, `countThrough()`.
  - `Application\Connection\{ConnectionAccess,UsableConnection}`: the one place the global
    switch, "can it work" and the application's list (or, for a third party, the domain flag)
    are combined — `available()`, `allows()`, `pools()`, `external()`.
    `Port\IdentityProviders::for(Connection)`, `IdentityProvider::name()` and its `Nonce`
    arguments; `Port\{OidcDiscovery,DiscoveredProvider,DiscoveryFailed}`.
  - `SignInWithPassword` looks in the application's pools only (`PasswordSignInUnavailable`
    when it has none); `BeginExternalSignIn` answers `ExternalSignInUnavailable` for a
    connection the application does not enable, and sends a nonce; `CompleteExternalSignIn`
    checks again (`ExternalSignInFailure::NotAvailable`); `ResolveExternalAccount` links by
    address within the application's pools and the connection itself; a new account belongs
    to the connection that made it. `Authorize` treats a session established through a
    connection the client does not allow as nobody signed in. `DescribeLoginPage` describes
    `SignInMethods` (the password form, the provider links).
  - `Management\Connections\{ReadConnections,DescribedConnection,NewConnection,
    CreateConnection,UpdateConnection,DeleteConnection,OidcConfiguration}`,
    `Management\Clients\ClientConnections`, `Management\Users\{ReadIdentities,UnlinkIdentity}`;
    `read|create|update|delete:connections`.
  - `Adapter\Secondary\Http\{OutboundUrlPolicy,OutboundUrlRefused,PinCheckedAddresses}`;
    `IdentityProvider\{ConnectionIdentityProviders,OidcIdentityProvider,IdTokenVerifier,
    JwksCache,HttpOidcDiscovery}`, `Redis\RedisJwksCache`, `PhpDb\PhpDbConnectionRepository`.
    Migration `0019_connections` (`connections`, `client_connections`, `users.connection` with
    `uq_users_connection_email`, the foreign key from `external_identities.provider`).
    `PhpDbUserRepository::save()` now stores a changed address, which it silently kept before.
  - `Management\{ConnectionsHandler,ConnectionHandler,ClientConnectionsHandler,
    UserIdentitiesHandler}`; `templates/auth/login.phtml` shows only the methods available.
    The dashboard has a Connections page, a client's connections, a user's pool and
    linked identities.
- **Error pages for browsers** (after Step 3): `Adapter\Primary\Http\Shared\ClientPreference`
  (`Accept` negotiation), `ErrorResponder` + `ErrorPage`, `PageRenderer` + `HtmlPage` (the
  layout, headers and CSP every server-rendered page shares). 404, 405, 500 and the
  authorization endpoint's non-redirectable errors are a page for a browser and JSON (plain
  text for 500) for anything else.

Conventions established in Step 0 that later steps keep:

- **Two namespaces sit outside the three rings.** `Clavia\Configuration` is the typed settings:
  plain data with no dependency, readable by adapters and the composition root, never by
  `Domain` or `Application` (they receive the few values they need as constructor arguments).
  `Clavia\Bootstrap` is the composition root: the only code that reads the container, the only
  code allowed to import every layer. `deptrac.yaml` encodes both.
- **One factory class per service**, in `Bootstrap\Container`, registered in
  `Bootstrap\ConfigProvider`. No closures in configuration, no autowiring, no service location
  anywhere else in `src/`.
- **A new setting is a constructor parameter of `Settings`** — with a default, a doc comment
  saying why it exists, a `#[Range]` when it is a number, and a test. Nothing else needs editing.
- **A new console command** is a `symfony/console` command in `Adapter\Primary\Cli`, a factory, and one line
  in `ConfigProvider::CONSOLE_COMMANDS`. `bin/clavia` refuses to run any command on an invalid
  configuration (exit 78) and prints `Settings::warnings()` to stderr.
- **JSON responses use the standard tooling** (Diactoros `JsonResponse`, or a thin PSR-17-based
  responder injected by interface) with encoding flags chosen for PHP and browsers, not for
  byte-parity with FastAPI. Generic error bodies are ours to design (consistent, documented in
  the OpenAPI document); an uncaught error stays a bare 500 that reveals nothing.
- **An uncaught error never describes itself to the client, in any environment.** The cause is
  logged (monolog → stderr → the PHP-FPM/container log). Every PHP warning or notice is an error:
  the entry points set `error_reporting(E_ALL)` and the pipeline turns them into exceptions.
- **No `X-Forwarded-*` header is trusted by default.** Behind Caddy over FastCGI the scheme and
  client address come from the web server. `CLAVIA_TRUSTED_PROXIES` names the proxies whose
  `X-Forwarded-Proto` is believed; the host is never taken from a header.
- **Caddy owns the files, PHP owns everything else.** `/auth/static/*` and `/favicon.ico` are
  served from `public/` by Caddy; `php_fastcgi` runs `index.php` and no other script. The host
  split (`/api/v1/*` only on `management.*`) is still enforced in the `Caddyfile`.
- **Acceptance tests extend `ClaviaTest\Support\AcceptanceTestCase`**: the real container,
  pipeline and routes, in-process, with settings built from `TestEnvironment::variables()` —
  never from the machine's `.env` — and a `RecordingLogger`. PHPUnit lowers `error_reporting`
  while a test runs; the base class restores `E_ALL`.
- **Every PHP file starts with the header in `.docheader`** (`LicenseHeaderTest`).
- **A deliberate difference from the Python server is recorded in `docs/DEVIATIONS.md`** in the
  same change that introduces it.

Conventions established in Step 1:

- **`RandomSource` lives in `Domain\Shared` next to `Clock`**, not in `Application\Port`: the
  domain itself mints secrets (`SecretGenerator`), and rule 1 says randomness reaches it
  through a port. `Application\Port` holds the ports only use cases need.
- **A value object is built by a named constructor that throws `InvalidValue`** (`fromString`,
  `fromHex`, `of`); its real constructor is private. Anchored patterns use the `D` modifier —
  without it `$` accepts a trailing newline.
- **Never read a value back from an array key.** PHP turns an all-digit string key into an
  integer (`'10'` → `10`); `ScopeSet` and the migrator keep keys for lookup only.
- **Every repository goes through `Adapter\Secondary\Persistence\PhpDb\Database`**: SQL written
  out, named parameters (`:client_id`), plain rows back. `fetchAll` / `fetchOne` / `fetchValue`
  / `execute` (returns the affected-row count — the answer to "did I win?" for a conditional
  `UPDATE … WHERE used_at IS NULL`). The library's query builder is reachable through
  `Database::adapter()` for dynamic filters only. Generated keys are read with
  `INSERT … RETURNING`, never "last insert id".
- **A use case that must be atomic wraps itself in `TransactionManager::transactional()`.** A
  nested call joins the outer transaction; an exception anywhere rolls all of it back; there
  are no savepoints, and catching a database error inside a transaction to carry on is not
  possible (PostgreSQL refuses everything after a failed statement). Isolation is READ
  COMMITTED; exactly-once rests on row locks or conditional writes, not on the isolation level.
- **Migrations are `migrations/<version>_<name>.sql`** (`0003_refresh_tokens.sql`), forward
  only, one transaction each, immutable once applied (checksummed), linear (a pending file
  older than an applied one is refused). A step adds its files in the same change as the code
  that needs them. No `CREATE INDEX CONCURRENTLY` in a migration: it cannot run in a transaction.
- **PostgreSQL and Redis connections are lazy.** Building the container opens neither;
  `/healthz` touches neither (there is a test for it).
- **Redis keys are `<prefix>:<identifier>`**, built by `Redis\Keys`: `forSecret()` digests
  whatever a browser could present (session ids, handles, device codes), `forIdentifier()` is
  for user ids and `sid`s.
- **Secrets that must be read back go through `SecretCipher`, with a row-specific context**
  (`kid`, `user:42:totp`). The token format is `base64(nonce ‖ ciphertext ‖ tag)`; a
  known-answer test pins it, so stored secrets cannot silently become unreadable.
- **bcrypt takes 72 bytes.** `PasswordHasher::hash()` throws `SecretNotHashable` beyond that
  (and on a NUL byte) instead of truncating; `verify()` returns false. Password and
  client-secret validation in later steps must turn that into a proper validation error.
- **Each port ships with a double and a contract.** `test/Support/Fake/X` plus, where behaviour
  is shared, an abstract `test/Support/Contract/XContract` that both the double's test and the
  adapter's test extend. A double that drifts from its adapter fails its own test.
- **Three test suites, three bases.** `Unit` (no I/O: domain, use cases with doubles, pure
  adapters such as crypto), `Integration` (`IntegrationTestCase`: one adapter against real
  PostgreSQL/Redis, with a scratch schema per test for tables of its own), `Acceptance`
  (`AcceptanceTestCase`: the whole application). The last two wipe every table and Redis
  database 1 before each test; `TestEnvironment` refuses a database whose name does not end in
  `_test` and Redis database 0.

Conventions established in Step 2:

- **A use case is an invokable class named for what it does** (`Authorize`, `IssueToken`),
  taking one request object and returning a result object. Expected outcomes are return values
  (`CodeIssued | RequestRefused | LoginRequired`); `OAuth2Error` is thrown only where the
  protocol answers with an error document. The primary adapter turns both into HTTP and decides nothing.
- **The authorization endpoint settles the client and the redirect URI before anything else,
  and throws if it cannot** — that error is shown, never redirected. Everything validated
  afterwards is reported *to* the registered redirect URI with `state` and `iss`. Validation
  comes before login: an invalid request never sends anyone to the sign-in page.
- **Redirect URIs match as exact strings** (`Client::hasRedirectUri`). No normalisation, no
  prefix, no wildcard — and the URI is appended to, never parsed and rebuilt.
- **`HEAD` is not `GET`.** Mezzio's `ImplicitHeadMiddleware` is deliberately absent: it would
  answer `HEAD /oauth2/authorize` by running the handler, which mints a code. FastAPI did not
  answer `HEAD` either.
- **Any repeated request parameter is refused** (RFC 6749 §3.1). Handlers read parameters
  with `RequestParameterReader`, never `getQueryParams()` / `getParsedBody()`, which silently
  keep the last value and rewrite names.
- **A secret handed to a client is stored as its `Digest` and looked up by it**
  (`code_hash`, `token_hash`). The aggregate never holds the plain value; the use case returns
  it once.
- **Exactly-once is a locked row.** `AuthorizationCodeRepository::lockForRedemption()`
  (`SELECT … FOR UPDATE`, refuses to run outside a transaction) → `AuthorizationCode::redeem()`
  → `save()`, all inside one `transactional()`. The code is spent *before* the redirect URI
  and the verifier are checked, so a wrong guess burns it; a refusal that must survive is
  returned from the transaction and thrown after commit — throwing inside would roll the
  spend back. A replay revokes what the code minted; a code presented by another client
  changes nothing.
- **Client authentication is one method per request, and it must be the registered one.**
  The method is read from what the request carries — an `Authorization` header means Basic, a
  body `client_secret` means `client_secret_post`, a bare `client_id` means `none` — and is
  never "tried in turn": failed Basic credentials fail the request even if the body names a
  valid public client, and mixing methods is refused (RFC 6749 §2.3). The method must equal
  the client's `token_endpoint_auth_method`, so the right secret through the wrong door
  fails, and a confidential client presenting only its id fails. Every failure is the same
  `invalid_client`.
- **A grant is a class implementing `Token\Grant`**, registered in `IssueTokenFactory`.
  `IssueToken` owns what every grant shares: repetitions, `grant_type`, client authentication,
  the client's permission to use the grant.
- **A table holds only the columns the code reads.** `nonce`, `auth_time`, `sid`, `amr`,
  `audience`, profile fields, `is_first_party`… are added by a migration in the step that
  introduces them, not ahead of time. Lists are `jsonb`; instants are `timestamptz`, written
  and read through `Timestamp` (UTC, microseconds).
- **Entities returned by a repository are copies**: a change exists in storage only once it is
  saved. The in-memory doubles clone on the way in and out to behave the same.
- **Identifiers**: UUID v4 value objects extending `UuidId` (`UserId`, `AuthorizationCodeId`,
  `AccessTokenId`), never equal across kinds. `ClientId` is 1–64 visible ASCII characters
  without a colon (HTTP Basic could not carry one); generated ids are 32 alphanumerics.
- **Development-only code checks for itself.** `DevelopmentAutoLogin` and
  `SeedDevelopmentData` receive `isDevelopment` and throw outside it, on top of the settings
  validation that already forbids the combination.
- **OAuth2 responses go through `Adapter\Primary\Http\OAuth2\OAuth2Responder`**, built on Diactoros
  `JsonResponse` and a PSR-17 `ResponseFactoryInterface`. Token-endpoint errors are 400, or 401
  with `WWW-Authenticate` for `invalid_client`; an authorization-endpoint error that cannot be
  redirected is a plain 400 and never a challenge (a browser would prompt for a client secret).
  A browser gets that last one as a page; see "An error is a page for a person".
- **Acceptance tests state behaviour, not Python parity.** `AuthorizationCodeFlowTest` and
  `PkceSecurityTest` cover every behaviour of the Python suites they came from, through
  `OAuth2Fixtures`; where the RFC-correct answer differs from what Python gave, the test
  asserts the RFC-correct one and `docs/DEVIATIONS.md` keeps the note.

Conventions established in Step 3:

- **One door per session operation.** `Sessions::establish()` is the only way a browser
  becomes authenticated (it always rotates: the identifier the browser held is ended),
  `resolve()` the only way one is read (it slides the idle window, never past the absolute
  ceiling, and deletes a session found past it), `end()` the only way one stops. Later
  sign-in flows (second factor, social, passwordless) call `establish()` with their own
  `AuthenticationMethod`s. The session identifier is a 43-character token stored as its
  digest; the `sid` is a second, unrelated token.
- **Sign-in failures are one outcome.** `CredentialsRejected` covers an unknown account, a
  wrong password, a deactivated account, one without a password and a throttled subject; the
  page shows one message with one status. Whenever no real hash is checked,
  `PasswordHasher::simulateVerification()` spends the same time. Throttling counts per account
  (case-insensitive) and per client address (`REMOTE_ADDR`, never a forwarded header).
- **`ResolveEndUser` answers "who is this?" for every browser-facing handler**, re-checking
  that the account is still active on every request.
- **A `Location` built from anything a client or a store supplied goes through `LocalPath`**
  (or, for sign-out, an https URL on an origin some client registered). Rejected, never
  repaired.
- **Cookies are read from the `Cookie` header** (`RequestCookies`, which keeps every value of a
  name in the order sent) **and written through `SetCookie`** (`HttpOnly; SameSite=Lax`, never
  a `Domain`, name and value validated so nothing can split the header). `AuthCookies` owns
  each cookie's name, path and lifetime, so a cookie is always deleted with the path it was set
  with.
- **CSRF is double-submit, per browser.** `AuthPageResponder` reuses the token the browser
  holds (minting one only when there is none) and refreshes its cookie on every page; every
  `/auth/*` form posts it and `CsrfToken::isValid()` accepts a match with any held value.
  Logout and the theme toggle need none (a `SameSite=Lax` session cookie never rides a
  cross-site POST; a colour scheme is not worth forging).
- **A server-rendered page is an `HtmlPage` view model rendered by `PageRenderer`** (the
  `layout::page` layout and the headers every page carries); `AuthPageResponder` adds the
  CSRF token for auth pages. The handler decides every value (`LoginPages` builds the login
  page's); templates print and loop. Every page gets `Cache-Control: no-store`,
  `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: same-origin` and a CSP with no script
  source and a `form-action` naming the application's redirect origins when the page belongs
  to an authorization request.
- **An error is a page for a person and data for a program.** `ClientPreference::prefersHtml()`
  says which: HTML only when `Accept` names `text/html` (or `text/*`, or
  `application/xhtml+xml`) at a weight at least as high as JSON's — `*/*` alone, or no
  `Accept`, is a program. `ErrorResponder::respond()` sends the same status and headers either
  way with an `ErrorPage` (title, what happened, what to do, an optional reference) or the
  JSON document. Error text never comes from the request, an error page offers no link or
  form onwards (the only address a refused request named is the untrusted one) and sets no
  cookie. Endpoints whose format a specification fixes — `/oauth2/token`, and later
  introspection, revocation, userinfo — answer JSON whatever `Accept` says. An uncaught error
  is logged under a 12-character reference, sent in `X-Error-Reference` and shown on the page;
  if the page itself fails to render, the plain `Internal Server Error` goes out instead.
- **Every printed value is escaped by the template** with `escapeHtml()` /
  `escapeHtmlAttr()` — laminas-view does not escape on its own. `AuthPagesEscapingTest`
  renders every page with hostile values; a new page or template variable gets a case there.
  A line under the heading goes in the `subtitle` placeholder.
- **An acceptance test that moves time calls `freezeClock()`** before its first request. The
  harness drops each test's container in `tearDown()`; PHPUnit keeps finished tests alive,
  and a container left on one holds a PostgreSQL connection.

Conventions established in Step 4:

- **Signing goes through `TokenSigner` and nothing else.** A caller asks for the active key's
  reference (`kid`, `alg`), builds the header and claims, and has `CompactJws` sign the
  signing input; no code outside a signing adapter ever sees a private key, and in the
  `postgres` backend only `PostgresTokenSigner::sign()` opens one. A later token type (the
  logout token of Step 17) is `CompactJws::sign()` with its own `typ`.
- **The JWKS is rendered from stored public keys** (`PublicJwk`, which has no field a private
  member could go in, and refuses a document carrying one). It is published with
  `Cache-Control: public, max-age=PublishSigningKeys::CACHE_MAX_AGE`; discovery likewise with
  `DiscoveryHandler::CACHE_MAX_AGE`. Both numbers are part of the rotation reasoning.
- **Key lifecycle**: one active key (enforced by the database too), `keys:generate` only when
  there is none, `keys:rotate` retires the active key with `RotateSigningKey::grace()` — twice
  the longest token lifetime plus a day — and publishes both. Nothing ever creates a key on
  first use; issuing without one is `NoActiveSigningKey`, a loud server error.
- **What a scope releases is `IdentityClaims::of()`**, for the ID token and userinfo alike;
  an unknown value is left out, never sent as null.
- **An ID token reports only what this server witnessed.** `auth_time` and `amr` come from
  the session that approved the code (`EndUser::authentication()`), captured on the code;
  without a session (the development auto-login) both are omitted.
- **A protected resource reads its token with `BearerCredentials`** (the `Authorization`
  header only, one method per request) **and refuses with `BearerChallenger`** (no
  credentials: a bare challenge; otherwise the RFC 6750 status, challenge and error document;
  never cacheable). Use cases throw `BearerTokenError`. The Management API (Step 6) reuses both.
- **Discovery names only what exists**, and states every field whose default differs from
  the server. `ProviderMetadata` holds the endpoint paths; `OidcTest` fetches each one, and a
  step that adds an endpoint or a grant adds it there (grants and client authentication
  methods are read from `IssueToken`, so they cannot drift).
- **An exchange that cannot be completed is not completed at all**: the ID token is signed
  inside the redemption's transaction, so a signing failure rolls back the access token and
  leaves the code unspent.

Conventions established in Step 5:

- **A client holds nothing of its own.** Acting as itself, what it may take from an API is its
  `ClientGrant` there, read through `grantableOn()` — intersected with the API's permissions
  *now*, so withdrawing a permission takes effect on the next token. A grant naming a scope
  the API does not define cannot be created.
- **A machine token always names its API.** `audience` is required by the grant and stored
  on the token (`aud`); `openid` is refused before anything else; a scope beyond the grant
  is refused, never narrowed; an omitted scope is the whole grant. The errors tell the
  caller what to fix: `invalid_request` (no audience), `invalid_target` (unknown API),
  `access_denied` (no grant there), `invalid_scope`.
- **A token without a subject answers no question about a person.** Every surface that
  describes a user (userinfo now; introspection's `sub`, the Management API's "me" later)
  refuses a token whose `userId` is null.
- **Client grants are written from the shell only**, never over HTTP: an endpoint that wrote
  them would let a caller widen its own access.

Conventions established in Step 6:

- **The Management API is contract-first.** `docs/openapi/management-api.yaml` is written by
  hand and is the source of truth: `ManagementApiMiddleware` validates every request against
  it, the scope each route enforces is the one its operation's `security` requirement names
  (there is no second list), and `ManagementFixtures::api()` checks every response the
  acceptance tests receive. A new operation is a path in the document, a route in
  `config/routes.php` behind `ManagementApiMiddleware`, and a handler; `ManagementApiTest`
  fails if the routes and the document disagree, and `ManagementContractTest` if the
  document's scopes are not exactly `ManagementPermission::cases()`.
- **One order of checks**: credentials, the token (live, issued for this API — `aud` before
  any scope — its subject still active), the scope, then the request: a parameter twice,
  unreadable JSON or bad percent-encoding (400), not JSON (415), anything the contract or the
  domain refuses (422) — every violation listed, at most fifty.
  `NotFound` is 404; `Conflict`, `AlreadyExists` and `SystemApiProtected` are 409.
- **Errors are RFC 9457 problem documents** (`type: about:blank`, `title`, `status`,
  `detail`, and `errors[]` with a `pointer` or a `parameter` for a contract violation).
  Bearer refusals stay RFC 6750 documents. An error never repeats the value at fault.
  Nothing the Management API answers is cacheable.
- **Handlers state the success only.** They read a `ManagementRequest` (the caller, the
  `ValidatedRequest` with its typed parameters, and the body as a `JsonObject`), call one use case and render with `ManagementViews`; the
  middleware turns the use cases' expected refusals into problems. A `JsonObject` value of
  the wrong type is a `LogicException`: the contract let something through it should not.
- **Lists are `ReadX::page(PageRequest)`**, newest first (`created_at DESC, id`), the search a
  case-insensitive literal (`Search` escapes `%` and `_`), returned as `{items, total, page,
  per_page}`.
- **A unique constraint is the arbiter of uniqueness.** A repository turns its violation
  (SQLSTATE 23505 on the named constraint, `Constraint::isUniqueViolation()`) into
  `AlreadyExists`; nobody checks first and inserts second.
- **A system API is the server's own.** The Management API is registered from the shell,
  marked `is_system`: it can be renamed, never deleted, and its permissions are
  `ManagementPermission`'s — re-registering after an upgrade brings them up to date. It
  always enforces roles (Step 10).
- **`audience` in a user's flow** names the API whose permissions the scope may hold next to
  the OIDC scopes; an unknown API is `invalid_target`, a malformed one `invalid_request`. It is
  stored on the code and re-checked at redemption: the scope is cut to what is still defined,
  and a code for an API that is gone is `invalid_grant`.

Conventions established in Step 7:

- **A correct password is not a session once a factor is confirmed.** It opens a challenge
  instead — in Redis, keyed by the digest of a handle the browser holds in `clavia_mfa`
  (`Path=/auth`, `HttpOnly`, as long as the challenge) — and the session is established only
  by `CompleteSecondFactor`, with `amr` = the first factor's methods + `otp` (an app code)
  + `mfa`. A pending factor enforces nothing: someone who scans and walks away is not locked
  out.
- **A code is spent when it is used.** The factor row is locked (`FOR UPDATE`) for the check
  and the step recorded; a recovery code is spent by one conditional `UPDATE`. Two requests
  with one code cannot both succeed.
- **Guesses are bounded twice**: per challenge (`CLAVIA_MFA_MAX_ATTEMPTS`, counted atomically,
  the challenge destroyed at the limit) and per account and address by the sign-in throttle,
  which a throttled attempt does not get past even with the right code. The account is
  re-read at the second step and must still be active.
- **Seeds are sealed, never hashed**: `SecretCipher` with `user:<id>:totp` as associated
  data, so a ciphertext moved onto another account's row does not open. The seed is
  decrypted only for a check.
- **Pages that change an account need a real session** (`ResolveEndUser::bySession()`, never
  the development auto-login); without one, `RequireSignIn` parks the page behind the login and
  the person comes back to it. Their forms check the CSRF token and, failing it, change nothing.
- **The QR code is drawn by the HTTP adapter** (`QrCodeSvg`), not behind a `QrRenderer`
  port: it is presentation, and the use cases hand out the provisioning URI. The SVG is
  cleaned for the page's policy — no `style`, no background, `fill="currentColor"` so it
  follows the theme, `role="img"` with a label — and the URI never appears in the markup.
- **The recovery codes exist in the clear once**, in the response that turns two-factor
  authentication on; only their digests are stored, and a new set replaces the old one.

Conventions established in Step 8:

- **Outbound HTTP is PSR-18, injected.** Adapters receive `Psr\Http\Client\ClientInterface`
  with PSR-17 request and stream factories, never a concrete client; the composition root
  builds Guzzle (`HttpClientFactory`: 5 s to connect, 10 s in all, no redirect followed, no
  exception on a status). Tests swap in `Fake\FakeHttpClient`, so nothing in the suite reaches
  a real provider. The PSR interfaces are the port: there is no `OutboundHttp` wrapper.
- **Clavia as an OAuth 2.0 client holds itself to its own rules**: an opaque `state` in the
  redirect and in a cookie (`clavia_external_state`, `Path=/auth`), the two compared in
  constant time before anything is looked up, then claimed with `GETDEL` so it works once;
  PKCE S256 sent to every provider; the same redirect URI (`ExternalCallbackUrl`, under the
  issuer) at both ends; the code exchanged server side with the secret in the body.
- **An identity is `(provider, subject)`, never an address.** `ResolveExternalAccount` applies,
  in order: a linked subject wins; an address the provider does not vouch for links and creates
  nothing; a verified address matching one account (ignoring case) links to it when
  `CLAVIA_SOCIAL_AUTO_LINK` allows, two is no answer; otherwise a password-less, verified account
  is created. A first sign-in racing with itself is settled by the primary key and resolved again.
- **Every first factor ends at `CompleteFirstFactor`**, so a second factor turned on is asked
  for whichever way the person signed in. `amr` is `ext` for an external sign-in: outside the
  RFC 8176 registry, which has no value for "another provider vouched for them".
- **A provider's words never reach the page.** Failures are an `ExternalSignInFailure`, worded by
  `ExternalSignInMessages`; the reason is logged by `ProviderHttp` (endpoint and status, never a
  body), and the refusal is the login form as if reached directly. An unknown and an
  unconfigured provider are the same 404.

Conventions established in Step 9:

- **A session ends at an application's request only on proof.** `EndSession` ends it at once
  when `id_token_hint` verifies against the keys this server publishes (retired ones
  included), names this issuer, and its `sub` is the session's person; the hint's expiry is
  not checked (RP-Initiated Logout 1.0 §2). Anything less shows a confirmation page whose
  form posts back with `confirmed=yes` — a same-site POST, so the `SameSite=Lax` session cookie
  is with it, while a forged cross-site one arrives without it. `confirmed` is read from a
  POST only.
- **Where the browser goes after sign-out is registered, per client, and matched exactly** —
  `post_logout_redirect_uris`, kept apart from redirect URIs — with `state` appended. The
  client is the hint's audience (`azp` when there are several) or `client_id`; the two must
  agree, or neither counts. Anything unregistered is not followed: the browser lands on the
  login page. `/auth/logout`'s own `next` keeps its origin rule for this server's pages.
- **Verifying is not signing.** `SignatureVerifier` checks a compact JWS against public keys
  only; the key is picked by `kid`, and the algorithm is the key's, never the header's.
  `web-token/jwt-library` does that and nothing else — it still never signs.
- **The dashboard is an ordinary public client**, registered by `seed-dev` with its callback
  and its signed-out page under `management.{domain}/dashboard/`; `frontend/.env.local` is
  written from the same values.

Conventions established in Step 10:

- **A person comes to hold a permission only through a role.** On an API with
  `enforce_policies`, the authorization endpoint refuses `access_denied` to somebody who holds
  nothing there (before a code exists, the error sent to the client), and redemption cuts the
  API's permissions in the scope to what their roles grant *then* — roles are read for every
  token, never trusted from a code. OIDC scopes pass untouched. Without `enforce_policies`, the
  API's definitions are the only bound. A machine client is governed by its client grant
  either way. A system API always enforces roles.
- **Links are foreign keys onto what they name.** A role grants `(resource_server_id, value)`
  through a composite key onto `permissions`, so a permission an API stops defining leaves every
  role; deleting a role or an account takes its assignments. Because of that,
  `PhpDbResourceServerRepository` reconciles permission rows (delete what went, upsert what
  stays) — a row deleted and inserted again would take every role's grant of it along. The
  in-memory doubles apply the same cascades as they read.
- **Conferring authority needs `update:roles`**, wherever it happens: on the role
  (`/roles/{id}/users`) or on the account (`PUT /users/{id}/roles`); `update:users` never
  suffices. The first holder is made at the shell (`roles:create`, `roles:assign`).
- **Assignments are idempotent and refused whole.** Giving a held role or taking one not held
  changes nothing; naming one account or role that does not exist is a 404 and changes
  nothing. A `DELETE` carries no body (OpenAPI 3.0 gives one no meaning): taking a role names the
  account in the path.
- **A collection small by nature is a JSON array** (`ManagementResponder::jsonList()`: an
  account's roles, its effective permissions); anything that grows is a page.

Conventions established in Step 11:

- **A refresh token is good for one refresh.** Every refresh spends it, under the row lock,
  and issues a new pair; there is no reuse grace period. A spent token presented again is a
  replay: the family and every access token it minted are revoked (RFC 6749 §10.4). A
  replayed authorization code revokes the family it started, too.
- **Only a refresh that succeeds spends the token.** A wider scope (`invalid_scope`), another
  client, an expired or revoked token, a deactivated account, roles taken away
  (`invalid_grant`) leave it as it was. Every bad token is the same `invalid_grant`.
- **What a token may carry is decided at every issuance** by `UserScope`: the API's current
  permissions, narrowed to the person's roles when it enforces them. A refresh token holds
  the ceiling — what was authorized, or narrowed by the client since — not what the last
  access token carried, so a role given back is honoured by the next refresh.
- **Three lifetimes**: the access token's; the refresh token's idle limit
  (`CLAVIA_REFRESH_TOKEN_LIFETIME`) from its own issuance; the family's deadline
  (`CLAVIA_REFRESH_TOKEN_ABSOLUTE_LIFETIME`) fixed at sign-in. No token outlives the family.
- **A refresh issues no ID token** (OIDC Core §12.2) and ignores `audience`: a family is for
  one API.

Conventions established in Step 12:

- **Ownership is identity, written in the id.** A third-party application is registered
  under `tpc_…` and stays third-party; nothing stores it a second time. A third-party
  application never gets a token for a system API — on anybody's behalf (refused at the
  authorization endpoint before anyone signs in) or as itself (refused by `clients:grant`
  and again at the token endpoint, so a grant written around the command mints nothing).
- **Who is asked is `ConsentPolicy`'s decision**, made after the roles check and before a
  code exists: `prompt=consent` asks; a first-party application does not ask for no API or
  an API that allows skipping; otherwise a consent on record must cover every scope for this
  application on this API. Allowing widens the record; refusing records nothing.
- **A request waiting for the person is resumed, not replayed from storage.** The login page
  and the consent screen send the browser back to `/oauth2/authorize` with every parameter
  (`AuthorizationRequest::resumption()`), minus a `prompt` value that has been satisfied, and
  the endpoint decides again with everything as it is then.
- **A handle is the only thing a page's URL or form carries**, for consent as for sign-in; a
  handle that is unknown, spent, expired, someone else's or names something deleted is the
  same "expired" page. Showing the screen leaves it; deciding claims it (`GETDEL`).

Conventions established in Step 16:

- **A mailbox is one factor, and its own connection.** Passwordless accounts belong to
  `email`, created on first sign-in with the address verified; a password account at the
  same address is another account. What follows the proof is `CompleteFirstFactor`, like
  every other first factor, so a second factor still applies. `amr` is `otp`.
- **A code answers one browser; a link answers whoever opens it — on a POST.** The code is
  checked against the challenge the browser's cookie names, within a small budget of wrong
  answers; a link's GET only asks, so a mail scanner spends nothing. A code challenge's
  handle is never accepted as a link.
- **Mail is sent synchronously and its failure is said plainly** (`503`); a message that
  cannot go out leaves nothing pending. A backend that sends nothing (`none`) makes the
  connection unusable rather than failing on use.

Conventions established in Step 15:

- **A device request is checked like an authorization request**, by the same code, and the
  person's decision like an authorization: the session counts only through a connection
  the application enables, and on an API enforcing roles somebody holding nothing there is
  refused. An approval is a consent on record.
- **A device code is a secret, and redeemed once**: kept only as a digest, consumed before
  any token exists. The user code is what a person types, and stands for one live request.
- **Polling follows RFC 8628 §3.5**: `slow_down` adds five seconds for good; only a pending
  request is held to the interval; past its life a request says `expired_token` for a minute,
  then nothing.

Conventions established in Step 14:

- **Introspection answers only a client that proves itself with a secret**, and only about a
  token it has a stake in: its own, or one issued for an API it holds a client grant on.
  Everything else — unknown, expired, revoked, spent, a deactivated account's, someone
  else's — is the same `{"active": false}`.
- **Revocation is giving back what one holds**: any client, a public one by its id, may
  revoke a token issued to it; another client's is `invalid_grant`, an unknown one a quiet
  `200`. A refresh token takes its family — refresh and access tokens — along; an access
  token goes alone.
- **The hint says where to look first, never where to look only.**

Conventions established in Step 13:

- **Every account belongs to one connection**, and an address is unique within it: the same
  address in two pools is two accounts. Accounts are created in a pool; an external
  connection's are made by signing in through it.
- **What an application may use is `ConnectionAccess`'s answer, and nobody else's.** The
  login page, the password post, the provider link, the callback and the authorization
  endpoint all ask it, so hiding and refusing cannot disagree. No application in play means
  every usable connection; a first-party application goes by its own list; a third-party
  one gets the domain connections.
- **A session remembers its connection**, and counts only for an application that allows it
  — checked at every authorization request, so taking a connection away takes effect at once.
- **The code's connections are switched, never created or deleted**: the default pool and
  the social providers (`BuiltInConnection`, 409). A connection anything depends on — an
  account, a linked identity — is not deleted either; deleting one stops every application
  enabling it.
- **The server fetches an operator's URLs on https only, and never at its own network**:
  `OutboundUrlPolicy` checks the issuer, the endpoints its document names, and every request
  again when it is made, at the addresses it checked. An ID token is believed only once its
  signature, issuer, audience, expiry and nonce check out.

**Known defect in the database library, worked around.** At the pinned commit,
`php-db/phpdb-pgsql` runs `SELECT LASTVAL()` after every statement to fetch a "last generated
value". In a session that has not used a sequence that query fails; the library swallows the
exception, but PostgreSQL has already aborted the surrounding transaction, so its writes are
silently discarded and the final `COMMIT` becomes a `ROLLBACK`. `PostgresConnection` overrides
that lookup; `DatabaseTest::testReadingInsideATransactionDoesNotDiscardItsWrites` and the test
after it fail without the override. **Do not `composer update php-db/*` without running the
Integration suite**, and report the defect upstream.

**The OpenAPI validator is Clavia's own** (`Adapter\Primary\Http\OpenApi`, replacing
`phayne-io/openapi-psr7-validator`, whose security and response validation did not work).
OpenAPI 3.0.x only; it loads a document once and validates PSR-7 messages against it:

- `Document` (`fromYamlFile|fromYaml|fromJson`) → `DocumentReader` checks the whole document
  on load and builds `Operation`s (`Parameter`, `RequestBody`, `Responses`/`Response`,
  `Header`, `Content`, `MediaType`, `SecurityRequirement`). `Node` carries each value with its
  JSON pointer, so every `InvalidDocument` names its place (`#/paths/~1users/get/…`);
  `References` follows local `$ref`s only, refusing siblings and loops.
- `Schema\SchemaCompiler` → `Schema` (references through `SchemaSlot`, so recursive schemas
  work); `Schema\SchemaValidator` collects every violation (`SchemaViolation`: pointer +
  message), with `Direction` for `readOnly`/`writeOnly`, `Formats` for the formats it knows and
  `JsonValue` for JSON equality. Instances are decoded with objects as `stdClass`, so `{}` and
  `[]` differ.
- `Routing\Router` + `PathTemplate`: exact, case-sensitive methods; literal segments before
  templated ones; server base paths; unreserved percent-encodings normalised.
- `Validation\RequestValidator` → `ValidatedRequest` (parameters coerced by
  `ParameterDecoder`, the body parsed) or a `RequestRejected`: `MalformedRequest`,
  `UnsupportedMediaType`, `RequestDoesNotMatch`, each with every `Violation` (location, name,
  pointer, message); `OperationNotFound` otherwise. `Validation\ResponseValidator` throws
  `ResponseDoesNotMatch`. The HTTP status of each rejection is the adapter's choice
  (`Management\ContractViolation`).

Its rules: **what it cannot enforce, it refuses at load** — unknown keywords (a misspelt
`minLenght`), 3.1 forms, external references, non-JSON media types, parameter styles other
than `form`/`simple`, object parameters, `content` parameters, server variables — rather than
silently dropping a constraint; **every violation is reported**, never just the first;
**no message repeats the value at fault**; **coercion is exact** (`"02"` is not an integer);
**strict where the specification is loose** — a query parameter the operation does not
describe, a body sent to an operation that takes none, and a single value sent twice are
all refused.

Running it: `cp .env.example .env`, `./setup-ssl.sh`, `make up install migrate seed`, then
`https://auth.{domain}/healthz`. Tooling runs in the container: `make check`, `make config`,
`make migrate`, `make db-status`, `make seed`, `make authorize-url`. To walk the flow, open the
link `make authorize-url` prints and sign in as `dev@{domain}` / `devpassword`. `make seed`
also prints the token request for the development machine client, which holds every
Management API scope.

## How the migration works

- **The Python code is the specification, not the source.** Port *behaviour*, not structure:
  Authlib subclasses, FastAPI dependencies and SQLAlchemy models do not map onto a hexagonal PHP
  codebase and must not be transliterated. Read the Python module, its tests and the matching
  paragraph of `../Clavia Python/clavia/CLAUDE.md`, then design the PHP feature from the domain out.
- **The Python tests are a checklist of behaviours, not a contract.** Port the *intent* of each
  test; names, request/response shapes and error bodies follow the best PHP/RFC design. Extra
  unit tests for the domain come on top.
- **The HTTP contract is not frozen to Python.** Paths, JSON shapes and error bodies are designed
  cleanly (OAuth2/OIDC endpoints stay RFC-exact). The React dashboard (`frontend/`) is adapted
  to the PHP API where the two differ, rather than the API being bent to fit it.
- **Port the final design, not the history.** The Python project changed its mind along the way
  (client scope column dropped, `client_id` became the primary key, `audience`/`sid`/`amr` added
  later). Each step creates its tables and models directly in their final shape.
- **One step = one end-to-end feature**, merged only when green: acceptance tests, unit tests,
  Psalm, PHPCS and the architecture check.

## Decisions (made 2026-11-20)

| Topic | Decision |
|---|---|
| Language | PHP 8.5, `declare(strict_types=1)` everywhere |
| HTTP | **Mezzio** (PSR-7/11/15, laminas-servicemanager, FastRoute) — as a primary adapter only |
| Architecture | **Strict hexagonal** (ports & adapters) + DDD tactical patterns, enforced by tooling |
| Adapter naming | `Clavia\Adapter\Primary` (driving: HTTP, CLI) and `Clavia\Adapter\Secondary` (driven: persistence, Redis, crypto…) — Cockburn's terms; no `Ui` / `Infrastructure` |
| OAuth2/OIDC engine | **Own implementation, inside Clavia**, written from the RFCs in the domain/application layers. No league/oauth2-server, no external protocol library |
| Persistence | PostgreSQL through **`php-db/phpdb-pgsql`** (on `php-db/phpdb`), behind repository ports |
| Migrations | Plain SQL files, **written step by step** as each feature needs its tables — no upfront schema |
| Runtime | **PHP-FPM behind Caddy** (share-nothing; no worker mode) |
| Short-TTL state | Redis (`ext-redis`), behind store ports |
| Outbound HTTP | **Guzzle** as the PSR-18 client, injected by interface with PSR-17 factories (decided 2026-11-20) |
| Outbound mail | **Symfony Mailer**'s ESMTP transport behind the `Mailer` port; console and `none` backends of our own (decided 2026-11-21) |
| Dashboard | The existing **React** dashboard (`frontend/`), copied, changed only where the API it calls is designed differently — until Phase E replaces it with a **Next.js** application in its own repository, still served at `management.{domain}/dashboard/`, styled with Tailwind v4 and shadcn/ui (decided 2026-11-21) |
| Auth pages | **laminas-view** PHP templates through `mezzio/mezzio-laminasviewrenderer` — no Twig, no other template language, no JavaScript — see "Auth pages" |
| Namespace / licence | `Clavia\` · BSD-3-Clause |
| Existing data | None to carry over — the PHP schema is free to be designed cleanly |


## Hexagonal architecture — the rules

Three rings. Dependencies point inward only; nothing in an inner ring knows an outer one exists.

```
            primary adapters                                  secondary adapters
 ┌──────────────────────────────┐                    ┌──────────────────────────────┐
 │ Http (Mezzio handlers,       │                    │ Persistence (phpdb-pgsql)    │
 │   middleware, HTML pages)    │                    │ Redis stores                 │
 │ Cli (console commands)       │                    │ Signing (postgres, KMS…)     │
 └──────────────┬───────────────┘                    │ Crypto, Mail, HttpClient,    │
                │ calls                              │ Clock, Random, Deferred      │
        ┌───────▼────────────────────────────┐       └──────────────▲───────────────┘
        │ Application                        │                      │ implements
        │   use cases (inbound ports)        │──── outbound ports ──┘
        │   ┌────────────────────────────┐   │
        │   │ Domain                     │   │
        │   │ aggregates, value objects, │   │
        │   │ policies, domain services, │   │
        │   │ repository interfaces      │   │
        │   └────────────────────────────┘   │
        └────────────────────────────────────┘
```

### Layout

```
src/
  Domain/                     # pure PHP. No vendor import at all — not even PSR interfaces.
    Shared/                   #   Clock, RandomSource, SecretGenerator, Digest, Url, Scope(Set),
                              #   Audience, InvalidValue
    Client/                   #   applications: Client, RedirectUri, ClientAuthMethod, ownership
    Identity/                 #   User, Connection, ExternalIdentity, credentials, linking policy
    ResourceServer/           #   APIs, Permission, ClientGrant
    Rbac/                     #   Role, assignments, effective permissions
    OAuth2/                   #   AuthorizationRequest, Pkce, AuthorizationCode, AccessToken,
                              #   RefreshToken + family, DeviceAuthorization, Consent, OAuth2Error
    Oidc/                     #   IdTokenClaims, LogoutToken, SigningKey, Nonce, discovery metadata
    Authentication/           #   Session, LoginState, Amr, Totp, RecoveryCode, PasswordlessChallenge,
                              #   throttling policy
  Application/                # orchestration. Imports Domain only.
    <Context>/<UseCase>/      #   Command|Query (readonly DTO) + Handler + Result — one folder each
    Port/                     #   technical outbound ports: TokenSigner, SecretCipher, PasswordHasher,
                              #   TransactionManager, SchemaMigrator, Mailer, OutboundHttp,
                              #   OutboundUrlPolicy, DeferredTasks, *Store (Redis-shaped state)
  Adapter/                    # everything that touches the outside world, in two kinds.
    Primary/                  #   primary (driving) adapters: what calls the application.
                              #   Calls Application use cases only.
      Http/OAuth2/  Http/Oidc/  Http/Auth/  Http/Management/  Http/Shared/ (middleware)
      Cli/
    Secondary/                #   secondary (driven) adapters: what the application calls.
                              #   Implements Domain + Application ports.
      Persistence/PhpDb/      #     Database (the one door to PostgreSQL), repositories, mappers
      Persistence/Migrations/ #     SqlFileMigrator
      Redis/  Signing/  Crypto/  Mail/  HttpClient/  System/ (clock, random, deferred)
  Configuration/              # the typed CLAVIA_* settings. Plain data; depends on nothing.
  Bootstrap/                  # composition root: ConfigProvider + one factory per service.
config/                       # Mezzio entry files: config, container, pipeline, routes
templates/                    # auth pages: laminas-view layout/, auth/ (one per page), partial/
public/                       # index.php, auth/static/ (auth.css, icon — served by Caddy)
frontend/                     # the React dashboard, copied from the Python project
migrations/  docs/
test/
  Unit/ (Domain, Application with in-memory adapters)   Integration/ (each secondary adapter)
  Acceptance/ (ported Python tests, through the PSR-15 pipeline)
  Support/ (Fake/ doubles, Contract/ shared suites, the three base test cases)
```

### Rules — a violation is a build failure, not a review comment

1. **Domain imports nothing** outside `Clavia\Domain` and PHP core. No Mezzio, PSR-7, phpdb,
   Redis, `new DateTimeImmutable()` for "now", `random_bytes()`, `getenv()`. Time and randomness arrive
   through `Clock` and `RandomSource`.
2. **Application imports Domain only.** Use cases receive a Command/Query of scalars and value
   objects and return a Result or throw a domain exception. They never see a PSR-7 request, a
   session cookie, an SQL row or an HTTP status.
3. **Repository interfaces live with their aggregate in Domain**; purely technical ports live in
   `Application/Port`. Ports speak the domain's language and express intent, never mechanism:
   `RefreshTokenRepository::lockForRedemption(Digest)` — not `selectForUpdate()`.
4. **Adapters never call each other.** An HTTP handler does not touch a repository or Redis; a
   repository does not sign tokens. Cross-cutting needs go through a use case or a port.
5. **Primary adapters are translators.** A Mezzio handler does exactly: parse and validate the
   transport shape → build a Command → call one use case → map Result/exception to a response.
   Protocol decisions (which OAuth2 error, whether consent is needed, scope narrowing) are domain
   or application code; *encoding* them (redirect vs JSON, `WWW-Authenticate`) is the adapter's.
6. **The composition root is the only place that knows everything.** Wiring is in
   `Clavia\Bootstrap` (ConfigProvider and factories) and the `config/` entry files; nothing
   else in `src/` reads the container.
7. **Transactions are an application concern**: `TransactionManager::transactional(callable)`
   wraps a use case; the adapter decides what that means.
8. **Domain objects are immutable where they can be** (`readonly` classes, PHP 8.5 `clone with`),
   always valid (constructors/named constructors enforce invariants), and never anaemic: the rule
   lives on the aggregate that owns the data.
9. **Each port has an in-memory fake** in `test/Support`, and each real adapter has a contract
   test that runs the same suite against the fake and the real thing.

### Enforcement

- **deptrac** (`deptrac.yaml`; layers Domain, Application, PrimaryAdapter, SecondaryAdapter, Configuration,
  Bootstrap, plus a Vendor layer that Domain, Application and Configuration may not touch) runs
  in `composer check` and CI. Adding an exception to its config requires a note in this file.
- **Psalm** at level 1, no baseline. **PHPCS** PSR-12. **PHPUnit** 12.
- `DependencyRuleTest` asserts that no file under `src/Domain` has a `use` statement outside
  `Clavia\Domain` (and likewise for `Application` and `Configuration`) — the cheap, unarguable
  version of rules 1 and 2.

## What changes from Python, and why it matters

| Python | PHP | Consequence |
|---|---|---|
| Authlib `AuthorizationServer` + subclasses closing its gaps | Own protocol core in `Domain/OAuth2` | The "Authlib gaps" list becomes plain invariants. No per-request server object, no threadpool. |
| FastAPI routers + `Depends` | Mezzio handlers + PSR-15 middleware per surface | Four pipelines (`/oauth2`, `/oidc`, `/auth`, `/api/v1`), each with its own authentication middleware. |
| Pydantic, `extra="forbid"` | OpenAPI document + Clavia's own validator (`Adapter\Primary\Http\OpenApi`, `additionalProperties: false`) at the edge, then typed Commands | The Management API is contract-first: `docs/openapi/management-api.yaml` is the source of truth. Errors are RFC 9457 problem documents, not FastAPI's `{"detail": …}`. |
| SQLAlchemy models + Alembic | Aggregates + phpdb-pgsql repositories + SQL migrations | Models are not table-shaped; mappers live in the adapter. |
| `pydantic-settings` | A typed, validated `Settings` object built once in the composition root | Same `CLAVIA_*` names and the same validators (e.g. console mail refused outside development). |
| Jinja2 | laminas-view PHP templates (layout, pages, partials) behind Mezzio's `TemplateRendererInterface` | No Twig. Escaping is explicit (`escapeHtml`/`escapeHtmlAttr`) and tested. Still **no JavaScript** on the auth origin. |
| `BackgroundTask` (back-channel logout) | `DeferredTasks` port; FPM adapter runs after `fastcgi_finish_request()` | Must work without a queue; keep the port so a queue adapter can replace it. |
| `httpx` + `MockTransport` | Guzzle, injected as a PSR-18 `ClientInterface`; `FakeHttpClient` in tests | `OutboundUrlPolicy` (SSRF guard, Step 13) checks every outbound URL, and `PinCheckedAddresses` makes the request to the addresses it checked (`CURLOPT_RESOLVE`). |
| `cryptography` | `ext-openssl`: RSASSA-PKCS1-v1_5/SHA-256, AES-256-GCM with AAD | JWS assembled by hand, as in Python. |
| `pwdlib[bcrypt]` | `password_hash(PASSWORD_BCRYPT)` behind `PasswordHasher` | |
| `joserfc` | `web-token/jwt-library` — **verification and JWK handling only** (`JoseSignatureVerifier`) | Never used to sign. |
| `qrcode` (SVG) | `bacon/bacon-qr-code` SVG writer | Server-side only. |
| `smtplib` | `symfony/mailer` — the ESMTP transport and `symfony/mime` only, behind the `Mailer` port | No Messenger, no bus: a sign-in email is sent while the person waits for the answer. |
| Typer CLI | `symfony/console` commands in `Adapter/Primary/Cli`, run by `bin/clavia` | Same command names: `clavia seed-dev`, `keys rotate`, … |
| uvicorn `--forwarded-allow-ips` | `CLAVIA_TRUSTED_PROXIES`, applied when the request is built | Empty by default: over FastCGI the web server reports the scheme itself. |
| pytest, `db-test` :5434, Redis db 1 | PHPUnit, same databases, real migrations | Acceptance tests run the PSR-15 pipeline in-process. |

PHP 8.5 features to use on purpose: the `Uri\Rfc3986\Uri` extension for redirect-URI and issuer
parsing (exact-match comparison must not depend on `parse_url`), `clone with` for immutable value
objects, `#[\NoDiscard]` on results that must be checked (signature verification, consume/spend
operations), the pipe operator where it clarifies a transformation chain.

### Risk to handle first: the database layer

`php-db/phpdb-pgsql` (https://github.com/php-db/phpdb-pgsql, read 2026-11-20): branch `0.1.x`,
allows PHP 8.3–8.5, requires `php-db/phpdb ^0.6.0`, has a test suite (PHPUnit + Infection) — but
it is **pre-1.0 with no tagged release** and `minimum-stability: dev`. Clavia's hardest
correctness properties (single-use codes, refresh-token rotation under `SELECT … FOR UPDATE`,
family revocation) sit on it. Step 1 therefore pins an exact commit in `composer.lock`, and
proves with integration tests that transactions, row locking and `RETURNING` behave as needed
before anything depends on them. Persistence is behind ports, so an API break in a 0.x release
touches `Adapter/Secondary/Persistence/PhpDb` and nothing else.

## Auth pages

The pages on `auth.{domain}` (login now; MFA, consent, device and passwordless later) are
**server-rendered HTML with no JavaScript**, written as laminas-view PHP templates
(`.phtml`) and rendered through `mezzio/mezzio-laminasviewrenderer`. No Twig, no other
template language, no front-end framework. (Decided 2026-11-20, replacing the earlier
"no template engine" line: laminas-view is PHP itself, used as Mezzio intends.)

- `templates/layout/page.phtml` + one template per page (`templates/auth/*.phtml`, and
  `templates/error/page.phtml` for every error shown to a browser) + reusable partials
  (`templates/partial/*.phtml`: `alert`, `csrf`, `field`; later `button`,
  `connection-list`). A repeated block becomes a partial, never a copy. Names are namespaced:
  `layout::page`, `auth::login`, `error::page`, `partial::field`.
- Templates print and loop; the handler passes a ready-made view model (`HtmlPage`, built for
  the login page by `LoginPages` and for errors by `ErrorPage::toHtmlPage()`).
- `PageRenderer` in `Adapter/Primary/Http/Shared` renders them with the per-page CSP and the
  common headers; `AuthPageResponder` adds the CSRF cookie to auth pages. Every value is
  escaped by the template; `AuthPagesEscapingTest` proves it for every page.
- One stylesheet, `public/auth/static/auth.css` (served at `/auth/static/auth.css`), copied
  from the Python project; light/dark through custom properties; the theme toggle is a POST
  that sets a cookie.
- No JavaScript on this origin is a security property, not a style choice.

The management dashboard is a separate concern: the React app in `frontend/`, kept as is until
Phase E replaces it (see "Dashboard as a Next.js application"). Until then it is maintained, not
extended: new API features reach it only where a page would otherwise break.

## Invariants carried over

Copied from `../Clavia Python/clavia/CLAUDE.md` and adapted to this codebase. They follow from the
RFCs and from mistakes already made once; violating one is a security bug, not a style issue.

### Four surfaces, four authentication mechanisms

| Namespace   | Purpose                                              | Caller authenticates with |
|-------------|-------------------------------------------------------|---------------------------|
| `/oauth2/*` | Authorization server (authorize, token, introspect…) | Client credentials / PKCE |
| `/oidc/*`   | OIDC endpoints (discovery, jwks, userinfo, logout)   | Bearer token, or public   |
| `/auth/*`   | Interactive login/logout/MFA, serves the login UI    | Browser session cookie    |
| `/api/v1/*` | Management API (CRUD, RBAC, audit)                   | Bearer access token       |

Keeping them separate is the central design constraint. The failure mode to avoid: authenticating
`/api/v1/*` with the `/auth/*` session cookie. The Management API is a machine plane reachable
only with an access token — the dashboard is an OAuth2 client like any other, not a trusted first
party with cookie access. In this codebase that means authentication middleware is attached **per
route group** in `config/routes.php`, never piped globally.

### Protocol invariants

- PKCE is mandatory with `S256`; `plain` does not exist.
- Authorization codes are single-use, short-lived, bound to `client_id`, `redirect_uri`, and
  `code_challenge`. Redirect URIs are pre-registered and matched exactly.
- Refresh token rotation issues a new token on every use; replay of a consumed token revokes the
  whole token family. No reuse grace period.
- Client Credentials is for confidential clients only, issues no refresh token, and a token from
  it has no subject — every surface that answers questions about a person must refuse it.
- A scope means nothing without an audience — check `aud` before checking scope.
- A permission belongs to an API (`read:users` on two different APIs are different permissions),
  and a client holds none of its own: no scope column on the client. Narrow scope at token
  issuance — the API's declared permissions, then the user's effective permissions (or, for a
  machine, its client grant) — and re-check at redemption, not at authorization time.
- A TOTP code is single-use: spend the matched time step, don't just accept-and-forget.
- Tokens are signed (RS256/ES256) and verified via JWKS; retired keys stay published until every
  token they signed has expired.
- Passwords and client secrets are hashed (bcrypt); authorization codes and access tokens are
  stored as SHA-256 digests, not encrypted or hashed-with-salt — they need indexed lookup.
- `prompt`, `max_age`, `request` and `request_uri` are part of the authorize decision, made once:
  no session, a session through a connection the client does not enable, `prompt=login` /
  `select_account`, or `max_age` exceeded all mean "the person must be seen";
  `prompt=none` then answers `login_required`. Request objects are refused
  (`request_not_supported` / `request_uri_not_supported`).
- Discovery states every field whose spec default differs from what the server does, and a test
  fetches every endpoint it advertises.

### Browser-facing invariants

- The login page is on the same origin as `/oauth2/authorize`, the session cookie has no
  `Domain` attribute, and there is **no JavaScript** on that origin.
- Never put a post-login redirect target in a URL parameter; hold it server-side (Redis) behind
  an opaque handle, and re-validate whatever it resolves to before using it as a `Location` —
  even when it came from our own store.
- Every `/auth/*` state change is a POST with a CSRF token.
- **The auth pages' CSP is built per page, not a constant.** Chromium applies `form-action` to a
  form submission's whole redirect chain, and a successful sign-in ends at the application's
  `redirect_uri`; a page tied to an authorization request therefore lists that client's origins
  next to `'self'`, and a page tied to nothing gets `'self'` alone. Leave `'self'` on its own and
  Chromium/Brave block the final hop, leaving the person on a stale login page whose CSRF token
  has just been spent.
- Social login: resolve identity by `(provider, subject)`, never by email; only use a *verified*
  email to link to an existing account; pair `state` with a cookie so the callback can tell the
  browser that started the flow from any other. Provider errors are never echoed.
- Every URL the server fetches on an operator's say-so (OIDC connection discovery and endpoints,
  back-channel logout URIs) goes through the outbound-URL policy: https only, never a
  non-global address as a literal or as resolved, checked at registration *and* at send time.
- Caddy sets `Cache-Control: no-store` on everything under `auth.*` except discovery, the JWKS
  and static assets, whose cacheability the application owns (the JWKS max-age is a
  rotation-safety number, not an HTTP detail).

### Storage split

- **PostgreSQL** — anything that must survive a restart, be auditable, or be consumed exactly once:
  users, clients, APIs, roles/permissions, authorization codes, access and refresh tokens, audit
  logs, signing-key metadata.
- **Redis** — short-TTL material: browser sessions, failed-login counters, pending MFA challenges,
  the `state`/PKCE verifier of an outbound social login, device/user codes, magic-link/OTP tokens.

Authorization codes and refresh tokens *look* like they belong in Redis and deliberately don't:
single-use enforcement needs an atomic `SELECT ... FOR UPDATE`, and refresh-token replay detection
needs to survive longer than any sensible TTL.

Authorization codes and refresh tokens are the reason `TransactionManager` and row locking are
proven in Step 1 before any feature uses them.

### Signing keys

The load-bearing decision from the prior attempt, carried over as-is: the port everything
issuing a token goes through is **sign**, not **fetch the key**.

```php
interface TokenSigner
{
    public function activeKey(): SigningKeyReference;                        // kid + alg, for the header

    public function sign(SigningKeyReference $key, string $signingInput): string; // raw signature bytes

    /** @return list<PublicJwk> */
    public function publicKeys(): array;                                     // what the JWKS publishes
}
```

That shape is the whole design, decided before any signing code is written. An interface that
returns a private key can only be implemented by backends that let key material into application
memory, which excludes every non-extractable option — cloud KMS, Vault Transit, a PKCS#11 HSM.
Those are the ones worth having in production, because an IdP signing key mints valid tokens for
any user and forgeries are indistinguishable from real tokens.

Consequences worth knowing before touching the OIDC/signing code:

- **No JOSE library signs.** Every one of them wants the private key in-process. The compact JWS
  is assembled by hand — header, claims, `base64url`, then `TokenSigner::sign()`.
  `web-token/jwt-library` is for JWK handling and *verification* (tests, external ID tokens) only.
- **There is no "load the private key" helper, ever, even temporarily.** Exactly one class reads
  a private key (or a reference to one): the signing adapter's own `sign`. For the postgres
  backend that is `PostgresTokenSigner::sign()`, the only code that ever decrypts one;
  `PostgresSigningKeyStore` generates and seals keys and never reads them back.
- **RS256 is spelled out as RSASSA-PKCS1-v1_5 over SHA-256** (`openssl_sign(…, OPENSSL_ALGO_SHA256)`)
  rather than delegated to a generic helper, because a remote backend has to name the same
  primitive precisely — AWS KMS's `RSASSA_PKCS1_V1_5_SHA_256`. Get it wrong and signatures verify
  locally and nowhere else.
- **Two differences between providers are easy to get wrong**: AWS hashes the message itself; GCP
  and Azure expect a pre-computed digest. Send the wrong shape and the signature covers the wrong
  bytes — a failure that shows up at every verifier and nowhere in this code. And the same
  primitive has three names: `RS256` is AWS's `RSASSA_PKCS1_V1_5_SHA_256`, GCP's
  `RSA_SIGN_PKCS1_2048_SHA256`, and Azure's own `RS256`.
- **`kid` is deliberately not the provider's full key reference.** An AWS ARN carries the account
  number, a GCP resource name carries the project — neither needs publishing to every client that
  fetches the JWKS.
- **`CLAVIA_SIGNING_BACKEND`** selects `postgres`, `aws-kms`, `gcp-kms`, `azure-key-vault`, or a
  custom adapter's class name, with `CLAVIA_SIGNING_KEY_REF` naming the provider's key. Cloud SDKs
  are Composer suggestions so a deployment installs one, not three. `postgres` (the key stored,
  AES-256-GCM-encrypted with `kid` as associated data, in the database) is the only extractable
  option and the only one needing no external service: right for development, a warning in
  production. `CLAVIA_SECRET_ENCRYPTION_KEY` is required by it; there is no plaintext fallback.
- **Production runs on `aws-kms`.** KMS does not rotate an asymmetric key itself; rotation means
  creating a second key and publishing both in the JWKS until every token signed with the old one
  has expired. The task role needs only `kms:Sign` and `kms:GetPublicKey`.

### Domain configuration

Clavia must not hard-code a domain. The prior attempt bound everything to `clavia.local` in
development and `clavia.io` in production — a `Caddyfile` full of literal hostnames and a CDK stack
that provisions `*.clavia.io` (see `../Clavia Python/clavia-old/Caddyfile` and `docs/DEPLOYMENT.md`). That pattern
is right; the literal domain baked into it is what needs generalizing so any operator can point
their own domain at Clavia.

A single setting — e.g. `CLAVIA_ROOT_DOMAIN` — names the deployment's domain (`clavia.io`,
`acme-idp.com`, whatever DNS an operator controls), and every host Clavia needs is derived from it
rather than written down anywhere. Two subdomains are non-negotiable and must exist wherever Clavia
runs:

- **`auth.{domain}`** — the OAuth2/OIDC/login origin. This is the same load-bearing origin the prior
  attempt's login design depends on: a host-only session cookie with no `Domain` attribute, so it is
  never shared with any other subdomain, and `redirect_uri`s that are validated against this origin
  specifically. Whatever `{domain}` is, this subdomain is where credentials get typed and tokens get
  minted — nothing else should share it.
- **`management.{domain}`** — the backoffice SPA *and* the Management API. Kept on its own origin,
  separate from `auth.*` and from the apex, for the same reason as before: an XSS in the end-user
  login UI must not be able to reach the administrative dashboard's token, and vice versa.

**There is deliberately no `api.{domain}` subdomain.** The Management API is served at
`management.{domain}/api/v1/*` — a path on the same origin as the dashboard — rather than its own
host; the prior attempt's `api.clavia.local` is not carried forward. Same-origin means the
dashboard's own calls to `/api/v1/*` need no CORS at all; the only cross-origin concern left on
`management.*` is the OAuth2/PKCE exchange against `auth.*`, not a second API host to whitelist. This
doesn't change *who* may call `/api/v1/*` — it's still the bearer-token-only machine plane described
in "Four surfaces" above, reachable by any client holding a valid access token regardless of
the origin it calls from. Putting it under `management.*` only fixes where the first-party dashboard
finds it, not who else is allowed to call it.

Other hosts (a landing page at the apex, per-tenant `{slug}.{domain}` if multi-tenancy is built) can
be added, merged toward the apex, or reshaped per deployment — those are conveniences. `auth.*` and
`management.*` are the two whose *separation* is a security property, not a routing choice, and a
deployment config that collapses them onto one origin is a regression regardless of what domain it's
for.

Consequences of making the domain a variable rather than a constant:

- **TLS has to cover whatever `{domain}` turns out to be** — a wildcard certificate for `*.{domain}`
  (plus the apex if it serves anything), issued per deployment rather than assumed to be
  `*.clavia.io`. Locally this is `mkcert` against a domain the operator has put in `/etc/hosts`; in
  production it's ACME/a CDK-managed certificate against whatever's actually registered.
- **Reserved subdomain labels must be domain-agnostic constants, not project-name coincidences.**
  The prior attempt reserved the tenant slug `clavia` because the deployment happened to be named
  `clavia.io` — a slug that collides with the project's own name, not with a real subdomain risk.
  The general rule that has to survive the rename is: `auth`, `management`, `www`, and any other
  infrastructure subdomain Clavia itself uses are reserved, on *any* `{domain}`, and tenant or client
  provisioning must check against that list rather than a single hard-coded string. `api` is not on
  it — it's a path under `management.*`, not a subdomain, so it needs no reservation of its own.
- **Provisioning a new host should stay a database row, not a redeploy**, on whatever domain is
  configured — the prior attempt's DEPLOYMENT.md already establishes this for `*.clavia.io`
  specifically (wildcard cert + `Host`-header routing); the requirement is the same mechanism, just
  parameterized by `{domain}` instead of assuming it.

## Migration plan

Each step lists: the Python sources to read, what to build per ring, and the tests to port.
Order is a dependency chain. `[ ]` → `[x]` when the step's acceptance tests are green.

### Phase A — Foundations

#### [x] Step 0 — Repository and toolchain
- `composer.json` (PHP 8.5, Mezzio, servicemanager, FastRoute, symfony/console, monolog;
  BSD-3-Clause, header enforced by `LicenseHeaderTest`), `Clavia\` PSR-4, `public/index.php`,
  `config/`, the rings under `src/` plus `Configuration` and `Bootstrap`.
- QA: PHPCS, Psalm level 1, PHPUnit, **deptrac with the full ruleset from day one**, `composer check`, CI.
- Infra: `docker-compose.yml` (Postgres :5433, `db-test` :5434, Redis, Caddy, **php-fpm 8.5**),
  `Caddyfile` ported to `php_fastcgi` (same hosts, same `Cache-Control` rules), `setup-ssl.sh`,
  `Makefile`, `.env.example`.
- `Settings`: every `CLAVIA_*` field of `config.py` with its validators; `clavia config`.
- Proxy trust (`CLAVIA_TRUSTED_PROXIES`); error handling that leaks nothing; FastAPI-shaped 404/405.
- `static/auth.css` and the icon under `public/auth/static/`; the invariant sections copied below.
- Python: `config.py`, `main.py`, `Caddyfile`, `docker-compose.yml`, `Makefile`.
- Verified: `GET /healthz` through Caddy over HTTPS (FastCGI to PHP-FPM 8.5), `composer check` green.
  Not yet exercised: the Docker image build itself and the GitHub workflow.

#### [x] Step 1 — Shared kernel, technical ports, persistence base
- Domain/Shared: `Clock`, `RandomSource`, `SecretGenerator`, `Digest` (SHA-256), `Url`,
  `Scope`/`ScopeSet`, `Audience`. Typed ids arrive with the aggregate they identify.
- Ports + adapters: `PasswordHasher` (bcrypt), `SecretCipher` (AES-256-GCM, AAD context, no
  plaintext fallback), `TransactionManager`, Redis connection + key-prefix convention.
- **Database adapter on `php-db/phpdb-pgsql`**, pinned in `composer.lock` (`phpdb-pgsql`
  `deddafa`, `phpdb` `008de26`): `Database`, `PostgresUrl`, `PhpDbTransactionManager`, and
  integration tests for parameters, types, transactions, `FOR UPDATE` (`NOWAIT`, `SKIP LOCKED`),
  conditional updates and `RETURNING`. One library defect found and worked around
  (`PostgresConnection`, see "Current state").
- Migrations: `SqlFileMigrator` behind the `SchemaMigrator` port; `clavia db:migrate`,
  `db:status`, a `schema_migrations` table. **The runner is built; no migration exists yet.**
  Each later step adds the files for the tables it introduces, in their final shape.
- Test kit: doubles for every port, contract suites, `IntegrationTestCase` with scratch schemas,
  storage reset through the real migrations, Redis database 1 flushed.
- `clavia secrets:generate-key` (moved here from Step 4: the cipher it serves lands here).
- Python: `security/*`, `redis_store.py`, `db/session.py`, `tests/conftest.py`.
- Verified against PostgreSQL 16 and Redis 7 outside Docker; the plan targets PostgreSQL 17.
  The acceptance harness's cookie jar arrived with the first cookie, in Step 3.

### Phase B — The original build order (Python steps 1–6)

#### [x] Step 2 — Authorization Code + PKCE
- Domain: `Client` (final shape: `client_id` PK, auth method, grant types, redirect URIs, no
  scope column), `AuthorizationRequest` validation, `Pkce` (S256 only), `AuthorizationCode`,
  opaque `AccessToken`, `OAuth2Error` taxonomy (RFC 6749 §4.1.2.1/§5.2).
- Application: `Authorize`, `IssueToken` + `AuthorizationCodeGrant`, `ClientAuthenticator`.
- Primary adapters: `GET /oauth2/authorize`, `POST /oauth2/token`; `state` echoed on every error redirect;
  RFC 9207 `iss`; `WWW-Authenticate` on 401; exact redirect-URI match; a replayed code revokes
  what it issued. Dev auto-login (`CLAVIA_DEV_AUTOLOGIN_EMAIL`) as a development-only adapter.
- CLI: `seed-dev` (first version), `authorize-url`. First migrations: `users`, `oauth2_clients`,
  `oauth2_authorization_codes`, `oauth2_access_tokens`.
- Python: `oauth2/{server,grants,requests,router}.py`, `db/models/{client,oauth2,user}.py`.
- Tests: `test_authorization_code_flow` (9), `test_pkce_security` (16) — ported as
  `AuthorizationCodeFlowTest` and `PkceSecurityTest`, plus unit, contract and integration tests.
- Deviations are recorded in `docs/DEVIATIONS.md` ("OAuth2 endpoints"). Left for the
  steps that own them: the login page behind `LoginRequired` (3), `nonce`/`openid` handling and
  the ID token (4), consent (15), per-client scopes and audiences (5, 16).

#### [x] Step 3 — Login page and sessions
- Domain: `Session` (idle + absolute lifetime, `sid`, `amr`, `connection`), `LoginState`,
  throttling policy, redirect-target validation.
- Ports: `SessionStore`, `LoginStateStore`, `AttemptCounter` (Redis adapters).
- Primary adapters: `GET/POST /auth/login`, `POST /auth/logout`, `POST /auth/theme`; `templates/` layout + `login` page, page renderer;
  per-page CSP builder; per-browser CSRF double-submit; host-only cookie; session rotation.
- Python: `auth/{router,sessions,login_state,throttle,redirects,pages,current_user}.py`,
  `forms.py`, `templates/`.
- Tests: `test_login` (35) — ported as `LoginTest` (42 cases), plus `AuthPagesEscapingTest`,
  unit tests for every new class and contracts run against the doubles and Redis.
- Left for the steps that own them: `connection` on the session and the per-application
  connection check (13), the user→sessions and session→clients indexes (17), the second
  factor between password and session (7).

#### [x] Step 4 — JWKS, ID token, discovery, userinfo
- Domain: `IdTokenClaims` (incl. `at_hash`, `nonce`, `auth_time`, `amr`), shared
  `IdentityClaims` for ID token and userinfo, `SigningKey` lifecycle (active/retired + grace),
  `PublicJwk` (RFC 7638 `kid`), `Nonce`, `Profile`, `AuthenticationContext`.
- Ports: `TokenSigner` (`activeKey`, `sign`, `publicKeys`), `SigningKeyStore`, `NonceRegistry`.
  Adapters: the postgres backend (RSA-2048, RS256, private key sealed with the `kid` as
  associated data), Redis nonce registry; compact JWS built by hand (`CompactJws`).
- Primary adapters: both `/.well-known/*` documents, `/oidc/jwks.json`, `/oidc/userinfo`
  (GET and POST, RFC 6750 challenges); nonce replay guard at the authorization endpoint.
- CLI: `keys:generate|rotate|list`; `seed-dev` creates a key when none is active.
- Python: `oidc/{router,grant,claims,keys,nonce}.py`, `oidc/signing/{__init__,_core,postgres}.py`.
- Tests: `test_oidc` (26) — ported as `OidcTest` (32 cases), the postgres part of
  `test_signing_backends` as `PostgresSigningBackendTest` (with `SigningBackendContract`,
  run against the in-memory double too), plus unit tests for every new class.
- ID tokens are checked with `web-token/jwt-library` (a dev dependency, verification only)
  against the JWKS as served. Left for the steps that own them: `sid` in the ID token (17),
  `prompt`/`max_age` (18), remote signing backends (19).

#### [x] Step 5 — Client Credentials
- Confidential only, no refresh token, refuses `openid`, subject-less tokens refused by userinfo.
- Domain brought forward from Step 6, because the final design gives a client no scope of
  its own: `ResourceServer`, `Permission` keyed `(resource_server, value)`, `ClientGrant`, and
  their storage; the token's `audience`.
- CLI: `clients:create-m2m`.
- Python: `oauth2/grants.py` (`ClaviaClientCredentialsGrant`), `db/models/resource_server.py`,
  `api/provisioning.py` (`grant_client`), `cli.py` (`clients create-m2m`).
- Tests: `test_client_credentials` (19) — ported as `ClientCredentialsTest` (23 cases), plus
  unit tests and `ResourceServerRepositoryContract` run against the doubles and PostgreSQL.
- Left for Step 6: registering APIs and writing grants from the shell (`management-api
  register|scopes`, `clients grant`), `audience` at the authorization endpoint, system APIs.

#### [x] Step 6 — Management API, resource servers, audiences
- Domain (the rest of it): `is_system` APIs, audience rules at the authorization endpoint
  (scopes of the named API), grant provisioning (`GrantClientAccess`); paging, uniqueness
  (`AlreadyExists`), the password policy, user and client changes, the client coherence rules.
- Primary adapter (`Http/Management`): `ManagementApiMiddleware` (bearer token, `aud` checked
  before scope, RFC 6750 challenges with the Management API as realm), OpenAPI validation,
  RFC 9457 problems, pagination, `/api/v1/{users,clients,resource-servers}`, secret rotation.
- `docs/openapi/management-api.yaml`, written from `api/schemas.py`: it validates requests
  *and* is asserted against every response in the acceptance tests.
- CLI: `management-api:register|scopes`, `clients:grant`; `seed-dev` registers the Management
  API and a machine client holding every management scope.
- Python: `api/*`, `db/models/resource_server.py`.
- Tests: `test_management_api` (36) — ported as `ManagementApiTest` (47 cases),
  `test_audience` (12) — ported as `AudienceTest` (16 cases); `ManagementContractTest`, unit
  tests for every new use case, the domain rules and the commands; the repository contracts
  gained paging, deletion and uniqueness.
- Left for the steps that own them: roles and the RBAC narrowing that replaces the
  system-API refusal (10), the connection scopes and endpoints (13), `refresh_token` and the
  device grant on registrations (11, 15), `is_first_party` (12).

#### [x] Step 7 — MFA (TOTP)
- Domain: own RFC 6238 `Totp` (single-use by time step), `Base32`, `TotpSecret`,
  `RecoveryCode` digests, `MfaFactor` (pending → confirmed), `MfaChallenge`.
- Port: `MfaChallengeStore` (Redis, attempts counted by a Lua script). Seeds sealed through
  `SecretCipher`. No `QrRenderer` port: the QR code is presentation, drawn by the HTTP
  adapter (see the Step 7 conventions).
- Primary adapters: `/auth/mfa`, `/auth/mfa/enroll`, `/enroll/confirm`, `/disable`;
  `DELETE /api/v1/users/{user_id}/mfa` and `mfa_enrolled` in the Management API contract.
- Python: `mfa/*`, `db/models/mfa.py`.
- Tests: `test_mfa` (17) — ported as `MfaTest` (20 cases); unit tests for `Totp` (the RFC 6238
  vectors), `Base32` (RFC 4648), `MfaFactor`, `RecoveryCode`, the enrollment use cases,
  `CompleteSecondFactor` and `QrCodeSvg`; `MfaRepositoriesContract` and
  `MfaChallengeStoreContract` run against the fakes, PostgreSQL and Redis; the new pages are in
  `AuthPagesEscapingTest`.
- Left for the steps that own them: `ext` as a first factor (social login, 8), the
  challenge's connection (13).

#### [x] Step 8 — Social login
- Domain: `ExternalIdentity` keyed `(provider, subject)`, `AssertedIdentity`, `ProviderName`,
  `PendingExternalSignIn`; the linking rules in `ResolveExternalAccount` (verified address
  only, case-insensitive, ambiguity refused, `CLAVIA_SOCIAL_AUTO_LINK`).
- Ports: `IdentityProvider` (`authorizationUrl()`, `identify()`), `IdentityProviders`,
  `ExternalSignInStore` (Redis, `GETDEL`). Adapters Google (userinfo) and GitHub (`/user` +
  `/user/emails`, the primary verified address), over PSR-18 with Guzzle behind it.
- Primary adapters: `GET /auth/social/{provider}` and `/callback`; `state` paired with a
  cookie; provider errors never echoed; the providers offered on the login page.
- `CompleteFirstFactor` extracted from `SignInWithPassword`, so an external sign-in meets the
  same second factor.
- Python: `social/*`, `db/models/identity.py`. Tests: `test_social_login` (18) — ported as
  `SocialLoginTest` (18 cases); unit tests for the domain values, both adapters against a fake
  wire, and the use cases; `ExternalIdentityRepositoryContract` and
  `ExternalSignInStoreContract` run against the fakes, PostgreSQL and Redis.
- Step 13 then made the providers connections a client enables, added operator-registered
  OIDC providers and pools, and unlinking.

#### [x] Step 9 — RP-Initiated Logout and the dashboard  ← first usable milestone
- `GET|POST /oidc/logout` (OpenID Connect RP-Initiated Logout 1.0): `id_token_hint` verified
  against the published keys (`SignatureVerifier`, on `web-token/jwt-library`, now a runtime
  dependency for verification only); `post_logout_redirect_uris` registered per client and
  matched exactly, `state` returned; without proof, a confirmation page. `end_session_endpoint`
  in discovery.
- Clients gain `post_logout_redirect_uris` (domain, migration `0015`, the Management API
  contract).
- `frontend/` copied unchanged from the Python project; `seed-dev` registers the dashboard as a
  public code-flow client (`SeedDashboardClient`) and writes `frontend/.env.local`; the
  `Caddyfile` already serves it at `management.{domain}/dashboard/`.
- Tests: `test_rp_logout` (6) — ported as `RpLogoutTest` (11 cases); `EndSessionTest`,
  `JoseSignatureVerifierTest`, the client contract and Management API cases for the new field,
  the confirmation page in `AuthPagesEscapingTest`.
- **Not yet usable end to end:** the dashboard asks for Management API permissions in a user's
  flow, which stays `access_denied` until roles exist (Step 10, done), and it renews tokens with
  a refresh token (Step 11). It signs in once both land; pages whose API arrives later
  (connections, consents, sessions) light up with their step.

### Phase C — Everything built after the chain

#### [x] Step 10 — RBAC
- `Role`, `user_roles`, `role_permissions` with a composite foreign key onto `permissions`
  (migration `0016`); `enforce_policies` on APIs, always on for a system API; `access_denied`
  at the authorization endpoint for somebody holding nothing, narrowing at redemption
  (`invalid_grant` once nothing is held).
- `/api/v1/roles` (CRUD), `/roles/{id}/users` (`GET`, `POST`), `/roles/{id}/users/{user_id}`
  (`DELETE`), `/users/{id}/roles` (`GET`, `PUT`), `/users/{id}/permissions`; the four `roles`
  scopes. CLI `roles:create|assign|list`; `seed-dev` gives the development user an
  Administrator role.
- Python: `db/models/rbac.py`, `api/roles.py`. Tests: `test_rbac` (17) — ported as `RbacTest`
  (17 cases); `RoleTest`, `RolesTest`, `RoleCommandsTest`, `RoleRepositoryContract` against the
  fakes and PostgreSQL, and the resource-server, seeding and contract cases for the new field.
- The dashboard now gets a token for the Management API, and keeps one with refresh tokens
  since Step 11.

#### [x] Step 11 — Refresh token rotation
- `RefreshToken` + `family_id`, spent under lock, a replay revokes the family and its access
  tokens (and a replayed code the family it started); idle + absolute lifetimes; every refusal
  checked before the spend. `UserScope` decides, at code redemption and at every refresh, what
  a person's token carries.
- Migration `0017`; `refresh_token` in discovery, the token response and client registrations
  (only beside `authorization_code`); the dashboard is seeded with it.
- Tests: `test_refresh_token` (15) — ported as `RefreshTokenTest` (16 cases); unit tests for
  `RefreshToken`, `RefreshTokenGrant` and the code grant's family; `RefreshTokenRepositoryContract`
  and the access token contract's family revocation against the fakes and PostgreSQL. The
  concurrent-refresh case is the row lock: the in-memory and PostgreSQL contracts lock inside a
  transaction, and only one spend can see the token unspent.

#### [x] Step 12 — Application ownership and consent
- Ownership in the client id (`tpc_`), `UserConsent` (migration `0018`), the consent decision
  table (`prompt=consent`, third-party, `allow_skipping_consent`), `ConsentStateStore`,
  `/auth/consent`, `/users/{id}/consents`; `prompt=none` answers `login_required` and
  `consent_required`. Third-party applications never reach a system API.
- Python: `oauth2/consent.py`, `auth/consent.py`. Tests: `test_consent` (23) — ported as
  `ConsentTest` (26 cases); `ConsentPolicyTest`, `UserConsentTest`, `PromptTest`,
  `ConsentScreenTest`, the consent cases of `AuthorizeTest`, `ConsentRepositoryContract`
  and `ConsentStateStoreContract` against the fakes, PostgreSQL and Redis.

#### [x] Step 13 — Connections
- Database pools, built-in social, operator-registered OIDC connections (discovery, nonce + PKCE,
  ID-token verification, JWKS cache), per-application enablement, `OutboundUrlPolicy`.
- `/api/v1/connections/*`, `PUT /clients/{id}/connections`, identity unlinking.
- Python: `auth/connections.py`, `api/connections.py`, `social/providers.py`,
  `db/models/connection.py`. Tests: `test_connections` (29) — ported as `ConnectionsTest`
  (29 cases); `test_oidc_connection` (16) — ported as `OidcConnectionTest` (14 tests, 25 cases
  with their data sets); `ConnectionTest`, `ConnectionAccessTest`, `OutboundUrlPolicyTest`,
  `PinCheckedAddressesTest`, `HttpOidcDiscoveryTest`, `OidcIdentityProviderTest` (the ID-token
  checks), the connection cases of `AuthorizeTest`, `SignInWithPasswordTest`,
  `ExternalSignInTest`, `DescribeLoginPageTest`, `ClientsTest` and `UsersTest`;
  `ConnectionRepositoryContract` and the per-pool cases of the user, client and identity
  contracts against the fakes and PostgreSQL; `RedisJwksCacheTest`.

#### [x] Step 14 — Introspection and revocation
- RFC 7662 / RFC 7009, per-endpoint client-auth methods, permission rules, family revocation.
- Tests: `test_introspection_revocation` (17) — ported as `IntrospectionRevocationTest`
  (18 cases, with a deactivated account's token); `PresentedTokenTest` (the request and the
  hint), the single revocation case of `AccessTokenRepositoryContract`.

#### [x] Step 15 — Device authorization
- RFC 8628: `/oauth2/device/code`, the device grant, polling (`slow_down`, `expired_token`),
  `/auth/device` review page. Python: `oauth2/device.py`, `auth/device.py`.
- Tests: `test_device_authorization` (22) — ported as `DeviceAuthorizationTest` (26 cases:
  another device client, the refresh token, the CSRF check, a code decided twice);
  `DeviceAuthorizationRulesTest` (the user code, polling, deciding),
  `DeviceAuthorizationStoreContract` against the fake and Redis, the device cases of
  `ClientTest`.

#### [x] Step 16 — Passwordless and mail
- `Mailer` port (console/outbox, SMTP, none); code and link challenges; send limits; the built-in
  `email` connection; CLI `mail:outbox`.
- Python: `auth/passwordless.py`, `mail.py`. Tests: `test_passwordless` (19) — ported as
  `PasswordlessTest` (25 cases: mail that cannot leave, the CSRF check, a second factor, the
  ID token's `amr`, a code handle presented as a link, the code page without a challenge);
  `PasswordlessSignInTest` (the use cases on fakes), `PasswordlessChallengeTest`,
  `SignInMailTest`, `MailersTest`, `MailOutboxCommandTest`, `PasswordlessChallengeStoreContract`
  against the fake and Redis, `RedisMailOutboxTest`.

#### [ ] Step 17 — Back-channel logout and session management
- Logout token (`typ: logout+jwt`), `sid` on codes and ID tokens, session→clients index,
  `DeferredTasks`, `/users/{id}/sessions`.
- Python: `oidc/backchannel.py`. Tests: `test_backchannel_logout` (22).

#### [ ] Step 18 — Authentication-request parameters and complete metadata
- `prompt`, `max_age`, `request`/`request_uri` refusal; discovery states every non-default
  field; a test fetches every endpoint the document advertises.
- Python: `oauth2/prompt.py`. Tests: `test_authorize_prompt` (15).

#### [ ] Step 19 — Remote signing backends
- `aws-kms`, `gcp-kms`, `azure-key-vault` and custom-class adapters behind `TokenSigner`
  (message-vs-digest semantics per provider); SDKs as optional Composer suggestions.
- Tests: rest of `test_signing_backends` (15), against fakes.

### Phase D — Parity and cut-over

#### [ ] Step 20 — Parity gate
- Parity matrix: every Python test mapped to its PHP counterpart (404/404).
- Run the OpenID Foundation conformance suite (Basic OP, Config OP) against both servers.
- Black-box diff: the same scripted flows against Python and PHP, responses compared.
- README, deployment docs, `docs/DEVIATIONS.md` reviewed; security review of every adapter.

#### [ ] Step 21 — Cut-over
- Publish the repository; archive the Python project as reference.

### Phase E — Beyond the Python project
- [ ] Audit logs (domain events → `AuditLog` port; the hexagonal seams make this an adapter).
- [ ] Dashboard as a Next.js application — right after audit logs (decided 2026-11-21); below.
- [ ] Multi-tenancy, if it turns out to be worth the complexity (see `clavia-old/CLAUDE.md`).

#### [ ] Dashboard as a Next.js application

The dashboard becomes what the server already treats it as — one first-party client of the
Management API among others — and stops living inside the server's repository.

- **Its own repository** (`clavia-dashboard`), built against the published contract only:
  `docs/openapi/management-api.yaml` and the discovery document. TypeScript types are generated
  from the OpenAPI document, not mirrored by hand (today's `types.ts`, `scopes.ts`). Nothing of the
  server's internals is reachable from it, which proves the API sufficient on its own; the two
  release independently.
- **Same address as today: `https://management.{domain}/dashboard/`.** Next.js runs with
  `basePath: '/dashboard'`; Caddy reverse-proxies `management.{domain}/dashboard/*` to the Next.js
  server and keeps `/api/v1/*` on PHP-FPM. Dashboard and Management API stay one origin, separate
  from `auth.*` ("Domain configuration"): the dashboard's server-side calls to `/api/v1/*` and the
  browser's requests to the dashboard never cross an origin. The dashboard's cookies are scoped to
  `Path=/dashboard`, `Secure`, `HttpOnly`, `SameSite=Lax`.
- **A backend for frontend, no token in the browser** (IETF "OAuth 2.0 for Browser-Based
  Applications", the BFF pattern). The dashboard is a **confidential** first-party client:
  authorization code + PKCE with `client_secret_basic`; the access, refresh and ID tokens are kept
  server-side in an encrypted session the browser holds only a cookie for; refresh happens on the
  server; every Management API call is made by the Next.js server (route handlers / server
  actions) with the operator's access token. The browser talks to the dashboard only.
- **Styling: Tailwind v4, kept from the current dashboard** (decided 2026-11-21) — its `@theme`
  tokens (light and dark, as CSS variables) and its `@utility` components (`btn-*`, `badge-*`,
  `card`, `input`) carry over, so the move changes the architecture, not the look. Components
  from **shadcn/ui** (Radix primitives, code owned in the repository) for what a back office
  needs beyond that — tables, dialogs, comboboxes, toasts; variants with `cva`. Panda CSS was
  weighed and set aside: typed tokens and recipes, but a rewrite of every page and a far smaller
  component ecosystem, for a dashboard whose design is settled. Worth reopening only for a
  design system shared by several Clavia front ends.
- **Authority stays the operator's**: the dashboard asks for the Management API scopes and gets
  what the operator's roles grant (Step 10), as today; a page offers only what the token holds.
- **Sign-out**: RP-Initiated Logout as today, the refresh token revoked server-side (Step 14), and
  a `backchannel_logout_uri` (Step 17) so a sign-out anywhere ends the dashboard's session too.
- **The audit trail** (the step before) gets its pages from the start.
- **On this side**: `frontend/` is removed, with Caddy's static `/dashboard/` handling (replaced by
  the reverse proxy) and the dashboard origin's entry in the CORS allowlist of `auth.*` (its token,
  refresh and revocation requests become server-to-server); `seed-dev` registers the
  dashboard as a confidential client — redirect, post-logout and back-channel logout URIs under
  `management.{domain}/dashboard/` — and hands its credentials to the dashboard's `.env.local` as
  it does today; `docker-compose.yml` gains the Next.js service for development.
- **Tests**: the OpenAPI contract is the only shared artefact, so the server keeps checking every
  response against it. The dashboard repository carries its own tests and a small end-to-end
  smoke suite run against a server started from a tagged image.

## Definition of done for a step

1. Every listed Python test has a passing PHP acceptance test of the same name.
2. Domain rules have unit tests that use no adapter.
3. Each new port has a fake and a contract test; each new adapter passes it.
4. `composer check` is green: PHPCS, Psalm level 1, deptrac, PHPUnit.
5. Public classes and every non-obvious decision are documented, with the RFC section cited.
6. "Current state" in this file is updated.

## Open questions

None at the moment. Record new ones here as they come up.
