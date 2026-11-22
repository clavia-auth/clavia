<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Configuration;

/**
 * Runtime configuration for the Clavia authorization server.
 *
 * **Every constructor parameter is an environment variable.** A parameter named
 * `rootDomain` is set with `CLAVIA_ROOT_DOMAIN` ({@see self::variableName()}), and the
 * default written here is only the value used when nothing supplies one. There is no
 * separate list to keep in step — adding a parameter adds a setting, and
 * `clavia config` prints the whole surface from this class.
 *
 * Instances are built by {@see self::fromEnvironment()}, which coerces, bounds-checks
 * and cross-checks every value. Precedence is decided by the caller that assembles the
 * variables: the process environment, then `.env`, then the default.
 *
 * This class belongs to no ring of the hexagon: it is plain configuration, readable by
 * the adapters and the composition root, and never by the domain or the application
 * layer, which receive the few values they need as arguments.
 */
final readonly class Settings
{
    public const string VARIABLE_PREFIX = 'CLAVIA_';

    /**
     * Subdomain labels Clavia itself occupies on any deployment's domain. Reserved so
     * that nothing provisioned later (a tenant slug, a per-client host) can shadow the
     * origin where credentials are typed or the one where the backoffice lives. `api`
     * is deliberately absent: the Management API is a path under `management.*`, not a
     * host — see "Domain configuration" in CLAUDE.md.
     */
    public const array RESERVED_SUBDOMAIN_LABELS = ['auth', 'management', 'www'];

    /**
     * @internal Use {@see self::fromEnvironment()}: this constructor checks nothing.
     *
     * @param list<non-empty-string> $trustedProxies
     * @param list<string> $signingRetiredKeyRefs
     * @param list<string> $scopesSupported
     */
    public function __construct(
        /**
         * The deployment's domain — `acme.com`, `clavia.io`, whatever DNS the operator
         * controls. Every host Clavia needs is derived from it: `auth.{rootDomain}` is
         * the OAuth2/OIDC/login origin and `management.{rootDomain}` the backoffice.
         * Required, with no default, because there is no domain that is right for
         * everyone and a wrong one silently issues tokens with a wrong `iss`.
         */
        public string $rootDomain,
        public Environment $env = Environment::Development,
        /**
         * The `iss` claim, and the base of every URL in the discovery document.
         * Derived as `https://auth.{rootDomain}` when unset. Relying parties pin this
         * and reject tokens whose `iss` does not match exactly, so overriding it — or
         * changing the domain — invalidates every token already issued.
         */
        public string $issuerUrl = '',
        /**
         * Reverse proxies whose `X-Forwarded-Proto` is believed: addresses or CIDR
         * ranges, or `*` for any. Empty by default, which is right when the web server
         * speaks FastCGI to PHP directly (it reports the scheme itself). Set it when a
         * load balancer terminates TLS in front of that web server; get it wrong and
         * every URL the server builds has the wrong scheme.
         */
        public array $trustedProxies = [],
        // ------------------------------------------------------------------
        // Token signing
        // ------------------------------------------------------------------
        /**
         * `postgres`, `aws-kms`, `gcp-kms`, `azure-key-vault`, or the class name of a
         * custom backend. The three cloud options are non-extractable; `postgres`
         * holds the key itself (encrypted with `secretEncryptionKey`) and is the
         * default only because it needs no external service.
         */
        public string $signingBackend = 'postgres',
        /**
         * Provider-specific key identifier. Required by every backend except
         * `postgres`, which keeps its keys in the database. It names one immutable key
         * version — an AWS key ARN or id, a GCP `cryptoKeyVersions/…` resource, a
         * versioned Key Vault key URL — never an alias that could be repointed.
         */
        public ?string $signingKeyRef = null,
        /**
         * Keys of the same remote backend that sign nothing any more but stay in the JWKS
         * until every token they signed has expired: the rotation path for a provider
         * that does not rotate an asymmetric key itself. Refused with `postgres`, which
         * retires its own keys.
         */
        public array $signingRetiredKeyRefs = [],
        /** JWS algorithm for issued tokens. RS256 is mandatory-to-implement for OIDC. */
        public string $signingAlgorithm = 'RS256',
        /** Region for the AWS KMS backend. Falls through to the AWS resolution chain when unset. */
        public ?string $awsRegion = null,
        /** Aims the AWS KMS backend at a local emulator. Refused outside development. */
        public ?string $awsKmsEndpointUrl = null,
        /**
         * The Microsoft Entra tenant for the Azure Key Vault backend. With
         * `azureClientId`, and a secret or a federated token file, the backend signs in
         * as that application; without them it uses the managed identity of the host.
         */
        public ?string $azureTenantId = null,
        /** The application to sign in as, or the user-assigned managed identity to use. */
        public ?string $azureClientId = null,
        public ?string $azureClientSecret = null,
        /** The token AKS workload identity projects into the pod, presented instead of a secret. */
        public ?string $azureFederatedTokenFile = null,
        /**
         * Base64 32-byte key encrypting secrets that must be readable back. Without
         * it the postgres backend refuses to create or use a key: there is no fallback
         * to storing it in the clear.
         */
        public ?string $secretEncryptionKey = null,
        /** Lifetime of an ID token, seconds. It is an authentication receipt, not an API credential. */
        #[Range(min: 1)]
        public int $idTokenLifetime = 300,
        /** Lifetime of a back-channel logout token (OIDC Back-Channel Logout 1.0 §2.4), seconds. */
        #[Range(min: 1, max: 600)]
        public int $backchannelLogoutTokenLifetime = 120,
        /**
         * Let outbound requests reach loopback, private and link-local addresses. That
         * check is an SSRF guard; refused outside development.
         */
        public bool $outboundAllowPrivateAddresses = false,
        // ------------------------------------------------------------------
        // PostgreSQL — the same CLAVIA_POSTGRES_* values docker-compose.yml uses
        // ------------------------------------------------------------------
        public string $postgresHost = 'localhost',
        #[Range(min: 1, max: 65535)]
        public int $postgresPort = 5433,
        public string $postgresUser = 'clavia',
        public string $postgresPassword = 'clavia',
        public string $postgresDb = 'clavia',
        /** `postgresql://user:password@host:port/database`. Assembled from the parts above when unset. */
        public string $databaseUrl = '',
        // ------------------------------------------------------------------
        // Redis — short-TTL material only: losing it signs everyone out and corrupts nothing
        // ------------------------------------------------------------------
        public string $redisHost = 'localhost',
        #[Range(min: 1, max: 65535)]
        public int $redisPort = 6379,
        #[Range(min: 0)]
        public int $redisDb = 0,
        /** `redis://host:port/db`. Assembled from the parts above when unset. */
        public string $redisUrl = '',
        // ------------------------------------------------------------------
        // Browser sessions
        // ------------------------------------------------------------------
        /** Name of the session cookie. Host-only: no `Domain` attribute is ever set. */
        public string $sessionCookieName = 'clavia_session',
        /** Sliding window: a session expires this long after its last use. Seconds. */
        #[Range(min: 1)]
        public int $sessionIdleLifetime = 28800,
        /** Hard ceiling regardless of activity. Seconds. */
        #[Range(min: 1)]
        public int $sessionAbsoluteLifetime = 604800,
        /** `Secure` flag on the session and CSRF cookies. Refused as false outside development. */
        public bool $sessionCookieSecure = true,
        /** Failed password attempts, per account and per client address, before the login endpoint refuses. */
        #[Range(min: 1)]
        public int $loginMaxAttempts = 10,
        #[Range(min: 1)]
        public int $loginAttemptWindow = 900,
        /** How long the audit trail keeps an event, days; `clavia audit:purge` removes what is older. */
        #[Range(min: 1)]
        public int $auditRetentionDays = 90,
        // ------------------------------------------------------------------
        // Multi-factor authentication
        // ------------------------------------------------------------------
        /** Seconds the browser has to finish the second step after its password was accepted. */
        #[Range(min: 1)]
        public int $mfaChallengeLifetime = 300,
        /** Wrong codes allowed on one challenge before it is destroyed. */
        #[Range(min: 1)]
        public int $mfaMaxAttempts = 5,
        /** Single-use recovery codes issued when a factor is confirmed. */
        #[Range(min: 1, max: 20)]
        public int $mfaRecoveryCodeCount = 10,
        // ------------------------------------------------------------------
        // Social login — a provider appears once both halves are set
        // ------------------------------------------------------------------
        public ?string $googleClientId = null,
        public ?string $googleClientSecret = null,
        public ?string $githubClientId = null,
        public ?string $githubClientSecret = null,
        /**
         * Whether a first social sign-in may attach itself to an existing local account
         * with the same address. Only ever with an address the provider reports as verified.
         */
        public bool $socialAutoLink = true,
        // ------------------------------------------------------------------
        // Email — passwordless sign-in
        // ------------------------------------------------------------------
        public EmailBackend $emailBackend = EmailBackend::Console,
        /** The `From` address. Derived from the domain when unset. */
        public ?string $emailFrom = null,
        public ?string $smtpHost = null,
        #[Range(min: 1)]
        public int $smtpPort = 587,
        public ?string $smtpUsername = null,
        public ?string $smtpPassword = null,
        public bool $smtpStarttls = true,
        /** How long a one-time code stays valid, seconds. */
        #[Range(min: 1, max: 1800)]
        public int $passwordlessCodeLifetime = 600,
        /** How long a sign-in link stays valid, seconds. */
        #[Range(min: 1, max: 3600)]
        public int $passwordlessLinkLifetime = 900,
        #[Range(min: 1, max: 10)]
        public int $passwordlessMaxAttempts = 5,
        /** Sign-in emails one address (and one client address) may trigger per hour. */
        #[Range(min: 1)]
        public int $passwordlessSendLimit = 5,
        /**
         * How long an email verification link stays valid, seconds: a day by default, since a
         * person signing up may read their mail later.
         */
        #[Range(min: 600, max: 604800)]
        public int $verificationLinkLifetime = 86400,
        /** How long a password reset link stays valid, seconds. */
        #[Range(min: 300, max: 86400)]
        public int $resetLinkLifetime = 1800,
        /**
         * Account emails — verification and reset links, the notice that an address is taken —
         * one address (and one client address) may trigger per hour.
         */
        #[Range(min: 1, max: 100)]
        public int $accountEmailSendLimit = 5,
        /** Accounts one client address may create from the sign-up page per hour. */
        #[Range(min: 1, max: 1000)]
        public int $signUpLimit = 10,
        // ------------------------------------------------------------------
        // Passkeys (docs/design/passkeys.md)
        // ------------------------------------------------------------------
        /** Turns every passkey page and flow on or off. */
        public bool $passkeysEnabled = true,
        /**
         * The WebAuthn relying party id: the domain every passkey is bound to. Derived as the
         * sign-in host; it may be a parent of it within CLAVIA_ROOT_DOMAIN, and nothing else, or
         * no browser would accept it. Changing it orphans every passkey already registered, so it
         * is decided once, per deployment.
         */
        public string $webauthnRpId = '',
        /** The name authenticators show beside a passkey. Derived as CLAVIA_ROOT_DOMAIN. */
        public string $webauthnRpName = '',
        /** How long a WebAuthn ceremony may take, seconds: from the options sent to the response. */
        #[Range(min: 60, max: 600)]
        public int $webauthnCeremonyLifetime = 300,
        /** Passkeys one account may hold. */
        #[Range(min: 1, max: 50)]
        public int $passkeyMaxPerUser = 10,
        /**
         * Seconds since sign-in within which a person may add or remove a passkey. Later, they sign
         * in again first: a browser left signed in should not be enough to change how the account
         * is protected.
         */
        #[Range(min: 60, max: 86400)]
        public int $passkeyReauthWindow = 600,
        // ------------------------------------------------------------------
        // OAuth2
        // ------------------------------------------------------------------
        /** Authorization codes are single-use and short-lived; OAuth 2.1 recommends one minute at most. */
        #[Range(min: 1, max: 600)]
        public int $authorizationCodeLifetime = 60,
        #[Range(min: 1)]
        public int $accessTokenLifetime = 3600,
        /** Idle limit of a refresh token: every refresh issues a new one with a fresh lifetime. Seconds. */
        #[Range(min: 1)]
        public int $refreshTokenLifetime = 2592000,
        /** The longest a chain of refresh tokens descended from one sign-in may live. Seconds. */
        #[Range(min: 1)]
        public int $refreshTokenAbsoluteLifetime = 7776000,
        /** How long a device has to get its user code typed in (RFC 8628 `expires_in`). Seconds. */
        #[Range(min: 1, max: 1800)]
        public int $deviceCodeLifetime = 600,
        /** Minimum seconds between two polls with one device code (RFC 8628 `interval`). */
        #[Range(min: 1)]
        public int $devicePollInterval = 5,
        /** Scopes this server is willing to issue in an interactive flow: the OIDC scopes. */
        public array $scopesSupported = ['openid', 'profile', 'email'],
        /**
         * Audience of the Management API. Derived from the domain when unset
         * (`https://management.{rootDomain}/api/v1/`). An identifier, never dereferenced.
         */
        public ?string $managementApiIdentifier = null,
        /**
         * Development-only bypass of the login page: `/oauth2/authorize` resolves the end
         * user to this address whenever no session cookie is presented. Refused outside
         * development.
         */
        public ?string $devAutologinEmail = null,
    ) {
    }

    /**
     * Build the settings from `CLAVIA_*` variables, validating every one of them.
     *
     * @param array<string, string> $variables Variable name to raw value; names without
     *                                         the prefix are ignored, and an empty value
     *                                         counts as unset.
     *
     * @throws InvalidSettings When a value is malformed, out of bounds, or the
     *                         combination is one Clavia refuses to run with.
     */
    public static function fromEnvironment(array $variables): self
    {
        return new SettingsBuilder()->build($variables);
    }

    /**
     * A copy with some values replaced, unchecked.
     *
     * @internal For {@see SettingsBuilder}, which derives values before validating them.
     *
     * @param array<string, mixed> $changes Parameter name to new value.
     */
    public function with(array $changes): self
    {
        return clone($this, $changes);
    }

    /**
     * The environment variable that sets a constructor parameter: `rootDomain` is
     * `CLAVIA_ROOT_DOMAIN`.
     */
    public static function variableName(string $parameter): string
    {
        return self::VARIABLE_PREFIX . strtoupper((string) preg_replace('/(?<!^)[A-Z]/', '_$0', $parameter));
    }

    public function isDevelopment(): bool
    {
        return $this->env === Environment::Development;
    }

    /** The origin's hostname: where credentials are typed and tokens are minted. */
    public function authHost(): string
    {
        return 'auth.' . $this->rootDomain;
    }

    /** The backoffice SPA and the Management API (`/api/v1/*`) share this host. */
    public function managementHost(): string
    {
        return 'management.' . $this->rootDomain;
    }

    /** The Management API's identifier, derived from the domain unless overridden. */
    public function managementApiAudience(): string
    {
        return $this->managementApiIdentifier ?? sprintf('https://%s/api/v1/', $this->managementHost());
    }

    /** The `From` address of every email: `CLAVIA_EMAIL_FROM`, or `no-reply@{rootDomain}`. */
    public function emailSender(): string
    {
        return $this->emailFrom ?? 'no-reply@' . $this->rootDomain;
    }

    /**
     * The origin a WebAuthn ceremony must come from: the issuer's scheme, host and port. The sign-in
     * pages are served there, and a browser reports exactly this.
     */
    public function webauthnOrigin(): string
    {
        $scheme = (string) parse_url($this->issuerUrl, PHP_URL_SCHEME);
        $host = (string) parse_url($this->issuerUrl, PHP_URL_HOST);
        $port = parse_url($this->issuerUrl, PHP_URL_PORT);

        return $scheme . '://' . $host . (is_int($port) ? ':' . $port : '');
    }

    /** The issuer identifier: the exact value of every `iss` claim. */
    public function issuer(): string
    {
        return $this->issuerUrl;
    }

    /**
     * Configurations that are legitimate but should be a decision somebody made rather
     * than a default nobody noticed. Not fatal; the entry points report them.
     *
     * @return list<string>
     */
    public function warnings(): array
    {
        $warnings = [];

        if (! $this->passkeysEnabled && parse_url($this->issuerUrl, PHP_URL_SCHEME) !== 'https') {
            $warnings[] = 'Passkeys are off: they need the sign-in pages on https, and the issuer is '
                . $this->issuerUrl . '.';
        }
        if ($this->signingBackend === 'postgres' && $this->env === Environment::Production) {
            $warnings[] = 'CLAVIA_SIGNING_BACKEND=postgres in production keeps the private signing key in the '
                . 'database, where anyone holding both a backup and CLAVIA_SECRET_ENCRYPTION_KEY can mint '
                . 'tokens. Prefer aws-kms, gcp-kms or azure-key-vault.';
        }

        return $warnings;
    }
}
