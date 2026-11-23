<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Client;

use Clavia\Domain\Authentication\MfaPolicy;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Url;
use DateTimeImmutable;

/**
 * A client application registered with this authorization server (RFC 6749 §2).
 *
 * A client holds no scope of its own. A scope means nothing without an API, so what
 * may be requested is decided by the API named in `audience` and by what the user (or,
 * for a machine, its client grant) holds there. A per-client scope list would be a
 * third answer to the same question, one that names no API and can only drift from the
 * two that do.
 *
 * Who runs it ({@see Ownership}) is read from its id: a third-party application is
 * registered under a `tpc_` id, and that never changes.
 *
 * A first-party application lists the connections its users may sign in through. A
 * third-party one lists none: it gets the domain connections, and those only.
 *
 * Every client proves its codes with PKCE unless relieved of it ({@see $requiresPkce}),
 * and only a confidential one can be: OAuth 2.1 §7.5.1 allows a client that holds a
 * secret to rely on the OpenID Connect `nonce` instead.
 */
final readonly class Client
{
    private const int MAX_NAME_LENGTH = 120;

    /**
     * @param non-empty-string|null $secretHash
     * @param list<Url>             $redirectUris
     * @param list<GrantType>       $grantTypes
     * @param list<ResponseType>    $responseTypes
     * @param list<Url>             $postLogoutRedirectUris
     * @param list<ConnectionName>  $connections            Unique, sorted by name.
     */
    private function __construct(
        public ClientId $id,
        public string $name,
        public ClientType $type,
        public ClientAuthMethod $authMethod,
        private ?string $secretHash,
        public array $redirectUris,
        public array $grantTypes,
        public array $responseTypes,
        public DateTimeImmutable $createdAt,
        public array $postLogoutRedirectUris,
        public array $connections,
        public ?BackChannelLogout $backChannelLogout,
        public bool $requiresPkce,
        public MfaPolicy $mfaPolicy,
    ) {
    }

    /**
     * Register a client. The same rules apply when one is read back from storage, so a
     * client that exists is always coherent.
     *
     * @param string|null        $secretHash    A hash from the password hasher, never the secret itself.
     * @param list<Url>          $redirectUris  Where authorization responses may be sent, matched exactly.
     * @param list<GrantType>    $grantTypes    What it may ask of the token endpoint.
     * @param list<ResponseType> $responseTypes What it may ask of the authorization endpoint.
     * @param list<Url>          $postLogoutRedirectUris Where a sign-out it starts may send the browser back
     *                                                  (RP-Initiated Logout 1.0 §3.1), matched exactly.
     * @param list<ConnectionName> $connections         The connections its users may sign in through.
     * @param BackChannelLogout|null $backChannelLogout Where to tell it that a session ended; null when
     *                                                  it does not want to be told.
     * @param bool               $requiresPkce  False lets an OpenID Connect request carrying a `nonce`
     *                                          go without PKCE; only for a confidential client.
     * @param MfaPolicy          $mfaPolicy     Whether its users must sign in with more than one factor.
     *
     * @throws InvalidValue When the registration contradicts itself, or a third-party client would
     *                      list connections.
     */
    public static function register(
        ClientId $id,
        string $name,
        ClientType $type,
        ClientAuthMethod $authMethod,
        #[\SensitiveParameter] ?string $secretHash,
        array $redirectUris,
        array $grantTypes,
        array $responseTypes,
        DateTimeImmutable $createdAt,
        array $postLogoutRedirectUris = [],
        array $connections = [],
        ?BackChannelLogout $backChannelLogout = null,
        bool $requiresPkce = true,
        MfaPolicy $mfaPolicy = MfaPolicy::Optional,
    ): self {
        $secretHash = $secretHash === '' ? null : $secretHash;

        if ($connections !== [] && $id->ownership() === Ownership::ThirdParty) {
            throw new InvalidValue(
                'A third-party application lists no connections: it signs people in through the domain '
                . 'connections.',
            );
        }

        if (strlen($name) > self::MAX_NAME_LENGTH) {
            throw new InvalidValue('A client name is at most 120 bytes.');
        }

        // RFC 6749 §2.1: the type is whether the client can keep a secret, so the type,
        // the secret and the authentication method have to tell the same story.
        if ($type === ClientType::Public && ($authMethod->usesASecret() || $secretHash !== null)) {
            throw new InvalidValue('A public client has no secret and authenticates with "none".');
        }
        if ($type === ClientType::Confidential && (! $authMethod->usesASecret() || $secretHash === null)) {
            throw new InvalidValue('A confidential client has a secret and authenticates with it.');
        }

        foreach ($redirectUris as $redirectUri) {
            // RFC 6749 §3.1.2: the redirection endpoint URI must not include a fragment.
            if ($redirectUri->hasFragment()) {
                throw new InvalidValue('A redirect URI must not contain a fragment.');
            }
        }
        foreach ($postLogoutRedirectUris as $postLogoutRedirectUri) {
            // `state` is appended to it as a query parameter, which a fragment would swallow.
            if ($postLogoutRedirectUri->hasFragment()) {
                throw new InvalidValue('A post-logout redirect URI must not contain a fragment.');
            }
        }

        // A code can only be delivered by redirect, and is worth nothing without the
        // grant that redeems it — and the reverse: the grant needs a way to get codes.
        $asksForCodes = in_array(ResponseType::Code, $responseTypes, true);
        $redeemsCodes = in_array(GrantType::AuthorizationCode, $grantTypes, true);
        if (($asksForCodes || $redeemsCodes) && $redirectUris === []) {
            throw new InvalidValue('A client that may ask for a code needs at least one redirect URI.');
        }
        if ($asksForCodes !== $redeemsCodes) {
            throw new InvalidValue(
                'The "code" response type and the "authorization_code" grant go together: '
                . 'one issues what the other redeems.',
            );
        }

        // A refresh token is only ever issued with a person's tokens — from a code or a
        // device — so without one of those grants it would have nothing to refresh.
        if (
            in_array(GrantType::RefreshToken, $grantTypes, true)
            && ! array_any($grantTypes, static fn (GrantType $grant): bool => $grant->actsForAPerson())
        ) {
            throw new InvalidValue(
                'The refresh token grant needs the "authorization_code" or the device code grant: it '
                . 'refreshes what those issue.',
            );
        }

        // A device code is approved by whoever types its user code, so a stranger's device
        // asking for access is a phishing kit waiting to happen: the grant is the operator's
        // applications' only.
        if (in_array(GrantType::DeviceCode, $grantTypes, true) && $id->ownership() === Ownership::ThirdParty) {
            throw new InvalidValue('The device code grant is available to first-party applications only.');
        }

        // OAuth 2.1 §7.5.1: the exception is for a client that authenticates — a public
        // client's codes would be anybody's.
        if (! $requiresPkce && $type !== ClientType::Confidential) {
            throw new InvalidValue('Only a confidential client can do without PKCE.');
        }

        // RFC 6749 §4.4: the client credentials grant is for clients that can keep a secret.
        if (in_array(GrantType::ClientCredentials, $grantTypes, true) && $type !== ClientType::Confidential) {
            throw new InvalidValue('The client credentials grant is available to confidential clients only.');
        }

        return new self(
            $id,
            $name,
            $type,
            $authMethod,
            $secretHash,
            $redirectUris,
            array_values(array_unique($grantTypes, SORT_REGULAR)),
            array_values(array_unique($responseTypes, SORT_REGULAR)),
            $createdAt,
            $postLogoutRedirectUris,
            self::sorted($connections),
            $backChannelLogout,
            $requiresPkce,
            $mfaPolicy,
        );
    }

    /**
     * The same client, its users signing in through exactly `$connections`.
     *
     * @param list<ConnectionName> $connections
     *
     * @throws InvalidValue When the client is third-party.
     */
    public function withConnections(array $connections): self
    {
        return self::register(
            $this->id,
            $this->name,
            $this->type,
            $this->authMethod,
            $this->secretHash,
            $this->redirectUris,
            $this->grantTypes,
            $this->responseTypes,
            $this->createdAt,
            $this->postLogoutRedirectUris,
            $connections,
            $this->backChannelLogout,
            $this->requiresPkce,
            $this->mfaPolicy,
        );
    }

    /** Whether it lists `$connection` among those its users may sign in through. */
    public function enables(ConnectionName $connection): bool
    {
        return array_any(
            $this->connections,
            static fn (ConnectionName $enabled): bool => $enabled->equals($connection),
        );
    }

    /**
     * The same client with a new registration — name, redirect URIs, grants, response
     * types and authentication method — checked by the same rules as a new one, so that
     * an edit cannot leave behind a client no flow could serve.
     *
     * The type is not among them: switching between public and confidential changes
     * how the client proves itself, which is a different client.
     *
     * @param list<Url>          $redirectUris
     * @param list<GrantType>    $grantTypes
     * @param list<ResponseType> $responseTypes
     * @param list<Url>|null     $postLogoutRedirectUris Null keeps the registered ones.
     *
     * @throws InvalidValue
     */
    public function reconfigure(
        string $name,
        array $redirectUris,
        array $grantTypes,
        array $responseTypes,
        ClientAuthMethod $authMethod,
        ?array $postLogoutRedirectUris = null,
    ): self {
        return self::register(
            $this->id,
            $name,
            $this->type,
            $authMethod,
            $this->secretHash,
            $redirectUris,
            $grantTypes,
            $responseTypes,
            $this->createdAt,
            $postLogoutRedirectUris ?? $this->postLogoutRedirectUris,
            $this->connections,
            $this->backChannelLogout,
            $this->requiresPkce,
            $this->mfaPolicy,
        );
    }

    /**
     * The same client told — or no longer told — when a session it signed in through ends.
     */
    public function withBackChannelLogout(?BackChannelLogout $backChannelLogout): self
    {
        return self::register(
            $this->id,
            $this->name,
            $this->type,
            $this->authMethod,
            $this->secretHash,
            $this->redirectUris,
            $this->grantTypes,
            $this->responseTypes,
            $this->createdAt,
            $this->postLogoutRedirectUris,
            $this->connections,
            $backChannelLogout,
            $this->requiresPkce,
            $this->mfaPolicy,
        );
    }

    /**
     * The same client, required to use PKCE or relieved of it.
     *
     * @throws InvalidValue When a public client would be relieved of it.
     */
    public function withPkceRequired(bool $required): self
    {
        return self::register(
            $this->id,
            $this->name,
            $this->type,
            $this->authMethod,
            $this->secretHash,
            $this->redirectUris,
            $this->grantTypes,
            $this->responseTypes,
            $this->createdAt,
            $this->postLogoutRedirectUris,
            $this->connections,
            $this->backChannelLogout,
            $required,
            $this->mfaPolicy,
        );
    }

    /**
     * The same client, taking its users in on one factor or not, from the next authorization on.
     */
    public function requiringMfa(MfaPolicy $policy): self
    {
        return self::register(
            $this->id,
            $this->name,
            $this->type,
            $this->authMethod,
            $this->secretHash,
            $this->redirectUris,
            $this->grantTypes,
            $this->responseTypes,
            $this->createdAt,
            $this->postLogoutRedirectUris,
            $this->connections,
            $this->backChannelLogout,
            $this->requiresPkce,
            $policy,
        );
    }

    /**
     * The same client with a new secret: the old one stops working at once.
     *
     * @param non-empty-string $secretHash A hash from the password hasher.
     *
     * @throws InvalidValue When the client is public: it has no secret to replace.
     */
    public function withSecretHash(#[\SensitiveParameter] string $secretHash): self
    {
        if ($this->type !== ClientType::Confidential) {
            throw new InvalidValue('Only a confidential client has a secret to rotate.');
        }

        return self::register(
            $this->id,
            $this->name,
            $this->type,
            $this->authMethod,
            $secretHash,
            $this->redirectUris,
            $this->grantTypes,
            $this->responseTypes,
            $this->createdAt,
            $this->postLogoutRedirectUris,
            $this->connections,
            $this->backChannelLogout,
            $this->requiresPkce,
            $this->mfaPolicy,
        );
    }

    /**
     * Whether `$redirectUri` is one this client registered — by exact string match.
     *
     * No prefix, wildcard, or normalisation matching: those are the classic route to an
     * open redirect and, with it, authorization code exfiltration (OAuth 2.1 §2.3.1).
     */
    public function hasRedirectUri(string $redirectUri): bool
    {
        return array_any($this->redirectUris, static fn (Url $registered): bool => $registered->value === $redirectUri);
    }

    /**
     * Whether `$uri` is a post-logout redirect URI this client registered — by exact
     * string match, like a redirect URI (RP-Initiated Logout 1.0 §3.1).
     */
    public function hasPostLogoutRedirectUri(string $uri): bool
    {
        return array_any(
            $this->postLogoutRedirectUris,
            static fn (Url $registered): bool => $registered->value === $uri,
        );
    }

    /**
     * The origins the registered redirect URIs point at, each once, in registration order.
     *
     * Where a browser may legitimately end up after this client's authorization
     * request: the login page lists them in its CSP `form-action`, because Chromium
     * applies that directive to the whole redirect chain of a form submission.
     *
     * @return list<string>
     */
    public function redirectOrigins(): array
    {
        $origins = array_map(static fn (Url $uri): string => $uri->origin(), $this->redirectUris);

        return array_values(array_unique($origins));
    }

    /** The redirect URI used when a request names none — only when exactly one is registered. */
    public function soleRedirectUri(): ?Url
    {
        return count($this->redirectUris) === 1 ? $this->redirectUris[0] : null;
    }

    public function mayUseGrant(GrantType $grantType): bool
    {
        return in_array($grantType, $this->grantTypes, true);
    }

    public function mayUseResponseType(ResponseType $responseType): bool
    {
        return in_array($responseType, $this->responseTypes, true);
    }

    public function isPublic(): bool
    {
        return $this->type === ClientType::Public;
    }

    /** Who runs it — fixed at registration, written into its id. */
    public function ownership(): Ownership
    {
        return $this->id->ownership();
    }

    /** Whether the operator of this server runs it; see {@see Ownership}. */
    public function isFirstParty(): bool
    {
        return $this->ownership() === Ownership::FirstParty;
    }

    /**
     * @param list<ConnectionName> $connections
     *
     * @return list<ConnectionName>
     */
    private static function sorted(array $connections): array
    {
        $byName = [];
        foreach ($connections as $connection) {
            $byName[$connection->value] = $connection;
        }
        ksort($byName, SORT_STRING);

        return array_values($byName);
    }

    /**
     * The stored hash of the client secret, for the hasher to verify against; null for
     * a public client, which has none.
     *
     * @return non-empty-string|null
     */
    public function secretHash(): ?string
    {
        return $this->secretHash;
    }
}
