<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\TokenManagement;

use Clavia\Application\OAuth2\ClientAuthentication\ClientAuthenticator;
use Clavia\Application\OAuth2\Token\TokenRequest;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\OAuth2\AccessToken;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\OAuth2\Refresh;
use Clavia\Domain\OAuth2\RefreshToken;
use Clavia\Domain\ResourceServer\ClientGrantRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Clock;

/**
 * `POST /oauth2/introspect` (RFC 7662): what a token is.
 *
 * Worth something to anyone holding a stolen token, so only a client that proves who it
 * is with a secret may ask, and it learns about a token only if it has a stake in it:
 * the token is its own, or was issued for an API it holds a grant on — how a resource
 * server, through its machine client, checks the bearer tokens presented to it without
 * sharing this server's database. Anything else is `active: false`, the same answer as
 * an unknown token (§2.2), so a caller cannot probe which tokens exist.
 *
 * Active means usable now: not expired, not revoked, a refresh token not spent, and —
 * for a token issued on a person's behalf — an account that exists and is active.
 */
final readonly class IntrospectToken
{
    /** No `none`: introspection open to anyone who can name a client id is a token oracle. */
    public const array AUTH_METHODS = [ClientAuthMethod::ClientSecretBasic, ClientAuthMethod::ClientSecretPost];

    public function __construct(
        private ClientAuthenticator $authenticator,
        private IssuedTokens $tokens,
        private ClientGrantRepository $clientGrants,
        private ResourceServerRepository $resourceServers,
        private UserRepository $users,
        private Clock $clock,
    ) {
    }

    /**
     * @return TokenIntrospection|null Null for a token that is not active — unknown, expired, revoked,
     *                                 spent, or one the caller has no stake in: one answer for all.
     *
     * @throws OAuth2Error `invalid_client` when the caller does not authenticate with a secret;
     *                     `invalid_request` or `unsupported_token_type` for a malformed request.
     */
    public function __invoke(TokenRequest $request): ?TokenIntrospection
    {
        $caller = $this->authenticator->authenticate($request->credentials(), self::AUTH_METHODS);
        $presented = PresentedToken::from($request->parameters);

        $token = $this->tokens->find($presented);
        if ($token === null || ! $this->mayLearnAbout($caller, $token)) {
            return null;
        }

        $now = $this->clock->now();
        $usable = $token instanceof AccessToken
            ? $token->isActiveAt($now)
            : $token->examine($token->clientId, $now) === Refresh::Usable;
        if (! $usable) {
            return null;
        }

        $username = null;
        if ($token->userId !== null) {
            $user = $this->users->find($token->userId);
            if ($user === null || ! $user->isActive()) {
                return null;
            }
            $username = $user->email;
        }

        return new TokenIntrospection(
            $token->clientId,
            $token->scope,
            $token->issuedAt,
            $token->expiresAt,
            $token->audience,
            $token->userId,
            $username,
            $token instanceof AccessToken ? AccessToken::TOKEN_TYPE : null,
        );
    }

    private function mayLearnAbout(Client $caller, AccessToken|RefreshToken $token): bool
    {
        if ($token->clientId->equals($caller->id)) {
            return true;
        }

        return $token->audience !== null && $this->holdsAGrantOn($caller, $token->audience);
    }

    private function holdsAGrantOn(Client $caller, Audience $audience): bool
    {
        $api = $this->resourceServers->findByIdentifier($audience);

        return $api !== null && $this->clientGrants->find($caller->id, $api->id) !== null;
    }
}
