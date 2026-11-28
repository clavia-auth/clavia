<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization\Caller;

use Clavia\Application\OAuth2\ProtectedResource\CheckSenderConstraint;
use Clavia\Application\OAuth2\ProtectedResource\PresentedCredentials;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\OAuth2\BearerTokenError;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\Digest;

/**
 * The Authorization API's access tokens (docs/design/fine-grained-authorization.md §5.2, step 1):
 * live, issued for the Authorization API, sender-constrained as they were issued, and — for a
 * person's token — a person still active. The audience is checked before any scope (RFC 6750 §3.1:
 * a scope means nothing without one).
 */
final readonly class AuthenticateAuthorizationCaller
{
    /**
     * @param Audience $authorizationApi The Authorization API's identifier: the `aud` a token must carry.
     */
    public function __construct(
        private AccessTokenRepository $tokens,
        private UserRepository $users,
        private Clock $clock,
        private Audience $authorizationApi,
        private CheckSenderConstraint $senderConstraint,
    ) {
    }

    /**
     * @param non-empty-string $method
     * @param non-empty-string $url    The resource's URL as this server knows it: a DPoP proof's `htu`.
     *
     * @throws BearerTokenError `invalid_token` or `invalid_dpop_proof`.
     */
    public function __invoke(PresentedCredentials $credentials, string $method, string $url): AuthorizationCaller
    {
        $token = $this->tokens->findByDigest(Digest::of($credentials->accessToken));

        if (
            $token === null
            || ! $token->isActiveAt($this->clock->now())
            || $token->audience === null
            || ! $token->audience->equals($this->authorizationApi)
        ) {
            throw self::refused();
        }
        // A bound token only with a proof from its key, a bearer one only as bearer (RFC 9449 §7).
        ($this->senderConstraint)($token, $credentials, $method, $url);

        if ($token->userId !== null) {
            $user = $this->users->find($token->userId);
            if ($user === null || ! $user->isActive()) {
                throw self::refused();
            }
        }

        return new AuthorizationCaller($token->clientId, $token->userId, $token->scope);
    }

    private static function refused(): BearerTokenError
    {
        return BearerTokenError::invalidToken('The access token is expired, revoked, or not valid for this API.');
    }
}
