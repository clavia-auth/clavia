<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Caller;

use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\OAuth2\BearerTokenError;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\Digest;

/**
 * Resolve the bearer token of a Management API request to its caller — or refuse it.
 *
 * Two of the three checks the API makes, in this order, each load-bearing:
 *
 * 1. **The token is live**: known, unrevoked, unexpired, and when it acts for a person,
 *    that account is still active. Re-checked on every request, so deactivating an
 *    operator takes effect at once.
 * 2. **It was issued for this API.** A scope means nothing without an audience:
 *    `read:users` on another API is a different permission spelled the same way. A
 *    token naming no API at all is refused too, whatever its scope says.
 *
 * The third — the scope the operation requires — is {@see ManagementCaller::require()}.
 * Every failure here is the same `invalid_token`: telling "expired" from "for another
 * API" helps only whoever holds a token that is not theirs.
 */
final readonly class AuthenticateManagementCaller
{
    /**
     * @param Audience $managementApi The Management API's identifier: the `aud` a token must carry.
     */
    public function __construct(
        private AccessTokenRepository $tokens,
        private UserRepository $users,
        private Clock $clock,
        private Audience $managementApi,
    ) {
    }

    /**
     * @throws BearerTokenError `invalid_token`.
     */
    public function __invoke(#[\SensitiveParameter] string $accessToken): ManagementCaller
    {
        $token = $this->tokens->findByDigest(Digest::of($accessToken));

        if (
            $token === null
            || ! $token->isActiveAt($this->clock->now())
            || $token->audience === null
            || ! $token->audience->equals($this->managementApi)
        ) {
            throw self::refused();
        }

        if ($token->userId !== null) {
            $user = $this->users->find($token->userId);
            if ($user === null || ! $user->isActive()) {
                throw self::refused();
            }
        }

        return new ManagementCaller($token->clientId, $token->userId, $token->scope);
    }

    private static function refused(): BearerTokenError
    {
        return BearerTokenError::invalidToken('The access token is expired, revoked, or not valid for this API.');
    }
}
