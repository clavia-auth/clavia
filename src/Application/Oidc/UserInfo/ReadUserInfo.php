<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Oidc\UserInfo;

use Clavia\Application\OAuth2\ProtectedResource\CheckSenderConstraint;
use Clavia\Application\OAuth2\ProtectedResource\PresentedCredentials;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\OAuth2\BearerTokenError;
use Clavia\Domain\Oidc\IdentityClaims;
use Clavia\Domain\Oidc\OidcScope;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;

/**
 * The userinfo endpoint (OIDC Core §5.3): the claims about the person an access token
 * was issued for, as far as its scope releases them.
 *
 * The token is looked up on every call, so revocation takes effect immediately, and
 * the account is re-checked, so a deactivated person stops being described. A token
 * that names nobody — a machine acting as itself — has nobody to describe. A token bound to a
 * DPoP key is accepted only with a proof from it ({@see CheckSenderConstraint}).
 */
final readonly class ReadUserInfo
{
    /**
     * @param non-empty-string $url This endpoint's URL, as discovery names it: a DPoP proof's `htu`.
     */
    public function __construct(
        private AccessTokenRepository $tokens,
        private UserRepository $users,
        private Clock $clock,
        private CheckSenderConstraint $senderConstraint,
        private string $url,
    ) {
    }

    /**
     * @return array<non-empty-string, string|bool|int>
     *
     * @param non-empty-string $method
     *
     * @throws BearerTokenError `invalid_token` for a token that cannot be used here, `invalid_dpop_proof`
     *                          for a bound one without a good proof, `insufficient_scope` for one not
     *                          granted `openid`.
     */
    public function __invoke(PresentedCredentials $credentials, string $method): array
    {
        $token = $this->tokens->findByDigest(Digest::of($credentials->accessToken));

        // One answer for unknown, revoked and expired: the caller learns nothing about
        // which tokens exist.
        if ($token === null || ! $token->isActiveAt($this->clock->now())) {
            throw BearerTokenError::invalidToken('The access token is invalid, expired or revoked.');
        }

        ($this->senderConstraint)($token, $credentials, $method, $this->url);

        if ($token->userId === null) {
            throw BearerTokenError::invalidToken('The access token was not issued for a person.');
        }

        $user = $this->users->find($token->userId);
        if ($user === null || ! $user->isActive()) {
            throw BearerTokenError::invalidToken('The access token was issued for an account that cannot be used.');
        }

        // Checked after the token is known to be valid: a scope problem is only worth
        // reporting about a token, and an account, that could otherwise be used.
        if (! $token->scope->contains(OidcScope::OPENID)) {
            throw BearerTokenError::insufficientScope(
                ScopeSet::fromString(OidcScope::OPENID),
                "The access token was not granted the 'openid' scope.",
            );
        }

        return IdentityClaims::of($user, $token->scope);
    }
}
