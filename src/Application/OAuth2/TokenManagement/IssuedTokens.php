<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\TokenManagement;

use Clavia\Domain\OAuth2\AccessToken;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\OAuth2\RefreshToken;
use Clavia\Domain\OAuth2\RefreshTokenRepository;
use Clavia\Domain\Shared\Digest;

/**
 * Finds an issued token by its value, whichever kind it is.
 *
 * The hint is an optimisation, not a constraint (RFC 7662 §2.1, RFC 7009 §2.1): it says
 * where to look first, and a token of the other kind is still found.
 */
final readonly class IssuedTokens
{
    public function __construct(
        private AccessTokenRepository $accessTokens,
        private RefreshTokenRepository $refreshTokens,
    ) {
    }

    public function find(PresentedToken $presented): AccessToken|RefreshToken|null
    {
        $digest = Digest::of($presented->value);

        if ($presented->hint === TokenTypeHint::RefreshToken) {
            return $this->refreshTokens->findByDigest($digest) ?? $this->accessTokens->findByDigest($digest);
        }

        return $this->accessTokens->findByDigest($digest) ?? $this->refreshTokens->findByDigest($digest);
    }
}
