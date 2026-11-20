<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Token;

use Clavia\Domain\Shared\ScopeSet;

/**
 * A successful token response (RFC 6749 §5.1). The only place the access token exists
 * in the clear.
 */
final readonly class IssuedToken
{
    /**
     * @param non-empty-string $accessToken
     * @param non-empty-string $tokenType
     * @param int              $expiresIn   Lifetime of the access token, in seconds.
     * @param ScopeSet         $scope       What was actually granted.
     * @param string|null      $idToken     The ID token, when the grant was an OpenID Connect
     *                                      request (OIDC Core §3.1.3.3).
     */
    public function __construct(
        #[\SensitiveParameter] public string $accessToken,
        public string $tokenType,
        public int $expiresIn,
        public ScopeSet $scope,
        #[\SensitiveParameter] public ?string $idToken = null,
    ) {
    }
}
