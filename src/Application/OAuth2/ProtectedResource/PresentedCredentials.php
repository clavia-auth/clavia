<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\ProtectedResource;

/**
 * An access token as a protected resource received it: the scheme, the token, and — for the
 * `DPoP` scheme — every `DPoP` header the request carried, for {@see CheckSenderConstraint}.
 */
final readonly class PresentedCredentials
{
    /**
     * @param non-empty-string $accessToken
     * @param list<string>     $dpopProofs
     */
    public function __construct(
        public TokenScheme $scheme,
        #[\SensitiveParameter] public string $accessToken,
        public array $dpopProofs = [],
    ) {
    }

    /** @param non-empty-string $accessToken */
    public static function bearer(#[\SensitiveParameter] string $accessToken): self
    {
        return new self(TokenScheme::Bearer, $accessToken);
    }
}
