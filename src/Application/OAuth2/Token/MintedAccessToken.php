<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Token;

use Clavia\Domain\OAuth2\AccessToken;

/**
 * An access token just recorded, and the value the client receives for it: a random
 * secret or a JWT. The value exists nowhere else.
 */
final readonly class MintedAccessToken
{
    /**
     * @param non-empty-string $value
     */
    public function __construct(
        public AccessToken $token,
        #[\SensitiveParameter] public string $value,
    ) {
    }
}
