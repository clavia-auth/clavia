<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Adapter\Secondary\Signing\Remote\AccessTokens;

/** One bearer token, always: what a signing service's API is called with in a test. */
final readonly class StaticAccessTokens implements AccessTokens
{
    /**
     * @param non-empty-string $token
     */
    public function __construct(private string $token)
    {
    }

    #[\Override]
    public function token(): string
    {
        return $this->token;
    }
}
