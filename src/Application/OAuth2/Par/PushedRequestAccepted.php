<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Par;

/**
 * A pushed authorization request held: the `request_uri` that names it and how long it lasts
 * (RFC 9126 §2.2).
 */
final readonly class PushedRequestAccepted
{
    /**
     * @param positive-int $expiresIn Seconds.
     */
    public function __construct(
        public string $requestUri,
        public int $expiresIn,
    ) {
    }
}
