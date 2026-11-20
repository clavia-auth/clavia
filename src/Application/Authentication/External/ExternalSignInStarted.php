<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\External;

/**
 * Where to send the browser, and the `state` handle it must also hold in a cookie.
 */
final readonly class ExternalSignInStarted
{
    /**
     * @param non-empty-string $handle
     */
    public function __construct(
        public string $authorizationUrl,
        #[\SensitiveParameter] public string $handle,
    ) {
    }
}
