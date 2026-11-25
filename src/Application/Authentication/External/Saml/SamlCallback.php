<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\External\Saml;

/** The GET the assertion consumer service sent the browser to, with the browser's cookies. */
final readonly class SamlCallback
{
    public function __construct(
        public string $connection,
        #[\SensitiveParameter] public ?string $handle,
        #[\SensitiveParameter] public ?string $browserState,
        #[\SensitiveParameter] public ?string $currentSessionId,
        public string $clientAddress = '',
    ) {
    }
}
