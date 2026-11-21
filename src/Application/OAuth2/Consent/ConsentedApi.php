<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Consent;

/**
 * The API a request names, and the permissions it asks for there.
 */
final readonly class ConsentedApi
{
    /**
     * @param string          $name        The API's name, or its identifier when it has none.
     * @param list<ScopeLine> $permissions With the descriptions the API defines.
     */
    public function __construct(
        public string $name,
        public string $identifier,
        public array $permissions,
    ) {
    }
}
