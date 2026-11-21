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
 * One thing an application asks for, in the words the consent screen uses.
 */
final readonly class ScopeLine
{
    /**
     * @param string $value       The scope itself, shown beside the words for whoever reads scopes.
     * @param string $description What it lets the application do, for the person deciding.
     */
    public function __construct(
        public string $value,
        public string $description,
    ) {
    }
}
