<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\ResourceServers;

/**
 * A permission as it is written: a scope value, and what it allows in words.
 */
final readonly class PermissionDefinition
{
    public function __construct(
        public string $value,
        public string $description = '',
    ) {
    }
}
