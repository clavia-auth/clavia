<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Roles;

/**
 * A permission as a request names it: the API's id and the value. Both halves, because a
 * value alone is ambiguous across APIs. Checked against what the API defines by
 * {@see RolePermissions::resolve()}.
 */
final readonly class PermissionReference
{
    public function __construct(
        public string $resourceServerId,
        public string $value,
    ) {
    }
}
