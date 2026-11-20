<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\ResourceServers\PermissionDefinition;
use LogicException;

/**
 * The `permissions` member of the `ResourceServerCreate` and `ResourceServerUpdate`
 * bodies, in the shape the use cases take it.
 */
final class ResourceServerFields
{
    private function __construct()
    {
    }

    /**
     * The `permissions` member, when the body has one.
     *
     * @return list<PermissionDefinition>|null
     */
    public static function permissions(JsonObject $body): ?array
    {
        $permissions = $body->objects('permissions');

        return $permissions === null ? null : array_map(
            static fn (JsonObject $permission): PermissionDefinition => new PermissionDefinition(
                $permission->string('value') ?? throw new LogicException("The contract requires 'value'."),
                $permission->string('description') ?? '',
            ),
            $permissions,
        );
    }
}
