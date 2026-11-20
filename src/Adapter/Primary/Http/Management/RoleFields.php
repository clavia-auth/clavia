<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Roles\PermissionReference;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Rbac\RoleId;
use LogicException;

/**
 * The members of the role bodies (`RoleCreate`, `RoleUpdate`, `UserIds`, `RoleIds`) in
 * the shape the use cases take them. The contract has already checked each id's form.
 */
final class RoleFields
{
    private function __construct()
    {
    }

    /**
     * The `permissions` member, when the body has one.
     *
     * @return list<PermissionReference>|null
     */
    public static function permissions(JsonObject $body): ?array
    {
        $permissions = $body->objects('permissions');

        return $permissions === null ? null : array_map(
            static fn (JsonObject $permission): PermissionReference => new PermissionReference(
                $permission->string('resource_server_id')
                    ?? throw new LogicException("The contract requires 'resource_server_id'."),
                $permission->string('value') ?? throw new LogicException("The contract requires 'value'."),
            ),
            $permissions,
        );
    }

    /**
     * @return list<UserId>
     */
    public static function userIds(JsonObject $body): array
    {
        return array_map(
            static fn (string $id): UserId => UserId::fromString($id),
            $body->strings('user_ids') ?? throw new LogicException("The contract requires 'user_ids'."),
        );
    }

    /**
     * @return list<RoleId>
     */
    public static function roleIds(JsonObject $body): array
    {
        return array_map(
            static fn (string $id): RoleId => RoleId::fromString($id),
            $body->strings('role_ids') ?? throw new LogicException("The contract requires 'role_ids'."),
        );
    }
}
