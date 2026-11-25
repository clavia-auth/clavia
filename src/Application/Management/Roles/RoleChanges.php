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
 * The body of `PATCH /api/v1/roles/{role_id}`: null leaves a field alone; `permissions`,
 * when given, is the whole new set.
 */
final readonly class RoleChanges
{
    /**
     * @param list<PermissionReference>|null $permissions
     */
    public function __construct(
        public ?string $name = null,
        public ?string $description = null,
        public ?array $permissions = null,
        public ?bool $provisionable = null,
    ) {
    }
}
