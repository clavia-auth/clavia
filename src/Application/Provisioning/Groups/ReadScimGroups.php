<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Provisioning\Groups;

use Clavia\Application\Provisioning\ProvisioningCaller;
use Clavia\Application\Provisioning\Users\ReadScimUsers;
use Clavia\Domain\Provisioning\ScimFilter;
use Clavia\Domain\Provisioning\ScimGroup;
use Clavia\Domain\Provisioning\ScimGroupId;
use Clavia\Domain\Provisioning\ScimGroupRepository;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `GET /scim/v2/Groups/{id}` and `GET /scim/v2/Groups` (RFC 7644 §3.4): the groups of the connection
 * the token reaches. Another connection's is not found (docs/design/scim-provisioning.md §7).
 */
final readonly class ReadScimGroups
{
    public function __construct(private ScimGroupRepository $groups)
    {
    }

    public function find(ProvisioningCaller $caller, string $id): ?ScimGroup
    {
        try {
            return $this->groups->find($caller->connection->name, ScimGroupId::fromString($id));
        } catch (InvalidValue) {
            return null;
        }
    }

    /**
     * @param int $startIndex 1-based; below 1 is 1.
     * @param int $count      At most {@see ReadScimUsers::MAX_COUNT}; below 0 is 0.
     */
    public function page(ProvisioningCaller $caller, ?ScimFilter $filter, int $startIndex, int $count): ScimGroupPage
    {
        $startIndex = max(1, $startIndex);
        $count = min(ReadScimUsers::MAX_COUNT, max(0, $count));
        $found = $this->groups->matching($caller->connection->name, $filter, $startIndex - 1, $count);

        return new ScimGroupPage($found['total'], $startIndex, $found['groups']);
    }
}
