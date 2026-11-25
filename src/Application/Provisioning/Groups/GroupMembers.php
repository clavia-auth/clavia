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
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Provisioning\ProvisionedAccountRepository;
use Clavia\Domain\Provisioning\ScimGroupResource;
use Clavia\Domain\Shared\InvalidValue;

/**
 * The accounts a group's `members` name: each one an account provisioned into the caller's
 * connection (docs/design/scim-provisioning.md §7, a token reaches one connection).
 */
final readonly class GroupMembers
{
    public function __construct(private ProvisionedAccountRepository $accounts)
    {
    }

    /**
     * @return list<UserId>
     *
     * @throws InvalidValue When a member names no account of the connection: never which.
     */
    public function of(ProvisioningCaller $caller, ScimGroupResource $resource): array
    {
        $members = [];
        foreach ($resource->members as $id) {
            try {
                $member = UserId::fromString($id);
            } catch (InvalidValue) {
                $member = null;
            }
            if ($member === null || $this->accounts->find($caller->connection->name, $member) === null) {
                throw new InvalidValue("'members.value' names no account of this connection.");
            }
            $members[] = $member;
        }

        return $members;
    }
}
