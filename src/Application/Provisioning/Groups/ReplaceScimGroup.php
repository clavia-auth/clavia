<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Provisioning\Groups;

use Clavia\Application\Port\TransactionManager;
use Clavia\Application\Provisioning\ProvisioningCaller;
use Clavia\Application\Provisioning\Users\AttributeTaken;
use Clavia\Application\Provisioning\Users\VersionMismatch;
use Clavia\Domain\Provisioning\ScimGroup;
use Clavia\Domain\Provisioning\ScimGroupRepository;
use Clavia\Domain\Provisioning\ScimGroupResource;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `PUT /scim/v2/Groups/{id}` (RFC 7644 §3.5.1), and what a `PATCH` becomes once applied: the group
 * made to be the resource sent. Everyone it held or holds now has their roles worked out again, in the
 * same transaction: a member who left loses the role the group gave, one who joined gains it, and a
 * renamed group stops granting one role and starts granting another.
 */
final readonly class ReplaceScimGroup
{
    public function __construct(
        private ReadScimGroups $read,
        private ScimGroupRepository $groups,
        private GroupMembers $members,
        private GroupRoles $roles,
        private TransactionManager $transactions,
        private Clock $clock,
    ) {
    }

    /**
     * @param list<string>|null $ifMatch The versions `If-Match` names; null without one.
     *
     * @throws InvalidValue When a member names no account of the connection.
     */
    public function __invoke(
        ProvisioningCaller $caller,
        string $id,
        ScimGroupResource $resource,
        ?array $ifMatch = null,
    ): ScimGroup|AttributeTaken|VersionMismatch|null {
        $current = $this->read->find($caller, $id);
        if ($current === null) {
            return null;
        }
        if (! $current->isAt($ifMatch)) {
            return new VersionMismatch();
        }
        $changed = $current->changedTo($resource, $this->members->of($caller, $resource), $this->clock->now());
        try {
            $this->transactions->transactional(function () use ($current, $changed): void {
                $this->groups->save($changed);
                $this->roles->reconcile([...$current->members, ...$changed->members]);
            });
        } catch (AlreadyExists $conflict) {
            return CreateScimGroup::taken($conflict);
        }

        return $changed;
    }
}
