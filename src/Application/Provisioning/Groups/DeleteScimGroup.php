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
use Clavia\Application\Provisioning\Users\VersionMismatch;
use Clavia\Domain\Provisioning\ScimGroup;
use Clavia\Domain\Provisioning\ScimGroupRepository;

/**
 * `DELETE /scim/v2/Groups/{id}` (RFC 7644 §3.6): the group gone, and the role it gave taken back
 * from its members, unless something else still gives it.
 */
final readonly class DeleteScimGroup
{
    public function __construct(
        private ReadScimGroups $read,
        private ScimGroupRepository $groups,
        private GroupRoles $roles,
        private TransactionManager $transactions,
    ) {
    }

    /**
     * @param list<string>|null $ifMatch The versions `If-Match` names; null without one.
     *
     * @return ScimGroup|VersionMismatch|null The group deleted; null when the connection has none such.
     */
    public function __invoke(
        ProvisioningCaller $caller,
        string $id,
        ?array $ifMatch = null,
    ): ScimGroup|VersionMismatch|null {
        $group = $this->read->find($caller, $id);
        if ($group === null) {
            return null;
        }
        if (! $group->isAt($ifMatch)) {
            return new VersionMismatch();
        }
        $this->transactions->transactional(function () use ($group): void {
            $this->groups->delete($group->id);
            $this->roles->reconcile($group->members);
        });

        return $group;
    }
}
