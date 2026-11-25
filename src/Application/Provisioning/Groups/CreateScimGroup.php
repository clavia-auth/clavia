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
use Clavia\Domain\Provisioning\ScimGroup;
use Clavia\Domain\Provisioning\ScimGroupId;
use Clavia\Domain\Provisioning\ScimGroupRepository;
use Clavia\Domain\Provisioning\ScimGroupResource;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;

/**
 * `POST /scim/v2/Groups` (RFC 7644 §3.3; docs/design/scim-provisioning.md §5.5): a group of the
 * connection the token reaches, its members accounts of that connection, and, in the same
 * transaction, the role it names given to them when that role is provisionable.
 */
final readonly class CreateScimGroup
{
    public function __construct(
        private ScimGroupRepository $groups,
        private GroupMembers $members,
        private GroupRoles $roles,
        private TransactionManager $transactions,
        private RandomSource $random,
        private Clock $clock,
    ) {
    }

    /**
     * @throws InvalidValue When a member names no account of the connection.
     */
    public function __invoke(ProvisioningCaller $caller, ScimGroupResource $resource): ScimGroup|AttributeTaken
    {
        $group = ScimGroup::provision(
            ScimGroupId::generate($this->random),
            $caller->connection->name,
            $resource,
            $this->members->of($caller, $resource),
            $caller->token->id,
            $this->clock->now(),
        );
        try {
            $this->transactions->transactional(function () use ($group): void {
                $this->groups->add($group);
                $this->roles->reconcile($group->members);
            });
        } catch (AlreadyExists $conflict) {
            return self::taken($conflict);
        }

        return $group;
    }

    /** The attribute a group's conflict is over. */
    public static function taken(AlreadyExists $conflict): AttributeTaken
    {
        return new AttributeTaken(
            $conflict->getMessage() === ScimGroupRepository::EXTERNAL_ID_TAKEN ? 'externalId' : 'displayName',
        );
    }
}
