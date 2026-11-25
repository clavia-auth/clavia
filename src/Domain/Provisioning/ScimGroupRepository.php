<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Provisioning;

use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\AlreadyExists;

/**
 * The groups directories provisioned, and their members. A group goes with its connection, a
 * membership with its account (cascades).
 */
interface ScimGroupRepository
{
    public const string DISPLAY_NAME_TAKEN = 'This displayName is already a group of the connection.';

    public const string EXTERNAL_ID_TAKEN = 'This externalId is already a group of the connection.';

    /**
     * @throws AlreadyExists With {@see DISPLAY_NAME_TAKEN} (ignoring case) or {@see EXTERNAL_ID_TAKEN}.
     */
    public function add(ScimGroup $group): void;

    /**
     * Record its name, `externalId` and members, whole.
     *
     * @throws AlreadyExists As {@see add()}.
     */
    public function save(ScimGroup $group): void;

    public function find(ConnectionName $connection, ScimGroupId $id): ?ScimGroup;

    public function delete(ScimGroupId $id): void;

    /**
     * The connection's groups matching every condition of the filter, oldest first.
     *
     * @param int<0, max> $offset
     * @param int<0, max> $limit
     *
     * @return array{total: int<0, max>, groups: list<ScimGroup>}
     */
    public function matching(ConnectionName $connection, ?ScimFilter $filter, int $offset, int $limit): array;

    /**
     * The groups the account is a member of.
     *
     * @return list<ScimGroup>
     */
    public function ofMember(UserId $user): array;

    /**
     * The groups of any connection with exactly this name: the ones that grant the role of that name.
     *
     * @return list<ScimGroup>
     */
    public function named(string $displayName): array;
}
