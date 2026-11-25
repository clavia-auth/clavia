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
 * The accounts directories provisioned. An account's record goes with it (a cascade).
 */
interface ProvisionedAccountRepository
{
    /** The message of the conflict over a `userName`: what tells it from one over an `externalId`. */
    public const string USER_NAME_TAKEN = 'This userName is already provisioned in the connection.';

    public const string EXTERNAL_ID_TAKEN = 'This externalId is already provisioned in the connection.';

    /**
     * @throws AlreadyExists When the connection already has the `userName` (ignoring case) or the
     *                       `externalId`, with {@see USER_NAME_TAKEN} or {@see EXTERNAL_ID_TAKEN}.
     */
    public function add(ProvisionedAccount $account): void;

    /** The account's record, if a directory provisioned it into this connection. */
    public function find(ConnectionName $connection, UserId $userId): ?ProvisionedAccount;

    /**
     * The connection's provisioned accounts matching every condition of the filter (all of them
     * without one), oldest first: the order a directory pages through.
     *
     * @param int<0, max> $offset
     * @param int<0, max> $limit
     *
     * @return array{total: int<0, max>, accounts: list<ProvisionedAccount>}
     */
    public function matching(ConnectionName $connection, ?ScimFilter $filter, int $offset, int $limit): array;
}
