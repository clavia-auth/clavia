<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Provisioning\Users;

use Clavia\Application\Provisioning\ProvisioningCaller;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Provisioning\ProvisionedAccountRepository;
use Clavia\Domain\Provisioning\ScimFilter;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `GET /scim/v2/Users/{id}` and `GET /scim/v2/Users` (RFC 7644 §3.4.1, §3.4.2;
 * docs/design/scim-provisioning.md §5.3): the accounts a directory provisioned into the connection its
 * token reaches. Any other account, whatever its connection, is not found: its existence is not told
 * (§7).
 */
final readonly class ReadScimUsers
{
    /** How many resources a page holds when the directory does not say. */
    public const int DEFAULT_COUNT = 100;

    /** The most a page holds (RFC 7644 §3.4.2.4: the service provider's maximum). */
    public const int MAX_COUNT = 200;

    public function __construct(
        private ProvisionedAccountRepository $accounts,
        private UserRepository $users,
    ) {
    }

    public function find(ProvisioningCaller $caller, string $id): ?ProvisionedUser
    {
        try {
            $userId = UserId::fromString($id);
        } catch (InvalidValue) {
            return null;
        }
        $account = $this->accounts->find($caller->connection->name, $userId);
        $user = $account === null ? null : $this->users->find($userId);

        return $account === null || $user === null ? null : new ProvisionedUser($user, $account);
    }

    /**
     * A page of the matching accounts, oldest first.
     *
     * @param int $startIndex 1-based (RFC 7644 §3.4.2.4); below 1 is 1.
     * @param int $count      At most {@see MAX_COUNT}; below 0 is 0, which only counts.
     */
    public function page(ProvisioningCaller $caller, ?ScimFilter $filter, int $startIndex, int $count): ScimUserPage
    {
        $startIndex = max(1, $startIndex);
        $count = min(self::MAX_COUNT, max(0, $count));
        $found = $this->accounts->matching($caller->connection->name, $filter, $startIndex - 1, $count);
        $users = [];
        // At most two hundred lookups by primary key, each its own account.
        foreach ($found['accounts'] as $account) {
            $user = $this->users->find($account->userId);
            if ($user !== null) {
                $users[] = new ProvisionedUser($user, $account);
            }
        }

        return new ScimUserPage($found['total'], $startIndex, $users);
    }
}
