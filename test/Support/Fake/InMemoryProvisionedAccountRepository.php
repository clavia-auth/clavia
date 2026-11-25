<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Provisioning\ProvisionedAccount;
use Clavia\Domain\Provisioning\ProvisionedAccountRepository;
use Clavia\Domain\Provisioning\ScimFilter;
use Clavia\Domain\Provisioning\ScimFilterAttribute;
use Clavia\Domain\Shared\AlreadyExists;

/**
 * Provisioned accounts in memory, with the storage's two uniqueness rules. The address a filter
 * compares is read from the users' double; an account deleted there takes its record along.
 */
final class InMemoryProvisionedAccountRepository implements ProvisionedAccountRepository
{
    /** @var array<string, ProvisionedAccount> By user id. */
    private array $accounts = [];

    public function __construct(private readonly UserRepository $users)
    {
    }

    #[\Override]
    public function add(ProvisionedAccount $account): void
    {
        foreach ($this->live() as $other) {
            if (! $other->connection->equals($account->connection)) {
                continue;
            }
            if ($other->userNameKey() === $account->userNameKey()) {
                throw new AlreadyExists(self::USER_NAME_TAKEN);
            }
            if ($account->externalId !== null && $other->externalId === $account->externalId) {
                throw new AlreadyExists(self::EXTERNAL_ID_TAKEN);
            }
        }
        $this->accounts[$account->userId->value] = $account;
    }

    #[\Override]
    public function find(ConnectionName $connection, UserId $userId): ?ProvisionedAccount
    {
        $account = $this->live()[$userId->value] ?? null;

        return $account !== null && $account->connection->equals($connection) ? $account : null;
    }

    #[\Override]
    public function matching(ConnectionName $connection, ?ScimFilter $filter, int $offset, int $limit): array
    {
        $matching = array_values(array_filter(
            $this->live(),
            fn (ProvisionedAccount $account): bool => $account->connection->equals($connection)
                && $this->matches($account, $filter),
        ));
        usort($matching, static fn (ProvisionedAccount $a, ProvisionedAccount $b): int
            => [$a->createdAt, $a->userId->value] <=> [$b->createdAt, $b->userId->value]);

        return ['total' => count($matching), 'accounts' => array_slice($matching, $offset, $limit)];
    }

    private function matches(ProvisionedAccount $account, ?ScimFilter $filter): bool
    {
        foreach ($filter->conditions ?? [] as [$attribute, $value]) {
            $holds = match ($attribute) {
                ScimFilterAttribute::UserName => $account->userNameKey() === ProvisionedAccount::keyOf($value),
                ScimFilterAttribute::ExternalId => $account->externalId === $value,
                ScimFilterAttribute::Id => strtolower($account->userId->value) === strtolower($value),
                ScimFilterAttribute::EmailValue => mb_strtolower(
                    $this->users->find($account->userId)->email ?? '',
                ) === mb_strtolower($value),
            };
            if (! $holds) {
                return false;
            }
        }

        return true;
    }

    /**
     * As the cascade does: an account deleted takes its record along.
     *
     * @return array<string, ProvisionedAccount>
     */
    private function live(): array
    {
        return $this->accounts = array_filter(
            $this->accounts,
            fn (ProvisionedAccount $account): bool => $this->users->find($account->userId) !== null,
        );
    }
}
