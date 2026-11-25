<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Provisioning\ProvisionedAccount;
use Clavia\Domain\Provisioning\ProvisionedAccountRepository;
use Clavia\Domain\Provisioning\ProvisioningTokenId;
use Clavia\Domain\Provisioning\ScimFilter;
use Clavia\Domain\Provisioning\ScimFilterAttribute;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\InvalidValue;
use Throwable;

/**
 * Provisioned accounts in `provisioned_accounts`. The two unique constraints are the arbiters of
 * `userName` (by its case-folded key) and `externalId`, per connection; a filter is turned into
 * conditions on bound parameters, the address read from `users`.
 *
 * @psalm-type AccountRow = array{user_id: string, connection: string, user_name: string,
 *                                external_id: string|null, provisioning_token_id: string,
 *                                created_at: string, updated_at: string}
 */
final readonly class PhpDbProvisionedAccountRepository implements ProvisionedAccountRepository
{
    private const string COLUMNS = 'pa.user_id, pa.connection, pa.user_name, pa.external_id, '
        . 'pa.provisioning_token_id, pa.created_at, pa.updated_at';

    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function add(ProvisionedAccount $account): void
    {
        try {
            $this->database->execute(
                <<<'SQL'
                    INSERT INTO provisioned_accounts (
                        user_id, connection, user_name, user_name_key, external_id, provisioning_token_id,
                        created_at, updated_at
                    ) VALUES (
                        :user_id, :connection, :user_name, :user_name_key, :external_id, :provisioning_token_id,
                        :created_at, :updated_at
                    )
                    SQL,
                [
                    'user_id' => $account->userId->value,
                    'connection' => $account->connection->value,
                    'user_name' => $account->userName,
                    'user_name_key' => $account->userNameKey(),
                    'external_id' => $account->externalId,
                    'provisioning_token_id' => $account->provisionedBy->value,
                    'created_at' => Timestamp::toDatabase($account->createdAt),
                    'updated_at' => Timestamp::toDatabase($account->updatedAt),
                ],
            );
        } catch (Throwable $failure) {
            throw self::conflict($failure);
        }
    }

    #[\Override]
    public function save(ProvisionedAccount $account): void
    {
        try {
            $this->database->execute(
                <<<'SQL'
                    UPDATE provisioned_accounts SET
                        user_name = :user_name,
                        user_name_key = :user_name_key,
                        external_id = :external_id,
                        updated_at = :updated_at
                    WHERE user_id = :user_id AND connection = :connection
                    SQL,
                [
                    'user_id' => $account->userId->value,
                    'connection' => $account->connection->value,
                    'user_name' => $account->userName,
                    'user_name_key' => $account->userNameKey(),
                    'external_id' => $account->externalId,
                    'updated_at' => Timestamp::toDatabase($account->updatedAt),
                ],
            );
        } catch (Throwable $failure) {
            throw self::conflict($failure);
        }
    }

    /** The unique constraint broken, as the conflict the interface names; anything else as it is. */
    private static function conflict(Throwable $failure): Throwable
    {
        return match (true) {
            Constraint::isUniqueViolation($failure, 'provisioned_accounts_user_name_key')
                => new AlreadyExists(self::USER_NAME_TAKEN, 0, $failure),
            Constraint::isUniqueViolation($failure, 'provisioned_accounts_external_id_key')
                => new AlreadyExists(self::EXTERNAL_ID_TAKEN, 0, $failure),
            default => $failure,
        };
    }

    #[\Override]
    public function find(ConnectionName $connection, UserId $userId): ?ProvisionedAccount
    {
        /** @var AccountRow|null $row */
        $row = $this->database->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM provisioned_accounts pa '
            . 'WHERE pa.connection = :connection AND pa.user_id = :user_id',
            ['connection' => $connection->value, 'user_id' => $userId->value],
        );

        return $row === null ? null : self::hydrate($row);
    }

    #[\Override]
    public function matching(ConnectionName $connection, ?ScimFilter $filter, int $offset, int $limit): array
    {
        $conditions = ['pa.connection = :connection'];
        $parameters = ['connection' => $connection->value];
        foreach ($filter->conditions ?? [] as $index => [$attribute, $value]) {
            $name = 'v' . $index;
            $conditions[] = match ($attribute) {
                ScimFilterAttribute::UserName => 'pa.user_name_key = :' . $name,
                ScimFilterAttribute::ExternalId => 'pa.external_id = :' . $name,
                ScimFilterAttribute::Id => 'pa.user_id = CAST(:' . $name . ' AS uuid)',
                ScimFilterAttribute::EmailValue => 'lower(u.email) = lower(:' . $name . ')',
            };
            if ($attribute === ScimFilterAttribute::Id) {
                try {
                    $value = UserId::fromString($value)->value;
                } catch (InvalidValue) {
                    // Not an id at all: nothing has it.
                    return ['total' => 0, 'accounts' => []];
                }
            }
            $parameters[$name] = $attribute === ScimFilterAttribute::UserName
                ? ProvisionedAccount::keyOf($value)
                : $value;
        }
        $from = 'FROM provisioned_accounts pa JOIN users u ON u.id = pa.user_id WHERE ' . implode(' AND ', $conditions);
        /** @var int|string $total */
        $total = $this->database->fetchValue('SELECT count(*) ' . $from, $parameters);
        if ($limit === 0) {
            return ['total' => max(0, (int) $total), 'accounts' => []];
        }
        /** @var list<AccountRow> $rows */
        $rows = $this->database->fetchAll(
            'SELECT ' . self::COLUMNS . ' ' . $from . ' ORDER BY pa.created_at, pa.user_id LIMIT :limit OFFSET :offset',
            $parameters + ['limit' => $limit, 'offset' => $offset],
        );

        return ['total' => max(0, (int) $total), 'accounts' => array_map(self::hydrate(...), $rows)];
    }

    /** @param AccountRow $row */
    private static function hydrate(array $row): ProvisionedAccount
    {
        $userName = $row['user_name'];
        $externalId = $row['external_id'];
        assert($userName !== '' && $externalId !== '');

        return ProvisionedAccount::reconstitute(
            UserId::fromString($row['user_id']),
            ConnectionName::fromString($row['connection']),
            $userName,
            $externalId,
            ProvisioningTokenId::fromString($row['provisioning_token_id']),
            Timestamp::fromDatabase($row['created_at']),
            Timestamp::fromDatabase($row['updated_at']),
        );
    }
}
