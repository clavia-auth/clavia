<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use Clavia\Domain\Authentication\Mfa\MfaFactor;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Mfa\MfaFactorType;
use Clavia\Domain\Identity\UserId;
use LogicException;

/**
 * Second factors in `mfa_factors`.
 */
final readonly class PhpDbMfaFactorRepository implements MfaFactorRepository
{
    private const string COLUMNS = 'user_id, type, secret_encrypted, confirmed_at, last_used_step, created_at';

    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function find(UserId $userId): ?MfaFactor
    {
        return $this->one(
            'SELECT ' . self::COLUMNS . ' FROM mfa_factors WHERE user_id = :user_id AND type = :type',
            $userId,
        );
    }

    #[\Override]
    public function lockForVerification(UserId $userId): ?MfaFactor
    {
        // Outside a transaction the lock would end with the statement, and two requests
        // presenting the same code could both read the step as unspent.
        if (! $this->database->inTransaction()) {
            throw new LogicException('A factor can only be locked inside a transaction.');
        }

        return $this->one(
            'SELECT ' . self::COLUMNS . ' FROM mfa_factors WHERE user_id = :user_id AND type = :type FOR UPDATE',
            $userId,
        );
    }

    #[\Override]
    public function save(MfaFactor $factor): void
    {
        $this->database->execute(
            <<<'SQL'
                INSERT INTO mfa_factors (user_id, type, secret_encrypted, confirmed_at, last_used_step, created_at)
                VALUES (:user_id, :type, :secret_encrypted, :confirmed_at, :last_used_step, :created_at)
                ON CONFLICT (user_id, type) DO UPDATE SET
                    secret_encrypted = EXCLUDED.secret_encrypted,
                    confirmed_at = EXCLUDED.confirmed_at,
                    last_used_step = EXCLUDED.last_used_step
                SQL,
            [
                'user_id' => $factor->userId->value,
                'type' => $factor->type->value,
                'secret_encrypted' => $factor->sealedSecret,
                'confirmed_at' => Timestamp::toDatabaseOrNull($factor->confirmedAt),
                'last_used_step' => $factor->lastUsedStep,
                'created_at' => Timestamp::toDatabase($factor->createdAt),
            ],
        );
    }

    #[\Override]
    public function removeAll(UserId $userId): void
    {
        $this->database->execute('DELETE FROM mfa_factors WHERE user_id = :user_id', ['user_id' => $userId->value]);
    }

    #[\Override]
    public function confirmedAmong(array $userIds): array
    {
        if ($userIds === []) {
            return [];
        }

        $parameters = [];
        foreach ($userIds as $index => $userId) {
            $parameters['user_' . $index] = $userId->value;
        }
        /** @var list<array{user_id: string}> $rows */
        $rows = $this->database->fetchAll(
            'SELECT user_id FROM mfa_factors WHERE confirmed_at IS NOT NULL AND user_id IN ('
            . implode(', ', array_map(static fn (string $name): string => ':' . $name, array_keys($parameters)))
            . ')',
            $parameters,
        );

        return array_map(static fn (array $row): UserId => UserId::fromString($row['user_id']), $rows);
    }

    private function one(string $sql, UserId $userId): ?MfaFactor
    {
        /**
         * @var array{user_id: string, type: string, secret_encrypted: string, confirmed_at: string|null,
         *            last_used_step: int|string|null, created_at: string}|null $row
         */
        $row = $this->database->fetchOne($sql, ['user_id' => $userId->value, 'type' => MfaFactorType::Totp->value]);

        return $row === null ? null : MfaFactor::reconstitute(
            UserId::fromString($row['user_id']),
            MfaFactorType::from($row['type']),
            $row['secret_encrypted'],
            Timestamp::fromDatabaseOrNull($row['confirmed_at']),
            $row['last_used_step'] === null ? null : (int) $row['last_used_step'],
            Timestamp::fromDatabase($row['created_at']),
        );
    }
}
