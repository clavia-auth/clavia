<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Authentication\Mfa\RecoveryCodeRepository;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\Digest;
use DateTimeImmutable;

/**
 * Recovery codes in `mfa_recovery_codes`, as digests.
 */
final readonly class PhpDbRecoveryCodeRepository implements RecoveryCodeRepository
{
    public function __construct(
        private Database $database,
        private TransactionManager $transactions,
    ) {
    }

    #[\Override]
    public function replaceAll(UserId $userId, array $digests, DateTimeImmutable $now): void
    {
        // In a transaction of its own (or of the caller's): never an account with half a set.
        $this->transactions->transactional(function () use ($userId, $digests, $now): void {
            $this->removeAll($userId);
            foreach ($digests as $digest) {
                $this->database->execute(
                    <<<'SQL'
                        INSERT INTO mfa_recovery_codes (user_id, code_hash, created_at)
                        VALUES (:user_id, :code_hash, :created_at)
                        SQL,
                    [
                        'user_id' => $userId->value,
                        'code_hash' => $digest->toString(),
                        'created_at' => Timestamp::toDatabase($now),
                    ],
                );
            }
        });
    }

    #[\Override]
    public function spend(UserId $userId, Digest $digest, DateTimeImmutable $now): bool
    {
        return $this->database->execute(
            <<<'SQL'
                UPDATE mfa_recovery_codes SET used_at = :used_at
                WHERE user_id = :user_id AND code_hash = :code_hash AND used_at IS NULL
                SQL,
            [
                'user_id' => $userId->value,
                'code_hash' => $digest->toString(),
                'used_at' => Timestamp::toDatabase($now),
            ],
        ) === 1;
    }

    #[\Override]
    public function unusedCount(UserId $userId): int
    {
        /** @var int|string $count */
        $count = $this->database->fetchValue(
            'SELECT count(*) FROM mfa_recovery_codes WHERE user_id = :user_id AND used_at IS NULL',
            ['user_id' => $userId->value],
        );

        return max(0, (int) $count);
    }

    #[\Override]
    public function removeAll(UserId $userId): void
    {
        $this->database->execute(
            'DELETE FROM mfa_recovery_codes WHERE user_id = :user_id',
            ['user_id' => $userId->value],
        );
    }
}
