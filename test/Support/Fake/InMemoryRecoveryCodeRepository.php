<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Authentication\Mfa\RecoveryCodeRepository;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\Digest;
use DateTimeImmutable;

/**
 * Recovery codes kept in an array: per account, digest => when it was spent.
 */
final class InMemoryRecoveryCodeRepository implements RecoveryCodeRepository
{
    /** @var array<string, array<string, ?DateTimeImmutable>> */
    private array $codes = [];

    #[\Override]
    public function replaceAll(UserId $userId, array $digests, DateTimeImmutable $now): void
    {
        $this->codes[$userId->value] = array_fill_keys(
            array_map(static fn (Digest $digest): string => $digest->toString(), $digests),
            null,
        );
    }

    #[\Override]
    public function spend(UserId $userId, Digest $digest, DateTimeImmutable $now): bool
    {
        $key = $digest->toString();
        $held = $this->codes[$userId->value] ?? [];
        if (! array_key_exists($key, $held) || $held[$key] !== null) {
            return false;
        }
        $this->codes[$userId->value][$key] = $now;

        return true;
    }

    #[\Override]
    public function unusedCount(UserId $userId): int
    {
        return count(array_filter(
            $this->codes[$userId->value] ?? [],
            static fn (?DateTimeImmutable $spentAt): bool => $spentAt === null,
        ));
    }

    #[\Override]
    public function removeAll(UserId $userId): void
    {
        unset($this->codes[$userId->value]);
    }
}
