<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Authentication\Mfa\MfaFactor;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Identity\UserId;
use LogicException;

/**
 * Second factors kept in an array, as copies: a factor changed after it was fetched
 * changes nothing until it is saved.
 *
 * The lock of {@see self::lockForVerification()} cannot be taken for real here; what is
 * kept is its precondition — a transaction must be open — so a use case that forgets
 * one fails in unit tests as it would against PostgreSQL.
 */
final class InMemoryMfaFactorRepository implements MfaFactorRepository
{
    /** @var array<string, MfaFactor> */
    private array $factors = [];

    public function __construct(private readonly InMemoryTransactionManager $transactions)
    {
    }

    #[\Override]
    public function find(UserId $userId): ?MfaFactor
    {
        return isset($this->factors[$userId->value]) ? clone $this->factors[$userId->value] : null;
    }

    #[\Override]
    public function lockForVerification(UserId $userId): ?MfaFactor
    {
        if (! $this->transactions->isActive()) {
            throw new LogicException('A factor is locked for verification only inside a transaction.');
        }

        return $this->find($userId);
    }

    #[\Override]
    public function save(MfaFactor $factor): void
    {
        $this->factors[$factor->userId->value] = clone $factor;
    }

    #[\Override]
    public function removeAll(UserId $userId): void
    {
        unset($this->factors[$userId->value]);
    }

    #[\Override]
    public function confirmedAmong(array $userIds): array
    {
        return array_values(array_filter(
            $userIds,
            fn (UserId $id): bool => ($this->factors[$id->value] ?? null)?->isConfirmed() === true,
        ));
    }
}
