<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Mfa;

use Clavia\Domain\Identity\UserId;

/**
 * Second factors, one per account and type.
 */
interface MfaFactorRepository
{
    /** The account's TOTP factor, pending or confirmed. */
    public function find(UserId $userId): ?MfaFactor;

    /**
     * The account's TOTP factor, locked for the rest of the transaction: two requests
     * presenting the same code race on this lock, and the second sees the step spent.
     *
     * @throws \LogicException Outside a transaction.
     */
    public function lockForVerification(UserId $userId): ?MfaFactor;

    public function save(MfaFactor $factor): void;

    /** Remove every factor of the account. Doing it twice is doing it once. */
    public function removeAll(UserId $userId): void;

    /**
     * Which of `$userIds` have a confirmed factor — for listing accounts without a query
     * each.
     *
     * @param list<UserId> $userIds
     *
     * @return list<UserId>
     */
    public function confirmedAmong(array $userIds): array;
}
