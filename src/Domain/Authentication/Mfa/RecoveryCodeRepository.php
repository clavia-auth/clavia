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
use Clavia\Domain\Shared\Digest;
use DateTimeImmutable;

/**
 * An account's recovery codes, held as digests ({@see RecoveryCode::digest()}).
 */
interface RecoveryCodeRepository
{
    /**
     * Replace the account's codes with these: issuing a new set invalidates the old one.
     *
     * @param list<Digest> $digests
     */
    public function replaceAll(UserId $userId, array $digests, DateTimeImmutable $now): void;

    /**
     * Spend the code with this digest, if the account holds it unused. Atomic — a
     * conditional write — so two requests presenting one code cannot both succeed.
     */
    #[\NoDiscard]
    public function spend(UserId $userId, Digest $digest, DateTimeImmutable $now): bool;

    /** @return non-negative-int */
    public function unusedCount(UserId $userId): int;

    /** Remove every code of the account. Doing it twice is doing it once. */
    public function removeAll(UserId $userId): void;
}
