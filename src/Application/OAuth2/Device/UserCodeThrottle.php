<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Device;

use Clavia\Application\Port\AttemptCounter;
use Clavia\Domain\Identity\UserId;

/**
 * Limits how many user codes may be typed wrong (RFC 8628 §5.1: user code entry SHOULD be
 * rate-limited).
 *
 * A user code is about 34 bits, short-lived, and worth nothing without a session to
 * approve it with — which is what makes it typable. Those three only hold together if
 * nobody can try codes without end: misses are counted per signed-in person and per client
 * address, as wrong passwords are, and a limit on either refuses every code until the
 * window passes.
 */
final readonly class UserCodeThrottle
{
    /**
     * @param positive-int $maxAttempts   Misses that trip either counter (`CLAVIA_LOGIN_MAX_ATTEMPTS`).
     * @param positive-int $windowSeconds How long a miss counts (`CLAVIA_LOGIN_ATTEMPT_WINDOW`), restarted
     *                                    by every new one.
     */
    public function __construct(
        private AttemptCounter $counter,
        private int $maxAttempts,
        private int $windowSeconds,
    ) {
    }

    public function isThrottled(UserId $person, string $clientAddress): bool
    {
        return array_any(
            $this->subjects($person, $clientAddress),
            fn (string $subject): bool => $this->counter->count($subject) >= $this->maxAttempts,
        );
    }

    public function recordMiss(UserId $person, string $clientAddress): void
    {
        foreach ($this->subjects($person, $clientAddress) as $subject) {
            $this->counter->increment($subject, $this->windowSeconds);
        }
    }

    /**
     * @return list<string>
     */
    private function subjects(UserId $person, string $clientAddress): array
    {
        return ['device-person:' . $person->value, 'device-address:' . $clientAddress];
    }
}
