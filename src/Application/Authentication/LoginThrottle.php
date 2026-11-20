<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication;

use Clavia\Application\Port\AttemptCounter;

/**
 * Failed-sign-in throttling.
 *
 * Without it the login endpoint is an unlimited password oracle. Two counters are kept
 * and either can trip:
 *
 * - **per account**, against a focused guessing attack on one person, wherever it
 *   comes from;
 * - **per client address**, against credential stuffing, where each account sees a
 *   handful of attempts but one source tries thousands.
 *
 * The address is only as trustworthy as the network path that reported it, which is
 * why it throttles alongside the account counter rather than instead of it.
 */
final readonly class LoginThrottle
{
    /**
     * @param positive-int $maxAttempts   Failures that trip either counter (`CLAVIA_LOGIN_MAX_ATTEMPTS`).
     * @param positive-int $windowSeconds How long a failure counts (`CLAVIA_LOGIN_ATTEMPT_WINDOW`),
     *                                    restarted by every new failure.
     */
    public function __construct(
        private AttemptCounter $counter,
        private int $maxAttempts,
        private int $windowSeconds,
    ) {
    }

    public function isThrottled(string $email, string $clientAddress): bool
    {
        return array_any(
            $this->subjects($email, $clientAddress),
            fn (string $subject): bool => $this->counter->count($subject) >= $this->maxAttempts,
        );
    }

    public function recordFailure(string $email, string $clientAddress): void
    {
        foreach ($this->subjects($email, $clientAddress) as $subject) {
            $this->counter->increment($subject, $this->windowSeconds);
        }
    }

    public function reset(string $email, string $clientAddress): void
    {
        $this->counter->reset(...$this->subjects($email, $clientAddress));
    }

    /**
     * The account counter ignores case: `Jane@Example.com` and `jane@example.com` are
     * one target for whoever is guessing, whatever the account lookup makes of them.
     *
     * @return list<string>
     */
    private function subjects(string $email, string $clientAddress): array
    {
        return ['account:' . mb_strtolower($email), 'address:' . $clientAddress];
    }
}
