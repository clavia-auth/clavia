<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);


namespace Clavia\Application\Authentication\Passwordless;

use Clavia\Application\Port\AttemptCounter;

/**
 * How many sign-in emails may go out, per hour.
 *
 * The email form creates accounts on demand and sends mail to whatever address it is
 * given; unlimited, it is a cannon pointed at strangers' mailboxes, and a way to burn the
 * deployment's sending reputation. Two counters, either of which can trip, as for
 * passwords ({@see \Clavia\Application\Authentication\LoginThrottle}):
 *
 * - **per address**, so no one mailbox can be flooded, from however many sources;
 * - **per client address**, so no one source can spray many mailboxes.
 *
 * Every send counts and restarts the window. Checking and counting are two steps, so a
 * burst of concurrent requests can overshoot the limit by the size of the burst; the limit
 * is about volume over an hour, where that does not matter.
 */
final readonly class PasswordlessSendLimit
{
    /** The window a send counts in, restarted by every new one. */
    public const int WINDOW_SECONDS = 3600;

    /**
     * @param positive-int $limit Sends per hour, per address and per client address
     *                            (`CLAVIA_PASSWORDLESS_SEND_LIMIT`).
     */
    public function __construct(
        private AttemptCounter $counter,
        private int $limit,
    ) {
    }

    /**
     * Whether one more email may go out — and if so, count it.
     *
     * @param non-empty-string $email An address normalized by
     *                                {@see \Clavia\Domain\Authentication\PasswordlessChallenge::address()}.
     */
    public function allowOne(string $email, string $clientAddress): bool
    {
        $subjects = ['passwordless-email:' . $email, 'passwordless-address:' . $clientAddress];
        if (array_any($subjects, fn (string $subject): bool => $this->counter->count($subject) >= $this->limit)) {
            return false;
        }
        foreach ($subjects as $subject) {
            $this->counter->increment($subject, self::WINDOW_SECONDS);
        }

        return true;
    }
}
