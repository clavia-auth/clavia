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
 * How many emails of one kind may go out, per hour.
 *
 * Every form that mails an address a stranger may type — a sign-in code or link, a
 * verification or reset link, a notice — is, unlimited, a cannon pointed at other people's
 * mailboxes and a way to burn the deployment's sending reputation. Two counters, either of
 * which can trip, as for passwords ({@see LoginThrottle}):
 *
 * - **per address**, so no one mailbox can be flooded, from however many sources;
 * - **per client address**, so no one source can spray many mailboxes.
 *
 * Each kind counts on its own (`$namespace`): asking for sign-in codes does not use up the
 * reset links. Every send counts and restarts the window. Checking and counting are two
 * steps, so a burst of concurrent requests can overshoot the limit by the size of the
 * burst; the limit is about volume over an hour, where that does not matter.
 */
final readonly class EmailSendLimit
{
    /** The window a send counts in, restarted by every new one. */
    public const int WINDOW_SECONDS = 3600;

    /**
     * @param positive-int     $limit     Sends per hour, per address and per client address.
     * @param non-empty-string $namespace The kind of email counted: `passwordless`, `account`.
     */
    public function __construct(
        private AttemptCounter $counter,
        private int $limit,
        private string $namespace,
    ) {
    }

    /**
     * Whether one more email may go out — and if so, count it.
     *
     * @param non-empty-string $email An address, normalized (trimmed, lower-cased).
     */
    public function allowOne(string $email, string $clientAddress): bool
    {
        $subjects = [$this->namespace . '-email:' . $email, $this->namespace . '-address:' . $clientAddress];
        if (array_any($subjects, fn (string $subject): bool => $this->counter->count($subject) >= $this->limit)) {
            return false;
        }
        foreach ($subjects as $subject) {
            $this->counter->increment($subject, self::WINDOW_SECONDS);
        }

        return true;
    }
}
