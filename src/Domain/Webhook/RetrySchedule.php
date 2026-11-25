<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Webhook;

use Clavia\Domain\Shared\RandomSource;

/**
 * When a failed delivery is tried again (Standard Webhooks' schedule): 5 s, 5 min, 30 min, 2 h, 5 h,
 * 10 h, 10 h after the attempt that failed, each with ±10 % of jitter so retries to one receiver do
 * not arrive in step; then the delivery is abandoned. About a day and a half in all.
 */
final readonly class RetrySchedule
{
    /** @var list<positive-int> Seconds after the 1st, 2nd… failed attempt. */
    public const array DELAYS = [5, 300, 1800, 7200, 18_000, 36_000, 36_000];

    private function __construct()
    {
    }

    /**
     * @param positive-int $attempts How many attempts were made, the one that just failed included.
     *
     * @return positive-int|null Seconds until the next attempt; null when there is none.
     */
    public static function delayAfter(int $attempts, RandomSource $random): ?int
    {
        $delay = self::DELAYS[$attempts - 1] ?? null;
        if ($delay === null) {
            return null;
        }
        $spread = intdiv($delay, 10);

        return max(1, $delay + ($spread === 0 ? 0 : $random->integer(-$spread, $spread)));
    }
}
