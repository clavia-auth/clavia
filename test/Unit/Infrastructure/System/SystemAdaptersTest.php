<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Infrastructure\System;

use Clavia\Infrastructure\System\SystemClock;
use Clavia\Infrastructure\System\SystemRandomSource;
use PHPUnit\Framework\TestCase;

final class SystemAdaptersTest extends TestCase
{
    public function testTheClockReadsUtcWhateverTheDefaultTimezoneIs(): void
    {
        $previous = date_default_timezone_get();
        date_default_timezone_set('Pacific/Kiritimati');

        try {
            $now = new SystemClock()->now();
        } finally {
            date_default_timezone_set($previous);
        }

        self::assertSame('UTC', $now->getTimezone()->getName());
        self::assertEqualsWithDelta(time(), $now->getTimestamp(), 2);
    }

    public function testTheRandomSourceReturnsTheRequestedNumberOfBytes(): void
    {
        $random = new SystemRandomSource();

        self::assertSame(32, strlen($random->bytes(32)));
        self::assertSame(1, strlen($random->bytes(1)));
        self::assertNotSame($random->bytes(32), $random->bytes(32));
    }

    public function testTheRandomSourceStaysWithinBoundsInclusive(): void
    {
        $random = new SystemRandomSource();
        $seen = [];
        for ($i = 0; $i < 400; $i++) {
            $seen[$random->integer(0, 3)] = true;
        }

        ksort($seen);
        self::assertSame([0, 1, 2, 3], array_keys($seen));
        self::assertSame(5, $random->integer(5, 5));
    }
}
