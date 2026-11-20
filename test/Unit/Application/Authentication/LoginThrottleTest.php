<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Authentication;

use Clavia\Application\Authentication\LoginThrottle;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAttemptCounter;
use PHPUnit\Framework\TestCase;

final class LoginThrottleTest extends TestCase
{
    private FrozenClock $clock;
    private LoginThrottle $throttle;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->throttle = new LoginThrottle(new InMemoryAttemptCounter($this->clock), 3, 900);
    }

    public function testNobodyIsThrottledBeforeFailing(): void
    {
        self::assertFalse($this->throttle->isThrottled('jane@example.com', '203.0.113.7'));
    }

    public function testAnAccountIsThrottledAtTheLimitFromAnyAddress(): void
    {
        $this->throttle->recordFailure('jane@example.com', '203.0.113.1');
        $this->throttle->recordFailure('jane@example.com', '203.0.113.2');
        self::assertFalse($this->throttle->isThrottled('jane@example.com', '203.0.113.9'));

        $this->throttle->recordFailure('jane@example.com', '203.0.113.3');

        self::assertTrue($this->throttle->isThrottled('jane@example.com', '203.0.113.9'));
        self::assertFalse($this->throttle->isThrottled('john@example.com', '203.0.113.9'));
    }

    public function testAnAddressIsThrottledAtTheLimitForEveryAccount(): void
    {
        $this->throttle->recordFailure('a@example.com', '203.0.113.7');
        $this->throttle->recordFailure('b@example.com', '203.0.113.7');
        $this->throttle->recordFailure('c@example.com', '203.0.113.7');

        self::assertTrue($this->throttle->isThrottled('someone-else@example.com', '203.0.113.7'));
        self::assertFalse($this->throttle->isThrottled('someone-else@example.com', '198.51.100.1'));
    }

    public function testTheAccountCounterIgnoresCase(): void
    {
        $this->throttle->recordFailure('Jane@Example.com', '203.0.113.1');
        $this->throttle->recordFailure('JANE@EXAMPLE.COM', '203.0.113.2');
        $this->throttle->recordFailure('jane@example.com', '203.0.113.3');

        self::assertTrue($this->throttle->isThrottled('jAnE@example.com', '198.51.100.1'));
    }

    public function testAResetClearsBothCounters(): void
    {
        foreach (range(1, 3) as $ignored) {
            $this->throttle->recordFailure('jane@example.com', '203.0.113.7');
        }

        $this->throttle->reset('jane@example.com', '203.0.113.7');

        self::assertFalse($this->throttle->isThrottled('jane@example.com', '203.0.113.7'));
    }

    public function testFailuresStopCountingWhenTheWindowHasPassedWithoutAnother(): void
    {
        foreach (range(1, 3) as $ignored) {
            $this->throttle->recordFailure('jane@example.com', '203.0.113.7');
            $this->clock->advance(899);
        }

        // Still locked: every failure restarted the window.
        self::assertTrue($this->throttle->isThrottled('jane@example.com', '203.0.113.7'));

        $this->clock->advance(1);
        self::assertFalse($this->throttle->isThrottled('jane@example.com', '203.0.113.7'));
    }
}
