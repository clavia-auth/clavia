<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\OAuth2;

use Clavia\Application\OAuth2\Device\UserCodeThrottle;
use Clavia\Domain\Identity\UserId;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAttemptCounter;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;

final class UserCodeThrottleTest extends TestCase
{
    public function testMissesAreCountedPerPersonAndPerAddressForTheWindow(): void
    {
        $clock = new FrozenClock();
        $throttle = new UserCodeThrottle(new InMemoryAttemptCounter($clock), 2, 600);
        $ada = UserId::generate(new SeededRandomSource(1));
        $bob = UserId::generate(new SeededRandomSource(2));

        $throttle->recordMiss($ada, '198.51.100.7');
        self::assertFalse($throttle->isThrottled($ada, '198.51.100.7'));
        $throttle->recordMiss($ada, '198.51.100.7');

        self::assertTrue($throttle->isThrottled($ada, '203.0.113.9'), 'The person, from anywhere.');
        self::assertTrue($throttle->isThrottled($bob, '198.51.100.7'), 'The address, whoever signs in there.');
        self::assertFalse($throttle->isThrottled($bob, '203.0.113.9'));

        $clock->advance(600);
        self::assertFalse($throttle->isThrottled($ada, '198.51.100.7'), 'Until the window passes.');
    }
}
