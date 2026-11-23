<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\OAuth2;

use Clavia\Application\OAuth2\ClientAuthentication\ClientFailureThrottle;
use Clavia\Application\OAuth2\ClientAuthentication\TooManyFailedRequests;
use ClaviaTest\Support\Clients;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAttemptCounter;
use PHPUnit\Framework\TestCase;

/**
 * Failures at the machine endpoints: counted per address, and per client only when the
 * client proved itself with a secret.
 */
final class ClientFailureThrottleTest extends TestCase
{
    private const string ATTACKER = '198.51.100.9';
    private const string OTHER = '203.0.113.7';

    private FrozenClock $clock;
    private ClientFailureThrottle $throttle;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->throttle = new ClientFailureThrottle(new InMemoryAttemptCounter($this->clock), 3, 300);
    }

    public function testAnAddressIsRefusedOnceItHasFailedTooOftenAndOthersAreNot(): void
    {
        for ($i = 0; $i < 3; ++$i) {
            $this->throttle->refuseIfLimited(self::ATTACKER);
            $this->throttle->recordFailedAuthentication(self::ATTACKER);
        }

        $this->throttle->refuseIfLimited(self::OTHER);
        try {
            $this->throttle->refuseIfLimited(self::ATTACKER);
            self::fail('The address is refused.');
        } catch (TooManyFailedRequests $refusal) {
            self::assertSame(300, $refusal->retryAfter);
        }
    }

    public function testAProvenClientsRejectedGrantsRefuseItFromAnyAddress(): void
    {
        $client = Clients::confidential('backend', 'hash');
        for ($i = 0; $i < 3; ++$i) {
            $this->throttle->recordRejectedGrant(self::ATTACKER, $client);
        }

        $this->expectException(TooManyFailedRequests::class);

        $this->throttle->refuseIfLimited(self::OTHER, $client);
    }

    public function testAPublicClientCannotBeLockedOutByWhoeverNamesIt(): void
    {
        // Its id is in every authorization URL: failures under it count against the address.
        $spa = Clients::public('spa');
        for ($i = 0; $i < 3; ++$i) {
            $this->throttle->recordRejectedGrant(self::ATTACKER, $spa);
        }

        $this->throttle->refuseIfLimited(self::OTHER, $spa);
        $this->expectException(TooManyFailedRequests::class);
        $this->throttle->refuseIfLimited(self::ATTACKER, $spa);
    }

    public function testTheWindowPasses(): void
    {
        for ($i = 0; $i < 3; ++$i) {
            $this->throttle->recordFailedAuthentication(self::ATTACKER);
        }

        $this->clock->advance(301);

        $this->expectNotToPerformAssertions();
        $this->throttle->refuseIfLimited(self::ATTACKER);
    }
}
