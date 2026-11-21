<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Application\Port\PasswordlessChallengeStore;
use Clavia\Domain\Authentication\PasswordlessChallenge;
use ClaviaTest\Support\Contract\PasswordlessChallengeStoreContract;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryPasswordlessChallengeStore;
use PHPUnit\Framework\TestCase;

final class InMemoryPasswordlessChallengeStoreTest extends TestCase
{
    use PasswordlessChallengeStoreContract;

    private FrozenClock $clock;
    private InMemoryPasswordlessChallengeStore $store;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->store = new InMemoryPasswordlessChallengeStore($this->clock);
    }

    #[\Override]
    protected function challenges(): PasswordlessChallengeStore
    {
        return $this->store;
    }

    public function testAChallengeExpiresAfterItsLifetimeAndAFailureDoesNotExtendIt(): void
    {
        $this->store->open('link-1', PasswordlessChallenge::forLink('jane@example.com', '/', null, null), 300);

        $this->clock->advance(299);
        self::assertTrue($this->store->recordFailure('link-1', 5));

        $this->clock->advance(1);
        self::assertNull($this->store->claim('link-1'));
    }
}
