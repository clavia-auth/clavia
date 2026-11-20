<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Application\Port\MfaChallengeStore;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\MfaChallenge;
use Clavia\Domain\Identity\UserId;
use ClaviaTest\Support\Contract\MfaChallengeStoreContract;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryMfaChallengeStore;
use PHPUnit\Framework\TestCase;

final class InMemoryMfaChallengeStoreTest extends TestCase
{
    use MfaChallengeStoreContract;

    private FrozenClock $clock;
    private InMemoryMfaChallengeStore $store;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->store = new InMemoryMfaChallengeStore($this->clock);
    }

    #[\Override]
    protected function challenges(): MfaChallengeStore
    {
        return $this->store;
    }

    public function testAChallengeExpiresAfterItsLifetimeAndAFailureDoesNotExtendIt(): void
    {
        $this->store->open('handle-1', new MfaChallenge(
            UserId::fromString('0190a4f2-7c1e-7b3a-9c2d-5e6f7a8b9c0d'),
            '/',
            null,
            [AuthenticationMethod::Password],
        ), 300);

        $this->clock->advance(299);
        self::assertTrue($this->store->recordFailure('handle-1', 5));

        $this->clock->advance(1);
        self::assertNull($this->store->find('handle-1'));
    }
}
