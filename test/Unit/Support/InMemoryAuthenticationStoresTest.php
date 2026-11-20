<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Application\Port\AttemptCounter;
use Clavia\Application\Port\SessionStore;
use ClaviaTest\Support\Contract\AttemptCounterContract;
use ClaviaTest\Support\Contract\SessionStoreContract;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAttemptCounter;
use ClaviaTest\Support\Fake\InMemorySessionStore;
use PHPUnit\Framework\TestCase;

final class InMemoryAuthenticationStoresTest extends TestCase
{
    use SessionStoreContract;
    use AttemptCounterContract;

    private FrozenClock $clock;
    private InMemorySessionStore $sessions;
    private InMemoryAttemptCounter $counter;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->sessions = new InMemorySessionStore($this->clock);
        $this->counter = new InMemoryAttemptCounter($this->clock);
    }

    #[\Override]
    protected function sessions(): SessionStore
    {
        return $this->sessions;
    }

    #[\Override]
    protected function counter(): AttemptCounter
    {
        return $this->counter;
    }

    public function testASessionExpiresAtTheEndOfItsTimeToLiveUnlessExtended(): void
    {
        $this->sessions->save('kept', $this->aSession(), 60);
        $this->sessions->save('left', $this->aSession(), 60);

        $this->clock->advance(59);
        $this->sessions->extend('kept', 60);
        $this->clock->advance(1);

        self::assertNotNull($this->sessions->find('kept'));
        self::assertNull($this->sessions->find('left'));
        self::assertSame(59, $this->sessions->ttl('kept'));
    }

    public function testAFailureCountsUntilItsWindowEndsAndEachFailureRestartsIt(): void
    {
        $this->counter->increment('a', 60);
        $this->clock->advance(59);
        $this->counter->increment('a', 60);
        $this->clock->advance(59);

        self::assertSame(2, $this->counter->count('a'));

        $this->clock->advance(1);
        self::assertSame(0, $this->counter->count('a'));
    }
}
