<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Authentication\LoginState;
use ClaviaTest\Support\Contract\LoginStateStoreContract;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryLoginStateStore;
use PHPUnit\Framework\TestCase;

final class InMemoryLoginStateStoreTest extends TestCase
{
    use LoginStateStoreContract;

    private FrozenClock $clock;
    private InMemoryLoginStateStore $store;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->store = new InMemoryLoginStateStore($this->clock);
    }

    #[\Override]
    protected function loginStates(): LoginStateStore
    {
        return $this->store;
    }

    public function testAnEntryExpiresAfterItsLifetimeAndReadingDoesNotExtendIt(): void
    {
        $this->store->put('handle-1', new LoginState('/a'));

        $this->clock->advance(LoginState::LIFETIME_SECONDS - 1);
        self::assertNotNull($this->store->get('handle-1'));

        $this->clock->advance(1);
        self::assertNull($this->store->get('handle-1'));
    }
}
