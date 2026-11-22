<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Application\Port\AccountLinkStore;
use Clavia\Domain\Identity\AccountLink;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use ClaviaTest\Support\Contract\AccountLinkStoreContract;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAccountLinkStore;
use PHPUnit\Framework\TestCase;

final class InMemoryAccountLinkStoreTest extends TestCase
{
    use AccountLinkStoreContract;

    private FrozenClock $clock;

    private InMemoryAccountLinkStore $store;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->store = new InMemoryAccountLinkStore($this->clock);
    }

    #[\Override]
    protected function links(): AccountLinkStore
    {
        return $this->store;
    }

    public function testALinkExpiresAfterItsLifetime(): void
    {
        $user = User::register(
            UserId::fromString('6f1d6f0e-6b2a-4c9e-9d8a-3b1f2c4d5e6f'),
            'jane@example.com',
            null,
            $this->clock->now(),
        );
        $this->store->open('token-1', AccountLink::verifyEmail($user, null), 300);

        $this->clock->advance(299);
        self::assertNotNull($this->store->find('token-1'));
        $this->clock->advance(1);
        self::assertNull($this->store->claim('token-1'));
    }
}
