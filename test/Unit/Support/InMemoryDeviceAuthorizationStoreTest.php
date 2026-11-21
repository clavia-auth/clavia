<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Application\Port\DeviceAuthorizationStore;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\OAuth2\DeviceAuthorization;
use Clavia\Domain\OAuth2\UserCode;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Contract\DeviceAuthorizationStoreContract;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryDeviceAuthorizationStore;
use PHPUnit\Framework\TestCase;

final class InMemoryDeviceAuthorizationStoreTest extends TestCase
{
    use DeviceAuthorizationStoreContract;

    private FrozenClock $clock;
    private InMemoryDeviceAuthorizationStore $store;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->store = new InMemoryDeviceAuthorizationStore($this->clock);
    }

    #[\Override]
    protected function deviceRequests(): DeviceAuthorizationStore
    {
        return $this->store;
    }

    #[\Override]
    protected function deviceClock(): FrozenClock
    {
        return $this->clock;
    }

    public function testARequestIsKeptAMinuteBeyondItsLife(): void
    {
        $this->store->open(DeviceAuthorization::request(
            Digest::of('device-1'),
            UserCode::fromTyped('BCDF-GHJK'),
            ClientId::fromString('tv'),
            ScopeSet::fromString('openid'),
            null,
            $this->clock->now(),
            600,
            5,
        ));

        $this->clock->advance(659);
        self::assertNotNull($this->store->findByUserCode(UserCode::fromTyped('BCDF-GHJK')));
        $this->clock->advance(1);
        self::assertNull($this->store->findByUserCode(UserCode::fromTyped('BCDF-GHJK')));
    }
}
