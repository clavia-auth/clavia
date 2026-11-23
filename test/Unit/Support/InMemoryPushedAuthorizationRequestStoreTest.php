<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Application\Port\PushedAuthorizationRequestStore;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\OAuth2\PushedAuthorizationRequest;
use ClaviaTest\Support\Contract\PushedAuthorizationRequestStoreContract;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryPushedAuthorizationRequestStore;
use PHPUnit\Framework\TestCase;

final class InMemoryPushedAuthorizationRequestStoreTest extends TestCase
{
    use PushedAuthorizationRequestStoreContract;

    private FrozenClock $clock;
    private InMemoryPushedAuthorizationRequestStore $store;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->store = new InMemoryPushedAuthorizationRequestStore($this->clock);
    }

    #[\Override]
    protected function pushedRequests(): PushedAuthorizationRequestStore
    {
        return $this->store;
    }

    public function testARequestExpires(): void
    {
        $this->store->push('handle-1', new PushedAuthorizationRequest(ClientId::fromString('spa'), []), 60);

        $this->clock->advance(60);

        self::assertNull($this->store->find('handle-1'));
    }
}
