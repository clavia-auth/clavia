<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Application\Port\ConsentStateStore;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Consent\PendingConsent;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Contract\ConsentStateStoreContract;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryConsentStateStore;
use PHPUnit\Framework\TestCase;

final class InMemoryConsentStateStoreTest extends TestCase
{
    use ConsentStateStoreContract;

    private FrozenClock $clock;
    private InMemoryConsentStateStore $store;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->store = new InMemoryConsentStateStore($this->clock);
    }

    #[\Override]
    protected function consentStates(): ConsentStateStore
    {
        return $this->store;
    }

    public function testARequestExpiresAfterItsLifetime(): void
    {
        $this->store->park('handle-1', new PendingConsent(
            '/oauth2/authorize',
            'https://app.example/cb',
            null,
            UserId::fromString('00000000-0000-4000-8000-000000000001'),
            ClientId::fromString('spa'),
            ScopeSet::empty(),
            null,
        ));

        $this->clock->advance(PendingConsent::LIFETIME_SECONDS - 1);
        self::assertNotNull($this->store->find('handle-1'));

        $this->clock->advance(1);
        self::assertNull($this->store->find('handle-1'));
        self::assertNull($this->store->claim('handle-1'));
    }
}
