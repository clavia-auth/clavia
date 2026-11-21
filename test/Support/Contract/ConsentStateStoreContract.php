<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\ConsentStateStore;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Consent\PendingConsent;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\ScopeSet;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see ConsentStateStore} must do. Expiry is asserted by each implementation's
 * own test.
 */
trait ConsentStateStoreContract
{
    abstract protected function consentStates(): ConsentStateStore;

    #[Test]
    public function aParkedRequestIsReadBackWhole(): void
    {
        $this->consentStates()->park('handle-1', self::pendingConsent());

        $pending = $this->consentStates()->find('handle-1');

        self::assertNotNull($pending);
        self::assertSame('/oauth2/authorize?client_id=tpc_partner&state=%C3%A9', $pending->resumeAt);
        self::assertSame('https://partner.example/cb', $pending->redirectUri);
        self::assertSame('xyz', $pending->state);
        self::assertSame('00000000-0000-4000-8000-000000000001', $pending->userId->value);
        self::assertSame('tpc_partner', $pending->clientId->value);
        self::assertSame('openid invoices:read', $pending->scope->toString());
        self::assertSame('rs_aaaaaaaaaaaaaaaa', $pending->resourceServerId?->value);
    }

    #[Test]
    public function aRequestWithoutStateOrApiKeepsNone(): void
    {
        $this->consentStates()->park('handle-1', self::pendingConsent(state: null, api: null));

        $pending = $this->consentStates()->find('handle-1');

        self::assertNotNull($pending);
        self::assertNull($pending->state);
        self::assertNull($pending->resourceServerId);
    }

    #[Test]
    public function findingLeavesItAndClaimingTakesItOnce(): void
    {
        $this->consentStates()->park('handle-1', self::pendingConsent());

        $this->consentStates()->find('handle-1');
        self::assertNotNull($this->consentStates()->claim('handle-1'));

        self::assertNull($this->consentStates()->claim('handle-1'));
        self::assertNull($this->consentStates()->find('handle-1'));
    }

    #[Test]
    public function anUnknownOrEmptyHandleIsNothing(): void
    {
        $this->consentStates()->park('handle-1', self::pendingConsent());

        self::assertNull($this->consentStates()->find('handle-2'));
        self::assertNull($this->consentStates()->find(''));
        self::assertNull($this->consentStates()->claim(''));
        self::assertNotNull($this->consentStates()->find('handle-1'));
    }

    private static function pendingConsent(?string $state = 'xyz', ?string $api = 'rs_aaaaaaaaaaaaaaaa'): PendingConsent
    {
        return new PendingConsent(
            '/oauth2/authorize?client_id=tpc_partner&state=%C3%A9',
            'https://partner.example/cb',
            $state,
            UserId::fromString('00000000-0000-4000-8000-000000000001'),
            ClientId::fromString('tpc_partner'),
            ScopeSet::fromString('openid invoices:read'),
            $api === null ? null : ResourceServerId::fromString($api),
        );
    }
}
