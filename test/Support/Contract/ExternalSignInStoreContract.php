<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\ExternalSignInStore;
use Clavia\Domain\Authentication\PendingExternalSignIn;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\ProviderName;
use Clavia\Domain\OAuth2\CodeVerifier;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see ExternalSignInStore} must do. Expiry is asserted by each
 * implementation's own test.
 */
trait ExternalSignInStoreContract
{
    abstract protected function pendingSignIns(): ExternalSignInStore;

    #[Test]
    public function anOpenedSignInIsClaimedWhole(): void
    {
        $verifier = CodeVerifier::generate(new SeededRandomSource(1));
        $this->pendingSignIns()->open('state-1', new PendingExternalSignIn(
            ProviderName::fromString('google'),
            $verifier,
            '/oauth2/authorize?client_id=spa&state=é%20x',
            ClientId::fromString('spa'),
            'login-handle',
        ));

        $pending = $this->pendingSignIns()->claim('state-1');

        self::assertNotNull($pending);
        self::assertSame('google', $pending->provider->value);
        self::assertSame($verifier->value, $pending->codeVerifier->value);
        self::assertSame('/oauth2/authorize?client_id=spa&state=é%20x', $pending->nextUrl);
        self::assertSame('spa', $pending->clientId?->value);
        self::assertSame('login-handle', $pending->loginState);
    }

    #[Test]
    public function aSignInWithoutAClientOrALoginPageKeepsNeither(): void
    {
        $this->pendingSignIns()->open('state-1', $this->aPendingSignIn());

        $pending = $this->pendingSignIns()->claim('state-1');

        self::assertNull($pending?->clientId);
        self::assertNull($pending?->loginState);
        self::assertSame('/auth/login', $pending?->nextUrl);
    }

    #[Test]
    public function aStateIsClaimedOnce(): void
    {
        $this->pendingSignIns()->open('state-1', $this->aPendingSignIn());

        self::assertNotNull($this->pendingSignIns()->claim('state-1'));
        self::assertNull($this->pendingSignIns()->claim('state-1'));
    }

    #[Test]
    public function anUnknownOrEmptyStateClaimsNothingAndOnlyItsOwnEntryIsClaimed(): void
    {
        $this->pendingSignIns()->open('state-1', $this->aPendingSignIn());

        self::assertNull($this->pendingSignIns()->claim('state-2'));
        self::assertNull($this->pendingSignIns()->claim(''));
        self::assertNotNull($this->pendingSignIns()->claim('state-1'));
    }

    private function aPendingSignIn(): PendingExternalSignIn
    {
        return new PendingExternalSignIn(
            ProviderName::fromString('github'),
            CodeVerifier::generate(new SeededRandomSource(2)),
            '/auth/login',
            null,
            null,
        );
    }
}
