<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Application\Port\ExternalSignInStore;
use Clavia\Domain\Authentication\PendingExternalSignIn;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\OAuth2\CodeVerifier;
use Clavia\Domain\Oidc\Nonce;
use ClaviaTest\Support\Contract\ExternalSignInStoreContract;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryExternalSignInStore;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;

final class InMemoryExternalSignInStoreTest extends TestCase
{
    use ExternalSignInStoreContract;

    private FrozenClock $clock;
    private InMemoryExternalSignInStore $store;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->store = new InMemoryExternalSignInStore($this->clock);
    }

    #[\Override]
    protected function pendingSignIns(): ExternalSignInStore
    {
        return $this->store;
    }

    public function testAPendingSignInExpiresAfterItsLifetime(): void
    {
        foreach (['early' => PendingExternalSignIn::LIFETIME_SECONDS - 1, 'late' => 1] as $handle => $wait) {
            $this->store->open($handle, new PendingExternalSignIn(
                ConnectionName::fromString('google'),
                CodeVerifier::generate(new SeededRandomSource()),
                '/',
                null,
                null,
                Nonce::fromString('nonce-1'),
            ));
        }

        $this->clock->advance(PendingExternalSignIn::LIFETIME_SECONDS - 1);
        self::assertNotNull($this->store->claim('early'));

        $this->clock->advance(1);
        self::assertNull($this->store->claim('late'));
    }
}
