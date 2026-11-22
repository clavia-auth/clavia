<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Application\Port\WebAuthnChallengeStore;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use ClaviaTest\Support\Contract\WebAuthnChallengeStoreContract;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryWebAuthnChallengeStore;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;

final class InMemoryWebAuthnChallengeStoreTest extends TestCase
{
    use WebAuthnChallengeStoreContract;

    private FrozenClock $clock;

    private InMemoryWebAuthnChallengeStore $store;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->store = new InMemoryWebAuthnChallengeStore($this->clock);
    }

    #[\Override]
    protected function ceremonies(): WebAuthnChallengeStore
    {
        return $this->store;
    }

    public function testACeremonyExpiresAfterItsLifetime(): void
    {
        $challenge = WebAuthnChallenge::forSignIn(new SeededRandomSource(1), 'login-state', $this->clock->now(), 300);
        $this->store->open('handle-1', $challenge, 300);
        $this->store->open('handle-2', $challenge, 300);

        $this->clock->advance(299);
        self::assertNotNull($this->store->claim('handle-1'));

        $this->clock->advance(1);
        self::assertNull($this->store->claim('handle-2'));
    }
}
