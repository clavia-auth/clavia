<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Application\Port\NonceRegistry;
use Clavia\Application\Port\SigningKeyStore;
use Clavia\Application\Port\TokenSigner;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Oidc\Nonce;
use ClaviaTest\Support\Contract\NonceRegistryContract;
use ClaviaTest\Support\Contract\SigningBackendContract;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryNonceRegistry;
use ClaviaTest\Support\Fake\InMemorySigningKeys;
use PHPUnit\Framework\TestCase;

final class InMemoryOidcStoresTest extends TestCase
{
    use NonceRegistryContract;
    use SigningBackendContract;

    private FrozenClock $clock;
    private InMemoryNonceRegistry $nonces;
    private InMemorySigningKeys $keys;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->nonces = new InMemoryNonceRegistry($this->clock);
        $this->keys = new InMemorySigningKeys($this->clock);
    }

    #[\Override]
    protected function nonces(): NonceRegistry
    {
        return $this->nonces;
    }

    #[\Override]
    protected function store(): SigningKeyStore
    {
        return $this->keys;
    }

    #[\Override]
    protected function signer(): TokenSigner
    {
        return $this->keys;
    }

    #[\Override]
    protected function clock(): FrozenClock
    {
        return $this->clock;
    }

    #[\Override]
    protected function transactional(callable $work): mixed
    {
        return $work();
    }

    public function testAClaimLastsForItsTimeToLive(): void
    {
        $client = ClientId::fromString('spa');
        $nonce = Nonce::fromString('n-1');
        self::assertTrue($this->nonces->claim($client, $nonce, 60));

        $this->clock->advance(59);
        self::assertTrue($this->nonces->isUsed($client, $nonce));

        $this->clock->advance(1);
        self::assertFalse($this->nonces->isUsed($client, $nonce));
        self::assertTrue($this->nonces->claim($client, $nonce, 60));
    }
}
