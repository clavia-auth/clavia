<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\NonceRegistry;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Oidc\Nonce;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see NonceRegistry} does. Expiry is the adapter's own test: the double
 * follows a clock, Redis follows its own.
 */
trait NonceRegistryContract
{
    abstract protected function nonces(): NonceRegistry;

    #[Test]
    public function aNonceNeverClaimedIsNotUsed(): void
    {
        self::assertFalse($this->nonces()->isUsed(ClientId::fromString('spa'), Nonce::fromString('n-1')));
    }

    #[Test]
    public function theFirstClaimWinsAndEveryLaterOneLoses(): void
    {
        $client = ClientId::fromString('spa');
        $nonce = Nonce::fromString('n-1');

        self::assertTrue($this->nonces()->claim($client, $nonce, 600));
        self::assertTrue($this->nonces()->isUsed($client, $nonce));
        self::assertFalse($this->nonces()->claim($client, $nonce, 600));
    }

    #[Test]
    public function aNonceBelongsToTheClientThatUsedIt(): void
    {
        $nonce = Nonce::fromString('shared-value');

        self::assertTrue($this->nonces()->claim(ClientId::fromString('spa'), $nonce, 600));

        self::assertFalse($this->nonces()->isUsed(ClientId::fromString('other-app'), $nonce));
        self::assertTrue($this->nonces()->claim(ClientId::fromString('other-app'), $nonce, 600));
    }

    #[Test]
    public function nonceValuesAreComparedExactly(): void
    {
        $client = ClientId::fromString('spa');
        self::assertTrue($this->nonces()->claim($client, Nonce::fromString('Value'), 600));

        self::assertFalse($this->nonces()->isUsed($client, Nonce::fromString('value')));
        self::assertFalse($this->nonces()->isUsed($client, Nonce::fromString('Value ')));
    }
}
