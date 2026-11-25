<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

use Clavia\Adapter\Secondary\Saml\Remote\RemoteDecryptionKey;
use Clavia\Adapter\Secondary\Saml\Remote\RemoteServiceProviderKeys;
use Clavia\Adapter\Secondary\Signing\Remote\RemoteSigningKey;
use Clavia\Application\Port\Saml\ServiceProviderKeys;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryCertificateCache;
use ClaviaTest\Support\Fake\SeededRandomSource;
use LogicException;

/**
 * For the remote backends' runs of the keys contract: one provider's keys arranged as the settings
 * would name them (a current pair, a next pair, a retired encryption key), each over its own
 * {@see \ClaviaTest\Support\Fake\LocalHsm} key, the cache in memory.
 */
trait RemoteServiceProviderKeysFixture
{
    private ?ServiceProviderKeys $remoteKeys = null;

    /** The role's signing key: 0 current, 2 next. */
    abstract protected function remoteSigningKey(int $index): RemoteSigningKey;

    /** The role's encryption key: 1 current, 3 next, 4 retired. */
    abstract protected function remoteDecryptionKey(int $index): RemoteDecryptionKey;

    #[\Override]
    protected function arrange(bool $next = false, bool $retired = false): void
    {
        $this->remoteKeys = new RemoteServiceProviderKeys(
            $this->remoteSigningKey(0),
            $this->remoteDecryptionKey(1),
            $next ? $this->remoteSigningKey(2) : null,
            $next ? $this->remoteDecryptionKey(3) : null,
            $retired ? [$this->remoteDecryptionKey(4)] : [],
            new InMemoryCertificateCache(),
            new FrozenClock('2026-03-04T09:00:00Z'),
            new SeededRandomSource(7),
            'auth.clavia.test',
        );
    }

    #[\Override]
    protected function serviceProviderKeys(): ServiceProviderKeys
    {
        return $this->remoteKeys ?? throw new LogicException('Arrange first.');
    }
}
