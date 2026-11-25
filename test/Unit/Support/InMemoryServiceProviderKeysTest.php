<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Application\Port\Saml\ServiceProviderKeys;
use Clavia\Application\Port\Saml\ServiceProviderKeyStore;
use ClaviaTest\Support\Contract\ServiceProviderKeysContract;
use ClaviaTest\Support\Contract\ServiceProviderKeyStoreContract;
use ClaviaTest\Support\Fake\InMemoryServiceProviderKeys;
use PHPUnit\Framework\TestCase;

final class InMemoryServiceProviderKeysTest extends TestCase
{
    use ServiceProviderKeysContract;
    use ServiceProviderKeyStoreContract;

    private InMemoryServiceProviderKeys $keys;

    #[\Override]
    protected function setUp(): void
    {
        $this->keys = new InMemoryServiceProviderKeys();
    }

    #[\Override]
    protected function serviceProviderKeyStore(): ServiceProviderKeyStore
    {
        return $this->keys;
    }

    #[\Override]
    protected function arrange(bool $next = false, bool $retired = false): void
    {
        $store = $this->keys;
        $moment = new \DateTimeImmutable('2026-03-04T09:00:00Z');
        if ($retired) {
            $old = $store->createPair(\Clavia\Domain\Connection\Saml\ServiceProviderKeyStatus::Current, $moment);
            $store->save($old['signing']->retired($moment));
            $store->save($old['encryption']->retired($moment));
            $store->delete($old['signing']->kid);
        }
        $store->createPair(\Clavia\Domain\Connection\Saml\ServiceProviderKeyStatus::Current, $moment);
        if ($next) {
            $store->createPair(\Clavia\Domain\Connection\Saml\ServiceProviderKeyStatus::Next, $moment);
        }
    }

    #[\Override]
    protected function serviceProviderKeys(): ServiceProviderKeys
    {
        return $this->keys;
    }
}
