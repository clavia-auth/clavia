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
use ClaviaTest\Support\Fake\InMemoryServiceProviderKeys;
use PHPUnit\Framework\TestCase;

final class InMemoryServiceProviderKeysTest extends TestCase
{
    use ServiceProviderKeysContract;

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
    protected function serviceProviderKeys(): ServiceProviderKeys
    {
        return $this->keys;
    }
}
