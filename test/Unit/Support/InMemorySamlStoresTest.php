<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Application\Port\Saml\SamlAssertionReplayCache;
use Clavia\Application\Port\Saml\SamlResponseStore;
use ClaviaTest\Support\Contract\SamlStoresContract;
use ClaviaTest\Support\Fake\InMemorySamlStores;
use PHPUnit\Framework\TestCase;

final class InMemorySamlStoresTest extends TestCase
{
    use SamlStoresContract;

    private InMemorySamlStores $stores;

    #[\Override]
    protected function setUp(): void
    {
        $this->stores = new InMemorySamlStores();
    }

    #[\Override]
    protected function samlResponses(): SamlResponseStore
    {
        return $this->stores;
    }

    #[\Override]
    protected function samlAssertions(): SamlAssertionReplayCache
    {
        return $this->stores;
    }
}
