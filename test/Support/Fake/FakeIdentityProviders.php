<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\IdentityProvider;
use Clavia\Application\Port\IdentityProviders;
use Clavia\Domain\Connection\Connection;

/**
 * The providers a test configured, found by the name of their connection: a connection
 * with none configured has no working provider, as one without credentials would.
 */
final readonly class FakeIdentityProviders implements IdentityProviders
{
    /** @var list<IdentityProvider> */
    private array $providers;

    public function __construct(IdentityProvider ...$providers)
    {
        $this->providers = array_values($providers);
    }

    #[\Override]
    public function for(Connection $connection): ?IdentityProvider
    {
        if (! $connection->isExternal()) {
            return null;
        }

        return array_find(
            $this->providers,
            static fn (IdentityProvider $provider): bool => $provider->name()->equals($connection->name),
        );
    }
}
