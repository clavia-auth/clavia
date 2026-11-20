<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\IdentityProvider;

use Clavia\Application\Port\IdentityProvider;
use Clavia\Application\Port\IdentityProviders;

/**
 * The providers this deployment configured, in the order given — built once by the
 * composition root from the `CLAVIA_<PROVIDER>_CLIENT_ID` / `_CLIENT_SECRET` pairs.
 */
final readonly class ConfiguredIdentityProviders implements IdentityProviders
{
    /** @var array<string, IdentityProvider> */
    private array $providers;

    /**
     * @param list<IdentityProvider> $providers
     */
    public function __construct(array $providers)
    {
        $byName = [];
        foreach ($providers as $provider) {
            $byName[$provider->name()->value] = $provider;
        }
        $this->providers = $byName;
    }

    #[\Override]
    public function find(string $name): ?IdentityProvider
    {
        return $this->providers[$name] ?? null;
    }

    #[\Override]
    public function all(): array
    {
        return array_values($this->providers);
    }
}
