<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Secondary\IdentityProvider\IdTokenVerifier;
use Clavia\Adapter\Secondary\IdentityProvider\JwksCache;
use Clavia\Adapter\Secondary\IdentityProvider\ProviderHttp;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class IdTokenVerifierFactory
{
    public function __invoke(ContainerInterface $container): IdTokenVerifier
    {
        /** @var ProviderHttp $http */
        $http = $container->get(ProviderHttp::class);
        /** @var JwksCache $cache */
        $cache = $container->get(JwksCache::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);

        return new IdTokenVerifier($http, $cache, $clock);
    }
}
