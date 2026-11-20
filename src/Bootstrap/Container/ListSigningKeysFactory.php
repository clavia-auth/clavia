<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Oidc\Keys\ListSigningKeys;
use Clavia\Application\Port\SigningKeyStore;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class ListSigningKeysFactory
{
    public function __invoke(ContainerInterface $container): ListSigningKeys
    {
        /** @var SigningKeyStore $keys */
        $keys = $container->get(SigningKeyStore::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);

        return new ListSigningKeys($keys, $clock);
    }
}
