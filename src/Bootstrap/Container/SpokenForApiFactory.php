<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authorization\SpokenForApi;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Psr\Container\ContainerInterface;

final class SpokenForApiFactory
{
    public function __invoke(ContainerInterface $container): SpokenForApi
    {
        /** @var ResourceServerRepository $resourceServers */
        $resourceServers = $container->get(ResourceServerRepository::class);

        return new SpokenForApi(
            $resourceServers,
        );
    }
}
