<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\ResourceServers\DeleteResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Psr\Container\ContainerInterface;

final class DeleteResourceServerFactory
{
    public function __invoke(ContainerInterface $container): DeleteResourceServer
    {
        /** @var ResourceServerRepository $resourceServers */
        $resourceServers = $container->get(ResourceServerRepository::class);

        return new DeleteResourceServer($resourceServers);
    }
}
