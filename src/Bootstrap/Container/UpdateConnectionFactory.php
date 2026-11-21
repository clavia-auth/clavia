<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Connections\OidcConfiguration;
use Clavia\Application\Management\Connections\UpdateConnection;
use Clavia\Domain\Connection\ConnectionRepository;
use Psr\Container\ContainerInterface;

final class UpdateConnectionFactory
{
    public function __invoke(ContainerInterface $container): UpdateConnection
    {
        /** @var ConnectionRepository $connections */
        $connections = $container->get(ConnectionRepository::class);
        /** @var OidcConfiguration $oidc */
        $oidc = $container->get(OidcConfiguration::class);

        return new UpdateConnection($connections, $oidc);
    }
}
