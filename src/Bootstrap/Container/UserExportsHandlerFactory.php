<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Management\ManagementResponder;
use Clavia\Adapter\Primary\Http\Management\UserExportsHandler;
use Clavia\Application\Management\Users\Jobs\QueueUserExport;
use Psr\Container\ContainerInterface;

final class UserExportsHandlerFactory
{
    public function __invoke(ContainerInterface $container): UserExportsHandler
    {
        /** @var QueueUserExport $queue */
        $queue = $container->get(QueueUserExport::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);

        return new UserExportsHandler($queue, $responder);
    }
}
