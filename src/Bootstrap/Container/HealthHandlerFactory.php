<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Configuration\Version;
use Clavia\Ui\Http\Shared\HealthHandler;
use Clavia\Ui\Http\Shared\JsonResponder;
use Psr\Container\ContainerInterface;

final class HealthHandlerFactory
{
    public function __invoke(ContainerInterface $container): HealthHandler
    {
        /** @var JsonResponder $json */
        $json = $container->get(JsonResponder::class);

        return new HealthHandler($json, Version::CURRENT);
    }
}
