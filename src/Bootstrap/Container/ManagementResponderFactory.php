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
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final class ManagementResponderFactory
{
    public function __invoke(ContainerInterface $container): ManagementResponder
    {
        /** @var ResponseFactoryInterface $responses */
        $responses = $container->get(ResponseFactoryInterface::class);

        return new ManagementResponder($responses);
    }
}
