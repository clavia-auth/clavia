<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Ui\Http\Shared\JsonResponder;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Container\ContainerInterface;

final class JsonResponderFactory
{
    public function __invoke(ContainerInterface $container): JsonResponder
    {
        /** @var ResponseFactoryInterface $responses */
        $responses = $container->get(ResponseFactoryInterface::class);
        /** @var StreamFactoryInterface $streams */
        $streams = $container->get(StreamFactoryInterface::class);

        return new JsonResponder($responses, $streams);
    }
}
