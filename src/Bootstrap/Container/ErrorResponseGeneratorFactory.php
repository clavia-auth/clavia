<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Shared\ErrorResponseGenerator;
use Clavia\Adapter\Primary\Http\Shared\PageRenderer;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;

final class ErrorResponseGeneratorFactory
{
    public function __invoke(ContainerInterface $container): ErrorResponseGenerator
    {
        /** @var StreamFactoryInterface $streams */
        $streams = $container->get(StreamFactoryInterface::class);
        /** @var LoggerInterface $logger */
        $logger = $container->get(LoggerInterface::class);
        /** @var PageRenderer $pages */
        $pages = $container->get(PageRenderer::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);

        return new ErrorResponseGenerator($streams, $logger, $pages, $secrets);
    }
}
