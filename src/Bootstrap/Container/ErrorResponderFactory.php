<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Shared\ErrorResponder;
use Clavia\Adapter\Primary\Http\Shared\PageRenderer;
use Psr\Container\ContainerInterface;

final class ErrorResponderFactory
{
    public function __invoke(ContainerInterface $container): ErrorResponder
    {
        /** @var PageRenderer $pages */
        $pages = $container->get(PageRenderer::class);

        return new ErrorResponder($pages);
    }
}
