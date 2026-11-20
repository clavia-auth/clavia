<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Shared\PageRenderer;
use Mezzio\Template\TemplateRendererInterface;
use Psr\Container\ContainerInterface;

final class PageRendererFactory
{
    public function __invoke(ContainerInterface $container): PageRenderer
    {
        /** @var TemplateRendererInterface $templates */
        $templates = $container->get(TemplateRendererInterface::class);

        return new PageRenderer($templates);
    }
}
