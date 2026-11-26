<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Auth\BrandingHandler;
use Clavia\Application\Authentication\Branding\DescribeBranding;
use Psr\Container\ContainerInterface;

final class BrandingHandlerFactory
{
    public function __invoke(ContainerInterface $container): BrandingHandler
    {
        /** @var DescribeBranding $describe */
        $describe = $container->get(DescribeBranding::class);

        return new BrandingHandler($describe);
    }
}
