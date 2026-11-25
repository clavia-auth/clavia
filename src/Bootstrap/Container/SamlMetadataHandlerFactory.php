<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Auth\Saml\SamlMetadataHandler;
use Clavia\Adapter\Primary\Http\Shared\ErrorResponder;
use Clavia\Application\Connection\Saml\DescribeSamlServiceProvider;
use Psr\Container\ContainerInterface;

final class SamlMetadataHandlerFactory
{
    public function __invoke(ContainerInterface $container): SamlMetadataHandler
    {
        /** @var DescribeSamlServiceProvider $describe */
        $describe = $container->get(DescribeSamlServiceProvider::class);
        /** @var ErrorResponder $errors */
        $errors = $container->get(ErrorResponder::class);

        return new SamlMetadataHandler($describe, $errors);
    }
}
