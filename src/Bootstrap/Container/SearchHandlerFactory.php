<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Access\SearchHandler;
use Clavia\Adapter\Primary\Http\Management\ManagementResponder;
use Clavia\Application\Authorization\Search\SearchAccess;
use Psr\Container\ContainerInterface;

final class SearchHandlerFactory
{
    public function __invoke(ContainerInterface $container): SearchHandler
    {
        /** @var SearchAccess $search */
        $search = $container->get(SearchAccess::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);

        return new SearchHandler(
            $search,
            $responder,
        );
    }
}
