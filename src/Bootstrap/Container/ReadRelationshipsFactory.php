<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authorization\Relationships\ReadRelationships;
use Clavia\Application\Authorization\SpokenForApi;
use Clavia\Application\Port\DecisionEngine;
use Psr\Container\ContainerInterface;

final class ReadRelationshipsFactory
{
    public function __invoke(ContainerInterface $container): ReadRelationships
    {
        /** @var SpokenForApi $apis */
        $apis = $container->get(SpokenForApi::class);
        /** @var DecisionEngine $engine */
        $engine = $container->get(DecisionEngine::class);

        return new ReadRelationships(
            $apis,
            $engine,
        );
    }
}
