<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Access\RelationshipsHandler;
use Clavia\Adapter\Primary\Http\Management\ManagementResponder;
use Clavia\Application\Authorization\Relationships\ReadRelationships;
use Clavia\Application\Authorization\Relationships\WriteRelationships;
use Psr\Container\ContainerInterface;

final class RelationshipsHandlerFactory
{
    public function __invoke(ContainerInterface $container): RelationshipsHandler
    {
        /** @var WriteRelationships $write */
        $write = $container->get(WriteRelationships::class);
        /** @var ReadRelationships $read */
        $read = $container->get(ReadRelationships::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);

        return new RelationshipsHandler(
            $write,
            $read,
            $responder,
        );
    }
}
