<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Clients\RemoveClientLogo;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Client\ClientLogoRepository;
use Psr\Container\ContainerInterface;

final class RemoveClientLogoFactory
{
    public function __invoke(ContainerInterface $container): RemoveClientLogo
    {
        /** @var ClientLogoRepository $logos */
        $logos = $container->get(ClientLogoRepository::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new RemoveClientLogo($logos, $events);
    }
}
