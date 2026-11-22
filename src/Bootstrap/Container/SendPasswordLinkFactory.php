<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Account\SendAccountLink;
use Clavia\Application\Management\Users\SendPasswordLink;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\Mailer;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Identity\UserRepository;
use Psr\Container\ContainerInterface;

final class SendPasswordLinkFactory
{
    public function __invoke(ContainerInterface $container): SendPasswordLink
    {
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var ConnectionRepository $connections */
        $connections = $container->get(ConnectionRepository::class);
        /** @var SendAccountLink $links */
        $links = $container->get(SendAccountLink::class);
        /** @var Mailer $mailer */
        $mailer = $container->get(Mailer::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new SendPasswordLink($users, $connections, $links, $mailer, $events);
    }
}
