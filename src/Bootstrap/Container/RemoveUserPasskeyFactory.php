<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Users\RemoveUserPasskey;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Identity\UserRepository;
use Psr\Container\ContainerInterface;

final class RemoveUserPasskeyFactory
{
    public function __invoke(ContainerInterface $container): RemoveUserPasskey
    {
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var PasskeyRepository $passkeys */
        $passkeys = $container->get(PasskeyRepository::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new RemoveUserPasskey($users, $passkeys, $events);
    }
}
