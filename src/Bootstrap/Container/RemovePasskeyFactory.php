<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Passkey\RecentSignIn;
use Clavia\Application\Authentication\Passkey\RemovePasskey;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Identity\ExternalIdentityRepository;
use Clavia\Domain\Identity\UserRepository;
use Psr\Container\ContainerInterface;

final class RemovePasskeyFactory
{
    public function __invoke(ContainerInterface $container): RemovePasskey
    {
        /** @var PasskeyRepository $passkeys */
        $passkeys = $container->get(PasskeyRepository::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var ConnectionRepository $connections */
        $connections = $container->get(ConnectionRepository::class);
        /** @var ExternalIdentityRepository $identities */
        $identities = $container->get(ExternalIdentityRepository::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);
        /** @var RecentSignIn $recentSignIn */
        $recentSignIn = $container->get(RecentSignIn::class);

        return new RemovePasskey($passkeys, $users, $connections, $identities, $events, $recentSignIn);
    }
}
