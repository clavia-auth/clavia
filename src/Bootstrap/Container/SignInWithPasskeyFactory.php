<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\LoginThrottle;
use Clavia\Application\Authentication\Passkey\UsePasskey;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Authentication\SignIn\CompleteFirstFactor;
use Clavia\Application\Authentication\SignIn\SignInWithPasskey;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\WebAuthnChallengeStore;
use Clavia\Configuration\Settings;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class SignInWithPasskeyFactory
{
    public function __invoke(ContainerInterface $container): SignInWithPasskey
    {
        /** @var WebAuthnChallengeStore $ceremonies */
        $ceremonies = $container->get(WebAuthnChallengeStore::class);
        /** @var UsePasskey $usePasskey */
        $usePasskey = $container->get(UsePasskey::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var LoginStateStore $loginStates */
        $loginStates = $container->get(LoginStateStore::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var ConnectionAccess $access */
        $access = $container->get(ConnectionAccess::class);
        /** @var LoginThrottle $throttle */
        $throttle = $container->get(LoginThrottle::class);
        /** @var Sessions $sessions */
        $sessions = $container->get(Sessions::class);
        /** @var CompleteFirstFactor $completeFirstFactor */
        $completeFirstFactor = $container->get(CompleteFirstFactor::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new SignInWithPasskey(
            $ceremonies,
            $usePasskey,
            $users,
            $loginStates,
            $clients,
            $access,
            $throttle,
            $sessions,
            $completeFirstFactor,
            $clock,
            $events,
            $settings->passkeySatisfiesMfa,
        );
    }
}
