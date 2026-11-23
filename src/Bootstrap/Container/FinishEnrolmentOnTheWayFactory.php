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
use Clavia\Application\Authentication\Mfa\FinishEnrolmentOnTheWay;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Identity\UserRepository;
use Psr\Container\ContainerInterface;

final class FinishEnrolmentOnTheWayFactory
{
    public function __invoke(ContainerInterface $container): FinishEnrolmentOnTheWay
    {
        /** @var LoginStateStore $loginStates */
        $loginStates = $container->get(LoginStateStore::class);
        /** @var Sessions $sessions */
        $sessions = $container->get(Sessions::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var SendAccountLink $mail */
        $mail = $container->get(SendAccountLink::class);

        return new FinishEnrolmentOnTheWay($loginStates, $sessions, $users, $mail);
    }
}
