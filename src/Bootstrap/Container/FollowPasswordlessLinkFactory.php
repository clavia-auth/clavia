<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Passwordless\FinishPasswordlessSignIn;
use Clavia\Application\Authentication\Passwordless\FollowPasswordlessLink;
use Clavia\Application\Port\PasswordlessChallengeStore;
use Psr\Container\ContainerInterface;

final class FollowPasswordlessLinkFactory
{
    public function __invoke(ContainerInterface $container): FollowPasswordlessLink
    {
        /** @var PasswordlessChallengeStore $challenges */
        $challenges = $container->get(PasswordlessChallengeStore::class);
        /** @var FinishPasswordlessSignIn $finish */
        $finish = $container->get(FinishPasswordlessSignIn::class);

        return new FollowPasswordlessLink($challenges, $finish);
    }
}
