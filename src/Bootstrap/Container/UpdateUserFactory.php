<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\SignOutEverywhere;
use Clavia\Application\Management\Users\UpdateUser;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class UpdateUserFactory
{
    public function __invoke(ContainerInterface $container): UpdateUser
    {
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var PasswordHasher $hasher */
        $hasher = $container->get(PasswordHasher::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var MfaFactorRepository $factors */
        $factors = $container->get(MfaFactorRepository::class);
        /** @var SignOutEverywhere $signOut */
        $signOut = $container->get(SignOutEverywhere::class);

        return new UpdateUser($users, $hasher, $clock, $factors, $signOut);
    }
}
