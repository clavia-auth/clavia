<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Users\ReadUserPasskeys;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Identity\UserRepository;
use Psr\Container\ContainerInterface;

final class ReadUserPasskeysFactory
{
    public function __invoke(ContainerInterface $container): ReadUserPasskeys
    {
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var PasskeyRepository $passkeys */
        $passkeys = $container->get(PasskeyRepository::class);

        return new ReadUserPasskeys($users, $passkeys);
    }
}
