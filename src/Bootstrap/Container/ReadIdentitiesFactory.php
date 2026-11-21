<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Users\ReadIdentities;
use Clavia\Domain\Identity\ExternalIdentityRepository;
use Clavia\Domain\Identity\UserRepository;
use Psr\Container\ContainerInterface;

final class ReadIdentitiesFactory
{
    public function __invoke(ContainerInterface $container): ReadIdentities
    {
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var ExternalIdentityRepository $identities */
        $identities = $container->get(ExternalIdentityRepository::class);

        return new ReadIdentities($users, $identities);
    }
}
