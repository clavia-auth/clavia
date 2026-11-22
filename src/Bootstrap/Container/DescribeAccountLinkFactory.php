<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Account\DescribeAccountLink;
use Clavia\Application\Port\AccountLinkStore;
use Clavia\Domain\Identity\UserRepository;
use Psr\Container\ContainerInterface;

final class DescribeAccountLinkFactory
{
    public function __invoke(ContainerInterface $container): DescribeAccountLink
    {
        /** @var AccountLinkStore $links */
        $links = $container->get(AccountLinkStore::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);

        return new DescribeAccountLink(
            $links,
            $users,
        );
    }
}
