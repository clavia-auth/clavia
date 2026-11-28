<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authorization\Feed\IdentityFeed;
use Clavia\Application\Authorization\Feed\SyncIdentityFeed;
use Clavia\Application\Port\DeferredTasks;
use Clavia\Configuration\Settings;
use Clavia\Domain\Authorization\IdentityFeedOutbox;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class IdentityFeedFactory
{
    public function __invoke(ContainerInterface $container): IdentityFeed
    {
        /** @var IdentityFeedOutbox $outbox */
        $outbox = $container->get(IdentityFeedOutbox::class);
        /** @var ResourceServerRepository $resourceServers */
        $resourceServers = $container->get(ResourceServerRepository::class);
        /** @var RoleRepository $roles */
        $roles = $container->get(RoleRepository::class);
        /** @var SyncIdentityFeed $sync */
        $sync = $container->get(SyncIdentityFeed::class);
        /** @var DeferredTasks $deferred */
        $deferred = $container->get(DeferredTasks::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new IdentityFeed(
            $outbox,
            $resourceServers,
            $roles,
            $sync,
            $deferred,
            $clock,
            $settings->fineGrainedAuthorization(),
        );
    }
}
