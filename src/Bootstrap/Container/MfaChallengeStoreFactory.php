<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Secondary\Redis\RedisConnection;
use Clavia\Adapter\Secondary\Redis\RedisMfaChallengeStore;
use Clavia\Application\Port\MfaChallengeStore;
use Psr\Container\ContainerInterface;

final class MfaChallengeStoreFactory
{
    public function __invoke(ContainerInterface $container): MfaChallengeStore
    {
        /** @var RedisConnection $redis */
        $redis = $container->get(RedisConnection::class);

        return new RedisMfaChallengeStore($redis);
    }
}
