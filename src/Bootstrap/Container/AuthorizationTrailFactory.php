<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Audit\Audit;
use Clavia\Application\Audit\Trail\AuthorizationTrail;
use Psr\Container\ContainerInterface;

final class AuthorizationTrailFactory
{
    public function __invoke(ContainerInterface $container): AuthorizationTrail
    {
        /** @var Audit $audit */
        $audit = $container->get(Audit::class);

        return new AuthorizationTrail($audit);
    }
}
