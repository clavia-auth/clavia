<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Management\AuthorizationEvaluationHandler;
use Clavia\Adapter\Primary\Http\Management\ManagementResponder;
use Clavia\Application\Management\ResourceServers\TryDecision;
use Psr\Container\ContainerInterface;

final class AuthorizationEvaluationHandlerFactory
{
    public function __invoke(ContainerInterface $container): AuthorizationEvaluationHandler
    {
        /** @var TryDecision $tryDecision */
        $tryDecision = $container->get(TryDecision::class);
        /** @var ManagementResponder $managementResponder */
        $managementResponder = $container->get(ManagementResponder::class);

        return new AuthorizationEvaluationHandler($tryDecision, $managementResponder);
    }
}
