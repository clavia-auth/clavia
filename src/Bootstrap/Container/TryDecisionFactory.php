<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authorization\Evaluation\EvaluateAccess;
use Clavia\Application\Management\ResourceServers\AuthorizedApi;
use Clavia\Application\Management\ResourceServers\TryDecision;
use Psr\Container\ContainerInterface;

final class TryDecisionFactory
{
    public function __invoke(ContainerInterface $container): TryDecision
    {
        /** @var AuthorizedApi $authorizedApi */
        $authorizedApi = $container->get(AuthorizedApi::class);
        /** @var EvaluateAccess $evaluateAccess */
        $evaluateAccess = $container->get(EvaluateAccess::class);

        return new TryDecision($authorizedApi, $evaluateAccess);
    }
}
