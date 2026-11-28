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
use Clavia\Application\Authorization\Evaluation\SubjectFacts;
use Clavia\Application\Authorization\SpokenForApi;
use Clavia\Application\Port\DecisionEngine;
use Psr\Container\ContainerInterface;

final class EvaluateAccessFactory
{
    public function __invoke(ContainerInterface $container): EvaluateAccess
    {
        /** @var SpokenForApi $apis */
        $apis = $container->get(SpokenForApi::class);
        /** @var DecisionEngine $engine */
        $engine = $container->get(DecisionEngine::class);
        /** @var SubjectFacts $facts */
        $facts = $container->get(SubjectFacts::class);

        return new EvaluateAccess(
            $apis,
            $engine,
            $facts,
        );
    }
}
