<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\ResourceServers;

use Clavia\Application\Authorization\Evaluation\Decision;
use Clavia\Application\Authorization\Evaluation\EvaluateAccess;
use Clavia\Application\Authorization\Evaluation\EvaluationRefused;
use Clavia\Application\Authorization\Evaluation\EvaluationRequest;
use Clavia\Application\Management\Conflict;
use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Domain\ResourceServer\ResourceServerId;

/**
 * `POST /api/v1/resource-servers/{id}/authorization/evaluation` (docs/design/fine-grained-authorization.md
 * §5.6): one AuthZEN evaluation an operator tries on the API they name, with every step an API's own
 * question goes through (§5.2), and the reason for a denial always given. Nothing is recorded: a
 * decision is a read.
 */
final readonly class TryDecision
{
    public function __construct(
        private AuthorizedApi $apis,
        private EvaluateAccess $evaluate,
    ) {
    }

    /**
     * @throws NotFound
     * @throws Conflict
     * @throws EvaluationRefused When it cannot be asked: pointing at the member at fault.
     * @throws DecisionEngineFailed When the engine gives no answer.
     */
    public function __invoke(ResourceServerId $id, EvaluationRequest $question): Decision
    {
        [$api, $settings] = $this->apis->of($id);

        return $this->evaluate->forOperator($api, $settings, $question);
    }
}
