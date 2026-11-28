<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Adapter\Primary\Http\Access\DecisionDocument;
use Clavia\Application\Authorization\Evaluation\EvaluationRefused;
use Clavia\Application\Authorization\Evaluation\EvaluationRequest;
use Clavia\Application\Management\ResourceServers\TryDecision;
use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `POST /api/v1/resource-servers/{resource_server_id}/authorization/evaluation`
 * (docs/design/fine-grained-authorization.md §5.6): an operator tries one AuthZEN evaluation on the
 * API. The body is AuthZEN's (§6.1); a question the API's model cannot take is `422` at the member at
 * fault, and the answer carries the reason for a denial.
 */
final readonly class AuthorizationEvaluationHandler implements RequestHandlerInterface
{
    public function __construct(
        private TryDecision $try,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);
        $body = $management->body;
        $subject = $body->object('subject') ?? JsonObject::empty();
        $action = $body->object('action') ?? JsonObject::empty();
        $resource = $body->object('resource') ?? JsonObject::empty();

        try {
            $decision = ($this->try)(
                ResourceServerId::fromString($management->path('resource_server_id')),
                new EvaluationRequest(
                    $subject->string('type') ?? '',
                    $subject->string('id') ?? '',
                    $action->string('name') ?? '',
                    $resource->string('type') ?? '',
                    $resource->string('id') ?? '',
                    $body->members('context') ?? [],
                ),
            );
        } catch (EvaluationRefused $refusal) {
            return $this->responder->problem(new Problem(
                StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY,
                ContractViolation::REFUSED,
                [['pointer' => $refusal->pointer, 'detail' => $refusal->getMessage()]],
            ));
        } catch (DecisionEngineFailed) {
            return $this->responder->problem(new Problem(
                StatusCodeInterface::STATUS_SERVICE_UNAVAILABLE,
                'The decision engine is unavailable; nothing was decided.',
            ));
        }

        return $this->responder->json(DecisionDocument::of($decision));
    }
}
