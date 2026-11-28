<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Access;

use Clavia\Adapter\Primary\Http\Management\ManagementResponder;
use Clavia\Application\Authorization\Evaluation\Decision;
use Clavia\Application\Authorization\Evaluation\EvaluateAccess;
use Clavia\Application\Authorization\Evaluation\EvaluationRefused;
use Clavia\Application\Authorization\Evaluation\EvaluationRequest;
use Clavia\Application\Authorization\Evaluation\EvaluationSemantic;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use stdClass;

/**
 * `POST /access/v1/evaluation` and `POST /access/v1/evaluations` (AuthZEN 1.0 §6, §7): the AuthZEN
 * shapes, translated to and from {@see EvaluateAccess}.
 *
 * A batch's top-level `subject`, `action`, `resource` and `context` are defaults an item's own replace
 * key by key (§7.1.1); a batch with no item is a single question (§7.1), answered as one. Members
 * AuthZEN does not define are ignored, as §10.1.1 asks.
 */
final readonly class EvaluationHandler implements RequestHandlerInterface
{
    public function __construct(
        private EvaluateAccess $evaluate,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $access = AccessRequest::of($request);
        $body = $access->body();
        /** @var mixed $items */
        $items = $body->evaluations ?? [];
        $batch = str_ends_with($request->getUri()->getPath(), '/evaluations');

        if (! $batch || ! is_array($items) || $items === []) {
            return $this->responder->json(DecisionDocument::of(
                $this->evaluate->one($access->caller->clientId, self::question($body, new stdClass())),
            ));
        }

        $questions = [];
        /** @var mixed $item */
        foreach ($items as $item) {
            $questions[] = self::question($body, $item instanceof stdClass ? $item : new stdClass());
        }
        /** @var mixed $options */
        $options = $body->options ?? null;
        /** @var mixed $semantic */
        $semantic = $options instanceof stdClass ? ($options->evaluations_semantic ?? null) : null;

        return $this->responder->json(['evaluations' => array_map(DecisionDocument::of(...), $this->evaluate->many(
            $access->caller->clientId,
            $questions,
            EvaluationSemantic::tryFrom(is_string($semantic) ? $semantic : '') ?? EvaluationSemantic::ExecuteAll,
        ))]);
    }

    /**
     * An item's members, or the request's where it has none (§7.1.1).
     *
     * @throws EvaluationRefused When the subject, the action or the resource is neither.
     */
    private static function question(stdClass $defaults, stdClass $item): EvaluationRequest
    {
        $subject = self::member($item, $defaults, 'subject');
        $action = self::member($item, $defaults, 'action');
        $resource = self::member($item, $defaults, 'resource');
        if ($subject === null || $action === null || $resource === null) {
            throw EvaluationRefused::incomplete();
        }
        $context = self::member($item, $defaults, 'context');

        return new EvaluationRequest(
            self::string($subject, 'type'),
            self::string($subject, 'id'),
            self::string($action, 'name'),
            self::string($resource, 'type'),
            self::string($resource, 'id'),
            $context === null ? [] : AccessRequest::members($context),
        );
    }

    private static function member(stdClass $item, stdClass $defaults, string $name): ?stdClass
    {
        /** @var mixed $value */
        $value = $item->{$name} ?? $defaults->{$name} ?? null;

        return $value instanceof stdClass ? $value : null;
    }

    private static function string(stdClass $object, string $name): string
    {
        /** @var mixed $value */
        $value = $object->{$name} ?? null;

        return is_string($value) ? $value : '';
    }
}
