<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization\Evaluation;

/**
 * One question, as AuthZEN 1.0 asks it (§6.1): may this subject do this action to that resource, in
 * this context? Kept as it was sent, defaults of a batch already merged in (§7.1.1); whether it names
 * anything the API's model knows is {@see EvaluateAccess}'s to say, item by item.
 *
 * The `properties` AuthZEN allows on the subject, the resource and the action are not read: OpenFGA
 * decides from relationships, and a condition reads the `context`.
 */
final readonly class EvaluationRequest
{
    /**
     * @param array<string, mixed> $context The question's context, JSON objects kept as objects.
     */
    public function __construct(
        public string $subjectType,
        public string $subjectId,
        public string $action,
        public string $resourceType,
        public string $resourceId,
        public array $context = [],
    ) {
    }
}
