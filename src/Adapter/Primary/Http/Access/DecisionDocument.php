<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Access;

use Clavia\Application\Authorization\Evaluation\Decision;

/**
 * AuthZEN's Decision (AuthZEN 1.0 §5.5): `decision`, and a context when there is something to say,
 * as the Authorization API and the Management API answer it.
 */
final readonly class DecisionDocument
{
    private function __construct()
    {
    }

    /** @return array<string, mixed> */
    public static function of(Decision $decision): array
    {
        $context = [];
        if ($decision->reason !== null) {
            $context['reason'] = $decision->reason->value;
        }
        if ($decision->errorStatus !== null) {
            $context['error'] = ['status' => $decision->errorStatus, 'message' => (string) $decision->errorMessage];
        }

        return $context === [] ? ['decision' => $decision->decision] : [
            'decision' => $decision->decision,
            'context' => $context,
        ];
    }
}
