<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use RuntimeException;

/**
 * The {@see DecisionEngine} gave no answer: it could not be reached, was slower than its timeout,
 * failed, or refused the request.
 *
 * Every failure is this one exception, and none is a decision: whoever asked must fail closed
 * (docs/design/fine-grained-authorization.md §2, "Failures"). When the engine refused the request
 * itself (a tuple its model does not allow, a model that does not hold together, an unknown
 * store), {@see self::$refusal} is the engine's error code, safe to show an operator; it is null
 * when the engine could not answer at all. The message never holds what was sent.
 */
final class DecisionEngineFailed extends RuntimeException
{
    private function __construct(string $message, public readonly ?string $refusal)
    {
        parent::__construct($message);
    }

    /** The engine could not answer: unreachable, too slow, failing, or not configured. */
    public static function unavailable(): self
    {
        return new self('The decision engine is unavailable.', null);
    }

    /**
     * The engine refused the request, with its error code (OpenFGA's `code`: `validation_error`,
     * `store_id_not_found`…).
     */
    public static function refused(string $code): self
    {
        return new self(sprintf('The decision engine refused the request (%s).', $code), $code);
    }
}
