<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi\Validation;

use RuntimeException;

/**
 * A request the document does not allow. The subclass says how the caller went wrong —
 * {@see MalformedRequest} (400), {@see UnsupportedMediaType} (415),
 * {@see RequestDoesNotMatch} (422) — so the HTTP status is the adapter's choice to make
 * and not this package's.
 */
abstract class RequestRejected extends RuntimeException
{
    /**
     * @param list<Violation> $violations
     */
    final public function __construct(string $message, public readonly array $violations = [])
    {
        parent::__construct($message);
    }
}
