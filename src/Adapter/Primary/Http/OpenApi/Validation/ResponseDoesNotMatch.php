<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi\Validation;

use Clavia\Adapter\Primary\Http\OpenApi\Operation;
use RuntimeException;

/**
 * A response the document does not describe for its operation: a defect of the server
 * (or of the document), never of the caller.
 */
final class ResponseDoesNotMatch extends RuntimeException
{
    /**
     * @param list<Violation> $violations
     */
    public function __construct(public readonly Operation $operation, public readonly array $violations)
    {
        parent::__construct(sprintf(
            "%s answered what the document does not describe:\n%s",
            $operation,
            implode("\n", array_map(
                static fn (Violation $violation): string => '  ' . $violation->describe(),
                $violations,
            )),
        ));
    }
}
