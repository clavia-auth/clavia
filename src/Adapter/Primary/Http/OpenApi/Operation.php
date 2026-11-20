<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi;

use Clavia\Adapter\Primary\Http\OpenApi\Routing\PathTemplate;
use Stringable;

/**
 * One operation: a method on a path, with everything a request to it must satisfy and
 * every response it may give.
 *
 * Parameters are the path item's and the operation's merged (the operation's win), and
 * the security requirements are the effective ones — the operation's, or the document's
 * when the operation states none.
 */
final readonly class Operation implements Stringable
{
    /**
     * @param string                    $method      Upper-case: `GET`, `PATCH`.
     * @param array<string, Parameter>  $parameters  By {@see Parameter::key()}.
     * @param list<SecurityRequirement> $security    Alternatives; empty means none required.
     */
    public function __construct(
        public string $method,
        public PathTemplate $path,
        public ?string $operationId,
        public array $parameters,
        public ?RequestBody $requestBody,
        public Responses $responses,
        public array $security,
    ) {
    }

    /**
     * @return list<Parameter>
     */
    public function parametersIn(ParameterLocation $location): array
    {
        return array_values(array_filter(
            $this->parameters,
            static fn (Parameter $parameter): bool => $parameter->location === $location,
        ));
    }

    /** `GET /api/v1/users`. */
    #[\Override]
    public function __toString(): string
    {
        return $this->method . ' ' . $this->path->template;
    }
}
