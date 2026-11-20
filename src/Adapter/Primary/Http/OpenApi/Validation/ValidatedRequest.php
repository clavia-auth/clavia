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
use Clavia\Adapter\Primary\Http\OpenApi\Parameter;
use Clavia\Adapter\Primary\Http\OpenApi\ParameterLocation;

/**
 * A request that satisfies its operation, with every part already decoded: parameters
 * coerced to the types their schemas give, the body parsed as JSON (objects as
 * `stdClass`). What is absent here was absent from the request.
 */
final readonly class ValidatedRequest
{
    /**
     * @param array<string, mixed> $parameters By {@see Parameter::key()}.
     */
    public function __construct(
        public Operation $operation,
        private array $parameters,
        public bool $hasBody,
        public mixed $body,
    ) {
    }

    /** Whether the parameter was sent. */
    public function has(ParameterLocation $location, string $name): bool
    {
        return array_key_exists(self::key($location, $name), $this->parameters);
    }

    /** The parameter's decoded value; null when it was not sent. */
    public function parameter(ParameterLocation $location, string $name): mixed
    {
        return $this->parameters[self::key($location, $name)] ?? null;
    }

    private static function key(ParameterLocation $location, string $name): string
    {
        return $location->value . ':' . ($location === ParameterLocation::Header ? strtolower($name) : $name);
    }
}
