<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Adapter\Primary\Http\OpenApi\ParameterLocation;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\ValidatedRequest;
use Clavia\Application\Management\Caller\ManagementCaller;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;

/**
 * What {@see ManagementApiMiddleware} established about a request before passing it on:
 * who is calling, and the request as the contract validated and decoded it.
 *
 * A handler reads it with {@see self::of()} and never looks at the raw request.
 */
final readonly class ManagementRequest
{
    private const string ATTRIBUTE = self::class;

    public function __construct(
        public ManagementCaller $caller,
        public ValidatedRequest $validated,
        public JsonObject $body,
    ) {
    }

    public function attachTo(ServerRequestInterface $request): ServerRequestInterface
    {
        return $request->withAttribute(self::ATTRIBUTE, $this);
    }

    /**
     * @throws LogicException When the route does not run {@see ManagementApiMiddleware} first.
     */
    public static function of(ServerRequestInterface $request): self
    {
        /** @var mixed $attached */
        $attached = $request->getAttribute(self::ATTRIBUTE);

        return $attached instanceof self
            ? $attached
            : throw new LogicException('A Management API handler was reached without ManagementApiMiddleware.');
    }

    /**
     * A path parameter (`{user_id}`), decoded.
     *
     * @throws LogicException When the operation has no such parameter.
     */
    public function path(string $name): string
    {
        /** @var mixed $value */
        $value = $this->validated->parameter(ParameterLocation::Path, $name);

        return is_string($value)
            ? $value
            : throw new LogicException(sprintf("The operation has no string path parameter '%s'.", $name));
    }

    /** A query parameter as its schema typed it; null when absent. */
    public function query(string $name): mixed
    {
        return $this->validated->parameter(ParameterLocation::Query, $name);
    }
}
