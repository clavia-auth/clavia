<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Caller\ManagementCaller;
use Clavia\Application\OAuth2\RequestParameters;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;

/**
 * What {@see ManagementApiMiddleware} established about a request before passing it on:
 * who is calling, its body and its query, both already checked against the contract.
 *
 * A handler reads it with {@see self::of()} and never looks at the raw request for these.
 */
final readonly class ManagementRequest
{
    private const string ATTRIBUTE = self::class;

    public function __construct(
        public ManagementCaller $caller,
        public JsonObject $body,
        public RequestParameters $query,
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
     * A route parameter (`{user_id}`), as FastRoute matched it.
     *
     * @throws LogicException When the route has no such parameter.
     */
    public static function pathParameter(ServerRequestInterface $request, string $name): string
    {
        /** @var mixed $value */
        $value = $request->getAttribute($name);

        return is_string($value)
            ? $value
            : throw new LogicException(sprintf("The route has no '%s' parameter.", $name));
    }
}
