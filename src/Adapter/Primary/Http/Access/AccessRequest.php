<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Access;

use Clavia\Adapter\Primary\Http\OpenApi\ParameterLocation;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\ValidatedRequest;
use Clavia\Application\Authorization\Caller\AuthorizationCaller;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use stdClass;

/**
 * What {@see AccessApiMiddleware} established about a request before passing it on: who is calling,
 * and the request as the contract validated and decoded it. A handler never reads the raw request.
 */
final readonly class AccessRequest
{
    private const string ATTRIBUTE = self::class;

    public function __construct(
        public AuthorizationCaller $caller,
        public ValidatedRequest $validated,
    ) {
    }

    public function attachTo(ServerRequestInterface $request): ServerRequestInterface
    {
        return $request->withAttribute(self::ATTRIBUTE, $this);
    }

    /**
     * @throws LogicException When the route does not run {@see AccessApiMiddleware} first.
     */
    public static function of(ServerRequestInterface $request): self
    {
        /** @var mixed $attached */
        $attached = $request->getAttribute(self::ATTRIBUTE);

        return $attached instanceof self
            ? $attached
            : throw new LogicException('An Authorization API handler was reached without AccessApiMiddleware.');
    }

    /** A query parameter as its schema typed it; null when absent. */
    public function query(string $name): mixed
    {
        return $this->validated->parameter(ParameterLocation::Query, $name);
    }

    /** The body, as the contract validated it: an object, or an empty one for an operation without. */
    public function body(): stdClass
    {
        return $this->validated->body instanceof stdClass ? $this->validated->body : new stdClass();
    }
}
