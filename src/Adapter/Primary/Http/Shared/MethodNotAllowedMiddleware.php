<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Shared;

use Laminas\Diactoros\Response\JsonResponse;
use Mezzio\Router\RouteResult;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Answers 405 when the path is routed but not for this method (RFC 9110 §15.5.6).
 *
 * A route answers exactly the methods it declares, and the `Allow` header lists them.
 * Nothing is implied — no automatic `HEAD`, no automatic `OPTIONS`: a `HEAD` that ran a
 * `GET` handler would issue an authorization code nobody receives.
 */
final readonly class MethodNotAllowedMiddleware implements MiddlewareInterface
{
    #[\Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $result = $request->getAttribute(RouteResult::class);
        if (! $result instanceof RouteResult || ! $result->isMethodFailure()) {
            return $handler->handle($request);
        }

        return new JsonResponse(
            ['detail' => 'Method Not Allowed'],
            405,
            ['Allow' => implode(', ', $result->getAllowedMethods() ?? [])],
        );
    }
}
