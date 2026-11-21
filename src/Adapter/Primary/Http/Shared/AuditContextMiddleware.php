<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Shared;

use Clavia\Adapter\Primary\Http\Auth\ClientAddress;
use Clavia\Application\Audit\AuditContext;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Starts each request's {@see AuditContext}: the address it came from and the user agent it
 * gave, and nobody known to be acting yet — before any handler can record an event.
 *
 * The address is the one the web server reports (`REMOTE_ADDR`), as for throttling: a
 * forwarded header is the client's word, and the trail must not take it.
 */
final readonly class AuditContextMiddleware implements MiddlewareInterface
{
    public function __construct(private AuditContext $context)
    {
    }

    #[\Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $userAgent = $request->getHeaderLine('User-Agent');
        $this->context->begin(ClientAddress::of($request), $userAgent === '' ? null : $userAgent);

        return $handler->handle($request);
    }
}
