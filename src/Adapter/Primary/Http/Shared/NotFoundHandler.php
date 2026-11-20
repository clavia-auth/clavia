<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Shared;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The end of the pipeline: no route matched the request path. A page for a browser,
 * `{"detail": "Not Found"}` for anything else.
 */
final readonly class NotFoundHandler implements RequestHandlerInterface
{
    public function __construct(private ErrorResponder $errors)
    {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return $this->errors->notFound($request);
    }
}
