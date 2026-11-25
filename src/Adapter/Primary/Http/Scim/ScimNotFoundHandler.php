<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Scim;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Any other path under `/scim/v2`: a SCIM `404`, behind the provisioning middleware like the rest,
 * so a request without a usable token learns nothing of what exists.
 */
final readonly class ScimNotFoundHandler implements RequestHandlerInterface
{
    public function __construct(private ScimResponder $responder)
    {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return $this->responder->notFound();
    }
}
