<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Scim;

use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/scim/v2/Bulk` (RFC 7644 §3.7) and `/scim/v2/Me` (§3.11): `501 Not Implemented`, which the
 * protocol answers for a feature a service provider does not offer (§3.12). No directory this is for
 * uses either (docs/design/scim-provisioning.md §1).
 */
final readonly class ScimNotImplementedHandler implements RequestHandlerInterface
{
    public function __construct(private ScimResponder $responder)
    {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return $this->responder->error(
            StatusCodeInterface::STATUS_NOT_IMPLEMENTED,
            'Not offered by this service provider.',
        );
    }
}
