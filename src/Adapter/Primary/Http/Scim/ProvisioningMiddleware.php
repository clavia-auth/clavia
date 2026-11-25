<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Scim;

use Clavia\Adapter\Primary\Http\Shared\ClientAddress;
use Clavia\Application\Audit\AuditContext;
use Clavia\Application\OAuth2\ClientAuthentication\TooManyFailedRequests;
use Clavia\Application\Provisioning\AuthenticateProvisioningToken;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The front door of every `/scim/v2/*` route (docs/design/scim-provisioning.md §5.2), the fifth
 * surface, on `management.{domain}`: a directory proves itself with its provisioning token, never
 * with a Management API access token or a cookie.
 *
 * In this order: an address past the limit of failed tokens is `429` before anything is read;
 * a missing, malformed, unknown, expired or revoked token, or one whose connection is gone, is one
 * `401`; then the audit trail names the token as the actor, and the handler reads the caller
 * ({@see ScimRequest}).
 */
final readonly class ProvisioningMiddleware implements MiddlewareInterface
{
    public function __construct(
        private AuthenticateProvisioningToken $authenticate,
        private AuditContext $audit,
        private ScimResponder $responder,
    ) {
    }

    #[\Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $address = ClientAddress::of($request);
        try {
            $secret = ProvisioningCredentials::fromRequest($request);
            if ($secret === null) {
                $this->authenticate->refuseIfLimited($address);

                return $this->responder->unauthorized(ProvisioningCredentials::presented($request));
            }
            $caller = ($this->authenticate)($secret, $address);
        } catch (TooManyFailedRequests $refusal) {
            return $this->responder->tooManyFailures($refusal->retryAfter);
        }
        if ($caller === null) {
            return $this->responder->unauthorized(true);
        }
        $this->audit->actAs($caller->actor());

        return $handler->handle(ScimRequest::attach($request, $caller));
    }
}
