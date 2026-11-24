<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Adapter\Primary\Http\OpenApi\Validation\RequestRejected;
use Clavia\Adapter\Primary\Http\Shared\BearerChallenger;
use Clavia\Adapter\Primary\Http\Shared\AccessTokenCredentials;
use Clavia\Application\Audit\AuditContext;
use Clavia\Application\Management\Caller\AuthenticateManagementCaller;
use Clavia\Application\Management\Conflict;
use Clavia\Application\Management\NotFound;
use Clavia\Application\OAuth2\ProtectedResource\TokenScheme;
use Clavia\Domain\Connection\BuiltInConnection;
use Clavia\Domain\OAuth2\BearerTokenError;
use Clavia\Domain\ResourceServer\SystemApiProtected;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\InvalidValue;
use Fig\Http\Message\StatusCodeInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use stdClass;

/**
 * The front door of every `/api/v1/*` route: it runs before the route's handler and
 * decides whether the handler runs at all.
 *
 * In this order, each step answering for itself:
 *
 *  1. **Credentials** — an access token in the `Authorization` header, and nowhere else:
 *     `Bearer`, or `DPoP` with its proof (RFC 9449 §7.1); none: a bare challenge, 401.
 *  2. **The token** — live, issued for this API, its subject usable
 *     ({@see AuthenticateManagementCaller}; `invalid_token`, 401). The audience is
 *     checked before any scope: a scope means nothing without one.
 *  3. **The scope** — the one the operation's `security` requirement names in the
 *     contract (`insufficient_scope`, 403).
 *  4. **The request** — readable (400: JSON syntax, a parameter sent twice), JSON at
 *     all (415), then everything the contract describes (422), every violation listed
 *     ({@see ContractViolation}).
 *
 * Authentication comes before validation on purpose: a caller without a token learns
 * nothing about what the API would have accepted.
 *
 * The handler then gets a {@see ManagementRequest}; the expected refusals of the use
 * cases are turned into problem documents here, so a handler only states the success.
 */
final readonly class ManagementApiMiddleware implements MiddlewareInterface
{
    /**
     * @param non-empty-string $origin This API's origin, as configured: what a DPoP proof's `htu` starts with.
     */
    public function __construct(
        private ManagementContract $contract,
        private AuthenticateManagementCaller $authenticate,
        private BearerChallenger $challenger,
        private ManagementResponder $responder,
        private AuditContext $audit,
        private string $origin,
    ) {
    }

    #[\Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $operation = $this->contract->operationFor($request) ?? throw new LogicException(sprintf(
            '%s %s is routed but not described in the Management API contract.',
            $request->getMethod(),
            $request->getUri()->getPath(),
        ));

        $credentials = null;
        try {
            $credentials = AccessTokenCredentials::fromRequest($request);
            if ($credentials === null) {
                return $this->challenger->missing();
            }
            $method = $request->getMethod();
            assert($method !== '');
            // The URL a DPoP proof names: this API's origin as configured, and the routed path.
            $caller = ($this->authenticate)($credentials, $method, $this->origin . $request->getUri()->getPath());
            $this->audit->actAs($caller->actor());
            $caller->require($this->contract->requiredPermission($operation));
        } catch (BearerTokenError $error) {
            return $this->challenger->refuse($error, $credentials->scheme ?? TokenScheme::Bearer);
        }

        try {
            $validated = $this->contract->validateRequest($request);
        } catch (RequestRejected $rejection) {
            return $this->responder->problem(ContractViolation::problem($rejection));
        }
        $body = $validated->body instanceof stdClass ? JsonObject::of($validated->body) : JsonObject::empty();

        try {
            return $handler->handle(new ManagementRequest($caller, $validated, $body)->attachTo($request));
        } catch (NotFound $refusal) {
            return $this->responder->problem(
                new Problem(StatusCodeInterface::STATUS_NOT_FOUND, $refusal->getMessage()),
            );
        } catch (Conflict | AlreadyExists | SystemApiProtected | BuiltInConnection $refusal) {
            return $this->responder->problem(new Problem(StatusCodeInterface::STATUS_CONFLICT, $refusal->getMessage()));
        } catch (InvalidValue $refusal) {
            return $this->responder->problem(
                new Problem(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, $refusal->getMessage()),
            );
        }
    }
}
