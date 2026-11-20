<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Adapter\Primary\Http\Shared\BearerChallenger;
use Clavia\Adapter\Primary\Http\Shared\BearerCredentials;
use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Application\Management\Caller\AuthenticateManagementCaller;
use Clavia\Application\Management\Conflict;
use Clavia\Application\Management\NotFound;
use Clavia\Domain\OAuth2\BearerTokenError;
use Clavia\Domain\ResourceServer\SystemApiProtected;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\InvalidValue;
use JsonException;
use LogicException;
use Phayne\OpenAPI\Validator\Message\Exception\ValidationFailed;
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
 *  1. **Credentials** — a bearer token in the `Authorization` header, and nowhere else
 *     (none: a bare challenge, 401).
 *  2. **The token** — live, issued for this API, its subject usable
 *     ({@see AuthenticateManagementCaller}; `invalid_token`, 401). The audience is
 *     checked before any scope: a scope means nothing without one.
 *  3. **The scope** — the one the operation's `security` requirement names in the
 *     contract (`insufficient_scope`, 403).
 *  4. **The request** — no parameter twice and readable JSON (400), JSON at all (415),
 *     then everything the contract describes (422).
 *
 * Authentication comes before validation on purpose: a caller without a token learns
 * nothing about what the API would have accepted.
 *
 * The handler then gets a {@see ManagementRequest}; the expected refusals of the use
 * cases are turned into problem documents here, so a handler only states the success.
 */
final readonly class ManagementApiMiddleware implements MiddlewareInterface
{
    public function __construct(
        private ManagementContract $contract,
        private AuthenticateManagementCaller $authenticate,
        private BearerChallenger $challenger,
        private ManagementResponder $responder,
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

        try {
            $token = BearerCredentials::fromRequest($request);
            if ($token === null) {
                return $this->challenger->missing();
            }
            $caller = ($this->authenticate)($token);
            $caller->require($this->contract->requiredPermission($operation));
        } catch (BearerTokenError $error) {
            return $this->challenger->refuse($error);
        }

        $query = RequestParameterReader::query($request);
        $repeated = $query->repeated();
        if ($repeated !== []) {
            return $this->responder->problem(new Problem(
                400,
                'A query parameter was sent more than once.',
                array_map(
                    static fn (string $name): array => ['parameter' => $name, 'detail' => 'Sent more than once.'],
                    $repeated,
                ),
            ));
        }

        $body = JsonObject::empty();
        if ($this->contract->takesBody($operation)) {
            $read = $this->readBody($request);
            if ($read instanceof Problem) {
                return $this->responder->problem($read);
            }
            $body = $read;
        }

        try {
            $this->contract->validateRequest($operation, $request);
        } catch (ValidationFailed $failure) {
            return $this->responder->problem(ContractViolation::problem($failure));
        }

        try {
            return $handler->handle(new ManagementRequest($caller, $body, $query)->attachTo($request));
        } catch (NotFound $refusal) {
            return $this->responder->problem(new Problem(404, $refusal->getMessage()));
        } catch (Conflict | AlreadyExists | SystemApiProtected $refusal) {
            return $this->responder->problem(new Problem(409, $refusal->getMessage()));
        } catch (InvalidValue $refusal) {
            return $this->responder->problem(new Problem(422, $refusal->getMessage()));
        }
    }

    /**
     * The body as a JSON object, or the problem with it: not JSON (415), not readable
     * (400), not an object (422 — the contract describes only objects).
     */
    private function readBody(ServerRequestInterface $request): JsonObject|Problem
    {
        $mediaType = strtolower(trim(explode(';', $request->getHeaderLine('Content-Type'))[0]));
        if ($mediaType !== 'application/json') {
            return new Problem(415, "The body must be 'application/json'.");
        }

        $raw = (string) $request->getBody();
        try {
            /** @var mixed $decoded */
            $decoded = json_decode($raw, false, 64, JSON_THROW_ON_ERROR);
            if (! $decoded instanceof stdClass) {
                return new Problem(422, ContractViolation::DETAIL, [
                    ['pointer' => '', 'detail' => 'The body must be a JSON object.'],
                ]);
            }
            /** @var array<array-key, mixed> $members */
            $members = json_decode($raw, true, 64, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return new Problem(400, 'The body is not valid JSON.');
        }

        return JsonObject::of($members);
    }
}
