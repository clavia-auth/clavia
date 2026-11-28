<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Access;

use Clavia\Adapter\Primary\Http\Management\ContractViolation;
use Clavia\Adapter\Primary\Http\Management\ManagementResponder;
use Clavia\Adapter\Primary\Http\Management\Problem;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\RequestRejected;
use Clavia\Adapter\Primary\Http\Shared\AccessTokenCredentials;
use Clavia\Adapter\Primary\Http\Shared\BearerChallenger;
use Clavia\Application\Authorization\Caller\AuthenticateAuthorizationCaller;
use Clavia\Application\Authorization\Evaluation\EvaluationRefused;
use Clavia\Application\Authorization\Relationships\RelationshipRefused;
use Clavia\Application\Authorization\SpeaksForNoApi;
use Clavia\Application\OAuth2\ProtectedResource\TokenScheme;
use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Domain\OAuth2\BearerTokenError;
use Clavia\Domain\Shared\InvalidValue;
use Fig\Http\Message\StatusCodeInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The front door of every `/access/v1/*` route (docs/design/fine-grained-authorization.md §5.2,
 * §5.3), in the Management API's order, each step answering for itself:
 *
 *  1. **Credentials**: an access token in the `Authorization` header and nowhere else, `Bearer`, or
 *     `DPoP` with its proof (RFC 9449 §7.1); none is a bare challenge, 401.
 *  2. **The token**: live, issued for the Authorization API, its subject usable
 *     ({@see AuthenticateAuthorizationCaller}; `invalid_token`, 401), the audience before any scope.
 *  3. **The scope** the operation's `security` names in `docs/openapi/authorization-api.yaml`
 *     (`insufficient_scope`, 403).
 *  4. **The request** against the contract: 400, 415 or 422, every violation listed. AuthZEN's own
 *     operations answer what the contract refuses with 400 (AuthZEN 1.0 §10.1.1), and a question
 *     that cannot be asked too.
 *
 * A request's `X-Request-ID` is echoed on every answer (AuthZEN 1.0 §10.1.3), when it is one a header
 * can carry back.
 *
 * The handler then gets an {@see AccessRequest}. The use cases' expected refusals become problem
 * documents here: a client speaking for no API is 403, a relationship refused 422 pointing at it,
 * and the decision engine not answering 503 — never a decision, never a write assumed done.
 */
final readonly class AccessApiMiddleware implements MiddlewareInterface
{
    /**
     * @param non-empty-string $origin This API's origin, as configured: what a DPoP proof's `htu` starts with.
     */
    public function __construct(
        private AccessContract $contract,
        private AuthenticateAuthorizationCaller $authenticate,
        private BearerChallenger $challenger,
        private ManagementResponder $responder,
        private string $origin,
    ) {
    }

    /** What an `X-Request-ID` echoed back may be: visible ASCII, at most 256 characters. */
    private const string REQUEST_ID = '/^[\x21-\x7E]{1,256}$/D';

    #[\Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $response = $this->answer($request, $handler);
        $id = $request->getHeaderLine('X-Request-ID');

        return preg_match(self::REQUEST_ID, $id) === 1 ? $response->withHeader('X-Request-ID', $id) : $response;
    }

    private function answer(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $operation = $this->contract->operationFor($request) ?? throw new LogicException(sprintf(
            '%s %s is routed but not described in the Authorization API contract.',
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
            $caller->require($this->contract->requiredPermission($operation));
        } catch (BearerTokenError $error) {
            return $this->challenger->refuse($error, $credentials->scheme ?? TokenScheme::Bearer);
        }

        try {
            $validated = $this->contract->validateRequest($request);
        } catch (RequestRejected $rejection) {
            $problem = ContractViolation::problem($rejection);
            $unprocessable = $problem->status === StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY;

            return $this->responder->problem(
                $unprocessable && $this->contract->isAuthZen($operation)
                    ? new Problem(StatusCodeInterface::STATUS_BAD_REQUEST, $problem->detail, $problem->errors)
                    : $problem,
            );
        }

        try {
            return $handler->handle(new AccessRequest($caller, $validated)->attachTo($request));
        } catch (SpeaksForNoApi $refusal) {
            return $this->responder->problem(
                new Problem(StatusCodeInterface::STATUS_FORBIDDEN, $refusal->getMessage()),
            );
        } catch (EvaluationRefused $refusal) {
            return $this->responder->problem(
                new Problem(StatusCodeInterface::STATUS_BAD_REQUEST, $refusal->getMessage()),
            );
        } catch (RelationshipRefused $refusal) {
            return $this->responder->problem(self::refused($refusal));
        } catch (InvalidValue $refusal) {
            return $this->responder->problem(
                new Problem(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, $refusal->getMessage()),
            );
        } catch (DecisionEngineFailed) {
            // Logged by the adapter, by operation and reason. Fail closed: nothing to assume.
            return $this->responder->problem(new Problem(
                StatusCodeInterface::STATUS_SERVICE_UNAVAILABLE,
                'The decision engine cannot answer now; nothing was done. Try again later.',
            ));
        }
    }

    private static function refused(RelationshipRefused $refusal): Problem
    {
        $error = ['detail' => $refusal->getMessage()];
        if ($refusal->pointer !== '') {
            $error = ['pointer' => $refusal->pointer] + $error;
        } elseif ($refusal->parameter !== '') {
            $error = ['parameter' => $refusal->parameter] + $error;
        }

        return new Problem(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, $refusal->getMessage(), [$error]);
    }
}
