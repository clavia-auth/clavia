<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Access;

use Clavia\Adapter\Primary\Http\OpenApi\Document;
use Clavia\Adapter\Primary\Http\OpenApi\InvalidDocument;
use Clavia\Adapter\Primary\Http\OpenApi\Operation;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\OperationNotFound;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\RequestRejected;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\RequestValidator;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\ResponseDoesNotMatch;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\ResponseValidator;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\ValidatedRequest;
use Clavia\Application\Authorization\AuthorizationPermission;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * `docs/openapi/authorization-api.yaml`, the Authorization API's contract (`/access/v1/*`): which
 * operation a request is, the scope it requires, and its request and response checked against it.
 */
final readonly class AccessContract
{
    private const string SECURITY_SCHEME = 'authorizationToken';

    private RequestValidator $requests;

    public function __construct(private Document $document)
    {
        $this->requests = new RequestValidator($document);
    }

    /**
     * @throws InvalidDocument
     */
    public static function fromFile(string $path): self
    {
        return new self(Document::fromYamlFile($path));
    }

    /** The operation `$request` is, when the document describes one. */
    public function operationFor(ServerRequestInterface $request): ?Operation
    {
        return $this->document->match($request->getMethod(), $request->getUri()->getPath())?->operation;
    }

    /**
     * The permission the operation's `security` requirement names.
     *
     * @throws LogicException When it names none, or one that is not the Authorization API's: a contract
     *                        no token could satisfy is a defect.
     */
    public function requiredPermission(Operation $operation): AuthorizationPermission
    {
        $scopes = [];
        foreach ($operation->security as $requirement) {
            $scopes = [...$scopes, ...($requirement->scopesFor(self::SECURITY_SCHEME) ?? [])];
        }
        if (count($scopes) !== 1) {
            throw new LogicException(sprintf('%s must require exactly one Authorization API permission.', $operation));
        }

        return AuthorizationPermission::tryFrom($scopes[0])
            ?? throw new LogicException(
                sprintf("%s requires '%s', which is not a permission.", $operation, $scopes[0]),
            );
    }

    /**
     * @throws OperationNotFound
     * @throws RequestRejected
     */
    public function validateRequest(ServerRequestInterface $request): ValidatedRequest
    {
        return $this->requests->validate($request);
    }

    /**
     * @throws ResponseDoesNotMatch
     */
    public function validateResponse(Operation $operation, ResponseInterface $response): void
    {
        ResponseValidator::validate($operation, $response);
    }

    /** @return list<Operation> */
    public function operations(): array
    {
        return $this->document->operations();
    }
}
