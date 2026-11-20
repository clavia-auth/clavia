<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Adapter\Primary\Http\OpenApi\Document;
use Clavia\Adapter\Primary\Http\OpenApi\InvalidDocument;
use Clavia\Adapter\Primary\Http\OpenApi\Operation;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\OperationNotFound;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\RequestRejected;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\RequestValidator;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\ResponseDoesNotMatch;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\ResponseValidator;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\ValidatedRequest;
use Clavia\Application\Management\ManagementPermission;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The Management API's OpenAPI document (`docs/openapi/management-api.yaml`), used as the
 * contract it is: which operation a request is, which permission that operation
 * requires, and whether the request — and, in tests, the response — matches it.
 *
 * The document is the single statement of what each operation needs: the scope named
 * in its `security` requirement is the one enforced, so a route cannot quietly demand
 * something else. Validation itself is {@see RequestValidator} and
 * {@see ResponseValidator}; this class adds what is particular to this API.
 */
final readonly class ManagementContract
{
    private const string SECURITY_SCHEME = 'managementToken';

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
     * @throws LogicException When the document names none, or one that is not a Management API
     *                        permission: a contract no token could ever satisfy is a defect.
     */
    public function requiredPermission(Operation $operation): ManagementPermission
    {
        $scopes = [];
        foreach ($operation->security as $requirement) {
            $scopes = [...$scopes, ...($requirement->scopesFor(self::SECURITY_SCHEME) ?? [])];
        }

        if (count($scopes) !== 1) {
            throw new LogicException(sprintf('%s must require exactly one Management API permission.', $operation));
        }

        return ManagementPermission::tryFrom($scopes[0])
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

    /**
     * @return list<Operation>
     */
    public function operations(): array
    {
        return $this->document->operations();
    }

    /**
     * Every permission some operation requires, for checking the document against
     * {@see ManagementPermission}.
     *
     * @return list<string>
     */
    public function requiredPermissions(): array
    {
        return array_values(array_unique(array_map(
            fn (Operation $operation): string => $this->requiredPermission($operation)->value,
            $this->operations(),
        )));
    }
}
