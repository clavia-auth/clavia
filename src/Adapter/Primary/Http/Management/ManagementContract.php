<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\ManagementPermission;
use LogicException;
use Phayne\OpenAPI\Specification\OpenApi;
use Phayne\OpenAPI\Validator\Message\Exception\ValidationFailed;
use Phayne\OpenAPI\Validator\Message\OperationAddress;
use Phayne\OpenAPI\Validator\Message\PathFinder;
use Phayne\OpenAPI\Validator\Message\MessageValidator;
use Phayne\OpenAPI\Specification\MediaType;
use Phayne\OpenAPI\Specification\PathItem;
use Phayne\OpenAPI\Specification\Response;
use Phayne\OpenAPI\Specification\Responses;
use Phayne\OpenAPI\Specification\SecurityRequirements;
use Phayne\OpenAPI\Validator\Message\Exception\NoResponseCode;
use Phayne\OpenAPI\Validator\Message\Exception\Validation\InvalidBody;
use Phayne\OpenAPI\Validator\Message\Exception\Validation\InvalidHeaders;
use Phayne\OpenAPI\Validator\Message\ResponseAddress;
use Phayne\OpenAPI\Validator\Message\SpecFinder;
use Phayne\OpenAPI\Validator\Message\ValidatorBuilder;
use Phayne\OpenAPI\Validator\Message\Validators\BodyValidator\BodyValidator;
use Phayne\OpenAPI\Validator\Message\Validators\BodyValidator\UnipartValidator;
use Phayne\OpenAPI\Validator\Message\Validators\CookiesValidator\CookiesValidator;
use Phayne\OpenAPI\Validator\Message\Validators\HeadersValidator;
use Phayne\OpenAPI\Validator\Message\Validators\PathValidator;
use Phayne\OpenAPI\Validator\Message\Validators\QueryArgumentsValidator;
use Phayne\OpenAPI\Validator\Message\Validators\ValidatorChain;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The Management API's OpenAPI document (`docs/openapi/management-api.yaml`), used as the
 * contract it is: which operation a request is, which permission that operation
 * requires, and whether the request — and, in tests, the response — matches it.
 *
 * The document is the single statement of what each operation needs: the scope named
 * in its `security` requirement is the one enforced, so a route cannot quietly demand
 * something else.
 *
 * Requests are checked against the operation {@see operationFor()} found — headers,
 * cookies, path, query and body — but not against `security`: the bearer token is
 * authenticated, its audience and its scope checked, by {@see ManagementApiMiddleware}
 * before validation runs, which is more than the library's presence check could say.
 *
 * Two parts of the library do not work at the pinned commit, and are not used: its
 * `SecurityValidator` (`SpecFinder::findSecuritySpecs()` expects an array where
 * php-openapi gives a `SecurityRequirements` object), and its `ResponseValidator`
 * (`SpecFinder::findResponseSpec()` calls a `ResponseAddress::responseCode()` method that
 * does not exist). Responses are checked here instead, with the library's own body
 * validator against the response the document describes for the status.
 */
final readonly class ManagementContract
{
    private const string SECURITY_SCHEME = 'managementToken';

    private MessageValidator $requests;

    private SpecFinder $finder;

    public function __construct(private OpenApi $document)
    {
        $this->finder = new SpecFinder($document);
        $this->requests = new ValidatorChain(
            new HeadersValidator($this->finder),
            new CookiesValidator($this->finder),
            new BodyValidator($this->finder),
            new QueryArgumentsValidator($this->finder),
            new PathValidator($this->finder),
        );
    }

    public static function fromFile(string $path): self
    {
        return new self(new ValidatorBuilder()->fromYamlFile($path)->serverRequestValidator()->schema());
    }

    /**
     * The operation `$request` is, when the document describes one: the most specific
     * path wins, `/clients/{client_id}/rotate-secret` over `/clients/{client_id}`.
     */
    public function operationFor(ServerRequestInterface $request): ?OperationAddress
    {
        /** @var list<OperationAddress> $found */
        $found = new PathFinder($this->document, (string) $request->getUri(), $request->getMethod())->search();
        usort(
            $found,
            static fn (OperationAddress $a, OperationAddress $b): int
                => $a->countPlaceholders() <=> $b->countPlaceholders(),
        );

        return $found[0] ?? null;
    }

    /**
     * The permission the operation's `security` requirement names.
     *
     * @throws LogicException When the document names none, or one that is not a Management API
     *                        permission: a contract no token could ever satisfy is a defect.
     */
    public function requiredPermission(OperationAddress $operation): ManagementPermission
    {
        // php-openapi documents `security` as an array; it is a SecurityRequirements object.
        /** @var mixed $security */
        $security = $this->finder->findOperationSpec($operation)->security;
        /** @var list<array<string, list<string>>> $requirements */
        $requirements = $security instanceof SecurityRequirements ? (array) $security->serializableData() : [];
        $scopes = [];
        foreach ($requirements as $requirement) {
            $scopes = [...$scopes, ...($requirement[self::SECURITY_SCHEME] ?? [])];
        }

        if (count($scopes) !== 1) {
            throw new LogicException(sprintf('%s must require exactly one Management API permission.', $operation));
        }

        return ManagementPermission::tryFrom($scopes[0])
            ?? throw new LogicException(
                sprintf("%s requires '%s', which is not a permission.", $operation, $scopes[0]),
            );
    }

    /** Whether the operation takes a request body: a JSON object, as its schema says. */
    public function takesBody(OperationAddress $operation): bool
    {
        return $this->finder->findOperationSpec($operation)->requestBody !== null;
    }

    /**
     * Whether `$request` matches what the document describes for `$operation`: path and
     * query parameters, headers, cookies and body. Not its credentials (see above).
     *
     * @throws ValidationFailed
     */
    public function validateRequest(OperationAddress $operation, ServerRequestInterface $request): void
    {
        $this->requests->validate($operation, $request);
    }

    /**
     * Whether `$response` is one the document describes for `$operation`: its status is
     * listed, and its body — JSON, of the media type listed — matches the schema. A
     * status described without content must come with an empty body.
     *
     * @throws ValidationFailed
     */
    public function validateResponse(OperationAddress $operation, ResponseInterface $response): void
    {
        $status = $response->getStatusCode();
        $address = new ResponseAddress($operation->path, $operation->method, $status);
        /** @var mixed $responses */
        $responses = $this->finder->findOperationSpec($operation)->responses;
        $described = $responses instanceof Responses ? $responses->response($status) : null;
        if (! $described instanceof Response) {
            throw NoResponseCode::fromPathAndMethodAndResponseCode($operation->path, $operation->method, $status);
        }

        /** @var array<string, MediaType> $content */
        $content = $described->content;
        if ($content === []) {
            if ((string) $response->getBody() !== '') {
                throw InvalidBody::fromAddr($address);
            }

            return;
        }

        $mediaType = strtolower(trim(explode(';', $response->getHeaderLine('Content-Type'))[0]));
        if (! isset($content[$mediaType])) {
            throw InvalidHeaders::fromAddr($address);
        }

        new UnipartValidator($content[$mediaType], $mediaType)->validate($address, $response);
    }

    /**
     * Every operation the document describes.
     *
     * @return list<OperationAddress>
     */
    public function operations(): array
    {
        $operations = [];
        /** @var iterable<string, PathItem> $paths */
        $paths = $this->document->paths;
        foreach ($paths as $pattern => $path) {
            /** @var array<string, mixed> $byMethod */
            $byMethod = $path->operations();
            foreach (array_keys($byMethod) as $method) {
                $operations[] = new OperationAddress($pattern, $method);
            }
        }

        return $operations;
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
            fn (OperationAddress $operation): string => $this->requiredPermission($operation)->value,
            $this->operations(),
        )));
    }
}
