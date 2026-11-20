<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Http\Management;

use Clavia\Adapter\Primary\Http\Management\ContractViolation;
use Clavia\Adapter\Primary\Http\Management\ManagementContract;
use Clavia\Adapter\Primary\Http\Management\Problem;
use Clavia\Application\Management\ManagementPermission;
use Clavia\Bootstrap\Container\ManagementContractFactory;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\StreamFactory;
use Phayne\OpenAPI\Validator\Message\Exception\ValidationFailed;
use Phayne\OpenAPI\Validator\Message\OperationAddress;
use PHPUnit\Framework\TestCase;

/**
 * `docs/openapi/management-api.yaml`, read as the contract it is.
 */
final class ManagementContractTest extends TestCase
{
    private static ?ManagementContract $contract = null;

    public function testTheDocumentRequiresExactlyTheManagementPermissions(): void
    {
        // Each operation names one; together they are every permission and nothing else,
        // so no scope is granted that no route checks, and no route checks one nobody holds.
        self::assertEqualsCanonicalizing(
            array_map(
                static fn (ManagementPermission $permission): string => $permission->value,
                ManagementPermission::cases(),
            ),
            self::contract()->requiredPermissions(),
        );
    }

    public function testTheMostSpecificPathIsTheOperation(): void
    {
        $operation = self::contract()->operationFor(
            new ServerRequest(uri: 'https://management.clavia.test/api/v1/clients/abc/rotate-secret', method: 'POST'),
        );

        self::assertNotNull($operation);
        self::assertSame('/api/v1/clients/{client_id}/rotate-secret', $operation->path);
        self::assertSame(ManagementPermission::UpdateClients, self::contract()->requiredPermission($operation));
    }

    public function testAPathTheDocumentDoesNotDescribeIsNoOperation(): void
    {
        self::assertNull(self::contract()->operationFor(
            new ServerRequest(uri: 'https://management.clavia.test/api/v1/roles', method: 'GET'),
        ));
    }

    public function testOnlyCreationsAndUpdatesTakeABody(): void
    {
        foreach (self::contract()->operations() as $operation) {
            self::assertSame(
                in_array($operation->method, ['post', 'patch'], true)
                    && ! str_ends_with($operation->path, 'rotate-secret'),
                self::contract()->takesBody($operation),
                (string) $operation,
            );
        }
    }

    public function testARequestIsCheckedAgainstItsOperation(): void
    {
        $valid = self::jsonRequest('POST', '/api/v1/users', '{"email":"a@b.test","password":"long-enough"}');
        self::contract()->validateRequest(new OperationAddress('/api/v1/users', 'post'), $valid);

        $this->expectException(ValidationFailed::class);
        self::contract()->validateRequest(
            new OperationAddress('/api/v1/users', 'post'),
            self::jsonRequest('POST', '/api/v1/users', '{"email":"a@b.test"}'),
        );
    }

    public function testAResponseMustBeOneTheOperationDescribes(): void
    {
        $delete = new OperationAddress('/api/v1/users/{user_id}', 'delete');
        self::contract()->validateResponse($delete, new Response(status: 204));

        foreach (
            [
            // A status the operation does not list.
            new Response(status: 200),
            // A body where the status has none.
            new JsonResponse(['deleted' => true], 204),
            // The wrong media type for a problem.
            new JsonResponse(['type' => 'about:blank', 'title' => 'Not Found', 'status' => 404, 'detail' => 'x'], 404),
            ] as $response
        ) {
            try {
                self::contract()->validateResponse($delete, $response);
                self::fail('A response the contract does not describe passed.');
            } catch (ValidationFailed) {
                self::assertTrue(true);
            }
        }
    }

    public function testAViolationInTheBodyPointsAtItWithoutRepeatingTheValue(): void
    {
        $problem = self::violation(self::jsonRequest(
            'POST',
            '/api/v1/resource-servers',
            '{"identifier":"https://x.test/","permissions":[{"value":"has space"}]}',
        ), '/api/v1/resource-servers', 'post');

        self::assertSame(422, $problem->status);
        self::assertSame('/permissions/0/value', $problem->errors[0]['pointer'] ?? null);
        self::assertStringNotContainsString('has space', $problem->errors[0]['detail']);
    }

    public function testAViolationInTheQueryNamesTheParameter(): void
    {
        $request = new ServerRequest(uri: 'https://management.clavia.test/api/v1/users?page=0', method: 'GET')
            ->withQueryParams(['page' => '0']);

        $problem = self::violation($request, '/api/v1/users', 'get');

        self::assertSame('page', $problem->errors[0]['parameter'] ?? null);
    }

    public function testAnUnknownMemberIsReportedOnTheObjectHoldingIt(): void
    {
        $problem = self::violation(
            self::jsonRequest('PATCH', '/api/v1/users/' . '6f1c8a52-1b1e-4c8e-9d38-0f2b3d7c9e10', '{"a/b~c":1}'),
            '/api/v1/users/{user_id}',
            'patch',
        );

        // An unknown member is reported on the object holding it, and named in the detail.
        self::assertSame('', $problem->errors[0]['pointer'] ?? null);
        self::assertStringContainsString('a/b~c', $problem->errors[0]['detail']);
    }

    private static function violation(ServerRequest $request, string $path, string $method): Problem
    {
        try {
            self::contract()->validateRequest(new OperationAddress($path, $method), $request);
        } catch (ValidationFailed $failure) {
            return ContractViolation::problem($failure);
        }

        self::fail('The request was valid.');
    }

    private static function jsonRequest(string $method, string $path, string $body): ServerRequest
    {
        return new ServerRequest(
            uri: 'https://management.clavia.test' . $path,
            method: $method,
            body: new StreamFactory()->createStream($body),
            headers: ['Content-Type' => 'application/json'],
        );
    }

    private static function contract(): ManagementContract
    {
        return self::$contract ??= new ManagementContractFactory()();
    }
}
