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
use Clavia\Adapter\Primary\Http\OpenApi\Validation\RequestRejected;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\ResponseDoesNotMatch;
use Clavia\Application\Management\ManagementPermission;
use Clavia\Bootstrap\Container\ManagementContractFactory;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\TestCase;
use stdClass;

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
        $operation = self::contract()->operationFor(self::request('POST', '/api/v1/clients/abc/rotate-secret'));

        self::assertNotNull($operation);
        self::assertSame('POST /api/v1/clients/{client_id}/rotate-secret', (string) $operation);
        self::assertSame(ManagementPermission::UpdateClients, self::contract()->requiredPermission($operation));
    }

    public function testAPathOrMethodTheDocumentDoesNotDescribeIsNoOperation(): void
    {
        self::assertNull(self::contract()->operationFor(self::request('GET', '/api/v1/connections')));
        self::assertNull(self::contract()->operationFor(self::request('PUT', '/api/v1/users')));
        self::assertNull(
            self::contract()->operationFor(self::request('DELETE', '/api/v1/roles/rol_aaaaaaaaaaaaaaaa/users')),
        );
        self::assertNull(self::contract()->operationFor(self::request('HEAD', '/api/v1/users')));
    }

    public function testOnlyCreationsAndUpdatesTakeABody(): void
    {
        // A DELETE never does: OpenAPI 3.0 gives a body on it no meaning, so taking a role
        // from somebody names them in the path.
        foreach (self::contract()->operations() as $operation) {
            self::assertSame(
                in_array($operation->method, ['POST', 'PATCH', 'PUT'], true)
                    && ! str_ends_with($operation->path->template, 'rotate-secret'),
                $operation->requestBody !== null,
                (string) $operation,
            );
        }
    }

    public function testAValidRequestComesBackDecoded(): void
    {
        $validated = self::contract()->validateRequest(
            self::request('POST', '/api/v1/users', '{"email":"a@b.test","password":"long-enough"}'),
        );

        self::assertTrue($validated->hasBody);
        self::assertInstanceOf(stdClass::class, $validated->body);
        self::assertSame('a@b.test', $validated->body->email);
    }

    public function testAViolationInTheBodyPointsAtItWithoutRepeatingTheValue(): void
    {
        $problem = self::problem(self::request(
            'POST',
            '/api/v1/resource-servers',
            '{"identifier":"https://x.test/","permissions":[{"value":"has space"}]}',
        ));

        self::assertSame(422, $problem->status);
        self::assertSame('/permissions/0/value', $problem->errors[0]['pointer'] ?? null);
        self::assertStringNotContainsString('has space', $problem->errors[0]['detail']);
    }

    public function testAViolationInTheQueryNamesTheParameter(): void
    {
        $problem = self::problem(self::request('GET', '/api/v1/users?page=0'));

        self::assertSame(422, $problem->status);
        self::assertSame(
            [['parameter' => 'page', 'detail' => 'Must be greater than or equal to 1.']],
            $problem->errors,
        );
    }

    public function testAnUnknownMemberIsReportedWhereItIs(): void
    {
        $problem = self::problem(self::request(
            'PATCH',
            '/api/v1/users/6f1c8a52-1b1e-4c8e-9d38-0f2b3d7c9e10',
            '{"a/b~c":1}',
        ));

        self::assertSame([['pointer' => '/a~1b~0c', 'detail' => 'Is not allowed.']], $problem->errors);
    }

    public function testUnreadableRequestsAreBadRequestsAndOtherMediaTypesUnsupported(): void
    {
        self::assertSame(400, self::problem(self::request('POST', '/api/v1/users', '{"email":'))->status);
        self::assertSame(400, self::problem(self::request('GET', '/api/v1/users?page=1&page=2'))->status);
        self::assertSame(
            415,
            self::problem(self::request('POST', '/api/v1/users', 'email=a', 'application/x-www-form-urlencoded'))
                ->status,
        );
    }

    public function testAResponseMustBeOneTheOperationDescribes(): void
    {
        $delete = self::contract()->operationFor(
            self::request('DELETE', '/api/v1/users/6f1c8a52-1b1e-4c8e-9d38-0f2b3d7c9e10'),
        );
        self::assertNotNull($delete);
        self::contract()->validateResponse($delete, new Response(status: 204));

        $responses = [
            // A status the operation does not list.
            new Response(status: 200),
            // A body where the status has none.
            new JsonResponse(['deleted' => true], 204),
            // The wrong media type for a problem.
            new JsonResponse(['type' => 'about:blank', 'title' => 'Not Found', 'status' => 404, 'detail' => 'x'], 404),
        ];
        foreach ($responses as $response) {
            try {
                self::contract()->validateResponse($delete, $response);
                self::fail('A response the contract does not describe passed.');
            } catch (ResponseDoesNotMatch $mismatch) {
                self::assertNotSame([], $mismatch->violations);
            }
        }
    }

    private static function problem(ServerRequest $request): Problem
    {
        try {
            self::contract()->validateRequest($request);
        } catch (RequestRejected $rejection) {
            return ContractViolation::problem($rejection);
        }

        self::fail('The request was valid.');
    }

    private static function request(
        string $method,
        string $target,
        ?string $body = null,
        string $contentType = 'application/json',
    ): ServerRequest {
        return new ServerRequest(
            uri: 'https://management.clavia.test' . $target,
            method: $method,
            body: new StreamFactory()->createStream($body ?? ''),
            headers: $body === null ? [] : ['Content-Type' => $contentType],
        );
    }

    private static function contract(): ManagementContract
    {
        return self::$contract ??= new ManagementContractFactory()();
    }
}
