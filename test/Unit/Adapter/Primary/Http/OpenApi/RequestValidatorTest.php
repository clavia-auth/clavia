<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Http\OpenApi;

use Clavia\Adapter\Primary\Http\OpenApi\Document;
use Clavia\Adapter\Primary\Http\OpenApi\ParameterLocation;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\MalformedRequest;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\OperationNotFound;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\RequestDoesNotMatch;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\RequestRejected;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\RequestValidator;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\UnsupportedMediaType;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\Violation;
use Fig\Http\Message\RequestMethodInterface;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * A PSR-7 request against the operation it is: routed, read, decoded, validated.
 */
final class RequestValidatorTest extends TestCase
{
    private static ?RequestValidator $validator = null;

    private const string DOCUMENT = <<<'YAML'
        openapi: 3.0.3
        info: {title: Test, version: '1'}
        servers: [{url: 'https://api.example/v2'}]
        paths:
          /items:
            get:
              parameters:
                - {name: limit, in: query, schema: {type: integer, minimum: 1}}
                - {name: tag, in: query, schema: {type: array, items: {type: string}}}
                - {name: ids, in: query, explode: false, schema: {type: array, items: {type: integer}}}
                - {name: active, in: query, schema: {type: boolean}}
                - {name: X-Tenant, in: header, required: true, schema: {type: string, minLength: 2}}
              responses: {'200': {description: ok}}
            post:
              requestBody:
                required: true
                content:
                  application/json:
                    schema:
                      type: object
                      required: [name]
                      additionalProperties: false
                      properties:
                        name: {type: string}
                        id: {type: string, readOnly: true}
              responses: {'201': {description: created}}
          /items/{id}:
            parameters:
              - {name: id, in: path, required: true, schema: {type: integer}}
            get:
              responses: {'200': {description: ok}}
            delete:
              responses: {'204': {description: deleted}}
          /items/latest:
            get:
              responses: {'200': {description: ok}}
          /token:
            post:
              requestBody:
                required: true
                content:
                  application/x-www-form-urlencoded:
                    schema:
                      oneOf:
                        - type: object
                          required: [grant_type, code]
                          additionalProperties: false
                          properties:
                            grant_type: {type: string, enum: [authorization_code]}
                            code: {type: string, minLength: 1}
                            redirect_uri: {type: string}
                        - type: object
                          required: [grant_type]
                          additionalProperties: false
                          properties:
                            grant_type: {type: string, enum: [client_credentials]}
                            scope: {type: string}
              responses: {'200': {description: ok}}
          /imports:
            post:
              requestBody:
                required: true
                content:
                  application/x-ndjson:
                    schema: {type: string, format: binary}
              responses: {'202': {description: queued}}
        YAML;

    public function testAnOpaqueBodyComesBackAsItsBytes(): void
    {
        // NDJSON is not JSON: the operation reads it line by line, and the validator leaves it whole.
        $lines = "{\"email\":\"ada@example.com\"}\nnot json at all\n";

        $validated = self::validator()->validate(
            self::request(RequestMethodInterface::METHOD_POST, '/v2/imports', $lines, 'application/x-ndjson'),
        );

        self::assertSame($lines, $validated->body);
        self::assertTrue($validated->hasBody);
    }

    public function testAFormComesBackAsAnObjectOfStrings(): void
    {
        $form = 'grant_type=authorization_code&code=a%2Bb+c&redirect_uri=https%3A%2F%2Fapp.example%2Fcb';

        $validated = self::validator()->validate(
            self::request(RequestMethodInterface::METHOD_POST, '/v2/token', $form, 'application/x-www-form-urlencoded'),
        );

        self::assertEquals((object) [
            'grant_type' => 'authorization_code',
            'code' => 'a+b c',
            'redirect_uri' => 'https://app.example/cb',
        ], $validated->body);
    }

    public function testAFormIsHeldToTheAlternativeItsFieldsMatch(): void
    {
        $refused = [
            'grant_type=authorization_code' => 'a code request without its code',
            'grant_type=client_credentials&code=x' => 'a field the alternative does not take',
            'grant_type=password&username=ada' => 'a grant no alternative describes',
        ];
        foreach ($refused as $form => $case) {
            try {
                self::validator()->validate(
                    self::request(
                        RequestMethodInterface::METHOD_POST,
                        '/v2/token',
                        $form,
                        'application/x-www-form-urlencoded',
                    ),
                );
                self::fail($case . ' was accepted.');
            } catch (RequestDoesNotMatch $mismatch) {
                self::assertNotEmpty($mismatch->violations, $case);
            }
        }

        $machine = self::validator()->validate(self::request(
            RequestMethodInterface::METHOD_POST,
            '/v2/token',
            'grant_type=client_credentials&scope=read%3Areports',
            'application/x-www-form-urlencoded; charset=utf-8',
        ));
        self::assertEquals((object) ['grant_type' => 'client_credentials', 'scope' => 'read:reports'], $machine->body);
    }

    /** RFC 6749 §3.1: a parameter sent twice is refused, never "the last one wins". */
    public function testAFormFieldSentTwiceIsMalformed(): void
    {
        try {
            self::validator()->validate(self::request(
                RequestMethodInterface::METHOD_POST,
                '/v2/token',
                'grant_type=client_credentials&scope=a&scope=b',
                'application/x-www-form-urlencoded',
            ));
            self::fail('A repeated field was accepted.');
        } catch (MalformedRequest $malformed) {
            self::assertEquals([Violation::inBody('/scope', 'Is sent more than once.')], $malformed->violations);
        }
    }

    public function testAFormIsUtf8(): void
    {
        $this->expectException(UnsupportedMediaType::class);

        self::validator()->validate(self::request(
            RequestMethodInterface::METHOD_POST,
            '/v2/token',
            'grant_type=client_credentials',
            'application/x-www-form-urlencoded; charset=iso-8859-1',
        ));
    }

    public function testJsonIsNoForm(): void
    {
        $this->expectException(UnsupportedMediaType::class);

        self::validator()->validate(
            self::request(RequestMethodInterface::METHOD_POST, '/v2/token', '{"grant_type":"client_credentials"}'),
        );
    }

    public function testAnOpaqueBodyOfAnotherMediaTypeIsUnsupported(): void
    {
        $this->expectException(UnsupportedMediaType::class);

        self::validator()->validate(
            self::request(RequestMethodInterface::METHOD_POST, '/v2/imports', '{"email":"a@example.com"}'),
        );
    }

    public function testAValidRequestComesBackDecoded(): void
    {
        $validated = self::validator()->validate(
            self::request(
                RequestMethodInterface::METHOD_GET,
                '/v2/items?limit=10&tag=a&tag=b&ids=1,2&active=true',
                headers: ['X-Tenant' => 'acme'],
            ),
        );

        self::assertSame('GET /items', (string) $validated->operation);
        self::assertSame(10, $validated->parameter(ParameterLocation::Query, 'limit'));
        self::assertSame(['a', 'b'], $validated->parameter(ParameterLocation::Query, 'tag'));
        self::assertSame([1, 2], $validated->parameter(ParameterLocation::Query, 'ids'));
        self::assertTrue($validated->parameter(ParameterLocation::Query, 'active'));
        self::assertSame('acme', $validated->parameter(ParameterLocation::Header, 'x-tenant'));
        self::assertFalse($validated->has(ParameterLocation::Query, 'unsent'));
        self::assertFalse($validated->hasBody);
    }

    public function testAConcretePathWinsOverATemplatedOne(): void
    {
        $latest = self::validator()->validate(self::request(RequestMethodInterface::METHOD_GET, '/v2/items/latest'));
        self::assertSame('GET /items/latest', (string) $latest->operation);

        $byId = self::validator()->validate(self::request(RequestMethodInterface::METHOD_GET, '/v2/items/42'));
        self::assertSame('GET /items/{id}', (string) $byId->operation);
        self::assertSame(42, $byId->parameter(ParameterLocation::Path, 'id'));
    }

    public function testAPathOutsideTheServerOrWithAnotherMethodIsNoOperation(): void
    {
        $requests = [
            [RequestMethodInterface::METHOD_GET, '/items'],
            [RequestMethodInterface::METHOD_GET, '/v2/items/'],
            [RequestMethodInterface::METHOD_HEAD, '/v2/items'],
            ['get', '/v2/items'],
            [RequestMethodInterface::METHOD_PUT, '/v2/items/1'],
        ];
        foreach ($requests as [$method, $path]) {
            try {
                self::validator()->validate(self::request($method, $path));
                self::fail(sprintf('%s %s was matched.', $method, $path));
            } catch (OperationNotFound $missing) {
                $known = [RequestMethodInterface::METHOD_PUT, RequestMethodInterface::METHOD_HEAD, 'get'];
                self::assertSame(in_array($method, $known, true), $missing->pathIsKnown);
            }
        }
    }

    public function testEveryParameterViolationIsReported(): void
    {
        $violations = self::rejected(
            self::request(
                RequestMethodInterface::METHOD_GET,
                '/v2/items?limit=0&active=yes&sort=name',
                headers: ['X-Tenant' => 'a'],
            ),
            RequestDoesNotMatch::class,
        );

        self::assertSame([
            'query sort: Is not a parameter of this operation.',
            'query limit: Must be greater than or equal to 1.',
            'query active: Must be a boolean.',
            'header x-tenant: Must be at least 2 characters long.',
        ], $violations);
    }

    public function testARequiredParameterMustBeSent(): void
    {
        self::assertSame(
            ['header x-tenant: Is required.'],
            self::rejected(self::request(RequestMethodInterface::METHOD_GET, '/v2/items'), RequestDoesNotMatch::class),
        );
    }

    public function testCoercionIsExact(): void
    {
        foreach (['02', '1e3', ' 1', '1.0', '9223372036854775808'] as $notAnInteger) {
            self::assertSame(
                ['query limit: Must be an integer.'],
                self::rejected(
                    self::request(
                        RequestMethodInterface::METHOD_GET,
                        '/v2/items?limit=' . rawurlencode($notAnInteger),
                        headers: ['X-Tenant' => 'acme'],
                    ),
                    RequestDoesNotMatch::class,
                ),
                $notAnInteger,
            );
        }
    }

    public function testASingleValueSentTwiceCannotBeRead(): void
    {
        self::assertSame(
            ['query limit: Is sent more than once.'],
            self::rejected(
                self::request(
                    RequestMethodInterface::METHOD_GET,
                    '/v2/items?limit=1&limit=2',
                    headers: ['X-Tenant' => 'acme'],
                ),
                MalformedRequest::class,
            ),
        );
    }

    public function testAPathValueThatIsNotUtf8CannotBeRead(): void
    {
        self::assertSame(
            ['path id: Is not valid UTF-8.'],
            self::rejected(self::request(RequestMethodInterface::METHOD_GET, '/v2/items/%FF'), MalformedRequest::class),
        );
    }

    public function testTheBodyIsParsedAndValidated(): void
    {
        $validated = self::validator()->validate(
            self::request(RequestMethodInterface::METHOD_POST, '/v2/items', '{"name":"a"}'),
        );
        self::assertTrue($validated->hasBody);
        self::assertInstanceOf(stdClass::class, $validated->body);

        self::assertSame(
            ['body /name: Is required.', 'body /id: Is read-only: it cannot be sent.', 'body /x: Is not allowed.'],
            self::rejected(
                self::request(RequestMethodInterface::METHOD_POST, '/v2/items', '{"id":"1","x":2}'),
                RequestDoesNotMatch::class,
            ),
        );
    }

    public function testABodyIsRequiredWhereTheOperationSaysSo(): void
    {
        self::assertSame(
            ['body: A body is required.'],
            self::rejected(self::request(RequestMethodInterface::METHOD_POST, '/v2/items'), RequestDoesNotMatch::class),
        );
    }

    public function testABodyWhereNoneIsTakenIsRefused(): void
    {
        self::assertSame(
            ['body: This operation takes no body.'],
            self::rejected(
                self::request(RequestMethodInterface::METHOD_DELETE, '/v2/items/1', '{}'),
                RequestDoesNotMatch::class,
            ),
        );
    }

    public function testJsonThatDoesNotParseCannotBeRead(): void
    {
        self::assertSame(
            ['body: Is not valid JSON.'],
            self::rejected(
                self::request(RequestMethodInterface::METHOD_POST, '/v2/items', '{"name":'),
                MalformedRequest::class,
            ),
        );
    }

    public function testTheMediaTypeMustBeOneTheOperationTakes(): void
    {
        $refused = [
            ['name=a', 'application/x-www-form-urlencoded'],
            ['{"name":"a"}', ''],
            ['{"name":"a"}', 'application/json; charset=iso-8859-1'],
        ];
        foreach ($refused as [$body, $contentType]) {
            self::rejected(
                self::request(RequestMethodInterface::METHOD_POST, '/v2/items', $body, $contentType),
                UnsupportedMediaType::class,
            );
        }

        // Parameters are allowed, and the type is case-insensitive.
        $accepted = self::validator()->validate(
            self::request(
                RequestMethodInterface::METHOD_POST,
                '/v2/items',
                '{"name":"a"}',
                'Application/JSON; charset=UTF-8',
            ),
        );
        self::assertTrue($accepted->hasBody);
    }

    /**
     * @param class-string<RequestRejected> $expected
     *
     * @return list<string>
     */
    private static function rejected(ServerRequest $request, string $expected): array
    {
        try {
            self::validator()->validate($request);
        } catch (RequestRejected $rejection) {
            self::assertInstanceOf($expected, $rejection);

            return array_map(
                static fn (Violation $violation): string => $violation->describe(),
                $rejection->violations,
            );
        }

        self::fail('The request was accepted.');
    }

    /**
     * @param array<non-empty-string, string> $headers
     */
    private static function request(
        string $method,
        string $target,
        ?string $body = null,
        string $contentType = 'application/json',
        array $headers = [],
    ): ServerRequest {
        if ($body !== null && $contentType !== '') {
            $headers['Content-Type'] = $contentType;
        }

        return new ServerRequest(
            uri: 'https://api.example' . $target,
            method: $method,
            body: new StreamFactory()->createStream($body ?? ''),
            headers: $headers,
        );
    }

    private static function validator(): RequestValidator
    {
        return self::$validator ??= new RequestValidator(Document::fromYaml(self::DOCUMENT));
    }
}
