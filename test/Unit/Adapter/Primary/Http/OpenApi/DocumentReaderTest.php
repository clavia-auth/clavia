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
use Clavia\Adapter\Primary\Http\OpenApi\InvalidDocument;
use Clavia\Adapter\Primary\Http\OpenApi\ParameterLocation;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * Loading an OpenAPI document: what it becomes, and everything it is refused for —
 * always with the place in the document.
 */
final class DocumentReaderTest extends TestCase
{
    public function testOperationsAreReadWithTheirParametersBodiesResponsesAndSecurity(): void
    {
        $document = Document::fromJson(self::document([
            'security' => [['token' => ['read']]],
            'paths' => [
                '/items/{id}' => [
                    'parameters' => [self::pathParameter('id')],
                    'get' => [
                        'operationId' => 'getItem',
                        'parameters' => [['name' => 'X-Trace', 'in' => 'header', 'schema' => ['type' => 'string']]],
                        'responses' => ['200' => ['description' => 'ok']],
                    ],
                    'put' => [
                        'security' => [],
                        'requestBody' => [
                            'required' => true,
                            'content' => ['application/json' => ['schema' => ['type' => 'object']]],
                        ],
                        'responses' => ['default' => ['description' => 'ok']],
                    ],
                ],
            ],
        ]));

        $operations = $document->operations();
        self::assertCount(2, $operations);
        $get = $operations[0];
        $put = $operations[1] ?? self::fail('No PUT.');
        self::assertSame('GET /items/{id}', (string) $get);
        self::assertSame('getItem', $get->operationId);
        self::assertSame(['path:id', 'header:x-trace'], array_keys($get->parameters));
        self::assertSame(ParameterLocation::Header, $get->parameters['header:x-trace']->location);
        // The document's security applies where the operation states none…
        self::assertSame(['read'], $get->security[0]->scopesFor('token'));
        // …and `security: []` means none at all.
        self::assertSame([], $put->security);
        self::assertTrue($put->requestBody?->required);
        self::assertNotNull($put->responses->for(500));
        self::assertNull($get->responses->for(404));
    }

    public function testHeadersTheSpecificationSaysToIgnoreAreIgnored(): void
    {
        $document = Document::fromJson(self::document(['paths' => ['/a' => ['get' => [
            'parameters' => [['name' => 'Authorization', 'in' => 'header', 'schema' => ['type' => 'string']]],
            'responses' => ['200' => ['description' => 'ok']],
        ]]]]));

        self::assertSame([], $document->operations()[0]->parameters);
    }

    public function testExtensionsAreAllowedAnywhere(): void
    {
        $document = Document::fromJson(self::document([
            'x-owner' => 'team',
            'paths' => ['/a' => ['get' => [
                'x-rate-limit' => 5,
                'responses' => ['200' => ['description' => 'ok', 'x-note' => 'y']],
            ]]],
        ]));

        self::assertCount(1, $document->operations());
    }

    /**
     * @param array<string, mixed> $overrides
     */
    #[DataProvider('refused')]
    public function testADocumentThisValidatorCannotEnforceIsRefused(array $overrides, string $expected): void
    {
        $this->expectException(InvalidDocument::class);
        $this->expectExceptionMessage($expected);

        Document::fromJson(self::document($overrides));
    }

    /** @return iterable<string, array{array<string, mixed>, string}> */
    public static function refused(): iterable
    {
        yield 'OpenAPI 3.1' => [['openapi' => '3.1.0'], "#/openapi: is '3.1.0': only OpenAPI 3.0.x is supported"];
        yield 'an unknown top-level member' => [['webhooks' => []], '#/webhooks: is not supported here'];
        yield 'a misspelt schema keyword' => [
            self::withSchema(['type' => 'string', 'minLenght' => 3]),
            '#/components/schemas/Probe/minLenght: is not supported here',
        ];
        yield 'a 3.1 exclusive minimum' => [
            self::withSchema(['minimum' => 1, 'exclusiveMinimum' => 1]),
            'must be a boolean in OpenAPI 3.0',
        ];
        yield 'an array without items' => [self::withSchema(['type' => 'array']), "is an array without 'items'"];
        yield 'a type list' => [self::withSchema(['type' => ['string', 'null']]), 'must be a string'];
        yield 'bounds no value satisfies' => [
            self::withSchema(['minLength' => 5, 'maxLength' => 2]),
            'is greater than its maximum',
        ];
        yield 'a pattern PCRE cannot compile' => [self::withSchema(['pattern' => '(']), 'is not a regular expression'];
        yield 'readOnly and writeOnly' => [
            self::withSchema(['readOnly' => true, 'writeOnly' => true]),
            'cannot be both readOnly and writeOnly',
        ];
        yield 'a reference outside the document' => [
            self::withSchema(['$ref' => 'common.yaml#/User']),
            'refers outside the document',
        ];
        yield 'a reference to nothing' => [
            self::withSchema(['$ref' => '#/components/schemas/Missing']),
            "refers to '#/components/schemas/Missing', which does not exist",
        ];
        yield 'a reference with a sibling' => [
            self::withSchema(['$ref' => '#/components/schemas/A', 'description' => 'x']),
            'cannot sit beside $ref',
        ];
        yield 'references that loop' => [
            ['components' => ['schemas' => [
                'A' => ['$ref' => '#/components/schemas/B'],
                'B' => ['$ref' => '#/components/schemas/A'],
            ]]],
            'is a circular reference',
        ];
        yield 'a path parameter the template does not hold' => [
            ['paths' => ['/a' => ['get' => [
                'parameters' => [self::pathParameter('id')],
                'responses' => ['200' => ['description' => 'ok']],
            ]]]],
            "is the path parameter 'id', which the template does not hold",
        ];
        yield 'a template parameter left undescribed' => [
            ['paths' => ['/a/{id}' => ['get' => ['responses' => ['200' => ['description' => 'ok']]]]]],
            "does not describe the path parameter 'id'",
        ];
        yield 'an optional path parameter' => [
            ['paths' => ['/a/{id}' => ['get' => [
                'parameters' => [['name' => 'id', 'in' => 'path', 'schema' => ['type' => 'string']]],
                'responses' => ['200' => ['description' => 'ok']],
            ]]]],
            'must be required: true',
        ];
        yield 'a template that is not one' => [
            ['paths' => ['/a/{' => ['get' => ['responses' => ['200' => ['description' => 'ok']]]]]],
            'is not a path template',
        ];
        yield 'an unsupported style' => [
            self::withQuery([
                'name' => 'f',
                'in' => 'query',
                'style' => 'deepObject',
                'schema' => ['type' => 'string'],
            ]),
            "is 'deepObject', which is not supported for a query parameter",
        ];
        yield 'an object parameter' => [
            self::withQuery(['name' => 'f', 'in' => 'query', 'schema' => ['type' => 'object']]),
            'describes an object parameter',
        ];
        yield 'a parameter described by content' => [
            self::withQuery(['name' => 'f', 'in' => 'query', 'content' => ['application/json' => []]]),
            'describe the parameter with a schema',
        ];
        yield 'a body that is not JSON' => [
            ['paths' => ['/a' => ['post' => [
                'requestBody' => ['content' => ['application/xml' => ['schema' => ['type' => 'object']]]],
                'responses' => ['200' => ['description' => 'ok']],
            ]]]],
            'is not a JSON media type',
        ];
        yield 'an operation without responses' => [
            ['paths' => ['/a' => ['get' => ['responses' => new stdClass()]]]],
            'must describe at least one response',
        ];
        yield 'a status that is not one' => [
            ['paths' => ['/a' => ['get' => ['responses' => ['20' => ['description' => 'ok']]]]]],
            'is not a status code',
        ];
        yield 'an operationId used twice' => [
            ['paths' => [
                '/a' => ['get' => ['operationId' => 'x', 'responses' => ['200' => ['description' => 'ok']]]],
                '/b' => ['get' => ['operationId' => 'x', 'responses' => ['200' => ['description' => 'ok']]]],
            ]],
            "repeats 'x', already used at #/paths/~1a/get",
        ];
        yield 'an undeclared security scheme' => [
            ['security' => [['nobody' => []]]],
            "names the security scheme 'nobody'",
        ];
        yield 'an undeclared scope' => [['security' => [['token' => ['write']]]], "is not a scope 'token' declares"];
        yield 'server variables' => [['servers' => [['url' => 'https://{region}.example/']]], 'uses server variables'];
    }

    public function testTheMessageNamesThePlaceInTheDocument(): void
    {
        try {
            Document::fromJson(self::document(self::withSchema(['type' => 'stringg'])));
            self::fail('The document loaded.');
        } catch (InvalidDocument $refusal) {
            self::assertStringStartsWith('#/components/schemas/Probe/type: must be one of', $refusal->getMessage());
        }
    }

    public function testYamlThatDoesNotParseIsRefused(): void
    {
        $this->expectException(InvalidDocument::class);
        $this->expectExceptionMessage('not valid YAML');

        Document::fromYaml("openapi: [unclosed\n");
    }

    public function testTheManagementApiDocumentLoads(): void
    {
        $document = Document::fromYamlFile(__DIR__ . '/../../../../../../docs/openapi/management-api.yaml');

        self::assertCount(17, $document->operations());
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private static function document(array $overrides): string
    {
        $document = $overrides + [
            'openapi' => '3.0.3',
            'info' => ['title' => 'Test', 'version' => '1'],
            'paths' => new stdClass(),
            'components' => ['securitySchemes' => ['token' => [
                'type' => 'oauth2',
                'flows' => ['clientCredentials' => ['tokenUrl' => '/token', 'scopes' => ['read' => 'Read']]],
            ]]],
        ];

        return json_encode($document, JSON_THROW_ON_ERROR);
    }

    /**
     * @param array<string, mixed> $schema
     *
     * @return array<string, mixed>
     */
    private static function withSchema(array $schema): array
    {
        return ['components' => ['schemas' => ['A' => ['type' => 'string'], 'Probe' => $schema]]];
    }

    /**
     * @param array<string, mixed> $parameter
     *
     * @return array<string, mixed>
     */
    private static function withQuery(array $parameter): array
    {
        return ['paths' => ['/a' => ['get' => [
            'parameters' => [$parameter],
            'responses' => ['200' => ['description' => 'ok']],
        ]]]];
    }

    /**
     * @return array<string, mixed>
     */
    private static function pathParameter(string $name): array
    {
        return ['name' => $name, 'in' => 'path', 'required' => true, 'schema' => ['type' => 'string']];
    }
}
