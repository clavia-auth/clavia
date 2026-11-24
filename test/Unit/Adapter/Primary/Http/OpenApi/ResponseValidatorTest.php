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
use Clavia\Adapter\Primary\Http\OpenApi\Operation;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\ResponseDoesNotMatch;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\ResponseValidator;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\Violation;
use Fig\Http\Message\StatusCodeInterface;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;
use PHPUnit\Framework\TestCase;

/**
 * A PSR-7 response against what its operation describes.
 */
final class ResponseValidatorTest extends TestCase
{
    private const string DOCUMENT = <<<'YAML'
        openapi: 3.0.3
        info: {title: Test, version: '1'}
        paths:
          /items:
            post:
              responses:
                '201':
                  description: created
                  headers:
                    Location: {required: true, schema: {type: string, pattern: '^/items/'}}
                    X-Count: {schema: {type: integer}}
                  content:
                    application/json:
                      schema:
                        type: object
                        required: [id, secret]
                        properties:
                          id: {type: integer}
                          secret: {type: string, writeOnly: true}
                '4XX':
                  description: refused
                  content:
                    application/problem+json: {schema: {type: object, required: [status]}}
                '204': {description: nothing}
        YAML;

    public function testADescribedResponsePasses(): void
    {
        ResponseValidator::validate(
            self::operation(),
            new JsonResponse(
                ['id' => 1],
                StatusCodeInterface::STATUS_CREATED,
                ['Location' => '/items/1', 'X-Count' => '3'],
            ),
        );
        ResponseValidator::validate(self::operation(), new Response(status: StatusCodeInterface::STATUS_NO_CONTENT));
        ResponseValidator::validate(
            self::operation(),
            new JsonResponse(
                ['status' => StatusCodeInterface::STATUS_CONFLICT],
                StatusCodeInterface::STATUS_CONFLICT,
                ['Content-Type' => 'application/problem+json'],
            ),
        );

        self::assertTrue(true);
    }

    public function testEverythingWrongWithAResponseIsListed(): void
    {
        self::assertSame(
            [
                'header location: Is required.',
                'header x-count: Must be an integer.',
                'body /id: Must be an integer.',
                'body /secret: Is write-only: it must never be returned.',
            ],
            self::mismatches(
                new JsonResponse(
                    ['id' => 'one', 'secret' => 'x'],
                    StatusCodeInterface::STATUS_CREATED,
                    ['X-Count' => 'many'],
                ),
            ),
        );
    }

    public function testAStatusTheOperationDoesNotListFails(): void
    {
        self::assertSame(
            ['status: 500 is not a status this operation describes.'],
            self::mismatches(new Response(status: StatusCodeInterface::STATUS_INTERNAL_SERVER_ERROR)),
        );
    }

    public function testABodyWhereNoneIsDescribedFails(): void
    {
        self::assertSame(
            ['body: Is present where the operation describes no body.'],
            self::mismatches(new JsonResponse(['x' => 1], StatusCodeInterface::STATUS_NO_CONTENT)),
        );
    }

    public function testTheMediaTypeMustBeDescribed(): void
    {
        self::assertSame(
            ['header content-type: Must be application/problem+json.'],
            self::mismatches(
                new JsonResponse(
                    ['status' => StatusCodeInterface::STATUS_NOT_FOUND],
                    StatusCodeInterface::STATUS_NOT_FOUND,
                ),
            ),
        );
    }

    public function testTheMessageNamesTheOperation(): void
    {
        $this->expectException(ResponseDoesNotMatch::class);
        $this->expectExceptionMessageIsOrContains('POST /items answered what the document does not describe');

        ResponseValidator::validate(
            self::operation(),
            new Response(status: StatusCodeInterface::STATUS_INTERNAL_SERVER_ERROR),
        );
    }

    /**
     * @return list<string>
     */
    private static function mismatches(ResponseInterface $response): array
    {
        try {
            ResponseValidator::validate(self::operation(), $response);
        } catch (ResponseDoesNotMatch $mismatch) {
            return array_map(static fn (Violation $violation): string => $violation->describe(), $mismatch->violations);
        }

        self::fail('The response passed.');
    }

    private static function operation(): Operation
    {
        return Document::fromYaml(self::DOCUMENT)->operations()[0];
    }
}
