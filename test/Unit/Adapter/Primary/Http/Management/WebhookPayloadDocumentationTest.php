<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Http\Management;

use Clavia\Adapter\Primary\Http\OpenApi\Node;
use Clavia\Adapter\Primary\Http\OpenApi\References;
use Clavia\Adapter\Primary\Http\OpenApi\Schema\Direction;
use Clavia\Adapter\Primary\Http\OpenApi\Schema\SchemaCompiler;
use Clavia\Adapter\Primary\Http\OpenApi\Schema\SchemaValidator;
use Clavia\Adapter\Primary\Http\OpenApi\Schema\SchemaViolation;
use Clavia\Domain\Webhook\StandardWebhookSignature;
use Clavia\Domain\Webhook\WebhookSecret;
use PHPUnit\Framework\TestCase;
use stdClass;
use Symfony\Component\Yaml\Yaml;

/**
 * What the Management API document tells receivers (`WebhookPayload`, docs/design/webhooks.md §6)
 * holds: its example is a payload, and the signature it quotes verifies with the example secret.
 * No operation carries the payload (OpenAPI 3.0 has no webhooks), so no other test reads it.
 */
final class WebhookPayloadDocumentationTest extends TestCase
{
    private const string PATH = __DIR__ . '/../../../../../../docs/openapi/management-api.yaml';

    public function testTheExampleIsAPayload(): void
    {
        $root = Node::root((object) [
            'schema' => (object) ['$ref' => '#/components/schemas/WebhookPayload'],
            'components' => self::document()->components,
        ]);
        $compiler = new SchemaCompiler(new References($root));
        $schema = $compiler->compile($root->member('schema'));
        $compiler->finish();

        self::assertSame([], array_map(
            static fn (SchemaViolation $violation): string => $violation->pointer . ': ' . $violation->message,
            SchemaValidator::validate(self::example(), $schema, Direction::Response),
        ));
    }

    public function testTheSignatureItQuotesVerifies(): void
    {
        $description = self::text('schemas', 'WebhookPayload', 'description');
        $secret = self::text('examples', 'WebhookWithSecret', 'value', 'secret');
        self::assertSame(1, preg_match('/webhook-id: ([0-9a-f-]+)`/', $description, $id));
        self::assertSame(1, preg_match('/webhook-timestamp: (\d+)`/', $description, $timestamp));
        self::assertSame(1, preg_match('/webhook-signature: (v1,[A-Za-z0-9+\/=]+)`/', $description, $signature));
        $body = json_encode(self::example(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);

        self::assertSame(
            $signature[1],
            StandardWebhookSignature::header($id[1], (int) $timestamp[1], $body, [WebhookSecret::unsealed($secret)]),
        );
        self::assertSame($id[1], self::text('schemas', 'WebhookPayload', 'example', 'data', 'id'), 'The event id.');
    }

    private static function example(): stdClass
    {
        $example = self::at('schemas', 'WebhookPayload', 'example');
        self::assertInstanceOf(stdClass::class, $example);

        return $example;
    }

    /** @return non-empty-string */
    private static function text(string ...$path): string
    {
        $value = self::at(...$path);
        self::assertIsString($value);

        return $value !== '' ? $value : self::fail('An empty string in the document.');
    }

    /** What is at `$path` under `components`. */
    private static function at(string ...$path): mixed
    {
        /** @var mixed $node */
        $node = self::document()->components;
        foreach ($path as $key) {
            self::assertInstanceOf(stdClass::class, $node, $key);
            self::assertTrue(property_exists($node, $key), $key);
            /** @var mixed $node */
            $node = $node->{$key};
        }

        return $node;
    }

    /** @return stdClass&object{components: stdClass} */
    private static function document(): stdClass
    {
        /** @var stdClass&object{components: stdClass} */
        return json_decode(
            json_encode(Yaml::parseFile(self::PATH, Yaml::PARSE_OBJECT_FOR_MAP), JSON_THROW_ON_ERROR),
            false,
            flags: JSON_THROW_ON_ERROR,
        );
    }
}
