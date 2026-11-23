<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Http\Management;

use Clavia\Adapter\Primary\Http\OpenApi\Content;
use Clavia\Adapter\Primary\Http\OpenApi\Document;
use Clavia\Adapter\Primary\Http\OpenApi\MediaType;
use Clavia\Adapter\Primary\Http\OpenApi\Schema\Direction;
use Clavia\Adapter\Primary\Http\OpenApi\Schema\SchemaValidator;
use Clavia\Adapter\Primary\Http\OpenApi\Schema\SchemaViolation;
use PHPUnit\Framework\TestCase;
use stdClass;
use Symfony\Component\Yaml\Yaml;

/**
 * The examples of `docs/openapi/management-api.yaml`, held to the contract they illustrate: every
 * one is validated against its schema by Clavia's own validator, in its direction, so an example
 * cannot drift from what the API takes and answers. And the reference has one wherever a reader
 * looks for one: each request body, each success response, each shared refusal.
 */
final class ManagementExamplesTest extends TestCase
{
    private const string PATH = __DIR__ . '/../../../../../../docs/openapi/management-api.yaml';
    private const string EXAMPLE_REF = '#/components/examples/';

    private static ?Document $document = null;
    private static ?stdClass $raw = null;

    public function testEveryExampleMatchesItsSchema(): void
    {
        $checked = 0;
        foreach (self::document()->operations() as $operation) {
            $raw = self::operation($operation->method, $operation->path->template);
            if ($operation->requestBody !== null) {
                $checked += self::check(
                    (string) $operation . ' request',
                    self::object(self::member($raw, 'requestBody')),
                    $operation->requestBody->content,
                    Direction::Request,
                );
            }
            foreach (self::children(self::object(self::member($raw, 'responses'))) as $status => $response) {
                $described = $operation->responses->for((int) $status);
                self::assertNotNull($described, (string) $operation . ' ' . $status);
                $checked += self::check(
                    (string) $operation . ' ' . $status,
                    self::resolve($response),
                    $described->content,
                    Direction::Response,
                );
            }
        }

        self::assertGreaterThan(50, $checked, 'Hardly any example was checked.');
    }

    public function testEveryBodyAndSuccessHasAnExample(): void
    {
        foreach (self::document()->operations() as $operation) {
            $raw = self::operation($operation->method, $operation->path->template);
            if ($operation->requestBody !== null) {
                self::assertNotSame(
                    [],
                    self::examplesIn(self::object(self::member($raw, 'requestBody'))),
                    (string) $operation . ' has no request example.',
                );
            }
            foreach (self::children(self::object(self::member($raw, 'responses'))) as $status => $response) {
                $response = self::resolve($response);
                if (! property_exists($response, 'content')) {
                    continue;
                }
                self::assertNotSame(
                    [],
                    self::examplesIn($response),
                    sprintf('%s %s has no example.', (string) $operation, $status),
                );
            }
        }
    }

    public function testEveryNamedExampleIsUsed(): void
    {
        $yaml = (string) file_get_contents(self::PATH);
        foreach (array_keys(self::children(self::object(self::member(self::components(), 'examples')))) as $name) {
            self::assertStringContainsString(
                "'" . self::EXAMPLE_REF . $name . "'",
                $yaml,
                $name . ' is in components/examples, and nowhere else.',
            );
        }
    }

    /**
     * Validate every example of a request body or a response against the schema of its media type.
     *
     * @return int The examples checked.
     */
    private static function check(string $where, stdClass $node, Content $content, Direction $direction): int
    {
        $checked = 0;
        if (! property_exists($node, 'content')) {
            return 0;
        }
        foreach (self::children(self::object($node->content)) as $type => $mediaType) {
            $entry = $content->for(MediaType::parse($type) ?? self::fail('Unreadable ' . $type));
            self::assertNotNull($entry, $where . ' ' . $type);
            if (! $entry[0]->isJson()) {
                // Opaque bytes (NDJSON, say): the example is the text itself.
                /** @var mixed $value */
                foreach (self::values($mediaType) as $name => $value) {
                    self::assertIsString($value, sprintf('%s %s, example %s', $where, $type, $name));
                    ++$checked;
                }
                continue;
            }
            $schema = $entry[1];
            self::assertNotNull($schema, $where . ' ' . $type . ' has no schema.');
            /** @var mixed $value */
            foreach (self::values($mediaType) as $name => $value) {
                $violations = SchemaValidator::validate($value, $schema, $direction);
                self::assertSame([], array_map(
                    static fn (SchemaViolation $violation): string => $violation->pointer . ': ' . $violation->message,
                    $violations,
                ), sprintf('%s %s, example %s', $where, $type, $name));
                ++$checked;
            }
        }

        return $checked;
    }

    /**
     * The examples of a media type, by name, references followed.
     *
     * @return array<string, mixed>
     *
     * @psalm-suppress MixedAssignment An example is any JSON value: what it must be is the schema's to say.
     */
    private static function values(stdClass $mediaType): array
    {
        $values = [];
        if (property_exists($mediaType, 'example')) {
            $values['(inline)'] = $mediaType->example;
        }
        if (property_exists($mediaType, 'examples')) {
            foreach (self::children(self::object($mediaType->examples)) as $name => $example) {
                $example = self::resolve($example);
                self::assertTrue(property_exists($example, 'value'), $name . ' has no value.');
                $values[$name] = $example->value;
            }
        }

        return $values;
    }

    /** @return list<mixed> Every example of every media type of a request body or a response. */
    private static function examplesIn(stdClass $node): array
    {
        $all = [];
        $content = property_exists($node, 'content') ? self::object($node->content) : new stdClass();
        foreach (self::children($content) as $mediaType) {
            $all = [...$all, ...array_values(self::values($mediaType))];
        }

        return $all;
    }

    /** Follow a `$ref` within the document; anything else is itself. */
    private static function resolve(mixed $node): stdClass
    {
        $node = self::object($node);
        if (! property_exists($node, '$ref')) {
            return $node;
        }
        $ref = $node->{'$ref'};
        self::assertIsString($ref);
        self::assertStringStartsWith('#/', $ref);
        $target = self::raw();
        foreach (explode('/', substr($ref, 2)) as $segment) {
            $target = self::object(self::member($target, str_replace(['~1', '~0'], ['/', '~'], $segment)));
        }

        return self::resolve($target);
    }

    private static function operation(string $method, string $path): stdClass
    {
        return self::object(self::member(
            self::object(self::member(self::object(self::member(self::raw(), 'paths')), $path)),
            strtolower($method),
        ));
    }

    private static function components(): stdClass
    {
        return self::object(self::member(self::raw(), 'components'));
    }

    /**
     * The members of a mapping, each a mapping itself (operations, responses, media types, examples).
     *
     * @return array<string, stdClass>
     */
    private static function children(stdClass $node): array
    {
        $children = [];
        /** @var mixed $child */
        foreach (get_object_vars($node) as $name => $child) {
            $children[(string) $name] = self::object($child);
        }

        return $children;
    }

    private static function member(stdClass $node, string $name): mixed
    {
        self::assertTrue(property_exists($node, $name), 'No ' . $name);

        return $node->{$name};
    }

    private static function object(mixed $node): stdClass
    {
        self::assertInstanceOf(stdClass::class, $node);

        return $node;
    }

    private static function document(): Document
    {
        return self::$document ??= Document::fromYamlFile(self::PATH);
    }

    /** The document as JSON would carry it: objects as objects, so an empty `{}` stays one. */
    private static function raw(): stdClass
    {
        if (self::$raw === null) {
            /** @var mixed $parsed */
            $parsed = Yaml::parseFile(self::PATH, Yaml::PARSE_OBJECT_FOR_MAP);
            self::$raw = self::object($parsed);
        }

        return self::$raw;
    }
}
