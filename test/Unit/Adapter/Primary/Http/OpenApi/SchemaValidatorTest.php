<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Http\OpenApi;

use Clavia\Adapter\Primary\Http\OpenApi\Node;
use Clavia\Adapter\Primary\Http\OpenApi\References;
use Clavia\Adapter\Primary\Http\OpenApi\Schema\Direction;
use Clavia\Adapter\Primary\Http\OpenApi\Schema\Schema;
use Clavia\Adapter\Primary\Http\OpenApi\Schema\SchemaCompiler;
use Clavia\Adapter\Primary\Http\OpenApi\Schema\SchemaValidator;
use Clavia\Adapter\Primary\Http\OpenApi\Schema\SchemaViolation;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The OpenAPI 3.0 Schema Object, keyword by keyword: what passes, what fails, and what
 * the failure says (where, and never the value).
 */
final class SchemaValidatorTest extends TestCase
{
    /**
     * @param list<string> $expected `pointer: message` per violation; empty when valid.
     */
    #[DataProvider('cases')]
    public function testAnInstanceIsJudgedByItsSchema(string $schema, string $instance, array $expected): void
    {
        self::assertSame($expected, self::violations($schema, $instance));
    }

    /** @return iterable<string, array{string, string, list<string>}> */
    public static function cases(): iterable
    {
        yield 'a string' => ['{"type":"string"}', '"x"', []];
        yield 'not a string' => ['{"type":"string"}', '5', [': Must be a string.']];
        yield 'an integer written as a float' => ['{"type":"integer"}', '3.0', []];
        yield 'not an integer' => ['{"type":"integer"}', '3.5', [': Must be an integer.']];
        yield 'a number' => ['{"type":"number"}', '3.5', []];
        yield 'a boolean is not a number' => ['{"type":"number"}', 'true', [': Must be a number.']];
        yield 'an empty object is an object' => ['{"type":"object"}', '{}', []];
        yield 'an empty list is not an object' => ['{"type":"object"}', '[]', [': Must be an object.']];
        yield 'an empty object is not an array' => [
            '{"type":"array","items":{}}',
            '{}',
            [': Must be an array.'],
        ];
        yield 'null where not nullable' => ['{"type":"string"}', 'null', [': Must be a string, not null.']];
        yield 'null where nullable' => ['{"type":"string","nullable":true,"minLength":3}', 'null', []];
        yield 'null without a type' => ['{}', 'null', []];
        yield 'an enum value' => ['{"enum":["a","b"]}', '"b"', []];
        yield 'not an enum value' => ['{"enum":["a",1]}', '"c"', [': Must be one of "a", 1.']];
        yield 'an enum compares numbers by value' => ['{"enum":[1]}', '1.0', []];
        yield 'too short, in code points' => [
            '{"type":"string","minLength":3}',
            '"éé"',
            [': Must be at least 3 characters long.'],
        ];
        yield 'three code points are three' => ['{"type":"string","minLength":3,"maxLength":3}', '"ééé"', []];
        yield 'too long' => ['{"maxLength":1}', '"ab"', [': Must be at most 1 character long.']];
        yield 'a pattern is unanchored' => ['{"pattern":"b"}', '"abc"', []];
        yield 'a pattern that does not match' => ['{"pattern":"^a$"}', '"b"', [': Must match the pattern ^a$.']];
        yield 'a pattern with a slash' => ['{"pattern":"^a/b$"}', '"a/b"', []];
        yield 'below a minimum' => ['{"minimum":1}', '0', [': Must be greater than or equal to 1.']];
        yield 'at an exclusive minimum' => [
            '{"minimum":1,"exclusiveMinimum":true}',
            '1',
            [': Must be greater than 1.'],
        ];
        yield 'above a maximum' => ['{"maximum":10}', '10.5', [': Must be less than or equal to 10.']];
        yield 'a decimal multiple' => ['{"multipleOf":0.01}', '19.99', []];
        yield 'not a multiple' => ['{"multipleOf":3}', '10', [': Must be a multiple of 3.']];
        yield 'items are checked where they are' => [
            '{"type":"array","items":{"type":"integer"}}',
            '[1,"x",3,null]',
            ['/1: Must be an integer.', '/3: Must be an integer, not null.'],
        ];
        yield 'too few items' => ['{"type":"array","items":{},"minItems":2}', '[1]', [': Must hold at least 2 items.']];
        yield 'duplicated items' => [
            '{"type":"array","items":{},"uniqueItems":true}',
            '[{"a":1,"b":2},{"b":2,"a":1}]',
            [': Must not hold the same item twice.'],
        ];
        yield 'a missing required member is reported where it belongs' => [
            '{"type":"object","required":["email"],"properties":{"email":{"type":"string"}}}',
            '{}',
            ['/email: Is required.'],
        ];
        yield 'an unknown member is reported where it is' => [
            '{"type":"object","additionalProperties":false,"properties":{"a":{}}}',
            '{"a":1,"b/c":2}',
            ['/b~1c: Is not allowed.'],
        ];
        yield 'additional members against a schema' => [
            '{"type":"object","additionalProperties":{"type":"integer"}}',
            '{"a":1,"b":"x"}',
            ['/b: Must be an integer.'],
        ];
        yield 'too few members' => ['{"minProperties":1}', '{}', [': Must hold at least 1 member.']];
        yield 'allOf merges every complaint' => [
            '{"allOf":[{"minLength":5},{"pattern":"^x"}]}',
            '"abc"',
            [': Must be at least 5 characters long.', ': Must match the pattern ^x.'],
        ];
        yield 'anyOf with no match' => [
            '{"anyOf":[{"type":"string"},{"type":"integer"}]}',
            'true',
            [': Must match at least one of the allowed shapes.'],
        ];
        yield 'oneOf with two matches' => [
            '{"oneOf":[{"type":"integer"},{"minimum":0}]}',
            '5',
            [': Must match exactly one of the allowed shapes; it matches 2.'],
        ];
        yield 'not' => ['{"not":{"type":"string"}}', '"x"', [': Must not match the excluded shape.']];
        yield 'a known format' => [
            '{"type":"string","format":"date-time"}',
            '"2026-02-30T10:00:00Z"',
            [': Must be a valid date-time.'],
        ];
        yield 'an unknown format constrains nothing' => ['{"type":"string","format":"colour"}', '"teal"', []];
        yield 'int32 bounds' => ['{"type":"integer","format":"int32"}', '2147483648', [': Must be a valid int32.']];
    }

    public function testEveryViolationIsCollected(): void
    {
        self::assertSame(
            ['/b: Is required.', '/a: Must be a string.', '/c: Is not allowed.'],
            self::violations(
                '{"type":"object","required":["a","b"],"additionalProperties":false,'
                . '"properties":{"a":{"type":"string"},"b":{}}}',
                '{"a":1,"c":true}',
            ),
        );
    }

    public function testAMessageNeverRepeatsTheValue(): void
    {
        foreach (self::violations('{"type":"string","minLength":20,"pattern":"^x"}', '"hunter2"') as $message) {
            self::assertStringNotContainsString('hunter2', $message);
        }
    }

    public function testReadOnlyIsNeverSentAndWriteOnlyNeverReturned(): void
    {
        $schema = '{"type":"object","required":["id","password"],"properties":'
            . '{"id":{"readOnly":true},"password":{"writeOnly":true}}}';

        self::assertSame(
            ['/id: Is read-only: it cannot be sent.'],
            self::violations($schema, '{"id":1,"password":"x"}'),
        );
        // Neither is required in the direction it does not travel.
        self::assertSame([], self::violations($schema, '{"password":"x"}'));
        self::assertSame([], self::violations($schema, '{"id":1}', Direction::Response));
        self::assertSame(
            ['/password: Is write-only: it must never be returned.'],
            self::violations($schema, '{"id":1,"password":"x"}', Direction::Response),
        );
    }

    public function testASchemaMayReferToItself(): void
    {
        $schema = self::compile(
            '{"$ref":"#/components/schemas/Tree"}',
            '{"Tree":{"type":"object","additionalProperties":false,"properties":'
            . '{"name":{"type":"string"},"children":{"type":"array","items":{"$ref":"#/components/schemas/Tree"}}}}}',
        );

        /** @var mixed $tree */
        $tree = self::json('{"name":"a","children":[{"name":"b","children":[]}]}');
        self::assertSame([], SchemaValidator::validate($tree, $schema, Direction::Request));
        self::assertSame(
            '/children/0/name',
            SchemaValidator::validate(self::json('{"children":[{"name":1}]}'), $schema, Direction::Request)[0]->pointer,
        );
    }

    /**
     * `pointer: message` for each violation, in the order found.
     *
     * @return list<string>
     */
    private static function violations(
        string $schema,
        string $instance,
        Direction $direction = Direction::Request,
    ): array {
        return array_map(
            static fn (SchemaViolation $violation): string => $violation->pointer . ': ' . $violation->message,
            SchemaValidator::validate(self::json($instance), self::compile($schema), $direction),
        );
    }

    private static function compile(string $schema, string $components = '{}'): Schema
    {
        $root = Node::root(self::json('{"schema":' . $schema . ',"components":{"schemas":' . $components . '}}'));
        $compiler = new SchemaCompiler(new References($root));
        $compiled = $compiler->compile($root->member('schema'));
        $compiler->finish();

        return $compiled;
    }

    private static function json(string $json): mixed
    {
        return json_decode($json, false, flags: JSON_THROW_ON_ERROR);
    }
}
