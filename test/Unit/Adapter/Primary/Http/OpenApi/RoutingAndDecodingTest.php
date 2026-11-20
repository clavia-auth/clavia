<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Http\OpenApi;

use Clavia\Adapter\Primary\Http\OpenApi\JsonPointer;
use Clavia\Adapter\Primary\Http\OpenApi\MediaType;
use Clavia\Adapter\Primary\Http\OpenApi\Routing\PathTemplate;
use Clavia\Adapter\Primary\Http\OpenApi\Schema\Formats;
use Clavia\Adapter\Primary\Http\OpenApi\Schema\JsonValue;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\QueryString;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * The small pieces requests are read with: path templates, query strings, media types,
 * JSON pointers, formats, JSON equality.
 */
final class RoutingAndDecodingTest extends TestCase
{
    public function testATemplateCapturesWholeSegmentsStillEncoded(): void
    {
        $template = PathTemplate::parse('/files/{name}.{extension}/raw');
        self::assertNotNull($template);

        self::assertSame(['name', 'extension'], $template->parameterNames());
        self::assertSame(['name' => 'a%2Fb', 'extension' => 'json'], $template->match(['files', 'a%2Fb.json', 'raw']));
        self::assertNull($template->match(['files', '.json', 'raw']));
        self::assertNull($template->match(['files', 'a.json']));
    }

    #[DataProvider('notTemplates')]
    public function testAMalformedTemplateIsNone(string $template): void
    {
        self::assertNull(PathTemplate::parse($template));
    }

    /** @return iterable<string, array{string}> */
    public static function notTemplates(): iterable
    {
        yield 'relative' => ['items/{id}'];
        yield 'unclosed' => ['/items/{id'];
        yield 'empty name' => ['/items/{}'];
        yield 'a name twice' => ['/{id}/{id}'];
        yield 'two placeholders side by side' => ['/{a}{b}'];
    }

    public function testALiteralSegmentIsMoreSpecificThanATemplatedOne(): void
    {
        $latest = PathTemplate::parse('/items/latest');
        $byId = PathTemplate::parse('/items/{id}');
        self::assertNotNull($latest);
        self::assertNotNull($byId);

        self::assertLessThan(0, $latest->compareSpecificity($byId));
        self::assertGreaterThan(0, $byId->compareSpecificity($latest));
    }

    public function testAQueryStringKeepsRepetitionsAndNamesAsSent(): void
    {
        $query = QueryString::parse('a=1&a=2&b.c=x+y&d%5B%5D=%E2%9C%93&e&=f');
        self::assertNotNull($query);

        self::assertSame(['1', '2'], $query->values('a'));
        self::assertSame(['x y'], $query->values('b.c'));
        self::assertSame(['✓'], $query->values('d[]'));
        self::assertSame([''], $query->values('e'));
        self::assertSame(['a', 'b.c', 'd[]', 'e', ''], $query->names());
        self::assertNull(QueryString::parse('a=%FF'));
    }

    public function testAMediaTypeIsParsedAndMatchedByTheMostSpecificRange(): void
    {
        $json = MediaType::parse('Application/Problem+JSON; charset="UTF-8"; q=1');
        self::assertNotNull($json);
        self::assertSame('application/problem+json', $json->essence());
        self::assertSame('utf-8', $json->charset);
        self::assertTrue($json->isJson());

        $any = MediaType::parse('*/*');
        $application = MediaType::parse('application/*');
        self::assertNotNull($any);
        self::assertNotNull($application);
        self::assertTrue($any->covers($json));
        self::assertTrue($application->covers($json));
        self::assertGreaterThan($any->specificity(), $application->specificity());

        foreach (['json', 'application/', '*/json', 'a b/c'] as $invalid) {
            self::assertNull(MediaType::parse($invalid), $invalid);
        }
    }

    public function testJsonPointersEscapeTildesAndSlashes(): void
    {
        $pointer = JsonPointer::append(JsonPointer::append('', 'a/b'), 'c~d');

        self::assertSame('/a~1b/c~0d', $pointer);
        self::assertSame(['a/b', 'c~d'], JsonPointer::tokens($pointer));
        self::assertSame([], JsonPointer::tokens(''));
    }

    /**
     * @param list<string> $valid
     * @param list<string> $invalid
     */
    #[DataProvider('formats')]
    public function testFormatsAcceptWhatTheyNameOnly(string $format, array $valid, array $invalid): void
    {
        foreach ($valid as $value) {
            self::assertTrue(Formats::accepts($format, $value), $value);
        }
        foreach ($invalid as $value) {
            self::assertFalse(Formats::accepts($format, $value), $value);
        }
    }

    /** @return iterable<string, array{string, list<string>, list<string>}> */
    public static function formats(): iterable
    {
        yield 'date-time' => [
            'date-time',
            ['2026-01-15T10:00:00Z', '2026-01-15t10:00:00.123+01:00'],
            ['2026-01-15 10:00:00Z', '2026-02-30T10:00:00Z', '2026-01-15T10:00:00', "2026-01-15T10:00:00Z\n"],
        ];
        yield 'date' => ['date', ['2024-02-29'], ['2023-02-29', '2024-2-1']];
        yield 'uuid' => [
            'uuid',
            ['6F1C8A52-1b1e-4c8e-9d38-0f2b3d7c9e10'],
            ['6f1c8a52-1b1e-4c8e-9d38-0f2b3d7c9e1', 'x'],
        ];
        yield 'email' => ['email', ['ada@example.com'], ['ada', 'ada@']];
        yield 'uri' => ['uri', ['https://example.com/a?b#c', 'urn:x:y'], ['/relative', 'not a uri']];
        yield 'byte' => ['byte', ['aGVsbG8=', ''], ['aGVsbG8', '@@@@']];
    }

    public function testAnUnknownFormatOrAnotherTypeIsNotChecked(): void
    {
        self::assertTrue(Formats::accepts('colour', 'teal'));
        self::assertTrue(Formats::accepts('uuid', 5));
        self::assertTrue(Formats::accepts('int32', 2147483647));
        self::assertFalse(Formats::accepts('int32', -2147483649));
    }

    public function testJsonEqualityIgnoresMemberOrderAndNumberRepresentation(): void
    {
        /** @var mixed $a */
        $a = json_decode('{"x":[1,{"y":2.0}],"z":null}', false, flags: JSON_THROW_ON_ERROR);
        /** @var mixed $b */
        $b = json_decode('{"z":null,"x":[1.0,{"y":2}]}', false, flags: JSON_THROW_ON_ERROR);

        self::assertTrue(JsonValue::equals($a, $b));
        self::assertFalse(JsonValue::equals([1, 2], [2, 1]));
        self::assertFalse(JsonValue::equals('1', 1));
        self::assertFalse(JsonValue::equals([], new stdClass()));
    }
}
