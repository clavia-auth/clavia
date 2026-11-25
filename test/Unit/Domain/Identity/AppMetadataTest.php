<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Identity;

use Clavia\Domain\Identity\AppMetadata;
use Clavia\Domain\Shared\InvalidValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AppMetadataTest extends TestCase
{
    public function testAnObjectIsKeptWithItsKeysSortedAtEveryLevel(): void
    {
        $metadata = AppMetadata::fromJson('{"plan":"pro","tenant":{"region":"eu","id":42},"tags":["b","a"]}');

        self::assertSame('{"plan":"pro","tags":["b","a"],"tenant":{"id":42,"region":"eu"}}', $metadata->toJson());
        $reordered = AppMetadata::fromJson('{"tenant":{"id":42,"region":"eu"},"tags":["b","a"],"plan":"pro"}');
        self::assertTrue($metadata->equals($reordered));
    }

    public function testEmptyObjectsAndListsStayWhatTheyAre(): void
    {
        self::assertTrue(AppMetadata::empty()->isEmpty());
        self::assertSame('{}', AppMetadata::fromJson('{}')->toJson());
        self::assertSame(
            '{"a":{},"b":[],"c":1.0,"d":"é/ü"}',
            AppMetadata::fromJson('{"d":"é/ü","c":1.0,"b":[],"a":{}}')->toJson(),
        );
        self::assertFalse(AppMetadata::fromJson('{"a":{}}')->isEmpty());
    }

    public function testFiveLevelsAreAcceptedAndSixAreNot(): void
    {
        self::assertSame('{"a":{"b":{"c":{"d":[1]}}}}', AppMetadata::fromJson('{"a":{"b":{"c":{"d":[1]}}}}')->toJson());

        $this->expectException(InvalidValue::class);
        AppMetadata::fromJson('{"a":{"b":{"c":{"d":{"e":[1]}}}}}');
    }

    public function testItIsBoundedInSize(): void
    {
        $fits = '{"a":"' . str_repeat('x', AppMetadata::MAX_BYTES - 8) . '"}';
        self::assertSame(AppMetadata::MAX_BYTES, strlen(AppMetadata::fromJson($fits)->toJson()));

        $this->expectException(InvalidValue::class);
        AppMetadata::fromJson('{"a":"' . str_repeat('x', AppMetadata::MAX_BYTES - 7) . '"}');
    }

    /** @return iterable<string, array{string}> */
    public static function refused(): iterable
    {
        yield 'not JSON' => ['{plan: pro}'];
        yield 'a list' => ['["pro"]'];
        yield 'a string' => ['"pro"'];
        yield 'null' => ['null'];
        yield 'an empty key' => ['{"":1}'];
        yield 'a key with a space' => ['{"the plan":1}'];
        yield 'a key of 65 characters' => ['{"' . str_repeat('k', 65) . '":1}'];
        yield 'a bad key deep down' => ['{"a":[{"ok":{"not ok":1}}]}'];
    }

    #[DataProvider('refused')]
    public function testWhatIsNotAnAcceptableObjectIsRefused(string $json): void
    {
        $this->expectException(InvalidValue::class);

        AppMetadata::fromJson($json);
    }

    public function testARefusalNeverRepeatsTheValue(): void
    {
        try {
            AppMetadata::fromJson('{"secret-looking key":"hunter2"}');
            self::fail('Refused.');
        } catch (InvalidValue $refusal) {
            self::assertStringNotContainsString('hunter2', $refusal->getMessage());
            self::assertStringNotContainsString('secret-looking', $refusal->getMessage());
        }
    }
}
