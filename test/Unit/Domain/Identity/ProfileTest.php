<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Identity;

use Clavia\Domain\Identity\Profile;
use Clavia\Domain\Shared\InvalidValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ProfileTest extends TestCase
{
    public function testEveryFieldIsOptional(): void
    {
        $profile = Profile::empty();

        self::assertNull($profile->name);
        self::assertNull($profile->givenName);
        self::assertNull($profile->familyName);
        self::assertNull($profile->nickname);
        self::assertNull($profile->picture);
        self::assertNull($profile->locale);
        self::assertTrue($profile->equals(Profile::of()));
    }

    public function testAnEmptyStringMeansUnset(): void
    {
        self::assertTrue(Profile::of('', '', '', '', '', '')->equals(Profile::empty()));
    }

    public function testAFullProfileKeepsItsValues(): void
    {
        $profile = Profile::of('Ada Lovelace', 'Ada', 'Lovelace', 'ada', 'https://example.com/a.png', 'en-GB');

        self::assertSame('Ada Lovelace', $profile->name);
        self::assertSame('Ada', $profile->givenName);
        self::assertSame('Lovelace', $profile->familyName);
        self::assertSame('ada', $profile->nickname);
        self::assertSame('https://example.com/a.png', $profile->picture?->value);
        self::assertSame('en-GB', $profile->locale);
    }

    public function testNamesMayBeAnyTextUpTo255Characters(): void
    {
        self::assertSame('Zoë Ōtsuka-Ñúñez', Profile::of(name: 'Zoë Ōtsuka-Ñúñez')->name);
        self::assertSame(255, mb_strlen((string) Profile::of(name: str_repeat('é', 255))->name));
    }

    public function testProfilesAreEqualWhenEveryFieldIs(): void
    {
        self::assertTrue(Profile::of(name: 'Ada')->equals(Profile::of(name: 'Ada')));
        self::assertFalse(Profile::of(name: 'Ada')->equals(Profile::of(name: 'Ada', locale: 'en')));
        self::assertFalse(
            Profile::of(picture: 'https://example.com/a.png')
                ->equals(Profile::of(picture: 'https://example.com/b.png')),
        );
    }

    /**
     * @param array<string, string> $fields
     */
    #[DataProvider('invalid')]
    public function testInvalidValuesAreRefused(array $fields): void
    {
        $this->expectException(InvalidValue::class);

        Profile::of(...$fields);
    }

    /** @return iterable<string, array{array<string, string>}> */
    public static function invalid(): iterable
    {
        yield 'a name of 256 characters' => [['name' => str_repeat('a', 256)]];
        yield 'a line break in a name' => [['givenName' => "Ada\nLovelace"]];
        yield 'a name that is not UTF-8' => [['familyName' => "\xFF"]];
        yield 'a picture that is not a URL' => [['picture' => 'a.png']];
        yield 'a picture that is not http(s)' => [['picture' => 'javascript://example.com/%0Aalert(1)']];
        yield 'a picture URL that is too long' => [['picture' => 'https://example.com/' . str_repeat('a', 2048)]];
        yield 'a locale that is not a language tag' => [['locale' => 'en US']];
        yield 'a one-letter locale' => [['locale' => 'e']];
        yield 'a locale with an underscore' => [['locale' => 'en_US']];
    }
}
