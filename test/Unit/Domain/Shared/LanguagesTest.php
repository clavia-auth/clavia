<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Shared;

use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Language;
use Clavia\Domain\Shared\Languages;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** A language is a BCP 47 tag; the offered ones are matched by RFC 4647 §3.4 lookup. */
final class LanguagesTest extends TestCase
{
    public function testATagIsNormalisedAsBcp47WritesIt(): void
    {
        self::assertSame('fr', Language::fromString('FR')->tag);
        self::assertSame('fr-CA', Language::fromString('fr-ca')->tag);
        self::assertSame('es-419', Language::fromString('es-419')->tag);
        self::assertTrue(Language::fromString('pt-br')->equals(Language::fromString('PT-BR')));
    }

    #[DataProvider('notLanguages')]
    public function testAnythingElseIsRefused(string $tag): void
    {
        $this->expectException(InvalidValue::class);

        Language::fromString($tag);
    }

    /** @return iterable<string, array{string}> */
    public static function notLanguages(): iterable
    {
        yield 'empty' => [''];
        yield 'one letter' => ['f'];
        yield 'a script' => ['zh-Hant'];
        yield 'a path' => ['../en'];
        yield 'a trailing newline' => ["fr\n"];
        yield 'an underscore' => ['fr_CA'];
    }

    public function testLookupShortensTheRangeUntilSomethingOfferedMatches(): void
    {
        $languages = self::offered('en', 'fr', 'pt-BR');

        self::assertSame('fr', $languages->lookup('fr-CA')?->tag);
        self::assertSame('fr', $languages->lookup('FR')?->tag);
        self::assertSame('pt-BR', $languages->lookup('pt-br')?->tag);
        self::assertNull($languages->lookup('pt'), 'A region is not dropped from what is offered.');
        self::assertSame(
            'en',
            $languages->lookup('en-Latn-US-x-private')?->tag,
            'The singleton goes with what follows.',
        );
        self::assertNull($languages->lookup('de'));
        self::assertNull($languages->lookup('*'));
        self::assertNull($languages->lookup('fr;q=1'));
    }

    public function testWhatIsOfferedHoldsTogether(): void
    {
        $refused = 0;
        foreach ([[[], 'en'], [['en', 'en'], 'en'], [['en'], 'fr']] as [$offered, $default]) {
            try {
                Languages::of(
                    array_map(static fn (string $tag): Language => Language::fromString($tag), $offered),
                    Language::fromString($default),
                );
            } catch (InvalidValue) {
                ++$refused;
            }
        }

        self::assertSame(3, $refused, 'None offered, one offered twice, and a default not offered.');
    }

    private static function offered(string ...$tags): Languages
    {
        $languages = array_map(static fn (string $tag): Language => Language::fromString($tag), array_values($tags));

        return Languages::of($languages, $languages[0]);
    }
}
