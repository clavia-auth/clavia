<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\OAuth2;

use Clavia\Domain\OAuth2\UiLocales;
use PHPUnit\Framework\TestCase;

/** `ui_locales` (OpenID Connect Core §3.1.2.1) is a hint: kept when well formed, dropped when not, never refused. */
final class UiLocalesTest extends TestCase
{
    public function testTagsAreKeptInTheirOrder(): void
    {
        self::assertSame(['fr-CA', 'fr', 'en'], UiLocales::fromString(' fr-CA  fr en ')->tags);
        self::assertSame(['zh-Hant-TW'], UiLocales::fromString('zh-Hant-TW')->tags, 'Matched later, by lookup.');
    }

    public function testWhatIsNotATagIsDroppedNotRefused(): void
    {
        self::assertSame(['fr', 'en'], UiLocales::fromString('fr ../etc <b> fr_CA en')->tags);
        self::assertTrue(UiLocales::fromString(null)->isEmpty());
        self::assertTrue(UiLocales::fromString('')->isEmpty());
        self::assertSame([], UiLocales::fromString(str_repeat('a', 40))->tags, 'Longer than any tag.');
    }

    public function testAtMostTenAreKept(): void
    {
        $many = implode(' ', array_map(static fn (int $i): string => 'x' . chr(97 + $i), range(0, 14)));

        self::assertCount(10, UiLocales::fromString($many)->tags);
    }

    public function testWhatIsKeptReadsBackTheSame(): void
    {
        $asked = UiLocales::fromString('fr-CA fr');

        self::assertSame($asked->tags, UiLocales::fromString($asked->toString())->tags);
    }
}
