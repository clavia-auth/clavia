<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Http\Shared;

use Clavia\Adapter\Primary\Http\Shared\LanguageChoice;
use Clavia\Domain\Shared\Language;
use Clavia\Domain\Shared\Languages;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** A page's language from `Accept-Language` (RFC 9110 §12.5.4), or the default. */
final class LanguageChoiceTest extends TestCase
{
    #[DataProvider('headers')]
    public function testTheBrowsersPreferenceChoosesAmongTheOfferedLanguages(string $header, string $expected): void
    {
        $choice = new LanguageChoice(Languages::of(
            [Language::fromString('en'), Language::fromString('fr')],
            Language::fromString('en'),
        ));

        $chosen = $choice(new ServerRequest(headers: $header === '' ? [] : ['Accept-Language' => $header]));

        self::assertSame($expected, $chosen->tag);
    }

    /** @return iterable<string, array{string, string}> */
    public static function headers(): iterable
    {
        yield 'none: the default' => ['', 'en'];
        yield 'French' => ['fr', 'fr'];
        yield 'a regional French' => ['fr-CA', 'fr'];
        yield 'the first one offered' => ['de-DE, fr;q=0.8, en;q=0.5', 'fr'];
        yield 'by weight, not by order' => ['en;q=0.4, fr;q=0.9', 'fr'];
        yield 'ties in the order sent' => ['fr;q=0.5, en;q=0.5', 'fr'];
        yield 'q=0 means not this' => ['fr;q=0, en;q=0.1', 'en'];
        yield 'nothing offered: the default' => ['de, it', 'en'];
        yield 'a wildcard: the default' => ['*', 'en'];
        yield 'a malformed weight is skipped' => ['fr;q=high, en', 'en'];
        yield 'beyond ten ranges is not read' => ['a,b,c,d,e,f,g,h,i,j, fr', 'en'];
        yield 'spaces and case' => ['  FR-ca ; Q = 0.7 ', 'fr'];
    }
}
