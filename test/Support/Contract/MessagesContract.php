<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\Messages;
use Clavia\Domain\Shared\Language;
use Clavia\Domain\Shared\Languages;
use LogicException;

/**
 * What every {@see Messages} does, the in-memory double and the ARB catalogue alike, over the same
 * messages: {@see self::CATALOGUES}.
 */
trait MessagesContract
{
    /** @var array<string, array<string, string>> */
    protected const array CATALOGUES = [
        'en' => [
            'greeting' => 'Hello, {name}.',
            'accounts' => '{count, plural, one {# account} other {# accounts}}',
            'only.english' => 'Only in English.',
        ],
        'fr' => [
            'greeting' => 'Bonjour, {name}.',
            'accounts' => '{count, plural, one {# compte} other {# comptes}}',
        ],
    ];

    /** The messages under test, over {@see self::CATALOGUES}. */
    abstract protected function messages(Languages $languages): Messages;

    public function testAMessageIsWordedWithItsValues(): void
    {
        self::assertSame(
            'Hello, Ada.',
            $this->messages(self::languages())->text(self::en(), 'greeting', ['name' => 'Ada']),
        );
        self::assertSame(
            'Bonjour, Ada.',
            $this->messages(self::languages())->text(self::fr(), 'greeting', ['name' => 'Ada']),
        );
    }

    public function testPluralsFollowEachLanguagesRules(): void
    {
        $messages = $this->messages(self::languages());

        self::assertSame('0 accounts', $messages->text(self::en(), 'accounts', ['count' => 0]));
        self::assertSame('1 account', $messages->text(self::en(), 'accounts', ['count' => 1]));
        self::assertSame('0 compte', $messages->text(self::fr(), 'accounts', ['count' => 0]), 'Singular in French.');
        self::assertSame('2 comptes', $messages->text(self::fr(), 'accounts', ['count' => 2]));
    }

    public function testAValueIsPrintedNeverInterpreted(): void
    {
        $text = $this->messages(
            self::languages(),
        )->text(self::en(), 'greeting', ['name' => '{count, plural, other {x}}']);

        self::assertSame('Hello, {count, plural, other {x}}.', $text);
    }

    public function testAMessageMissingFromATranslationIsTheDefaultLanguages(): void
    {
        self::assertSame('Only in English.', $this->messages(self::languages())->text(self::fr(), 'only.english'));
    }

    public function testAMessageMissingFromTheDefaultLanguageIsADefect(): void
    {
        $this->expectException(LogicException::class);

        $this->messages(self::languages())->text(self::fr(), 'nowhere');
    }

    private static function languages(): Languages
    {
        return Languages::of([self::en(), self::fr()], self::en());
    }

    private static function en(): Language
    {
        return Language::fromString('en');
    }

    private static function fr(): Language
    {
        return Language::fromString('fr');
    }
}
