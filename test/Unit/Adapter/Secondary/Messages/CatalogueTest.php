<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Messages;

use Clavia\Bootstrap\LanguageCatalogues;
use MessageFormatter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

/**
 * The shipped catalogues (`translations/*.arb`) are complete and sound (docs/design/
 * translated-sign-in-pages.md §8): a translation has exactly the source's messages, each parses for its
 * language and takes the same arguments, none holds markup, and the source describes what needs it. A
 * key the code uses exists, and a key the code no longer uses goes.
 */
final class CatalogueTest extends TestCase
{
    private const string SOURCE = 'en';

    /** A message is text: a tag or an entity in it would be escaped, or worse, not. */
    private const string MARKUP = '/<[A-Za-z\/!]|&[A-Za-z#0-9]+;/';

    /** Where the code names keys: the templates, and the HTTP adapter's pages. */
    private const array USES = ['templates', 'src/Adapter/Primary/Http'];

    #[DataProvider('languages')]
    public function testEachFileNamesItsLanguage(string $language): void
    {
        self::assertSame($language, self::file($language)['@@locale'] ?? null);
    }

    #[DataProvider('translations')]
    public function testATranslationHasExactlyTheSourcesMessages(string $language): void
    {
        $source = array_keys(self::messages(self::SOURCE));
        $translation = array_keys(self::messages($language));

        self::assertSame([], array_values(array_diff($source, $translation)), $language . ' lacks these.');
        self::assertSame(
            [],
            array_values(array_diff($translation, $source)),
            $language . ' has these the source has not.',
        );
    }

    #[DataProvider('translations')]
    public function testATranslationDescribesNothing(string $language): void
    {
        $described = array_filter(
            array_keys(self::file($language)),
            static fn (string $key): bool => str_starts_with($key, '@') && $key !== '@@locale',
        );

        self::assertSame([], array_values($described), 'Descriptions belong to the source.');
    }

    #[DataProvider('languages')]
    public function testEachMessageParsesAndHoldsNoMarkup(string $language): void
    {
        foreach (self::messages($language) as $key => $message) {
            self::assertNotNull(
                MessageFormatter::create($language, $message),
                $language . ' ' . $key . ' does not parse.',
            );
            self::assertDoesNotMatchRegularExpression(self::MARKUP, $message, $language . ' ' . $key);
        }
    }

    #[DataProvider('translations')]
    public function testATranslationTakesTheSourcesArguments(string $language): void
    {
        $source = self::messages(self::SOURCE);
        foreach (self::messages($language) as $key => $message) {
            self::assertSame(self::arguments($source[$key] ?? ''), self::arguments($message), $language . ' ' . $key);
        }
    }

    /** A message with arguments says what each is, with an example: what a translator needs to place it. */
    public function testTheSourceDescribesEachMessagesArguments(): void
    {
        $file = self::file(self::SOURCE);
        foreach (self::messages(self::SOURCE) as $key => $message) {
            $arguments = self::arguments($message);
            $placeholders = $file['@' . $key]['placeholders'] ?? [];
            self::assertIsArray($placeholders, $key);
            $named = array_keys($placeholders);
            sort($named);
            self::assertSame($arguments, $named, $key . ': its placeholders are its arguments.');
            /** @var mixed $placeholder */
            foreach ($placeholders as $name => $placeholder) {
                self::assertIsArray($placeholder);
                self::assertArrayHasKey('example', $placeholder, $key . ' ' . $name);
            }
        }
        foreach (array_keys($file) as $entry) {
            if (str_starts_with($entry, '@') && $entry !== '@@locale') {
                self::assertArrayHasKey(substr($entry, 1), $file, $entry . ' describes nothing.');
            }
        }
    }

    public function testEveryKeyTheCodeNamesExists(): void
    {
        $messages = self::messages(self::SOURCE);
        $namespaces = array_unique(
            array_map(static fn (string $key): string => explode('.', $key)[0], array_keys($messages)),
        );
        foreach (self::usedKeys() as $key => $where) {
            if (in_array(explode('.', $key)[0], $namespaces, true)) {
                self::assertArrayHasKey($key, $messages, $where . ' names a message that does not exist.');
            }
        }
    }

    public function testEveryMessageIsUsed(): void
    {
        $used = self::usedKeys();
        foreach (array_keys(self::messages(self::SOURCE)) as $key) {
            self::assertArrayHasKey($key, $used, $key . ' is used nowhere.');
        }
    }

    /** @return iterable<string, array{string}> */
    public static function languages(): iterable
    {
        $paths = glob(LanguageCatalogues::DIRECTORY . '/*.arb');
        foreach ($paths === false ? [] : $paths as $path) {
            $language = basename($path, '.arb');
            yield $language => [$language];
        }
    }

    /** @return iterable<string, array{string}> */
    public static function translations(): iterable
    {
        foreach (self::languages() as $name => $arguments) {
            if ($arguments[0] !== self::SOURCE) {
                yield $name => $arguments;
            }
        }
    }

    /** @return array<string, mixed> */
    private static function file(string $language): array
    {
        $decoded = json_decode(
            (string) file_get_contents(LanguageCatalogues::DIRECTORY . '/' . $language . '.arb'),
            true,
            flags: JSON_THROW_ON_ERROR,
        );
        self::assertIsArray($decoded);

        /** @var array<string, mixed> */
        return $decoded;
    }

    /** @return array<string, string> */
    private static function messages(string $language): array
    {
        $messages = [];
        foreach (self::file($language) as $key => $message) {
            if (! str_starts_with($key, '@')) {
                self::assertIsString($message, $key);
                $messages[$key] = $message;
            }
        }

        return $messages;
    }

    /**
     * The argument names of an ICU message, nested ones included, sorted. ICU's structure, not a pattern:
     * an argument is `{name}` or `{name, type, …}`, and a plural's or a select's branches are messages
     * of their own (`one {# account}`), whose words are no arguments.
     *
     * @return list<string>
     */
    private static function arguments(string $message): array
    {
        $names = [];
        self::scan($message, 0, $names);
        $names = array_values(array_unique($names));
        sort($names);

        return $names;
    }

    /**
     * Reads a message from `$at` to its end or to the `}` closing it, collecting arguments.
     *
     * @param list<string> $names
     */
    private static function scan(string $message, int $at, array &$names): int
    {
        $length = strlen($message);
        while ($at < $length) {
            $char = $message[$at];
            if ($char === '}') {
                return $at;
            }
            if ($char !== '{') {
                ++$at;
                continue;
            }
            // An argument: its name, then nothing, a type, or a type and a style or branches.
            $end = strcspn($message, ',}', $at + 1) + $at + 1;
            $names[] = trim(substr($message, $at + 1, $end - $at - 1));
            if ($end < $length && $message[$end] === ',') {
                $typeEnd = strcspn($message, ',}', $end + 1) + $end + 1;
                $type = trim(substr($message, $end + 1, $typeEnd - $end - 1));
                $end = $typeEnd;
                if (in_array($type, ['plural', 'select', 'selectordinal'], true)) {
                    // Branches: selector {message} … up to the argument's own closing brace.
                    while ($end < $length && $message[$end] !== '}') {
                        if ($message[$end] === '{') {
                            $end = self::scan($message, $end + 1, $names);
                        }
                        ++$end;
                    }
                } else {
                    $close = strpos($message, '}', $end);
                    $end = $close === false ? $length : $close;
                }
            }
            $at = $end + 1;
        }

        return $at;
    }

    /**
     * Every key-shaped literal the code names, where first: `'login.submit'` in a template or a page class.
     *
     * @return array<string, string>
     */
    private static function usedKeys(): array
    {
        $root = dirname(LanguageCatalogues::DIRECTORY);
        $used = [];
        foreach (self::USES as $directory) {
            $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root . '/' . $directory));
            /** @var \SplFileInfo $file */
            foreach ($files as $file) {
                $path = $file->getPathname();
                if (! preg_match('/\.(php|phtml)$/D', $path)) {
                    continue;
                }
                preg_match_all("/'([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)'/", (string) file_get_contents($path), $keys);
                foreach ($keys[1] as $key) {
                    $used[$key] ??= substr($path, strlen($root) + 1);
                }
            }
        }

        return $used;
    }
}
