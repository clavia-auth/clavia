<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Messages;

use Clavia\Application\Port\Messages;
use Clavia\Domain\Shared\Language;
use Clavia\Domain\Shared\Languages;
use JsonException;
use LogicException;
use MessageFormatter;
use Psr\Log\LoggerInterface;

/**
 * The catalogue as ARB files (Application Resource Bundle: JSON), one per language in `$directory`
 * (`translations/en.arb`), worded by ICU's `MessageFormatter`: plurals and selections as each language
 * has them. A file is read with `json_decode` when its language is first needed, never included: a
 * translation is data. Its `@` entries describe messages for translators and are skipped here.
 *
 * Values are arguments, never part of a pattern, so a value holding ICU syntax is printed as it is.
 */
final class IcuMessages implements Messages
{
    /** @var array<string, array<string, string>> Messages by language tag, then key. */
    private array $catalogues = [];

    /** @var array<string, true> Keys already reported missing, once each. */
    private array $reported = [];

    public function __construct(
        private readonly string $directory,
        private readonly Languages $languages,
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * Where a language's catalogue is: what the composition root checks before anything starts. The
     * directory is the server's own, and a tag is letters, digits and one hyphen, checked again here:
     * the path stays a file in that directory, never a parent, a stream wrapper or a URL, whatever
     * language a request asked for.
     *
     * @psalm-taint-escape ssrf
     * @psalm-taint-escape file
     * @psalm-taint-escape url_component
     * @psalm-taint-escape url_path
     * @psalm-taint-escape url_scheme
     */
    public static function path(string $directory, Language $language): string
    {
        if (preg_match('/^[a-z]{2,3}(?:-(?:[A-Z]{2}|[0-9]{3}))?$/D', $language->tag) !== 1) {
            throw new LogicException('A language tag names no catalogue.');
        }

        return rtrim($directory, '/') . '/' . $language->tag . '.arb';
    }

    #[\Override]
    public function text(Language $language, string $key, array $values = []): string
    {
        $pattern = $this->catalogue($language)[$key] ?? null;
        $wording = $language;
        if ($pattern === null && ! $language->equals($this->languages->default)) {
            if (! isset($this->reported[$language->tag . ' ' . $key])) {
                $this->reported[$language->tag . ' ' . $key] = true;
                $this->logger->warning('No {language} message {key}: the default language\'s is shown.', [
                    'language' => $language->tag,
                    'key' => $key,
                ]);
            }
            $wording = $this->languages->default;
            $pattern = $this->catalogue($wording)[$key] ?? null;
        }
        if ($pattern === null) {
            throw new LogicException(sprintf('There is no message %s in the default language.', $key));
        }

        $text = MessageFormatter::formatMessage($wording->tag, $pattern, $values);
        if ($text === false) {
            throw new LogicException(sprintf('The %s message %s cannot be worded.', $wording->tag, $key));
        }

        return $text;
    }

    /** @return array<string, string> */
    private function catalogue(Language $language): array
    {
        if (isset($this->catalogues[$language->tag])) {
            return $this->catalogues[$language->tag];
        }
        if (! $this->languages->has($language)) {
            throw new LogicException(sprintf('%s is not an offered language.', $language->tag));
        }

        return $this->catalogues[$language->tag] = self::read(self::path($this->directory, $language));
    }

    /**
     * The messages of an ARB file: every member but `@@locale` and the `@key` descriptions.
     *
     * @return array<string, string>
     */
    public static function read(string $path): array
    {
        $json = @file_get_contents($path);
        if (! is_string($json)) {
            throw new LogicException(sprintf('The catalogue %s cannot be read.', basename($path)));
        }
        try {
            /** @var mixed $decoded */
            $decoded = json_decode($json, true, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException $failure) {
            throw new LogicException(sprintf('The catalogue %s is not JSON.', basename($path)), 0, $failure);
        }
        if (! is_array($decoded)) {
            throw new LogicException(sprintf('The catalogue %s is not an object.', basename($path)));
        }

        $messages = [];
        /** @var mixed $message */
        foreach ($decoded as $key => $message) {
            $key = (string) $key;
            if (str_starts_with($key, '@')) {
                continue;
            }
            if (! is_string($message)) {
                throw new LogicException(sprintf('The message %s of %s is not text.', $key, basename($path)));
            }
            $messages[$key] = $message;
        }

        return $messages;
    }
}
