<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Shared;

/**
 * The languages this deployment offers, and the one it falls back to (`CLAVIA_LANGUAGES`,
 * `CLAVIA_DEFAULT_LANGUAGE`). Whatever a person, an application or a browser asks for is matched against
 * these and nothing else ({@see lookup()}), so no request ever chooses a language without a catalogue.
 */
final readonly class Languages
{
    /**
     * @param non-empty-list<Language> $offered
     */
    private function __construct(
        public array $offered,
        public Language $default,
    ) {
    }

    /**
     * @param list<Language> $offered
     *
     * @throws InvalidValue When none is offered, one is offered twice, or the default is not offered.
     */
    public static function of(array $offered, Language $default): self
    {
        if ($offered === []) {
            throw new InvalidValue('At least one language is offered.');
        }
        $tags = array_map(static fn (Language $language): string => $language->tag, $offered);
        if (count(array_unique($tags)) !== count($tags)) {
            throw new InvalidValue('A language is offered once.');
        }
        if (! in_array($default->tag, $tags, true)) {
            throw new InvalidValue('The default language is one of those offered.');
        }

        return new self($offered, $default);
    }

    public function has(Language $language): bool
    {
        return $this->find($language->tag) !== null;
    }

    /**
     * The offered language a language range asks for, by RFC 4647 §3.4 lookup: the range as it is, then
     * shortened a subtag at a time from the end (`fr-CA` then `fr`), compared without regard to case.
     * Null when nothing offered matches, for `*`, and for anything that is not a range at all.
     */
    public function lookup(string $range): ?Language
    {
        if (preg_match('/^[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*$/D', $range) !== 1) {
            return null;
        }
        $subtags = explode('-', strtolower($range));
        while ($subtags !== []) {
            $found = $this->find(implode('-', $subtags));
            if ($found !== null) {
                return $found;
            }
            array_pop($subtags);
            // RFC 4647 §3.4: a single-letter subtag (an extension's singleton) goes with what follows it.
            if ($subtags !== [] && strlen(end($subtags)) === 1) {
                array_pop($subtags);
            }
        }

        return null;
    }

    private function find(string $tag): ?Language
    {
        foreach ($this->offered as $language) {
            if (strcasecmp($language->tag, $tag) === 0) {
                return $language;
            }
        }

        return null;
    }
}
