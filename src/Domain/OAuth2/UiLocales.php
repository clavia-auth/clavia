<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2;

/**
 * The languages an application asks the sign-in pages to be shown in: `ui_locales` (OpenID Connect Core
 * §3.1.2.1), BCP 47 tags by preference, space-separated.
 *
 * A hint, never a reason to refuse: a malformed tag is dropped and the rest kept, in order. At most ten
 * are kept, and each is a language range (letters, then subtags of letters and digits), so whatever an
 * application sends, only a short list of well-formed tags is ever held and matched against the offered
 * languages (`Languages::lookup()`).
 */
final readonly class UiLocales
{
    private const int MAX_TAGS = 10;
    private const int MAX_TAG_LENGTH = 35;
    private const string TAG = '/^[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*$/D';

    /** @param list<non-empty-string> $tags */
    private function __construct(public array $tags)
    {
    }

    public static function none(): self
    {
        return new self([]);
    }

    /** A `ui_locales` value as a request carries it; absent is none. */
    public static function fromString(?string $value): self
    {
        $tags = preg_split('/\s+/', trim($value ?? ''), flags: PREG_SPLIT_NO_EMPTY);

        return self::fromList($tags === false ? [] : $tags);
    }

    /**
     * Tags read back from where a request was held, held to the same rules.
     *
     * @param list<string> $tags
     */
    public static function fromList(array $tags): self
    {
        $kept = [];
        foreach ($tags as $tag) {
            if (count($kept) === self::MAX_TAGS) {
                break;
            }
            if ($tag !== '' && strlen($tag) <= self::MAX_TAG_LENGTH && preg_match(self::TAG, $tag) === 1) {
                $kept[] = $tag;
            }
        }

        return new self($kept);
    }

    public function isEmpty(): bool
    {
        return $this->tags === [];
    }

    /** As `ui_locales` writes it: space-separated. */
    public function toString(): string
    {
        return implode(' ', $this->tags);
    }
}
