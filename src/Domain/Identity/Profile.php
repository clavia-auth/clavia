<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity;

use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Url;

/**
 * What a person is called and how they present themselves: the standard claims of the
 * OIDC `profile` scope (OIDC Core §5.1, §5.4).
 *
 * Every field is optional, and an unset field is absent — never an empty string — so a
 * relying party can tell "unknown" from a value. An empty string given for a field
 * means "unset".
 */
final readonly class Profile
{
    private const int MAX_TEXT_LENGTH = 255;

    private const int MAX_URL_LENGTH = 2048;

    /** A BCP 47 language tag, in the shape OIDC Core §5.1 asks for (`en-US`, `fr-CA`). */
    private const string LOCALE = '/^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$/D';

    /**
     * @param non-empty-string|null $name
     * @param non-empty-string|null $givenName
     * @param non-empty-string|null $familyName
     * @param non-empty-string|null $nickname
     * @param non-empty-string|null $locale
     */
    private function __construct(
        public ?string $name,
        public ?string $givenName,
        public ?string $familyName,
        public ?string $nickname,
        public ?Url $picture,
        public ?string $locale,
    ) {
    }

    /** Nothing known. */
    public static function empty(): self
    {
        return new self(null, null, null, null, null, null);
    }

    /**
     * @param string|null $picture An absolute http(s) URL of a picture of the person.
     * @param string|null $locale  A BCP 47 language tag.
     *
     * @throws InvalidValue When a name is longer than 255 characters or holds a control character,
     *                      the picture is not an http(s) URL of at most 2048 bytes, or the
     *                      locale is not a language tag.
     */
    public static function of(
        ?string $name = null,
        ?string $givenName = null,
        ?string $familyName = null,
        ?string $nickname = null,
        ?string $picture = null,
        ?string $locale = null,
    ): self {
        return new self(
            self::text($name, 'name'),
            self::text($givenName, 'given_name'),
            self::text($familyName, 'family_name'),
            self::text($nickname, 'nickname'),
            self::picture($picture),
            self::locale($locale),
        );
    }

    public function equals(self $other): bool
    {
        return $this->name === $other->name
            && $this->givenName === $other->givenName
            && $this->familyName === $other->familyName
            && $this->nickname === $other->nickname
            && $this->picture?->value === $other->picture?->value
            && $this->locale === $other->locale;
    }

    /**
     * @return non-empty-string|null
     *
     * @throws InvalidValue
     */
    private static function text(?string $value, string $claim): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }

        if (
            ! mb_check_encoding($value, 'UTF-8')
            || mb_strlen($value, 'UTF-8') > self::MAX_TEXT_LENGTH
            || preg_match('/[\x00-\x1F\x7F]/', $value) === 1
        ) {
            throw new InvalidValue(sprintf(
                "'%s' is UTF-8 text of at most %d characters, with no control characters.",
                $claim,
                self::MAX_TEXT_LENGTH,
            ));
        }

        return $value;
    }

    /**
     * @throws InvalidValue
     */
    private static function picture(?string $value): ?Url
    {
        if ($value === null || $value === '') {
            return null;
        }

        $url = strlen($value) <= self::MAX_URL_LENGTH ? Url::fromString($value) : null;
        if ($url === null || ! in_array($url->scheme(), ['https', 'http'], true)) {
            throw new InvalidValue("'picture' is an absolute http(s) URL of at most 2048 bytes.");
        }

        return $url;
    }

    /**
     * @return non-empty-string|null
     *
     * @throws InvalidValue
     */
    private static function locale(?string $value): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }

        if (strlen($value) > 35 || preg_match(self::LOCALE, $value) !== 1) {
            throw new InvalidValue("'locale' is a BCP 47 language tag, such as 'en-US'.");
        }

        return $value;
    }
}
