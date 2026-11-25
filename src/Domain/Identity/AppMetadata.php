<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity;

use Clavia\Domain\Shared\CanonicalJson;
use Clavia\Domain\Shared\InvalidValue;
use JsonException;
use stdClass;

/**
 * Facts an operator keeps about an account (a tenant, a plan, a department), which claim mappings
 * can copy into tokens (docs/design/custom-claims.md). A JSON object written by operators alone,
 * through the Management API with `update:users_app_metadata`: never by the person, never by a
 * provider at sign-in. It holds facts, never secrets: what is here can end up in a token an
 * application reads.
 *
 * Kept as its canonical JSON, so an empty object stays `{}` and an empty list `[]`, which a PHP
 * array would confuse, and with the keys of every object sorted: PostgreSQL's `jsonb` reorders
 * them, and the same metadata must read back as the same value.
 *
 * Bounded where it is written, so a token built from it stays carriable: {@see MAX_BYTES}
 * encoded, {@see MAX_DEPTH} levels of objects and lists, keys of {@see KEY_PATTERN} at every
 * level.
 */
final readonly class AppMetadata
{
    public const int MAX_BYTES = 16_384;

    /** An object of scalars is one level; each object or list inside it adds one. */
    public const int MAX_DEPTH = 5;

    public const string KEY_PATTERN = '/^[A-Za-z0-9_-]{1,64}$/D';


    /** @param non-empty-string $json The canonical encoding of a JSON object. */
    private function __construct(private string $json)
    {
    }

    public static function empty(): self
    {
        return new self('{}');
    }

    /**
     * Read the JSON of an object, and hold it to the bounds. The message names the rule broken,
     * never the value.
     *
     * @throws InvalidValue
     */
    public static function fromJson(string $json): self
    {
        try {
            /** @var mixed $decoded */
            $decoded = json_decode($json, false, 64, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new InvalidValue('The application metadata is not valid JSON.');
        }
        if (! $decoded instanceof stdClass) {
            throw new InvalidValue('The application metadata is a JSON object.');
        }
        if (self::depthOf($decoded) > self::MAX_DEPTH) {
            throw new InvalidValue(sprintf('The application metadata nests at most %d levels.', self::MAX_DEPTH));
        }
        self::checkKeys($decoded);
        $canonical = CanonicalJson::encode($decoded);
        if (strlen($canonical) > self::MAX_BYTES) {
            throw new InvalidValue(sprintf('The application metadata is at most %d bytes.', self::MAX_BYTES));
        }

        return new self($canonical);
    }

    /** @return non-empty-string */
    public function toJson(): string
    {
        return $this->json;
    }

    public function isEmpty(): bool
    {
        return $this->json === '{}';
    }

    /**
     * What is at `$path` (keys into objects), boxed; null when nothing is there or it is `null`.
     *
     * @param list<string> $path
     *
     * @return list{mixed}|null
     */
    public function at(array $path): ?array
    {
        /** @var mixed $value */
        $value = json_decode($this->json, false, 64, JSON_THROW_ON_ERROR);
        foreach ($path as $key) {
            if (! $value instanceof stdClass || ! property_exists($value, $key)) {
                return null;
            }
            /** @var mixed $value */
            $value = $value->{$key};
        }

        return $value === null ? null : [$value];
    }

    public function equals(self $other): bool
    {
        return $this->json === $other->json;
    }


    private static function depthOf(mixed $value): int
    {
        if (! $value instanceof stdClass && ! is_array($value)) {
            return 0;
        }
        $deepest = 0;
        /** @var mixed $item */
        foreach ($value instanceof stdClass ? get_object_vars($value) : $value as $item) {
            $deepest = max($deepest, self::depthOf($item));
        }

        return 1 + $deepest;
    }

    /** @throws InvalidValue */
    private static function checkKeys(mixed $value): void
    {
        if ($value instanceof stdClass) {
            /** @var mixed $item */
            foreach (get_object_vars($value) as $key => $item) {
                if (preg_match(self::KEY_PATTERN, (string) $key) !== 1) {
                    throw new InvalidValue(
                        'The keys of the application metadata are 1 to 64 letters, digits, "_" or "-".',
                    );
                }
                self::checkKeys($item);
            }
        } elseif (is_array($value)) {
            /** @var mixed $item */
            foreach ($value as $item) {
                self::checkKeys($item);
            }
        }
    }
}
