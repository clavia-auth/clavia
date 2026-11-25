<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Claims;

use Clavia\Domain\Identity\AppMetadata;
use Clavia\Domain\Shared\CanonicalJson;
use Clavia\Domain\Shared\InvalidValue;
use JsonException;

/**
 * What a custom claim reads, written as the Management API writes it: `email`, `email_verified`,
 * `connection`, `profile.<field>`, `app_metadata.<path>` (at most {@see AppMetadata::MAX_DEPTH}
 * keys), `roles`, or `constant` with a value of at most {@see MAX_CONSTANT_BYTES} of JSON. Nothing a
 * request carries (docs/design/custom-claims.md §2).
 */
final readonly class ClaimSource
{
    public const int MAX_CONSTANT_BYTES = 1024;

    public const array PROFILE_FIELDS = ['name', 'given_name', 'family_name', 'nickname', 'picture', 'locale'];

    /**
     * @param list<non-empty-string> $path     The profile field, or the keys into the metadata.
     * @param string|null           $constant A constant's canonical JSON.
     */
    private function __construct(
        public ClaimSourceKind $kind,
        public array $path,
        public ?string $constant,
    ) {
    }

    /**
     * @param string|null $value A constant's value as JSON; only a constant takes one.
     *
     * @throws InvalidValue
     */
    public static function fromString(string $source, ?string $value = null): self
    {
        if ($source === ClaimSourceKind::Constant->value) {
            return new self(ClaimSourceKind::Constant, [], self::constant($value));
        }
        if ($value !== null) {
            throw new InvalidValue("Only a 'constant' source takes a value.");
        }
        $plain = [
            ClaimSourceKind::Email,
            ClaimSourceKind::EmailVerified,
            ClaimSourceKind::Connection,
            ClaimSourceKind::Roles,
        ];
        foreach ($plain as $kind) {
            if ($source === $kind->value) {
                return new self($kind, [], null);
            }
        }
        if (str_starts_with($source, 'profile.')) {
            $field = substr($source, strlen('profile.'));
            if ($field === '' || ! in_array($field, self::PROFILE_FIELDS, true)) {
                throw new InvalidValue('A profile source names one of: ' . implode(', ', self::PROFILE_FIELDS) . '.');
            }

            return new self(ClaimSourceKind::ProfileField, [$field], null);
        }
        if (str_starts_with($source, 'app_metadata.')) {
            $keys = explode('.', substr($source, strlen('app_metadata.')));
            if (count($keys) > AppMetadata::MAX_DEPTH) {
                throw new InvalidValue(sprintf('A metadata path is at most %d keys.', AppMetadata::MAX_DEPTH));
            }
            $path = [];
            foreach ($keys as $key) {
                if (preg_match(AppMetadata::KEY_PATTERN, $key) !== 1) {
                    throw new InvalidValue(
                        'A metadata path is keys of 1 to 64 letters, digits, "_" or "-", joined by ".".',
                    );
                }
                /** @var non-empty-string $key The pattern above wants at least one character. */
                $path[] = $key;
            }

            return new self(ClaimSourceKind::AppMetadata, $path, null);
        }

        throw new InvalidValue(
            "A source is 'email', 'email_verified', 'connection', 'profile.<field>', 'app_metadata.<path>', "
            . "'roles' or 'constant'.",
        );
    }

    /** As the Management API writes it. */
    public function toString(): string
    {
        return match ($this->kind) {
            ClaimSourceKind::ProfileField => 'profile.' . $this->path[0],
            ClaimSourceKind::AppMetadata => 'app_metadata.' . implode('.', $this->path),
            default => $this->kind->value,
        };
    }

    /** Whether two sources read the same metadata, or one reads inside what the other does. */
    public function overlaps(self $other): bool
    {
        if ($this->kind !== ClaimSourceKind::AppMetadata || $other->kind !== ClaimSourceKind::AppMetadata) {
            return false;
        }
        $shorter = min(count($this->path), count($other->path));

        return array_slice($this->path, 0, $shorter) === array_slice($other->path, 0, $shorter);
    }

    /** @throws InvalidValue */
    private static function constant(?string $value): string
    {
        if ($value === null) {
            throw new InvalidValue("A 'constant' source takes a value.");
        }
        try {
            /** @var mixed $decoded */
            $decoded = json_decode($value, false, 16, JSON_THROW_ON_ERROR);
            // Canonical, keys sorted: what storage reorders must read back the same.
            $canonical = CanonicalJson::encode($decoded);
        } catch (JsonException) {
            throw new InvalidValue("A constant's value is JSON.");
        }
        if ($decoded === null) {
            throw new InvalidValue("A constant's value is not null: a claim without a value is left out.");
        }
        if (strlen($canonical) > self::MAX_CONSTANT_BYTES) {
            throw new InvalidValue(
                sprintf("A constant's value is at most %d bytes of JSON.", self::MAX_CONSTANT_BYTES),
            );
        }

        return $canonical;
    }
}
