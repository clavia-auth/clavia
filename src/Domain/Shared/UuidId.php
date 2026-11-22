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
 * Base of the identifiers that are UUIDs: users, authorization codes, tokens.
 *
 * Random (version 4) on purpose. These identifiers leave the server — a user's is the
 * OIDC `sub` — and must say nothing about when or in what order the things they name
 * were created. Each aggregate gets its own subclass so that a `UserId` cannot be
 * passed where an `AccessTokenId` is expected.
 */
abstract readonly class UuidId
{
    private const string PATTERN = '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/D';

    final private function __construct(public string $value)
    {
    }

    /**
     * @throws InvalidValue When the value is not a lower-case, hyphenated UUID.
     */
    final public static function fromString(string $value): static
    {
        if (preg_match(self::PATTERN, $value) !== 1) {
            throw new InvalidValue('An identifier must be a lower-case UUID such as 3f2b8c1e-…');
        }

        return new static($value);
    }

    /** A fresh version 4 (random) UUID, RFC 9562 §5.4. */
    final public static function generate(RandomSource $random): static
    {
        $bytes = $random->bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40); // version 4
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80); // RFC variant

        return new static(vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4)));
    }

    /**
     * The sixteen bytes of the UUID: what WebAuthn calls a user handle, which is an opaque byte
     * string of at most 64 bytes (WebAuthn Level 3 §5.4.3) and must not be personal data.
     *
     * @return non-empty-string
     */
    final public function toBytes(): string
    {
        $bytes = hex2bin(str_replace('-', '', $this->value));
        assert($bytes !== false && $bytes !== '');

        return $bytes;
    }

    /**
     * The identifier whose bytes these are.
     *
     * @throws InvalidValue When it is not sixteen bytes.
     */
    final public static function fromBytes(string $bytes): static
    {
        if (strlen($bytes) !== 16) {
            throw new InvalidValue('An identifier is sixteen bytes.');
        }

        return static::fromString(vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4)));
    }

    final public function equals(self $other): bool
    {
        return $other::class === static::class && $this->value === $other->value;
    }

    final public function toString(): string
    {
        return $this->value;
    }
}
