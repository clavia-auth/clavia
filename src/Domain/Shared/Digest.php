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
 * The at-rest form of a high-entropy secret: its SHA-256 digest, in hexadecimal.
 *
 * Authorization codes, access and refresh tokens, and the identifiers of Redis-held
 * state are stored as this, never in plaintext: a leaked dump must not be directly
 * replayable. SHA-256 is the right primitive here even though passwords use PBKDF2 —
 * these are 256-bit random values, so there is no low-entropy guess space to brute
 * force, and a deterministic digest is what lets a token be looked up through an
 * indexed unique column. A salted, deliberately slow hash would turn that lookup into
 * a table scan.
 *
 * Never use this for a password or anything else a person chose.
 */
final readonly class Digest
{
    private const string PATTERN = '/^[0-9a-f]{64}$/D';

    private function __construct(private string $hex)
    {
    }

    /** Digest a secret as presented by a caller or as just generated. */
    public static function of(#[\SensitiveParameter] string $secret): self
    {
        return new self(hash('sha256', $secret));
    }

    /**
     * Rehydrate a digest read back from storage.
     *
     * @throws InvalidValue When the value is not 64 lower-case hexadecimal characters.
     */
    public static function fromHex(string $hex): self
    {
        if (preg_match(self::PATTERN, $hex) !== 1) {
            throw new InvalidValue('A digest is 64 lower-case hexadecimal characters.');
        }

        return new self($hex);
    }

    /** Whether a presented secret is the one this digest was made from. Constant-time. */
    public function matches(#[\SensitiveParameter] string $secret): bool
    {
        return hash_equals($this->hex, hash('sha256', $secret));
    }

    /** Constant-time comparison with another digest. */
    public function equals(self $other): bool
    {
        return hash_equals($this->hex, $other->hex);
    }

    public function toString(): string
    {
        return $this->hex;
    }
}
