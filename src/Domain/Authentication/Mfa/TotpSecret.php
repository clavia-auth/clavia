<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Mfa;

use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;

/**
 * The seed a TOTP factor shares with the person's authenticator app.
 *
 * The one credential this server must be able to read back — it computes the expected
 * code from it — so it is stored sealed ({@see MfaFactor::$sealedSecret}), never hashed,
 * and exists in the clear only for one check or for being shown once at enrollment.
 */
final readonly class TotpSecret
{
    /** 160 bits: the size RFC 4226 §4 recommends for HMAC-SHA-1. */
    public const int BYTES = 20;

    private function __construct(#[\SensitiveParameter] private string $bytes)
    {
    }

    public static function generate(RandomSource $random): self
    {
        return new self($random->bytes(self::BYTES));
    }

    /**
     * @throws InvalidValue When the value is not base32, or shorter than 128 bits (RFC 4226 §4).
     */
    public static function fromBase32(#[\SensitiveParameter] string $encoded): self
    {
        $bytes = Base32::decode($encoded);
        if (strlen($bytes) < 16) {
            throw new InvalidValue('A TOTP seed has at least 128 bits.');
        }

        return new self($bytes);
    }

    /** For HMAC, during one check. */
    public function bytes(): string
    {
        return $this->bytes;
    }

    /** As typed into an app that cannot scan, and as sealed for storage. */
    public function base32(): string
    {
        return Base32::encode($this->bytes);
    }

    /** @return array<never, never> Nothing: the seed never appears in a dump or a log. */
    public function __debugInfo(): array
    {
        return [];
    }
}
