<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Passkey;

use Clavia\Domain\Shared\Base64Url;
use Clavia\Domain\Shared\InvalidValue;

/**
 * A WebAuthn credential id: the opaque bytes an authenticator names a passkey by
 * (WebAuthn Level 3 §4: "at least 16 bytes ... at most 1023 bytes").
 *
 * Kept as raw bytes; {@see self::toBase64Url()} is the form the browser exchanges.
 */
final readonly class CredentialId
{
    public const int MIN_LENGTH = 16;

    public const int MAX_LENGTH = 1023;

    private function __construct(private string $bytes)
    {
    }

    /** @throws InvalidValue When it is shorter than 16 or longer than 1023 bytes. */
    public static function fromBytes(string $bytes): self
    {
        $length = strlen($bytes);
        if ($length < self::MIN_LENGTH || $length > self::MAX_LENGTH) {
            throw new InvalidValue(sprintf(
                'A credential id is %d to %d bytes.',
                self::MIN_LENGTH,
                self::MAX_LENGTH,
            ));
        }

        return new self($bytes);
    }

    /** @throws InvalidValue When it is not unpadded base64url, or its bytes are out of bounds. */
    public static function fromBase64Url(string $encoded): self
    {
        return self::fromBytes(Base64Url::decode($encoded));
    }

    public function bytes(): string
    {
        return $this->bytes;
    }

    public function toBase64Url(): string
    {
        return Base64Url::encode($this->bytes);
    }

    public function equals(self $other): bool
    {
        return hash_equals($this->bytes, $other->bytes);
    }
}
