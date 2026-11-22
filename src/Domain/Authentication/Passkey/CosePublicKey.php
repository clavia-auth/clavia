<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Passkey;

use Clavia\Domain\Shared\InvalidValue;

/**
 * A passkey's public key, as registered: a COSE_Key (RFC 9052 §7) in its CBOR encoding.
 *
 * Opaque to the domain: only the verifier adapter reads it. It is not a secret, so it is
 * stored in the clear.
 */
final readonly class CosePublicKey
{
    /** Far above any RSA-4096 key; a bound, not an expectation. */
    public const int MAX_LENGTH = 4096;

    private function __construct(private string $bytes)
    {
    }

    /** @throws InvalidValue When it is empty or longer than {@see self::MAX_LENGTH} bytes. */
    public static function fromBytes(string $bytes): self
    {
        if ($bytes === '' || strlen($bytes) > self::MAX_LENGTH) {
            throw new InvalidValue(sprintf('A public key is 1 to %d bytes.', self::MAX_LENGTH));
        }

        return new self($bytes);
    }

    public function bytes(): string
    {
        return $this->bytes;
    }
}
