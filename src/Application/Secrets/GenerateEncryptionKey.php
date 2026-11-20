<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Secrets;

use Clavia\Domain\Shared\RandomSource;

/**
 * Produces a fresh key for `CLAVIA_SECRET_ENCRYPTION_KEY`.
 *
 * The key encrypts the secrets this server has to be able to *read* rather than merely
 * compare (see {@see \Clavia\Application\Port\SecretCipher}). It is generated here and
 * printed once; it is the operator who stores it. Changing it later makes everything
 * encrypted under the old one unreadable — rotate it only on purpose.
 */
final readonly class GenerateEncryptionKey
{
    /** AES-256. */
    private const int KEY_BYTES = 32;

    public function __construct(private RandomSource $random)
    {
    }

    /**
     * @return non-empty-string Base64 of 32 random bytes.
     */
    public function __invoke(): string
    {
        return base64_encode($this->random->bytes(self::KEY_BYTES));
    }
}
