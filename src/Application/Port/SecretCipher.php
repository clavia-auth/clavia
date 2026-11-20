<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

/**
 * Authenticated encryption for the few secrets that have to be read back.
 *
 * Almost everything sensitive is stored as a one-way digest, because verification only
 * ever compares. The exceptions are values the server must *use*: the private signing
 * key of the postgres backend, TOTP seeds, the client secret of an upstream OIDC
 * connection. Hashing is not an option for those, and storing them in the clear would
 * mean a database backup or a read-only SQL injection hands over the ability to mint
 * tokens for every user.
 *
 * The key comes from configuration and is never written to the database, so a backup
 * alone is not enough. The `$context` is authenticated but not encrypted: it is not a
 * secret, it is a statement about where a ciphertext belongs — a key id, a user id and
 * factor type. Bind it to the owning row and an attacker who can *write* to the
 * database still cannot move one row's secret onto another.
 */
interface SecretCipher
{
    /**
     * @param string $context Stable, row-specific associated data; required again to decrypt.
     *
     * @return non-empty-string An opaque, printable token safe to store in a text column.
     *
     * @throws EncryptionUnavailable When no usable key is configured.
     */
    public function encrypt(#[\SensitiveParameter] string $plaintext, string $context): string;

    /**
     * Reverse {@see self::encrypt()}, insisting on the same `$context`.
     *
     * @throws DecryptionFailed      When the ciphertext, the key or the context does not match.
     * @throws EncryptionUnavailable When no usable key is configured.
     */
    public function decrypt(string $ciphertext, string $context): string;
}
