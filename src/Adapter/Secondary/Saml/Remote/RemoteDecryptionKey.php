<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Saml\Remote;

use Clavia\Application\Port\DecryptionFailed;
use Clavia\Application\Port\Saml\OaepDigest;

/**
 * An RSA key in a KMS that decrypts and never leaves it: the SAML service provider's encryption key
 * (docs/design/saml-connections.md §2). It is handed the content-encryption key of one assertion,
 * tens of bytes, never the assertion itself.
 */
interface RemoteDecryptionKey
{
    /**
     * What the provider calls the key, as configured: never published.
     *
     * @return non-empty-string
     */
    public function reference(): string;

    /**
     * The public half (`BEGIN PUBLIC KEY`), read from the provider, after checking the key is one
     * that decrypts with RSA-OAEP.
     *
     * @return non-empty-string
     *
     * @throws DecryptionFailed When the provider cannot be reached, or the key is not such a key.
     */
    public function publicKeyPem(): string;

    /** @throws DecryptionFailed Whatever went wrong. */
    public function decrypt(string $ciphertext, OaepDigest $digest): string;
}
