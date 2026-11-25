<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port\Saml;

use Clavia\Application\Port\DecryptionFailed;
use Clavia\Application\Port\SigningFailed;
use Clavia\Domain\Connection\Saml\ServiceProviderKeySet;

/**
 * This server's keys as a SAML service provider, as everything that uses them sees them
 * (docs/design/saml-connections.md §2, §4): it **signs** and **decrypts**, and never hands out a
 * private key, so a backend that keeps its keys where they cannot be read (a KMS) implements it as
 * well as one that keeps them sealed in PostgreSQL. Exactly one class per backend opens a private
 * key: its own {@see sign()} and {@see decryptKey()}.
 */
interface ServiceProviderKeys
{
    /** Every key, with its certificate and its place in the rotation; never key material. */
    public function certificates(): ServiceProviderKeySet;

    /**
     * RSASSA-PKCS1-v1_5 over SHA-256 of `$data`, with the current signing key named (Bindings
     * §3.4.4.1 for a request; RFC 5280 §4.1.1.3 for a certificate).
     *
     * @param non-empty-string $kid
     *
     * @return non-empty-string The raw signature.
     *
     * @throws SigningFailed When the key is not the current signing key, or the backend fails.
     */
    public function sign(string $kid, string $data): string;

    /**
     * The content-encryption key of an assertion encrypted to the encryption key named (XML
     * Encryption §5.4, RSA-OAEP): tens of bytes, never the assertion. Next, current and retired
     * encryption keys all decrypt; a signing key never does.
     *
     * @param non-empty-string $kid
     *
     * @throws DecryptionFailed Whatever went wrong, the same exception: no oracle (§7).
     */
    public function decryptKey(string $kid, string $encryptedKey, OaepDigest $digest): string;
}
