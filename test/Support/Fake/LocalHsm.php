<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use ClaviaTest\Support\TestSigningKeys;
use RuntimeException;

/**
 * A key held outside every backend, standing in for a provider's HSM: it signs a SHA-256
 * digest as RSASSA-PKCS1-v1_5 — the DigestInfo prefix added here, as KMS, Cloud KMS and
 * Key Vault add it — and describes its public half in each provider's encoding.
 */
final readonly class LocalHsm
{
    /** DER of the DigestInfo header for SHA-256 (RFC 8017 §9.2, note 1). */
    private const string SHA256_DIGEST_INFO = "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65"
        . "\x03\x04\x02\x01\x05\x00\x04\x20";

    public function __construct(private int $index = 0)
    {
    }

    public function signDigest(string $digest): string
    {
        if (strlen($digest) !== 32) {
            throw new RuntimeException(sprintf('Handed %d bytes, not a SHA-256 digest.', strlen($digest)));
        }
        $encoded = self::SHA256_DIGEST_INFO . $digest;
        if (! openssl_private_encrypt($encoded, $signature, TestSigningKeys::privateKey($this->index))) {
            throw new RuntimeException('OpenSSL could not sign.');
        }

        /** @var string $signature */
        return $signature;
    }

    public function publicPem(): string
    {
        $details = openssl_pkey_get_details(TestSigningKeys::privateKey($this->index));
        /** @var array{key: string} $details */

        return $details['key'];
    }

    public function publicDer(): string
    {
        $base64 = preg_replace('/-----[A-Z ]+-----|\s/', '', $this->publicPem()) ?? '';

        $der = base64_decode($base64, true);

        return $der !== false ? $der : throw new RuntimeException('Unreadable PEM.');
    }

    /**
     * @return array{n: string, e: string} Unsigned big-endian bytes.
     */
    public function numbers(): array
    {
        $details = openssl_pkey_get_details(TestSigningKeys::privateKey($this->index));
        /** @var array{rsa: array{n: string, e: string}} $details */

        return ['n' => $details['rsa']['n'], 'e' => $details['rsa']['e']];
    }

    /**
     * The kid this server publishes the key under: its RFC 7638 thumbprint.
     *
     * @return non-empty-string
     */
    public function kid(): string
    {
        return TestSigningKeys::publicJwk($this->index)->kid;
    }
}
