<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Infrastructure\Crypto;

use Clavia\Application\Port\DecryptionFailed;
use Clavia\Application\Port\EncryptionUnavailable;
use Clavia\Application\Port\SecretCipher;
use Clavia\Domain\Shared\RandomSource;

/**
 * AES-256-GCM with the key from `CLAVIA_SECRET_ENCRYPTION_KEY`.
 *
 * The stored token is `base64(nonce ‖ ciphertext ‖ tag)` — a 12-byte nonce, then the
 * ciphertext, then the 16-byte tag — which is byte-compatible with what the Python
 * implementation wrote.
 *
 * The key is checked when it is first needed, not when this object is built: a
 * deployment on a remote signing backend with no TOTP legitimately runs without one,
 * and the operations that do need it must refuse loudly rather than degrade.
 */
final readonly class AesGcmSecretCipher implements SecretCipher
{
    private const string ALGORITHM = 'aes-256-gcm';

    /** AES-256. Anything else is refused rather than stretched, so a truncated variable fails loudly. */
    public const int KEY_BYTES = 32;

    /** GCM's standard nonce length: the size the mode is optimised for. */
    public const int NONCE_BYTES = 12;

    public const int TAG_BYTES = 16;

    /**
     * @param string|null $encodedKey The configured key: base64 of 32 bytes, or null when unset.
     */
    public function __construct(
        #[\SensitiveParameter] private ?string $encodedKey,
        private RandomSource $random,
    ) {
    }

    #[\Override]
    public function encrypt(#[\SensitiveParameter] string $plaintext, string $context): string
    {
        $key = $this->key();
        $nonce = $this->random->bytes(self::NONCE_BYTES);
        $tag = '';

        $sealed = openssl_encrypt(
            $plaintext,
            self::ALGORITHM,
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $context,
            self::TAG_BYTES,
        );

        if ($sealed === false || strlen($tag) !== self::TAG_BYTES) {
            throw new EncryptionUnavailable('The encryption backend refused to encrypt.');
        }

        return base64_encode($nonce . $sealed . $tag);
    }

    #[\Override]
    public function decrypt(string $ciphertext, string $context): string
    {
        $key = $this->key();

        $raw = base64_decode($ciphertext, true);
        if ($raw === false) {
            throw new DecryptionFailed('not valid base64');
        }
        if (strlen($raw) < self::NONCE_BYTES + self::TAG_BYTES) {
            throw new DecryptionFailed('ciphertext is too short to contain a nonce and a tag');
        }

        $opened = openssl_decrypt(
            substr($raw, self::NONCE_BYTES, -self::TAG_BYTES),
            self::ALGORITHM,
            $key,
            OPENSSL_RAW_DATA,
            substr($raw, 0, self::NONCE_BYTES),
            substr($raw, -self::TAG_BYTES),
            $context,
        );

        if ($opened === false) {
            // One error for a wrong key, a tampered ciphertext and a mismatched context
            // alike. GCM cannot tell them apart, and neither should we.
            throw new DecryptionFailed('authentication failed');
        }

        return $opened;
    }

    /**
     * @return non-empty-string
     *
     * @throws EncryptionUnavailable
     */
    private function key(): string
    {
        if ($this->encodedKey === null || $this->encodedKey === '') {
            throw new EncryptionUnavailable(
                'CLAVIA_SECRET_ENCRYPTION_KEY is not set. Generate one with `clavia secrets:generate-key` '
                . 'and add it to .env.',
            );
        }

        $material = base64_decode($this->encodedKey, true);
        if ($material === false) {
            throw new EncryptionUnavailable('CLAVIA_SECRET_ENCRYPTION_KEY must be base64-encoded.');
        }
        if (strlen($material) !== self::KEY_BYTES) {
            throw new EncryptionUnavailable(sprintf(
                'CLAVIA_SECRET_ENCRYPTION_KEY must decode to %d bytes, got %d.',
                self::KEY_BYTES,
                strlen($material),
            ));
        }
        assert($material !== '');

        return $material;
    }
}
