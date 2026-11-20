<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Crypto;

use Clavia\Adapter\Secondary\Crypto\AesGcmSecretCipher;
use Clavia\Application\Port\DecryptionFailed;
use Clavia\Application\Port\EncryptionUnavailable;
use Clavia\Application\Port\SecretCipher;
use ClaviaTest\Support\Contract\SecretCipherContract;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\Attributes\DataProvider;

final class AesGcmSecretCipherTest extends SecretCipherContract
{
    /** base64 of the bytes 0x00…0x1f. */
    private const string KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=';

    #[\Override]
    protected function cipher(): SecretCipher
    {
        return new AesGcmSecretCipher(self::KEY, new SeededRandomSource());
    }

    /**
     * A known-answer vector: AES-256-GCM under this key, nonce 0x64…0x6f and the context
     * below. Stored secrets must stay readable, so a change to the primitive, the layout
     * or the encoding fails here rather than in production.
     */
    public function testAKnownAnswerVectorDecrypts(): void
    {
        $vector = 'ZGVmZ2hpamtsbW5vK3SsFByKIr5WDS2bv0UInDa2Y3jyTIAGxqHALdtBJdy0Gd9U3e8yyx6NGSe49kdHisrrmpc=';

        self::assertSame(
            'correct horse battery staple — 🔑',
            $this->cipher()->decrypt($vector, 'kid:2026-11-key'),
        );
    }

    public function testTheTokenIsNonceThenCiphertextThenTag(): void
    {
        $plaintext = 'sixteen byte msg';
        $raw = (string) base64_decode($this->cipher()->encrypt($plaintext, 'ctx'), true);

        self::assertSame(
            AesGcmSecretCipher::NONCE_BYTES + strlen($plaintext) + AesGcmSecretCipher::TAG_BYTES,
            strlen($raw),
        );
        self::assertSame(new SeededRandomSource()->bytes(AesGcmSecretCipher::NONCE_BYTES), substr($raw, 0, 12));
    }

    public function testAnotherKeyCannotReadIt(): void
    {
        $sealed = $this->cipher()->encrypt('a secret value', 'ctx');
        $otherKey = new AesGcmSecretCipher(base64_encode(str_repeat("\x01", 32)), new SeededRandomSource());

        $this->expectException(DecryptionFailed::class);

        $otherKey->decrypt($sealed, 'ctx');
    }

    public function testATruncatedTagIsRefused(): void
    {
        $raw = (string) base64_decode($this->cipher()->encrypt('a secret value', 'ctx'), true);

        $this->expectException(DecryptionFailed::class);

        // GCM would accept a shorter tag if asked to; the full 16 bytes are always required.
        $this->cipher()->decrypt(base64_encode(substr($raw, 0, -4)), 'ctx');
    }

    /**
     * @return iterable<string, array{string|null, string}>
     */
    public static function unusableKeys(): iterable
    {
        yield 'unset' => [null, 'CLAVIA_SECRET_ENCRYPTION_KEY is not set'];
        yield 'empty' => ['', 'CLAVIA_SECRET_ENCRYPTION_KEY is not set'];
        yield 'not base64' => ['not base64!', 'must be base64-encoded'];
        yield 'a 16-byte key' => [base64_encode(str_repeat('k', 16)), 'must decode to 32 bytes, got 16'];
        yield 'a 33-byte key' => [base64_encode(str_repeat('k', 33)), 'must decode to 32 bytes, got 33'];
    }

    #[DataProvider('unusableKeys')]
    public function testWithoutAUsableKeyItRefusesRatherThanStoreInTheClear(?string $key, string $reason): void
    {
        $cipher = new AesGcmSecretCipher($key, new SeededRandomSource());

        foreach (['encrypt', 'decrypt'] as $operation) {
            try {
                $cipher->{$operation}('anything', 'ctx');
                self::fail(sprintf('%s succeeded without a usable key.', $operation));
            } catch (EncryptionUnavailable $refusal) {
                self::assertStringContainsString($reason, $refusal->getMessage());
            }
        }
    }

    public function testBuildingItWithoutAKeyIsNotAnError(): void
    {
        // A deployment on a remote signing backend with no TOTP runs without a key.
        $this->expectNotToPerformAssertions();

        new AesGcmSecretCipher(null, new SeededRandomSource());
    }
}
