<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

use Clavia\Adapter\Secondary\Crypto\AesGcmSecretCipher;
use Clavia\Adapter\Secondary\Persistence\PhpDb\Database;
use Clavia\Adapter\Secondary\Persistence\PhpDb\Jsonb;
use Clavia\Adapter\Secondary\Persistence\PhpDb\Timestamp;
use Clavia\Adapter\Secondary\System\SystemRandomSource;
use Clavia\Domain\Oidc\PublicJwk;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Oidc\SigningKey;
use DateTimeImmutable;
use OpenSSLAsymmetricKey;
use RuntimeException;

/**
 * RSA key pairs for tests, generated once per run and reused: generating a 2048-bit key
 * takes long enough that doing it per test would dominate the suite.
 *
 * {@see install()} puts one in `oidc_signing_keys` exactly as the `postgres` backend
 * would — sealed with the test encryption key, the kid as associated data — so that an
 * acceptance test can issue ID tokens without generating anything.
 */
final class TestSigningKeys
{
    /** @var array<int, string> PKCS #8 PEM, by index. */
    private static array $pems = [];

    private function __construct()
    {
    }

    /** The private key number `$index`, as PKCS #8 PEM. */
    public static function pem(int $index = 0): string
    {
        if (! isset(self::$pems[$index])) {
            $pair = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
            if ($pair === false || ! openssl_pkey_export($pair, $pem)) {
                throw new RuntimeException('OpenSSL could not generate a test key.');
            }
            self::$pems[$index] = $pem;
        }

        return self::$pems[$index];
    }

    public static function privateKey(int $index = 0): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_get_private(self::pem($index));

        return $key !== false ? $key : throw new RuntimeException('Unreadable test key.');
    }

    public static function publicJwk(int $index = 0, SigningAlgorithm $algorithm = SigningAlgorithm::RS256): PublicJwk
    {
        $details = openssl_pkey_get_details(self::privateKey($index));
        /** @var array{rsa: array{n: string, e: string}} $details */

        return PublicJwk::rsa($details['rsa']['n'], $details['rsa']['e'], $algorithm);
    }

    /**
     * Store key number `$index` as the active key of the `postgres` backend.
     */
    public static function install(
        Database $database,
        int $index = 0,
        DateTimeImmutable $createdAt = new DateTimeImmutable('2026-01-01T00:00:00Z'),
    ): SigningKey {
        $key = SigningKey::activate(self::publicJwk($index), $createdAt);
        $cipher = new AesGcmSecretCipher(TestEnvironment::SECRET_ENCRYPTION_KEY, new SystemRandomSource());

        $database->execute(
            <<<'SQL'
                INSERT INTO oidc_signing_keys (kid, algorithm, private_key_encrypted, public_jwk, status, created_at)
                VALUES (:kid, :algorithm, :sealed, CAST(:public_jwk AS jsonb), 'active', :created_at)
                SQL,
            [
                'kid' => $key->kid(),
                'algorithm' => $key->algorithm()->value,
                'sealed' => $cipher->encrypt(self::pem($index), $key->kid()),
                'public_jwk' => Jsonb::encode($key->publicJwk->toArray()),
                'created_at' => Timestamp::toDatabase($createdAt),
            ],
        );

        return $key;
    }
}
