<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Signing\Postgres;

use Clavia\Adapter\Secondary\Persistence\PhpDb\Database;
use Clavia\Adapter\Secondary\Persistence\PhpDb\Jsonb;
use Clavia\Adapter\Secondary\Persistence\PhpDb\Timestamp;
use Clavia\Application\Port\SecretCipher;
use Clavia\Application\Port\SigningKeyStore;
use Clavia\Domain\Oidc\PublicJwk;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Oidc\SigningKey;
use DateTimeImmutable;
use LogicException;
use RuntimeException;

/**
 * The `postgres` backend's keys, in `oidc_signing_keys`.
 *
 * A key pair is generated here with OpenSSL — RSA-2048 for RS256 — and the private half
 * is sealed with {@see SecretCipher} under the key's own `kid` before it is written, so
 * a database backup alone yields no signing key, and a ciphertext moved onto another
 * row does not open. This class writes the sealed value and never reads it back; the
 * only code that does is {@see PostgresTokenSigner::sign()}.
 */
final readonly class PostgresSigningKeyStore implements SigningKeyStore
{
    /** NIST SP 800-57 puts RSA-2048 at 112-bit security, acceptable until 2030. */
    private const int RSA_BITS = 2048;

    public function __construct(
        private Database $database,
        private SecretCipher $cipher,
    ) {
    }

    #[\Override]
    public function create(SigningAlgorithm $algorithm, DateTimeImmutable $now): SigningKey
    {
        $pair = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => self::RSA_BITS]);
        if ($pair === false || ! openssl_pkey_export($pair, $privatePem)) {
            throw new RuntimeException('OpenSSL could not generate a key pair: ' . (string) openssl_error_string());
        }

        $details = openssl_pkey_get_details($pair);
        /** @var array{rsa?: array{n?: string, e?: string}}|false $details */
        $rsa = $details === false ? [] : ($details['rsa'] ?? []);
        if (! isset($rsa['n'], $rsa['e'])) {
            throw new RuntimeException('OpenSSL did not describe the RSA key it generated.');
        }

        $key = SigningKey::activate(PublicJwk::rsa($rsa['n'], $rsa['e'], $algorithm), $now);

        // Sealed before anything is written: if the cipher is unavailable, nothing is.
        $sealed = $this->cipher->encrypt($privatePem, $key->kid());

        $this->database->execute(
            <<<'SQL'
                INSERT INTO oidc_signing_keys (
                    kid, algorithm, private_key_encrypted, public_jwk, status, created_at, retired_at, published_until
                ) VALUES (
                    :kid, :algorithm, :private_key_encrypted, CAST(:public_jwk AS jsonb), :status, :created_at,
                    NULL, NULL
                )
                SQL,
            [
                'kid' => $key->kid(),
                'algorithm' => $key->algorithm()->value,
                'private_key_encrypted' => $sealed,
                'public_jwk' => Jsonb::encode($key->publicJwk->toArray()),
                'status' => $key->status()->value,
                'created_at' => Timestamp::toDatabase($key->createdAt),
            ],
        );

        return $key;
    }

    #[\Override]
    public function lockActive(): ?SigningKey
    {
        if (! $this->database->inTransaction()) {
            throw new LogicException('The active signing key can only be locked inside a transaction.');
        }

        $row = $this->database->fetchOne(
            'SELECT ' . SigningKeyRow::COLUMNS . " FROM oidc_signing_keys WHERE status = 'active' FOR UPDATE",
        );

        return $row === null ? null : SigningKeyRow::hydrate($row);
    }

    #[\Override]
    public function save(SigningKey $key): void
    {
        $this->database->execute(
            <<<'SQL'
                UPDATE oidc_signing_keys
                SET status = :status, retired_at = :retired_at, published_until = :published_until
                WHERE kid = :kid
                SQL,
            [
                'kid' => $key->kid(),
                'status' => $key->status()->value,
                'retired_at' => Timestamp::toDatabaseOrNull($key->retiredAt()),
                'published_until' => Timestamp::toDatabaseOrNull($key->publishedUntil()),
            ],
        );
    }

    #[\Override]
    public function all(): array
    {
        return array_map(
            SigningKeyRow::hydrate(...),
            $this->database->fetchAll(
                'SELECT ' . SigningKeyRow::COLUMNS . ' FROM oidc_signing_keys ' . SigningKeyRow::ORDER,
            ),
        );
    }
}
