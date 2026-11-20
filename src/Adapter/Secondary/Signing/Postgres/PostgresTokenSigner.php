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
use Clavia\Application\Port\NoActiveSigningKey;
use Clavia\Application\Port\SecretCipher;
use Clavia\Application\Port\SigningFailed;
use Clavia\Application\Port\SigningKeyReference;
use Clavia\Application\Port\TokenSigner;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Shared\Clock;

/**
 * The `postgres` signing backend: keys kept, sealed, in `oidc_signing_keys`.
 *
 * {@see sign()} is the one place in the codebase that opens a private key. It does so
 * for one signature, only for the key that is active at that moment, and lets go of it
 * when it returns.
 *
 * RS256 is spelled out as what it is — RSASSA-PKCS1-v1_5 over SHA-256 (RFC 7518 §3.3) —
 * because a remote backend has to name the same primitive exactly (AWS KMS calls it
 * `RSASSA_PKCS1_V1_5_SHA_256`), and a mismatch verifies here and nowhere else.
 */
final readonly class PostgresTokenSigner implements TokenSigner
{
    public function __construct(
        private Database $database,
        private SecretCipher $cipher,
        private Clock $clock,
    ) {
    }

    #[\Override]
    public function activeKey(): SigningKeyReference
    {
        /** @var array{kid: non-empty-string, algorithm: string}|null $row */
        $row = $this->database->fetchOne("SELECT kid, algorithm FROM oidc_signing_keys WHERE status = 'active'");
        if ($row === null) {
            throw NoActiveSigningKey::create();
        }

        return new SigningKeyReference($row['kid'], SigningAlgorithm::from($row['algorithm']));
    }

    #[\Override]
    public function sign(SigningKeyReference $key, string $signingInput): string
    {
        /** @var string|null $sealed */
        $sealed = $this->database->fetchValue(
            <<<'SQL'
                SELECT private_key_encrypted FROM oidc_signing_keys
                WHERE kid = :kid AND algorithm = :algorithm AND status = 'active'
                SQL,
            ['kid' => $key->kid, 'algorithm' => $key->algorithm->value],
        );
        if ($sealed === null) {
            throw new SigningFailed(sprintf('Signing key %s is not the active key.', $key->kid));
        }

        // The kid is the associated data: a ciphertext copied from another row fails here.
        $privateKey = openssl_pkey_get_private($this->cipher->decrypt($sealed, $key->kid));
        if ($privateKey === false) {
            throw new SigningFailed(sprintf('Signing key %s could not be read.', $key->kid));
        }

        $algorithm = match ($key->algorithm) {
            SigningAlgorithm::RS256 => OPENSSL_ALGO_SHA256,
        };
        if (! openssl_sign($signingInput, $signature, $privateKey, $algorithm) || $signature === '') {
            throw new SigningFailed('OpenSSL could not sign: ' . (string) openssl_error_string());
        }

        return $signature;
    }

    #[\Override]
    public function publicKeys(): array
    {
        $now = $this->clock->now();

        $published = [];
        foreach (
            $this->database->fetchAll(
                'SELECT ' . SigningKeyRow::COLUMNS . ' FROM oidc_signing_keys ' . SigningKeyRow::ORDER,
            ) as $row
        ) {
            // The domain decides what is still published; the table is a handful of rows.
            $key = SigningKeyRow::hydrate($row);
            if ($key->isPublishedAt($now)) {
                $published[] = $key->publicJwk;
            }
        }

        return $published;
    }
}
