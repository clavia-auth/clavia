<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Saml\Postgres;

use Clavia\Adapter\Secondary\Persistence\PhpDb\Database;
use Clavia\Adapter\Secondary\Persistence\PhpDb\Timestamp;
use Clavia\Adapter\Secondary\Signing\X509\SelfSignedCertificate;
use Clavia\Application\Port\Saml\ServiceProviderKeyStore;
use Clavia\Application\Port\SecretCipher;
use Clavia\Domain\Connection\Saml\ServiceProviderKey;
use Clavia\Domain\Connection\Saml\ServiceProviderKeySet;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyStatus;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyUsage;
use Clavia\Domain\Oidc\PublicJwk;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Shared\RandomSource;
use DateTimeImmutable;
use LogicException;
use OpenSSLAsymmetricKey;
use RuntimeException;

/**
 * The `postgres` backend's service provider keys, in `saml_service_provider_keys`.
 *
 * A pair is made here with OpenSSL: two RSA keys (3072 bits, NIST SP 800-57's 128-bit level), the
 * signing key's certificate signed by itself and the encryption key's by the signing key, then each
 * private half sealed with {@see SecretCipher} under `saml-sp:<kid>` before anything is written. This
 * class never reads a sealed key back: only {@see PostgresServiceProviderKeys} does, to sign and to
 * decrypt.
 */
final readonly class PostgresServiceProviderKeyStore implements ServiceProviderKeyStore
{
    public const int RSA_BITS = 3072;
    public const int VALIDITY_YEARS = 10;

    /**
     * @param non-empty-string $host The sign-in host, named in the certificates.
     * @param positive-int     $bits Tests make smaller keys, faster.
     */
    public function __construct(
        private Database $database,
        private SecretCipher $cipher,
        private RandomSource $random,
        private string $host,
        private int $bits = self::RSA_BITS,
    ) {
    }

    /** The associated data a key is sealed under: a ciphertext moved onto another row does not open. */
    public static function context(string $kid): string
    {
        return 'saml-sp:' . $kid;
    }

    #[\Override]
    public function createPair(ServiceProviderKeyStatus $status, DateTimeImmutable $now): array
    {
        [$signingKey, $signingPem, $signingKid] = $this->keyPair();
        [$encryptionKey, $encryptionPem, $encryptionKid] = $this->keyPair();
        $until = $now->modify(sprintf('+%d years', self::VALIDITY_YEARS));
        $issuer = $this->host . ' SAML SP';
        $sign = static function (string $tbs) use ($signingKey): string {
            if (! openssl_sign($tbs, $signature, $signingKey, OPENSSL_ALGO_SHA256) || $signature === '') {
                throw new RuntimeException('OpenSSL could not sign a certificate.');
            }

            return $signature;
        };
        $signingPublic = self::publicPem($signingKey);
        $signing = ServiceProviderKey::introduce(
            $signingKid,
            ServiceProviderKeyUsage::Signing,
            $status,
            base64_encode(SelfSignedCertificate::build(
                $issuer,
                $issuer,
                $signingPublic,
                $signingPublic,
                ServiceProviderKeyUsage::Signing,
                $this->serial(),
                $now,
                $until,
                $sign,
            )),
            $until,
            $now,
        );
        $encryption = ServiceProviderKey::introduce(
            $encryptionKid,
            ServiceProviderKeyUsage::Encryption,
            $status,
            base64_encode(SelfSignedCertificate::build(
                $issuer . ' encryption',
                $issuer,
                self::publicPem($encryptionKey),
                $signingPublic,
                ServiceProviderKeyUsage::Encryption,
                $this->serial(),
                $now,
                $until,
                $sign,
            )),
            $until,
            $now,
        );

        // Sealed before anything is written: if the cipher is unavailable, nothing is.
        $sealed = [
            $signingKid => $this->cipher->encrypt($signingPem, self::context($signingKid)),
            $encryptionKid => $this->cipher->encrypt($encryptionPem, self::context($encryptionKid)),
        ];
        foreach ([$signing, $encryption] as $key) {
            $this->database->execute(
                <<<'SQL'
                    INSERT INTO saml_service_provider_keys (kid, usage, status, certificate, private_key_encrypted,
                        valid_until, created_at, promoted_at, retired_at)
                    VALUES (:kid, :usage, :status, :certificate, :sealed, :valid_until, :created_at, :promoted_at, NULL)
                    SQL,
                [
                    'kid' => $key->kid,
                    'usage' => $key->usage->value,
                    'status' => $key->status->value,
                    'certificate' => $key->certificate,
                    'sealed' => $sealed[$key->kid],
                    'valid_until' => Timestamp::toDatabase($key->validUntil),
                    'created_at' => Timestamp::toDatabase($key->createdAt),
                    'promoted_at' => Timestamp::toDatabaseOrNull($key->promotedAt),
                ],
            );
        }

        return ['signing' => $signing, 'encryption' => $encryption];
    }

    #[\Override]
    public function lockAll(): ServiceProviderKeySet
    {
        if (! $this->database->inTransaction()) {
            throw new LogicException('The service provider keys can only be locked inside a transaction.');
        }

        return ServiceProviderKeyRow::set($this->database->fetchAll(
            'SELECT ' . ServiceProviderKeyRow::COLUMNS . ' FROM saml_service_provider_keys ORDER BY kid FOR UPDATE',
        ));
    }

    #[\Override]
    public function save(ServiceProviderKey $key): void
    {
        $this->database->execute(
            <<<'SQL'
                UPDATE saml_service_provider_keys
                SET status = :status, promoted_at = :promoted_at, retired_at = :retired_at
                WHERE kid = :kid
                SQL,
            [
                'kid' => $key->kid,
                'status' => $key->status->value,
                'promoted_at' => Timestamp::toDatabaseOrNull($key->promotedAt),
                'retired_at' => Timestamp::toDatabaseOrNull($key->retiredAt),
            ],
        );
    }

    #[\Override]
    public function delete(string $kid): void
    {
        $this->database->execute('DELETE FROM saml_service_provider_keys WHERE kid = :kid', ['kid' => $kid]);
    }

    #[\Override]
    public function all(): ServiceProviderKeySet
    {
        return ServiceProviderKeyRow::set($this->database->fetchAll(
            'SELECT ' . ServiceProviderKeyRow::COLUMNS . ' FROM saml_service_provider_keys',
        ));
    }

    /** @return array{0: OpenSSLAsymmetricKey, 1: non-empty-string, 2: non-empty-string} The key, its PEM, its kid. */
    private function keyPair(): array
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => $this->bits]);
        if ($key === false || ! openssl_pkey_export($key, $pem) || $pem === '') {
            throw new RuntimeException('OpenSSL could not generate a key pair: ' . (string) openssl_error_string());
        }
        $details = openssl_pkey_get_details($key);
        /** @var array{rsa?: array{n?: string, e?: string}}|false $details */
        $rsa = $details === false ? [] : ($details['rsa'] ?? []);
        if (! isset($rsa['n'], $rsa['e'])) {
            throw new RuntimeException('OpenSSL did not describe the RSA key it generated.');
        }

        // The RFC 7638 thumbprint, as token keys are named.
        return [$key, $pem, PublicJwk::rsa($rsa['n'], $rsa['e'], SigningAlgorithm::RS256)->kid];
    }

    /** @return non-empty-string */
    private static function publicPem(OpenSSLAsymmetricKey $key): string
    {
        $details = openssl_pkey_get_details($key);
        /** @var mixed $pem */
        $pem = is_array($details) ? ($details['key'] ?? null) : null;

        return is_string($pem) && $pem !== '' ? $pem : throw new RuntimeException('No public key.');
    }

    /** @return non-empty-string 16 random bytes, positive. */
    private function serial(): string
    {
        $bytes = $this->random->bytes(16);

        return chr((ord($bytes[0]) & 0x7F) | 0x01) . substr($bytes, 1);
    }
}
