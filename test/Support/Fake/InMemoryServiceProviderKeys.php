<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Adapter\Secondary\Signing\X509\SelfSignedCertificate;
use Clavia\Application\Port\DecryptionFailed;
use Clavia\Application\Port\Saml\OaepDigest;
use Clavia\Application\Port\Saml\ServiceProviderKeys;
use Clavia\Application\Port\Saml\ServiceProviderKeyStore;
use Clavia\Application\Port\SigningFailed;
use Clavia\Domain\Connection\Saml\ServiceProviderKey;
use Clavia\Domain\Connection\Saml\ServiceProviderKeySet;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyStatus;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyUsage;
use Clavia\Domain\Oidc\PublicJwk;
use Clavia\Domain\Oidc\SigningAlgorithm;
use DateTimeImmutable;
use LogicException;

/**
 * Both SAML key ports in memory, with real RSA keys (2048 bits, for speed) and real certificates, so
 * it passes {@see \ClaviaTest\Support\Contract\ServiceProviderKeysContract} as the PostgreSQL backend
 * does. The private halves stay in this object and never leave it.
 */
final class InMemoryServiceProviderKeys implements ServiceProviderKeys, ServiceProviderKeyStore
{
    /** @var array<string, ServiceProviderKey> */
    private array $keys = [];

    /** @var array<string, string> Private PEMs, by kid. */
    private array $private = [];

    #[\Override]
    public function createPair(ServiceProviderKeyStatus $status, DateTimeImmutable $now): array
    {
        [$signingPem, $signingPublic, $signingKid] = self::keyPair();
        [$encryptionPem, $encryptionPublic, $encryptionKid] = self::keyPair();
        $until = $now->modify('+10 years');
        $sign = static function (string $tbs) use ($signingPem): string {
            openssl_sign($tbs, $signature, $signingPem, OPENSSL_ALGO_SHA256);

            return $signature !== '' ? $signature : throw new LogicException('No signature.');
        };
        $certificate = static fn (string $subject, string $public, ServiceProviderKeyUsage $usage): string
            => base64_encode(SelfSignedCertificate::build(
                $subject,
                'test SAML SP',
                $public !== '' ? $public : throw new LogicException('No key.'),
                $signingPublic,
                $usage,
                random_bytes(8) | "\x01",
                $now,
                $until,
                $sign,
            ));
        $pair = [
            'signing' => ServiceProviderKey::introduce(
                $signingKid,
                ServiceProviderKeyUsage::Signing,
                $status,
                $certificate('test SAML SP', $signingPublic, ServiceProviderKeyUsage::Signing),
                $until,
                $now,
            ),
            'encryption' => ServiceProviderKey::introduce(
                $encryptionKid,
                ServiceProviderKeyUsage::Encryption,
                $status,
                $certificate('test SAML SP encryption', $encryptionPublic, ServiceProviderKeyUsage::Encryption),
                $until,
                $now,
            ),
        ];
        // As the database's unique indexes do.
        ServiceProviderKeySet::of([...array_values($this->keys), ...array_values($pair)]);
        foreach ([$signingKid => $signingPem, $encryptionKid => $encryptionPem] as $kid => $pem) {
            $this->private[$kid] = $pem;
        }
        $this->keys[$signingKid] = $pair['signing'];
        $this->keys[$encryptionKid] = $pair['encryption'];

        return $pair;
    }

    #[\Override]
    public function lockAll(): ServiceProviderKeySet
    {
        return $this->all();
    }

    #[\Override]
    public function save(ServiceProviderKey $key): void
    {
        if (isset($this->keys[$key->kid])) {
            $this->keys[$key->kid] = $key;
        }
    }

    #[\Override]
    public function delete(string $kid): void
    {
        unset($this->keys[$kid], $this->private[$kid]);
    }

    #[\Override]
    public function all(): ServiceProviderKeySet
    {
        return ServiceProviderKeySet::of(array_values($this->keys));
    }

    #[\Override]
    public function certificates(): ServiceProviderKeySet
    {
        return $this->all();
    }

    #[\Override]
    public function sign(string $kid, string $data): string
    {
        $key = $this->keys[$kid] ?? null;
        if ($key === null || ! $key->signs()) {
            throw new SigningFailed(sprintf('Service provider key %s is not the current signing key.', $kid));
        }
        openssl_sign($data, $signature, $this->private[$kid], OPENSSL_ALGO_SHA256);

        return $signature !== '' ? $signature : throw new SigningFailed('No signature.');
    }

    #[\Override]
    public function decryptKey(string $kid, string $encryptedKey, OaepDigest $digest): string
    {
        $key = $this->keys[$kid] ?? null;
        if (
            $key === null
            || ! $key->decrypts()
            || ! @openssl_private_decrypt(
                $encryptedKey,
                $decrypted,
                $this->private[$kid],
                OPENSSL_PKCS1_OAEP_PADDING,
                $digest->value,
            )
            || $decrypted === ''
        ) {
            throw new DecryptionFailed('The content key does not decrypt.');
        }

        return $decrypted;
    }

    /** @return array{0: string, 1: string, 2: non-empty-string} */
    private static function keyPair(): array
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        if ($key === false || ! openssl_pkey_export($key, $pem)) {
            throw new LogicException('No key.');
        }
        $details = openssl_pkey_get_details($key);
        /** @var array{key: string, rsa: array{n: string, e: string}} $details */

        $kid = PublicJwk::rsa($details['rsa']['n'], $details['rsa']['e'], SigningAlgorithm::RS256)->kid;

        return [$pem, $details['key'], $kid];
    }
}
