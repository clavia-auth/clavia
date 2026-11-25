<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Saml\Remote;

use Clavia\Adapter\Secondary\Signing\Remote\RemoteSigningKey;
use Clavia\Adapter\Secondary\Signing\X509\SelfSignedCertificate;
use Clavia\Application\Port\DecryptionFailed;
use Clavia\Application\Port\Saml\OaepDigest;
use Clavia\Application\Port\Saml\ServiceProviderKeys;
use Clavia\Application\Port\SigningFailed;
use Clavia\Domain\Connection\Saml\ServiceProviderKey;
use Clavia\Domain\Connection\Saml\ServiceProviderKeySet;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyStatus;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyUsage;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use DateTimeImmutable;
use Throwable;

/**
 * The SAML service provider's keys in a KMS (AWS KMS, Google Cloud KMS, Azure Key Vault): they never
 * exist here (docs/design/saml-connections.md §2, §3). The settings name them and their place in the
 * rotation, which is the operator's: a next pair, then current, the old encryption key retired.
 *
 * - **Signing** goes to the KMS as a SHA-256 digest (RSASSA-PKCS1-v1_5, the token signers' clients),
 *   and the signature is verified with the key's public half before it is returned.
 * - **Decrypting** hands the KMS the content key alone, with RSA-OAEP; every failure is the same.
 * - **Certificates** are built once through the KMS (the encryption key's signed by the signing key
 *   of its pair; a retired one's by the current signing key) and kept by reference, so listing the
 *   keys or serving the metadata never calls the KMS again.
 */
final readonly class RemoteServiceProviderKeys implements ServiceProviderKeys
{
    /**
     * @param list<RemoteDecryptionKey> $retired
     * @param non-empty-string          $host The sign-in host, named in the certificates.
     */
    public function __construct(
        private RemoteSigningKey $signing,
        private RemoteDecryptionKey $encryption,
        private ?RemoteSigningKey $nextSigning,
        private ?RemoteDecryptionKey $nextEncryption,
        private array $retired,
        private CertificateCache $cache,
        private Clock $clock,
        private RandomSource $random,
        private string $host,
    ) {
    }

    #[\Override]
    public function certificates(): ServiceProviderKeySet
    {
        $keys = [
            $this->signingKey($this->signing, ServiceProviderKeyStatus::Current),
            $this->encryptionKey($this->encryption, ServiceProviderKeyStatus::Current, $this->signing),
        ];
        if ($this->nextSigning !== null && $this->nextEncryption !== null) {
            $keys[] = $this->signingKey($this->nextSigning, ServiceProviderKeyStatus::Next);
            $keys[] = $this->encryptionKey($this->nextEncryption, ServiceProviderKeyStatus::Next, $this->nextSigning);
        }
        foreach ($this->retired as $key) {
            $keys[] = $this->encryptionKey($key, ServiceProviderKeyStatus::Retired, $this->signing);
        }

        return ServiceProviderKeySet::of($keys);
    }

    #[\Override]
    public function sign(string $kid, string $data): string
    {
        $current = $this->signingKey($this->signing, ServiceProviderKeyStatus::Current);
        if ($kid !== $current->kid) {
            throw new SigningFailed(sprintf('Service provider key %s is not the current signing key.', $kid));
        }

        return $this->signedBy($this->signing, $data, self::publicKeyOf($current));
    }

    #[\Override]
    public function decryptKey(string $kid, string $encryptedKey, OaepDigest $digest): string
    {
        $candidates = [
            [$this->encryption, ServiceProviderKeyStatus::Current, $this->signing],
            ...($this->nextEncryption !== null && $this->nextSigning !== null
                ? [[$this->nextEncryption, ServiceProviderKeyStatus::Next, $this->nextSigning]]
                : []),
            ...array_map(
                fn (RemoteDecryptionKey $key): array => [$key, ServiceProviderKeyStatus::Retired, $this->signing],
                $this->retired,
            ),
        ];
        foreach ($candidates as [$key, $status, $issuer]) {
            try {
                if ($this->encryptionKey($key, $status, $issuer)->kid !== $kid) {
                    continue;
                }
                $contentKey = $key->decrypt($encryptedKey, $digest);
            } catch (Throwable $failed) {
                throw new DecryptionFailed('The content key does not decrypt.', previous: $failed);
            }

            return $contentKey;
        }

        throw new DecryptionFailed('The content key does not decrypt.');
    }

    private function signingKey(RemoteSigningKey $key, ServiceProviderKeyStatus $status): ServiceProviderKey
    {
        $cached = $this->cache->get($key->reference());
        if ($cached === null) {
            $pem = RsaPublicKey::fromJwk($key->publicKey(SigningAlgorithm::RS256));
            $cached = $this->build($pem, ServiceProviderKeyUsage::Signing, $key, $pem);
            $this->cache->put($key->reference(), $cached);
        }

        return self::key($cached, ServiceProviderKeyUsage::Signing, $status);
    }

    private function encryptionKey(
        RemoteDecryptionKey $key,
        ServiceProviderKeyStatus $status,
        RemoteSigningKey $issuer,
    ): ServiceProviderKey {
        $cached = $this->cache->get($key->reference());
        if ($cached === null) {
            $issuerPem = self::publicKeyOf($this->signingKey($issuer, ServiceProviderKeyStatus::Current));
            $cached = $this->build($key->publicKeyPem(), ServiceProviderKeyUsage::Encryption, $issuer, $issuerPem);
            $this->cache->put($key->reference(), $cached);
        }

        return self::key($cached, ServiceProviderKeyUsage::Encryption, $status);
    }

    private function build(
        string $publicPem,
        ServiceProviderKeyUsage $usage,
        RemoteSigningKey $issuer,
        string $issuerPem,
    ): CachedCertificate {
        $now = $this->clock->now();
        $until = $now->modify('+10 years');
        $name = $this->host . ' SAML SP';
        $der = SelfSignedCertificate::build(
            $usage === ServiceProviderKeyUsage::Signing ? $name : $name . ' encryption',
            $name,
            $publicPem,
            $issuerPem,
            $usage,
            $this->serial(),
            $now,
            $until,
            fn (string $tbs): string => $this->signedBy($issuer, $tbs, $issuerPem),
        );

        return new CachedCertificate(RsaPublicKey::kid($publicPem), $usage, base64_encode($der), $until, $now);
    }

    /**
     * The KMS's signature over SHA-256 of `$data`, verified with the key's public half before it is
     * used, as the token signers do.
     *
     * @return non-empty-string
     */
    private function signedBy(RemoteSigningKey $key, string $data, string $pem): string
    {
        $signature = $key->sign(hash('sha256', $data, true), SigningAlgorithm::RS256);
        if (openssl_verify($data, $signature, $pem, OPENSSL_ALGO_SHA256) !== 1) {
            throw new SigningFailed(
                'The signature the KMS returned does not verify with its public key: the key, its algorithm or '
                . 'the service is not what this server expects.',
            );
        }

        return $signature;
    }

    private static function key(
        CachedCertificate $cached,
        ServiceProviderKeyUsage $usage,
        ServiceProviderKeyStatus $status,
    ): ServiceProviderKey {
        return ServiceProviderKey::reconstitute(
            $cached->kid,
            $usage,
            $status,
            $cached->certificate,
            $cached->validUntil,
            $cached->createdAt,
            $status === ServiceProviderKeyStatus::Next ? null : $cached->createdAt,
            $status === ServiceProviderKeyStatus::Retired ? $cached->createdAt : null,
        );
    }

    /** The public key a certificate this class built carries. */
    private static function publicKeyOf(ServiceProviderKey $key): string
    {
        $pem = SelfSignedCertificate::pem((string) base64_decode($key->certificate, true));
        $public = openssl_pkey_get_public($pem);
        $details = $public === false ? false : openssl_pkey_get_details($public);
        /** @var mixed $key */
        $key = is_array($details) ? ($details['key'] ?? null) : null;

        return is_string($key) ? $key : throw new SigningFailed('A cached certificate does not read.');
    }

    /** @return non-empty-string 16 random bytes, positive. */
    private function serial(): string
    {
        $bytes = $this->random->bytes(16);

        return chr((ord($bytes[0]) & 0x7F) | 0x01) . substr($bytes, 1);
    }
}
