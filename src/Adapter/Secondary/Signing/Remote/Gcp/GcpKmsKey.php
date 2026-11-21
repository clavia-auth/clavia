<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Signing\Remote\Gcp;

use Clavia\Adapter\Secondary\Signing\Remote\AccessTokens;
use Clavia\Adapter\Secondary\Signing\Remote\InvalidKeyReference;
use Clavia\Adapter\Secondary\Signing\Remote\JsonApi;
use Clavia\Adapter\Secondary\Signing\Remote\RemoteSigningKey;
use Clavia\Adapter\Secondary\Signing\Remote\SubjectPublicKeyInfo;
use Clavia\Application\Port\SigningFailed;
use Clavia\Domain\Oidc\PublicJwk;
use Clavia\Domain\Oidc\SigningAlgorithm;

/**
 * A key version in Google Cloud KMS (`CLAVIA_SIGNING_BACKEND=gcp-kms`), through its REST
 * API: `asymmetricSign` and `getPublicKey`, the two calls `roles/cloudkms.signerVerifier`
 * allows.
 *
 * Name the **key version** (`…/cryptoKeys/k/cryptoKeyVersions/1`): a key's primary
 * version can change, and with it the key under every token issued. Create the key with
 * purpose `ASYMMETRIC_SIGN` and an `RSA_SIGN_PKCS1_*_SHA256` algorithm.
 *
 * Cloud KMS signs a digest. Both directions are checked with the CRC32C checksums it
 * offers: the digest sent (`verifiedDigestCrc32c`), the signature and the public key
 * received — corruption in transit is reported, not signed or published.
 */
final readonly class GcpKmsKey implements RemoteSigningKey
{
    public const string API = 'https://cloudkms.googleapis.com/v1/';

    private const string KEY_VERSION
        = '/^projects\/[^\/]+\/locations\/[^\/]+\/keyRings\/[^\/]+\/cryptoKeys\/[^\/]+\/cryptoKeyVersions\/[0-9]+$/D';

    /** @var non-empty-string */
    private string $reference;

    /**
     * @throws InvalidKeyReference When `$reference` is not a key version's resource name.
     */
    public function __construct(
        private JsonApi $api,
        private AccessTokens $tokens,
        string $reference,
    ) {
        if (preg_match(self::KEY_VERSION, $reference) !== 1) {
            throw new InvalidKeyReference(sprintf(
                'A Google Cloud KMS signing key is named by its key version, '
                . "'projects/…/locations/…/keyRings/…/cryptoKeys/…/cryptoKeyVersions/N', not %s.",
                var_export($reference, true),
            ));
        }
        assert($reference !== '');

        $this->reference = $reference;
    }

    /** Whether Cloud KMS's algorithm `$name` is the primitive `$algorithm` names. */
    public static function signsWith(string $name, SigningAlgorithm $algorithm): bool
    {
        return match ($algorithm) {
            SigningAlgorithm::RS256 => preg_match('/^RSA_SIGN_PKCS1_(2048|3072|4096)_SHA256$/D', $name) === 1,
        };
    }

    #[\Override]
    public function reference(): string
    {
        return $this->reference;
    }

    #[\Override]
    public function sign(string $digest, SigningAlgorithm $algorithm): string
    {
        $answer = $this->api->postJson(
            self::API . $this->reference . ':asymmetricSign',
            [
                'digest' => [$algorithm->hashAlgorithm() => base64_encode($digest)],
                'digestCrc32c' => self::crc32c($digest),
            ],
            $this->authorization(),
        );

        if (($answer['verifiedDigestCrc32c'] ?? null) !== true || ($answer['name'] ?? null) !== $this->reference) {
            throw new SigningFailed('Google Cloud KMS did not confirm the digest it signed.');
        }
        /** @var mixed $encoded */
        $encoded = $answer['signature'] ?? null;
        $signature = is_string($encoded) ? base64_decode($encoded, true) : false;
        /** @var mixed $checksum */
        $checksum = $answer['signatureCrc32c'] ?? null;
        if ($signature === false || $signature === '' || $checksum !== self::crc32c($signature)) {
            throw new SigningFailed('Google Cloud KMS returned a signature that does not match its checksum.');
        }

        return $signature;
    }

    #[\Override]
    public function publicKey(SigningAlgorithm $algorithm): PublicJwk
    {
        $answer = $this->api->get(self::API . $this->reference . '/publicKey', $this->authorization());

        $name = $answer['algorithm'] ?? null;
        if (! is_string($name) || ! self::signsWith($name, $algorithm)) {
            throw new SigningFailed(sprintf(
                'The Google Cloud KMS key version %s does not sign with %s.',
                $this->reference,
                $algorithm->value,
            ));
        }
        $pem = $answer['pem'] ?? null;
        if (! is_string($pem) || ($answer['pemCrc32c'] ?? null) !== self::crc32c($pem)) {
            throw new SigningFailed('Google Cloud KMS returned a public key that does not match its checksum.');
        }

        return SubjectPublicKeyInfo::toJwk($pem, $algorithm);
    }

    /**
     * @return array{Authorization: string}
     */
    private function authorization(): array
    {
        return ['Authorization' => 'Bearer ' . $this->tokens->token()];
    }

    /** CRC32C as Cloud KMS sends it: an int64, which JSON carries as a decimal string. */
    private static function crc32c(string $bytes): string
    {
        return (string) hexdec(hash('crc32c', $bytes));
    }
}
