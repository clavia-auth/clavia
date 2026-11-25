<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Saml\Remote;

use Aws\Exception\AwsException;
use Aws\Exception\CredentialsException;
use Aws\Kms\KmsClient;
use Aws\Result;
use Clavia\Adapter\Secondary\Signing\Remote\Aws\AwsKmsKey;
use Clavia\Adapter\Secondary\Signing\Remote\InvalidKeyReference;
use Clavia\Application\Port\DecryptionFailed;
use Clavia\Application\Port\Saml\OaepDigest;
use Closure;

/**
 * An AWS KMS `ENCRYPT_DECRYPT` RSA key: `Decrypt` with `RSAES_OAEP_SHA_1` or `RSAES_OAEP_SHA_256`
 * (KMS's names for OAEP with MGF1 over the same digest), named as a signing key is.
 */
final readonly class AwsKmsDecryptionKey implements RemoteDecryptionKey
{
    /** @var non-empty-string */
    private string $reference;

    /** @throws InvalidKeyReference */
    public function __construct(private KmsClient $client, string $reference)
    {
        $this->reference = AwsKmsKey::checked($reference);
    }

    public static function algorithmName(OaepDigest $digest): string
    {
        return match ($digest) {
            OaepDigest::Sha1 => 'RSAES_OAEP_SHA_1',
            OaepDigest::Sha256 => 'RSAES_OAEP_SHA_256',
        };
    }

    #[\Override]
    public function reference(): string
    {
        return $this->reference;
    }

    #[\Override]
    public function publicKeyPem(): string
    {
        $result = $this->call(fn (): Result => $this->client->getPublicKey(['KeyId' => $this->reference]));
        /** @var mixed $algorithms */
        $algorithms = $result['EncryptionAlgorithms'] ?? [];
        /** @var mixed $der */
        $der = $result['PublicKey'] ?? null;
        if (
            ($result['KeyUsage'] ?? null) !== 'ENCRYPT_DECRYPT'
            || ! is_array($algorithms)
            || ! in_array(self::algorithmName(OaepDigest::Sha256), $algorithms, true)
            || ! is_string($der)
            || $der === ''
        ) {
            throw new DecryptionFailed(sprintf(
                'The AWS KMS key %s is not an ENCRYPT_DECRYPT RSA key that decrypts with RSA-OAEP.',
                $this->reference,
            ));
        }

        return RsaPublicKey::pemFromDer($der);
    }

    #[\Override]
    public function decrypt(string $ciphertext, OaepDigest $digest): string
    {
        $result = $this->call(fn (): Result => $this->client->decrypt([
            'KeyId' => $this->reference,
            'CiphertextBlob' => $ciphertext,
            'EncryptionAlgorithm' => self::algorithmName($digest),
        ]));
        /** @var mixed $plaintext */
        $plaintext = $result['Plaintext'] ?? null;

        return is_string($plaintext) && $plaintext !== ''
            ? $plaintext
            : throw new DecryptionFailed('The content key does not decrypt.');
    }

    /**
     * @param Closure(): Result $call
     *
     * @throws DecryptionFailed
     */
    private function call(Closure $call): Result
    {
        try {
            return $call();
        } catch (AwsException | CredentialsException $refused) {
            throw new DecryptionFailed('The content key does not decrypt.', previous: $refused);
        }
    }
}
