<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Saml\Remote;

use Clavia\Adapter\Secondary\Signing\Remote\AccessTokens;
use Clavia\Adapter\Secondary\Signing\Remote\Gcp\GcpKmsKey;
use Clavia\Adapter\Secondary\Signing\Remote\InvalidKeyReference;
use Clavia\Adapter\Secondary\Signing\Remote\JsonApi;
use Clavia\Application\Port\DecryptionFailed;
use Clavia\Application\Port\SigningFailed;
use Clavia\Application\Port\Saml\OaepDigest;

/**
 * A Google Cloud KMS `ASYMMETRIC_DECRYPT` key version: `asymmetricDecrypt`, with CRC32C on the
 * ciphertext and the plaintext. Its OAEP digest is the key version's own
 * (`RSA_DECRYPT_OAEP_<bits>_SHA1` or `_SHA256`), so a content key encrypted with the other is
 * refused here, before Cloud KMS is asked.
 */
final readonly class GcpKmsDecryptionKey implements RemoteDecryptionKey
{
    /** @var non-empty-string */
    private string $reference;

    /** @throws InvalidKeyReference */
    public function __construct(
        private JsonApi $api,
        private AccessTokens $tokens,
        string $reference,
    ) {
        $this->reference = GcpKmsKey::checked($reference);
    }

    #[\Override]
    public function reference(): string
    {
        return $this->reference;
    }

    #[\Override]
    public function publicKeyPem(): string
    {
        [$pem] = $this->described();

        return $pem;
    }

    #[\Override]
    public function decrypt(string $ciphertext, OaepDigest $digest): string
    {
        [, $keysDigest] = $this->described();
        if ($keysDigest !== $digest) {
            throw new DecryptionFailed('The content key does not decrypt.');
        }
        try {
            $answer = $this->api->postJson(
                GcpKmsKey::API . $this->reference . ':asymmetricDecrypt',
                ['ciphertext' => base64_encode($ciphertext), 'ciphertextCrc32c' => self::crc32c($ciphertext)],
                $this->authorization(),
            );
        } catch (SigningFailed $unreachable) {
            throw new DecryptionFailed('The content key does not decrypt.', previous: $unreachable);
        }
        /** @var mixed $encoded */
        $encoded = $answer['plaintext'] ?? null;
        $plaintext = is_string($encoded) ? base64_decode($encoded, true) : false;
        if (
            ($answer['verifiedCiphertextCrc32c'] ?? null) !== true
            || $plaintext === false
            || $plaintext === ''
            || ($answer['plaintextCrc32c'] ?? null) !== self::crc32c($plaintext)
        ) {
            throw new DecryptionFailed('The content key does not decrypt.');
        }

        return $plaintext;
    }

    /**
     * The public key and the OAEP digest of the key version, checked.
     *
     * @return array{0: non-empty-string, 1: OaepDigest}
     *
     * @throws DecryptionFailed
     */
    private function described(): array
    {
        try {
            $answer = $this->api->get(GcpKmsKey::API . $this->reference . '/publicKey', $this->authorization());
        } catch (SigningFailed $unreachable) {
            throw new DecryptionFailed('Google Cloud KMS could not be reached.', previous: $unreachable);
        }
        $algorithm = $answer['algorithm'] ?? null;
        $pem = $answer['pem'] ?? null;
        if (
            ! is_string($algorithm)
            || preg_match('/^RSA_DECRYPT_OAEP_(2048|3072|4096)_(SHA1|SHA256)$/D', $algorithm, $match) !== 1
            || ! is_string($pem)
            || $pem === ''
            || ($answer['pemCrc32c'] ?? null) !== self::crc32c($pem)
        ) {
            throw new DecryptionFailed(sprintf(
                'The Google Cloud KMS key version %s is not an RSA-OAEP decryption key, or its key does not match '
                . 'its checksum.',
                $this->reference,
            ));
        }

        return [$pem, $match[2] === 'SHA1' ? OaepDigest::Sha1 : OaepDigest::Sha256];
    }

    /** @return array{Authorization: string} */
    private function authorization(): array
    {
        try {
            return ['Authorization' => 'Bearer ' . $this->tokens->token()];
        } catch (SigningFailed $unauthenticated) {
            throw new DecryptionFailed('No Google credentials to call Cloud KMS with.', previous: $unauthenticated);
        }
    }

    private static function crc32c(string $bytes): string
    {
        return (string) hexdec(hash('crc32c', $bytes));
    }
}
