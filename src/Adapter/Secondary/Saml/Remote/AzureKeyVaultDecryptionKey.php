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
use Clavia\Adapter\Secondary\Signing\Remote\Azure\AzureKeyVaultKey;
use Clavia\Adapter\Secondary\Signing\Remote\InvalidKeyReference;
use Clavia\Adapter\Secondary\Signing\Remote\JsonApi;
use Clavia\Application\Port\DecryptionFailed;
use Clavia\Application\Port\SigningFailed;
use Clavia\Application\Port\Saml\OaepDigest;
use Clavia\Domain\Shared\Base64Url;
use Clavia\Domain\Shared\InvalidValue;

/**
 * An Azure Key Vault (or Managed HSM) RSA key that may decrypt: `decrypt` with `RSA-OAEP` (SHA-1)
 * or `RSA-OAEP-256`, named by its versioned URL as a signing key is.
 */
final readonly class AzureKeyVaultDecryptionKey implements RemoteDecryptionKey
{
    /** @var non-empty-string */
    private string $reference;

    /** @throws InvalidKeyReference */
    public function __construct(
        private JsonApi $api,
        private AccessTokens $tokens,
        string $reference,
    ) {
        AzureKeyVaultKey::scopeFor($reference);
        assert($reference !== '');
        $this->reference = $reference;
    }

    public static function algorithmName(OaepDigest $digest): string
    {
        return match ($digest) {
            OaepDigest::Sha1 => 'RSA-OAEP',
            OaepDigest::Sha256 => 'RSA-OAEP-256',
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
        try {
            $answer = $this->api->get(
                $this->reference . '?api-version=' . AzureKeyVaultKey::API_VERSION,
                $this->authorization(),
            );
        } catch (SigningFailed $unreachable) {
            throw new DecryptionFailed('Azure Key Vault could not be reached.', previous: $unreachable);
        }
        /** @var mixed $key */
        $key = $answer['key'] ?? null;
        /** @var mixed $attributes */
        $attributes = $answer['attributes'] ?? [];
        /** @var mixed $operations */
        $operations = is_array($key) ? ($key['key_ops'] ?? []) : null;
        if (
            ! is_array($key)
            || ($key['kid'] ?? null) !== $this->reference
            || ! in_array($key['kty'] ?? null, ['RSA', 'RSA-HSM'], true)
            || ! is_array($operations)
            || ! in_array('decrypt', $operations, true)
            || (is_array($attributes) && ($attributes['enabled'] ?? true) === false)
        ) {
            throw new DecryptionFailed(sprintf(
                'Azure Key Vault key %s is not an enabled RSA key that may decrypt.',
                $this->reference,
            ));
        }
        try {
            return RsaPublicKey::pem(self::decoded($key['n'] ?? null), self::decoded($key['e'] ?? null));
        } catch (InvalidValue $unusable) {
            throw new DecryptionFailed('Azure Key Vault returned an unusable public key.', previous: $unusable);
        }
    }

    #[\Override]
    public function decrypt(string $ciphertext, OaepDigest $digest): string
    {
        try {
            $answer = $this->api->postJson(
                $this->reference . '/decrypt?api-version=' . AzureKeyVaultKey::API_VERSION,
                ['alg' => self::algorithmName($digest), 'value' => Base64Url::encode($ciphertext)],
                $this->authorization(),
            );
            $plaintext = ($answer['kid'] ?? null) === $this->reference ? self::decoded($answer['value'] ?? null) : '';
        } catch (SigningFailed | InvalidValue $failed) {
            throw new DecryptionFailed('The content key does not decrypt.', previous: $failed);
        }

        return $plaintext !== '' ? $plaintext : throw new DecryptionFailed('The content key does not decrypt.');
    }

    /** @return array{Authorization: string} */
    private function authorization(): array
    {
        try {
            return ['Authorization' => 'Bearer ' . $this->tokens->token()];
        } catch (SigningFailed $unauthenticated) {
            throw new DecryptionFailed('No Azure credentials to call Key Vault with.', previous: $unauthenticated);
        }
    }

    /** @throws InvalidValue */
    private static function decoded(mixed $value): string
    {
        return is_string($value) ? Base64Url::decode($value) : '';
    }
}
