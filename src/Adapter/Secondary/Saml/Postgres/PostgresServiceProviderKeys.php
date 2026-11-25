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
use Clavia\Application\Port\DecryptionFailed;
use Clavia\Application\Port\Saml\OaepDigest;
use Clavia\Application\Port\Saml\ServiceProviderKeys;
use Clavia\Application\Port\SecretCipher;
use Clavia\Application\Port\SigningFailed;
use Clavia\Domain\Connection\Saml\ServiceProviderKeySet;
use OpenSSLAsymmetricKey;
use Throwable;

/**
 * The `postgres` backend's service provider keys at work. {@see sign()} and {@see decryptKey()} are
 * the only places that open one of these private keys, for one operation, and let go of it when they
 * return. The signing key signs only while current; an encryption key decrypts while next, current
 * or retired, and never signs; a signing key never decrypts.
 */
final readonly class PostgresServiceProviderKeys implements ServiceProviderKeys
{
    public function __construct(
        private Database $database,
        private SecretCipher $cipher,
    ) {
    }

    #[\Override]
    public function certificates(): ServiceProviderKeySet
    {
        return ServiceProviderKeyRow::set($this->database->fetchAll(
            'SELECT ' . ServiceProviderKeyRow::COLUMNS . ' FROM saml_service_provider_keys',
        ));
    }

    #[\Override]
    public function sign(string $kid, string $data): string
    {
        $key = $this->open(
            $kid,
            "usage = 'signing' AND status = 'current'",
            new SigningFailed(sprintf('Service provider key %s is not the current signing key.', $kid)),
        );
        if (! openssl_sign($data, $signature, $key, OPENSSL_ALGO_SHA256) || $signature === '') {
            throw new SigningFailed('OpenSSL could not sign: ' . (string) openssl_error_string());
        }

        return $signature;
    }

    #[\Override]
    public function decryptKey(string $kid, string $encryptedKey, OaepDigest $digest): string
    {
        $key = $this->open($kid, "usage = 'encryption'", new DecryptionFailed('The content key does not decrypt.'));
        if (
            ! openssl_private_decrypt($encryptedKey, $decrypted, $key, OPENSSL_PKCS1_OAEP_PADDING, $digest->value)
            || $decrypted === ''
        ) {
            throw new DecryptionFailed('The content key does not decrypt.');
        }

        return $decrypted;
    }

    /**
     * @param non-empty-string $where What the key must be for this operation.
     *
     * @throws SigningFailed|DecryptionFailed $refusal, whatever is wrong.
     */
    private function open(string $kid, string $where, SigningFailed|DecryptionFailed $refusal): OpenSSLAsymmetricKey
    {
        /** @var string|null $sealed */
        $sealed = $this->database->fetchValue(
            'SELECT private_key_encrypted FROM saml_service_provider_keys WHERE kid = :kid AND ' . $where,
            ['kid' => $kid],
        );
        if ($sealed === null || $sealed === '') {
            throw $refusal;
        }
        try {
            // The kid is the associated data: a ciphertext copied from another row fails here.
            $pem = $this->cipher->decrypt($sealed, PostgresServiceProviderKeyStore::context($kid));
            $key = openssl_pkey_get_private($pem);
        } catch (Throwable) {
            throw $refusal;
        }

        return $key !== false ? $key : throw $refusal;
    }
}
