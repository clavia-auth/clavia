<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Integration\Saml;

use Clavia\Adapter\Secondary\Crypto\AesGcmSecretCipher;
use Clavia\Adapter\Secondary\Saml\Postgres\PostgresServiceProviderKeys;
use Clavia\Adapter\Secondary\Saml\Postgres\PostgresServiceProviderKeyStore;
use Clavia\Adapter\Secondary\System\SystemRandomSource;
use Clavia\Application\Port\Saml\ServiceProviderKeys;
use Clavia\Application\Port\Saml\ServiceProviderKeyStore;
use Clavia\Application\Port\SigningFailed;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyStatus;
use ClaviaTest\Support\Contract\ServiceProviderKeysContract;
use ClaviaTest\Support\Contract\ServiceProviderKeyStoreContract;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestEnvironment;
use ClaviaTest\Support\TestStorage;
use DateTimeImmutable;
use Throwable;

/** The `postgres` backend: sealed private halves, read only to sign and to decrypt. */
final class PostgresServiceProviderKeysTest extends IntegrationTestCase
{
    use ServiceProviderKeysContract;
    use ServiceProviderKeyStoreContract;

    private AesGcmSecretCipher $cipher;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->cipher = new AesGcmSecretCipher(TestEnvironment::SECRET_ENCRYPTION_KEY, new SystemRandomSource());
    }

    #[\Override]
    protected function serviceProviderKeyStore(): ServiceProviderKeyStore
    {
        return new PostgresServiceProviderKeyStore(
            TestStorage::database(),
            $this->cipher,
            new SystemRandomSource(),
            'auth.clavia.test',
            2048,
        );
    }

    #[\Override]
    protected function arrange(bool $next = false, bool $retired = false): void
    {
        $store = $this->serviceProviderKeyStore();
        $moment = new \DateTimeImmutable('2026-03-04T09:00:00Z');
        if ($retired) {
            $old = $store->createPair(\Clavia\Domain\Connection\Saml\ServiceProviderKeyStatus::Current, $moment);
            $store->save($old['signing']->retired($moment));
            $store->save($old['encryption']->retired($moment));
            $store->delete($old['signing']->kid);
        }
        $store->createPair(\Clavia\Domain\Connection\Saml\ServiceProviderKeyStatus::Current, $moment);
        if ($next) {
            $store->createPair(\Clavia\Domain\Connection\Saml\ServiceProviderKeyStatus::Next, $moment);
        }
    }

    #[\Override]
    protected function serviceProviderKeys(): ServiceProviderKeys
    {
        return new PostgresServiceProviderKeys(TestStorage::database(), $this->cipher);
    }

    public function testKeysAreRsa3072SealedUnderTheirKidAndNamedForTheHost(): void
    {
        $store = new PostgresServiceProviderKeyStore(
            TestStorage::database(),
            $this->cipher,
            new SystemRandomSource(),
            'auth.clavia.test',
        );
        $pair = $store->createPair(ServiceProviderKeyStatus::Current, new DateTimeImmutable('2026-03-04T09:00:00Z'));

        $certificate = openssl_x509_read(
            "-----BEGIN CERTIFICATE-----\n" . chunk_split($pair['signing']->certificate, 64, "\n")
                . "-----END CERTIFICATE-----\n",
        );
        self::assertNotFalse($certificate);
        $details = openssl_pkey_get_details(openssl_pkey_get_public($certificate) ?: self::fail('No key.'));
        self::assertSame(3072, is_array($details) ? $details['bits'] : null);
        self::assertSame('auth.clavia.test SAML SP', openssl_x509_parse($certificate)['subject']['CN'] ?? null);

        /** @var list<array{kid: string, private_key_encrypted: string}> $rows */
        $rows = TestStorage::database()->fetchAll('SELECT kid, private_key_encrypted FROM saml_service_provider_keys');
        foreach ($rows as $row) {
            self::assertStringNotContainsString('PRIVATE KEY', $row['private_key_encrypted']);
            self::assertStringContainsString(
                'PRIVATE KEY',
                $this->cipher->decrypt($row['private_key_encrypted'], 'saml-sp:' . $row['kid']),
            );
        }
    }

    public function testASealedKeyMovedOntoAnotherRowDoesNotOpen(): void
    {
        $pair = $this->serviceProviderKeyStore()->createPair(
            ServiceProviderKeyStatus::Current,
            new DateTimeImmutable('2026-03-04T09:00:00Z'),
        );
        TestStorage::database()->execute(
            'UPDATE saml_service_provider_keys SET private_key_encrypted = (SELECT private_key_encrypted FROM '
            . 'saml_service_provider_keys WHERE kid = :from) WHERE kid = :to',
            ['from' => $pair['encryption']->kid, 'to' => $pair['signing']->kid],
        );

        $this->expectException(SigningFailed::class);
        $this->serviceProviderKeys()->sign($pair['signing']->kid, 'data');
    }

    public function testTheDatabaseRefusesASecondCurrentPair(): void
    {
        $store = $this->serviceProviderKeyStore();
        $store->createPair(ServiceProviderKeyStatus::Current, new DateTimeImmutable('2026-03-04T09:00:00Z'));

        try {
            $store->createPair(ServiceProviderKeyStatus::Current, new DateTimeImmutable('2026-03-04T09:00:00Z'));
            self::fail('Two current pairs.');
        } catch (Throwable $refused) {
            self::assertStringContainsString(
                'saml_sp_keys_one_current',
                $refused->getMessage() . ($refused->getPrevious()?->getMessage() ?? ''),
            );
        }
    }
}
