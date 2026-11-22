<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Integration\Signing;

use Clavia\Adapter\Secondary\Crypto\AesGcmSecretCipher;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbTransactionManager;
use Clavia\Adapter\Secondary\Signing\Postgres\PostgresSigningKeyStore;
use Clavia\Adapter\Secondary\Signing\Postgres\PostgresTokenSigner;
use Clavia\Adapter\Secondary\System\SystemRandomSource;
use Clavia\Application\Port\DecryptionFailed;
use Clavia\Application\Port\EncryptionUnavailable;
use Clavia\Application\Port\SigningFailed;
use Clavia\Application\Port\SigningKeyStore;
use Clavia\Application\Port\TokenSigner;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Oidc\SigningKey;
use ClaviaTest\Support\Contract\SigningBackendContract;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestEnvironment;
use ClaviaTest\Support\TestStorage;
use LogicException;
use PDOException;
use Throwable;

/**
 * The `postgres` signing backend against a real database: the backend contract, and
 * what only this backend has — a sealed private key in a row.
 */
final class PostgresSigningBackendTest extends IntegrationTestCase
{
    use SigningBackendContract;

    private FrozenClock $clock;
    private AesGcmSecretCipher $cipher;
    private PostgresSigningKeyStore $store;
    private PostgresTokenSigner $signer;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FrozenClock();
        $this->cipher = new AesGcmSecretCipher(TestEnvironment::SECRET_ENCRYPTION_KEY, new SystemRandomSource());
        $this->store = new PostgresSigningKeyStore(TestStorage::database(), $this->cipher);
        $this->signer = new PostgresTokenSigner(TestStorage::database(), $this->cipher, $this->clock);
    }

    #[\Override]
    protected function store(): SigningKeyStore
    {
        return $this->store;
    }

    #[\Override]
    protected function signer(): TokenSigner
    {
        return $this->signer;
    }

    #[\Override]
    protected function clock(): FrozenClock
    {
        return $this->clock;
    }

    #[\Override]
    protected function transactional(callable $work): mixed
    {
        return new PhpDbTransactionManager(TestStorage::database())->transactional($work);
    }

    public function testThePrivateKeyIsStoredSealedAndBoundToItsOwnKid(): void
    {
        $key = $this->created();
        $other = $this->transactional(function () use ($key): SigningKey {
            $key->retire($this->clock->now(), 60);
            $this->store->save($key);

            return $this->store->create(SigningAlgorithm::RS256, $this->clock->now());
        });

        /** @var string $sealed */
        $sealed = TestStorage::database()->fetchValue(
            'SELECT private_key_encrypted FROM oidc_signing_keys WHERE kid = :kid',
            ['kid' => $key->kid()],
        );

        // A database backup alone does not yield the key…
        self::assertStringNotContainsString('PRIVATE KEY', $sealed);
        // …the encryption key and the row's own kid do…
        self::assertStringContainsString('BEGIN PRIVATE KEY', $this->cipher->decrypt($sealed, $key->kid()));
        // …and the same ciphertext under another row's kid does not.
        $this->expectException(DecryptionFailed::class);
        $this->cipher->decrypt($sealed, $other->kid());
    }

    public function testACiphertextMovedOntoAnotherRowDoesNotSign(): void
    {
        $donor = $this->created();
        $target = $this->transactional(function () use ($donor): SigningKey {
            $donor->retire($this->clock->now(), 60);
            $this->store->save($donor);

            return $this->store->create(SigningAlgorithm::RS256, $this->clock->now());
        });
        TestStorage::database()->execute(
            <<<'SQL'
                UPDATE oidc_signing_keys
                SET private_key_encrypted = (SELECT private_key_encrypted FROM oidc_signing_keys WHERE kid = :donor)
                WHERE kid = :target
                SQL,
            ['donor' => $donor->kid(), 'target' => $target->kid()],
        );

        $this->expectException(DecryptionFailed::class);

        $_ = $this->signer->sign($this->signer->activeKey(), 'header.payload');
    }

    public function testWithoutAnEncryptionKeyNoKeyIsCreatedAtAll(): void
    {
        $store = new PostgresSigningKeyStore(
            TestStorage::database(),
            new AesGcmSecretCipher(null, new SystemRandomSource()),
        );

        try {
            $this->transactional(fn (): SigningKey => $store->create(SigningAlgorithm::RS256, $this->clock->now()));
            self::fail('A key was created without an encryption key.');
        } catch (EncryptionUnavailable) {
            // As it should: there is no plaintext fallback.
        }

        self::assertSame(0, TestStorage::database()->fetchValue('SELECT count(*) FROM oidc_signing_keys'));
    }

    public function testTheDatabaseRefusesASecondActiveKey(): void
    {
        $this->created();

        try {
            $this->created();
            self::fail('Two keys were active at once.');
        } catch (Throwable $refused) {
            self::assertInstanceOf(PDOException::class, $refused->getPrevious() ?? $refused);
        }

        self::assertCount(1, $this->store->all());
    }

    public function testLockingTheActiveKeyOutsideATransactionIsRefused(): void
    {
        $this->expectException(LogicException::class);

        $this->store->lockActive();
    }

    public function testASignatureIsRsaPkcs1OverSha256OfTheExactInput(): void
    {
        $this->created();
        $reference = $this->signer->activeKey();

        $signature = $this->signer->sign($reference, 'eyJhbGciOiJSUzI1NiJ9.e30');

        // 2048-bit RSA: a 256-byte signature, deterministic for PKCS #1 v1.5.
        self::assertSame(256, strlen($signature));
        self::assertSame($signature, $this->signer->sign($reference, 'eyJhbGciOiJSUzI1NiJ9.e30'));
    }

    public function testARetiredKidCannotBeUsedToSign(): void
    {
        $key = $this->created();
        $reference = $this->signer->activeKey();
        $this->transactional(function () use ($key): void {
            $key->retire($this->clock->now(), 60);
            $this->store->save($key);
        });

        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessageIsOrContains('is not the active key');

        $_ = $this->signer->sign($reference, 'header.payload');
    }
}
