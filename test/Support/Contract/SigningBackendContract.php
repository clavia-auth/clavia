<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\NoActiveSigningKey;
use Clavia\Application\Port\SigningFailed;
use Clavia\Application\Port\SigningKeyReference;
use Clavia\Application\Port\SigningKeyStore;
use Clavia\Application\Port\TokenSigner;
use Clavia\Domain\Oidc\PublicJwk;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Oidc\SigningKey;
use ClaviaTest\Support\Fake\FrozenClock;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\RS256;
use PHPUnit\Framework\Attributes\Test;

/**
 * What a signing backend whose keys this server manages does: its {@see SigningKeyStore}
 * and its {@see TokenSigner}, which share one set of keys.
 *
 * Signatures are checked with OpenSSL against the *published* JWK, the way a relying
 * party would, never against the private key.
 */
trait SigningBackendContract
{
    abstract protected function store(): SigningKeyStore;

    abstract protected function signer(): TokenSigner;

    /** The clock both of them read. */
    abstract protected function clock(): FrozenClock;

    /**
     * Run `$work` inside a transaction of the storage under test.
     *
     * @template T
     * @param callable(): T $work
     * @return T
     */
    abstract protected function transactional(callable $work): mixed;

    #[Test]
    public function withoutAKeyNothingSignsAndNothingIsPublished(): void
    {
        self::assertSame([], $this->signer()->publicKeys());
        self::assertSame([], $this->store()->all());
        self::assertNull($this->transactional(fn (): ?SigningKey => $this->store()->lockActive()));

        $this->expectException(NoActiveSigningKey::class);

        $this->signer()->activeKey();
    }

    #[Test]
    public function aCreatedKeyIsTheActiveKeyAndWhatItSignsVerifiesAgainstItsPublishedJwk(): void
    {
        $key = $this->created();

        $active = $this->signer()->activeKey();
        self::assertSame($key->kid(), $active->kid);
        self::assertSame(SigningAlgorithm::RS256, $active->algorithm);

        $signature = $this->signer()->sign($active, 'header.payload');

        $published = $this->signer()->publicKeys()[0] ?? null;
        self::assertNotNull($published);
        self::assertSame($key->kid(), $published->kid);
        self::assertTrue(self::verifies($published, 'header.payload', $signature));
        self::assertFalse(self::verifies($published, 'header.tampered', $signature));
    }

    #[Test]
    public function aKeyIsRecordedWithItsPublicHalfOnly(): void
    {
        $key = $this->created();

        $stored = $this->store()->all()[0] ?? null;
        self::assertNotNull($stored);
        self::assertSame($key->kid(), $stored->kid());
        self::assertTrue($stored->isActive());
        self::assertEquals($this->clock()->now(), $stored->createdAt);
        self::assertSame(['kty', 'use', 'alg', 'kid', 'n', 'e'], array_keys($stored->publicJwk->toArray()));
    }

    #[Test]
    public function theLockedActiveKeyIsTheOneThatSigns(): void
    {
        $key = $this->created();

        $locked = $this->transactional(fn (): ?SigningKey => $this->store()->lockActive());

        self::assertSame($key->kid(), $locked?->kid());
    }

    #[Test]
    public function aRetiredKeySignsNothingAndIsPublishedUntilItsGraceEnds(): void
    {
        $old = $this->created();
        $reference = $this->signer()->activeKey();

        $new = $this->transactional(function () use ($old): SigningKey {
            $old->retire($this->clock()->now(), 3600);
            $this->store()->save($old);

            return $this->store()->create(SigningAlgorithm::RS256, $this->clock()->now());
        });

        self::assertSame($new->kid(), $this->signer()->activeKey()->kid);
        self::assertSame(
            [$new->kid(), $old->kid()],
            array_map(static fn (PublicJwk $jwk): string => $jwk->kid, $this->signer()->publicKeys()),
        );

        try {
            $_ = $this->signer()->sign($reference, 'header.payload');
            self::fail('A retired key signed.');
        } catch (SigningFailed) {
            // As it should.
        }

        $this->clock()->advance(3599);
        self::assertCount(2, $this->signer()->publicKeys());

        $this->clock()->advance(1);
        self::assertSame(
            [$new->kid()],
            array_map(static fn (PublicJwk $jwk): string => $jwk->kid, $this->signer()->publicKeys()),
        );
        // Withdrawn from the JWKS, still on record.
        self::assertCount(2, $this->store()->all());
    }

    #[Test]
    public function keysAreListedNewestFirstWithTheirRetirement(): void
    {
        $first = $this->created();
        $this->clock()->advance(60);

        $second = $this->transactional(function () use ($first): SigningKey {
            $first->retire($this->clock()->now(), 600);
            $this->store()->save($first);

            return $this->store()->create(SigningAlgorithm::RS256, $this->clock()->now());
        });

        $listed = $this->store()->all();
        self::assertCount(2, $listed);
        [$newest, $oldest] = [$listed[0] ?? null, $listed[1] ?? null];
        self::assertNotNull($newest);
        self::assertNotNull($oldest);
        self::assertSame($second->kid(), $newest->kid());
        self::assertTrue($newest->isActive());
        self::assertSame($first->kid(), $oldest->kid());
        self::assertFalse($oldest->isActive());
        self::assertEquals($this->clock()->now(), $oldest->retiredAt());
        self::assertEquals($this->clock()->now()->modify('+600 seconds'), $oldest->publishedUntil());
    }

    #[Test]
    public function aKeyThatDoesNotExistSignsNothing(): void
    {
        $key = $this->created();
        $reference = new SigningKeyReference($key->kid() . 'x', SigningAlgorithm::RS256);

        $this->expectException(SigningFailed::class);

        $_ = $this->signer()->sign($reference, 'header.payload');
    }

    private function created(): SigningKey
    {
        return $this->transactional(fn (): SigningKey => $this->store()->create(
            SigningAlgorithm::RS256,
            $this->clock()->now(),
        ));
    }

    /** RSASSA-PKCS1-v1_5 / SHA-256, as a relying party checks an RS256 signature. */
    private static function verifies(PublicJwk $jwk, string $input, string $signature): bool
    {
        return new RS256()->verify(new JWK($jwk->toArray()), $input, $signature);
    }
}
