<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Connection;

use Clavia\Application\Connection\Saml\GenerateServiceProviderKeys;
use Clavia\Application\Connection\Saml\RotateServiceProviderKeys;
use Clavia\Application\Connection\Saml\RotationStep;
use Clavia\Application\Connection\Saml\ServiceProviderKeysExist;
use Clavia\Application\Port\Saml\OaepDigest;
use Clavia\Domain\Connection\Saml\Event\ServiceProviderKeysGenerated;
use Clavia\Domain\Connection\Saml\Event\ServiceProviderKeysRotated;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyStatus;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyUsage;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemoryServiceProviderKeys;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use PHPUnit\Framework\TestCase;

/** The rollover of docs/design/saml-connections.md §5.1: next, then current, then retired, then gone. */
final class RotateServiceProviderKeysTest extends TestCase
{
    private const int DAY = 86_400;

    private InMemoryServiceProviderKeys $keys;
    private FrozenClock $clock;
    private InMemoryDomainEvents $events;

    #[\Override]
    protected function setUp(): void
    {
        $this->keys = new InMemoryServiceProviderKeys();
        $this->clock = new FrozenClock('2026-03-01T09:00:00Z');
        $this->events = new InMemoryDomainEvents();
    }

    public function testEachRotationTakesOneStepAndARetiredKeyDecryptsUntilItsOverlapIsOver(): void
    {
        $transactions = new InMemoryTransactionManager();
        $rotate = new RotateServiceProviderKeys($this->keys, $transactions, $this->clock, 14, $this->events);

        self::assertSame(RotationStep::Generated, $rotate()->step);
        $first = $this->keys->all();
        $firstEncryption = $first->current(ServiceProviderKeyUsage::Encryption);
        self::assertNotNull($firstEncryption);

        $introduced = $rotate();
        self::assertSame(RotationStep::Introduced, $introduced->step);
        self::assertEquals(new \DateTimeImmutable('2026-03-15T09:00:00Z'), $introduced->promotesAt);
        self::assertCount(4, $introduced->keys->published()->keys, 'Both pairs in the metadata.');
        self::assertSame(
            $first->current(ServiceProviderKeyUsage::Signing)?->kid,
            $introduced->keys->current(ServiceProviderKeyUsage::Signing)?->kid,
            'The current pair still signs.',
        );

        $this->clock->advance(13 * self::DAY);
        self::assertSame(RotationStep::Waiting, $rotate()->step);

        $this->clock->advance(self::DAY);
        $promoted = $rotate();
        self::assertSame(RotationStep::Promoted, $promoted->step);
        $next = $introduced->keys->next(ServiceProviderKeyUsage::Signing);
        self::assertSame($next?->kid, $promoted->keys->current(ServiceProviderKeyUsage::Signing)?->kid);
        self::assertSame(ServiceProviderKeyStatus::Retired, $promoted->keys->byKid($firstEncryption->kid)?->status);
        self::assertNull($promoted->keys->next(ServiceProviderKeyUsage::Signing));

        $public = openssl_pkey_get_details(openssl_pkey_get_public(
            "-----BEGIN CERTIFICATE-----\n" . chunk_split($firstEncryption->certificate, 64, "\n")
                . "-----END CERTIFICATE-----\n",
        ) ?: self::fail('No key.'));
        self::assertIsArray($public);
        self::assertIsString($public['key']);
        openssl_public_encrypt('k', $encrypted, $public['key'], OPENSSL_PKCS1_OAEP_PADDING);
        self::assertSame(
            'k',
            $this->keys->decryptKey($firstEncryption->kid, $encrypted, OaepDigest::Sha1),
            'Still decrypts.',
        );

        $this->clock->advance(14 * self::DAY + 1);
        $cleaned = $rotate();
        self::assertSame(RotationStep::Introduced, $cleaned->step, 'The next rotation starts over.');
        self::assertContains($firstEncryption->kid, $cleaned->deleted);
        self::assertNull($cleaned->keys->byKid($firstEncryption->kid));

        self::assertCount(1, $this->events->ofType(ServiceProviderKeysGenerated::class));
        $rotations = $this->events->ofType(ServiceProviderKeysRotated::class);
        self::assertSame(
            [false, true, false],
            array_map(static fn (ServiceProviderKeysRotated $e): bool => $e->promoted, $rotations),
        );
    }

    public function testGeneratingNeverReplacesKeys(): void
    {
        $transactions = new InMemoryTransactionManager();
        $generate = new GenerateServiceProviderKeys($this->keys, $transactions, $this->clock, $this->events);

        $keys = $generate();
        self::assertCount(2, $keys->published()->keys);

        $this->expectException(ServiceProviderKeysExist::class);
        $generate();
    }
}
