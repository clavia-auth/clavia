<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Integration\Saml;

use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbSamlCertificateCache;
use Clavia\Adapter\Secondary\Saml\Remote\CachedCertificate;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyUsage;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestStorage;
use DateTimeImmutable;

/** Remote SAML key certificates, kept by reference: read back whole, the first one written kept. */
final class PhpDbSamlCertificateCacheTest extends IntegrationTestCase
{
    private const string REFERENCE = 'arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-123456789001';

    public function testACertificateIsKeptByReferenceAndTheFirstWins(): void
    {
        $cache = new PhpDbSamlCertificateCache(TestStorage::database());
        $first = new CachedCertificate(
            'kQ7v1Zr3Xx9JmE2pY6tWcN4bL8sDfHgA0uI5oR2eT1M',
            ServiceProviderKeyUsage::Encryption,
            'MIIBfirst',
            new DateTimeImmutable('2036-03-04T09:00:00.000000Z'),
            new DateTimeImmutable('2026-03-04T09:00:00.000000Z'),
        );

        self::assertNull($cache->get(self::REFERENCE));
        $cache->put(self::REFERENCE, $first);
        $cache->put(self::REFERENCE, new CachedCertificate(
            'another',
            ServiceProviderKeyUsage::Encryption,
            'MIIBsecond',
            new DateTimeImmutable('2036-03-04T09:00:00Z'),
            new DateTimeImmutable('2026-03-04T09:00:00Z'),
        ));

        self::assertEquals($first, $cache->get(self::REFERENCE));
        self::assertNull($cache->get('another-reference'));
    }
}
