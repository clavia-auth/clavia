<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Adapter\Secondary\Signing\X509\SelfSignedCertificate;
use Clavia\Application\Port\DecryptionFailed;
use Clavia\Application\Port\Saml\OaepDigest;
use Clavia\Application\Port\Saml\ServiceProviderKeys;
use Clavia\Application\Port\Saml\ServiceProviderKeyStore;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyStatus;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyUsage;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/** The lifecycle store of the keys this server makes (`postgres`), the double and PostgreSQL alike. */
trait ServiceProviderKeyStoreContract
{
    abstract protected function serviceProviderKeyStore(): ServiceProviderKeyStore;

    abstract protected function serviceProviderKeys(): ServiceProviderKeys;

    #[Test]
    public function aNextPairIsPromotedAndTheCurrentOneRetired(): void
    {
        $store = $this->serviceProviderKeyStore();
        $moment = new DateTimeImmutable('2026-03-04T09:00:00.000000Z');
        $current = $store->createPair(ServiceProviderKeyStatus::Current, $moment);
        $next = $store->createPair(ServiceProviderKeyStatus::Next, $moment);
        $later = $moment->modify('+14 days');

        $store->save($current['signing']->retired($later));
        $store->save($current['encryption']->retired($later));
        $store->save($next['signing']->promoted($later));
        $store->save($next['encryption']->promoted($later));

        $keys = $this->serviceProviderKeys()->certificates();
        self::assertSame($next['signing']->kid, $keys->current(ServiceProviderKeyUsage::Signing)?->kid);
        self::assertEquals($later, $keys->current(ServiceProviderKeyUsage::Signing)?->promotedAt);
        self::assertSame(ServiceProviderKeyStatus::Retired, $keys->byKid($current['signing']->kid)?->status);
        self::assertNotSame('', $this->serviceProviderKeys()->sign($next['signing']->kid, 'data'));
    }

    #[Test]
    public function aDeletedKeyDecryptsNoMore(): void
    {
        $store = $this->serviceProviderKeyStore();
        $pair = $store->createPair(ServiceProviderKeyStatus::Current, new DateTimeImmutable('2026-03-04T09:00:00Z'));
        $der = (string) base64_decode($pair['encryption']->certificate, true);
        $public = openssl_pkey_get_details(openssl_pkey_get_public(SelfSignedCertificate::pem($der)) ?: self::fail());
        self::assertIsArray($public);
        self::assertIsString($public['key']);
        openssl_public_encrypt('content-key', $encrypted, $public['key'], OPENSSL_PKCS1_OAEP_PADDING);

        $store->delete($pair['encryption']->kid);

        self::assertCount(1, $store->all()->keys);
        $this->expectException(DecryptionFailed::class);
        $this->serviceProviderKeys()->decryptKey($pair['encryption']->kid, $encrypted, OaepDigest::Sha1);
    }
}
