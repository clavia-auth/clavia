<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Connection;

use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionStrategy;
use Clavia\Domain\Connection\Saml\SamlCertificate;
use Clavia\Domain\Connection\Saml\SamlOptions;
use Clavia\Domain\Connection\Saml\SamlSettings;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Url;
use ClaviaTest\Support\Saml\TestIdentityProvider as Idp;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

/** A SAML connection's settings (docs/design/saml-connections.md §4). */
final class SamlSettingsTest extends TestCase
{
    public function testTheDefaultsAskForAPersistentNameIdSignRequestsAndRequireGcm(): void
    {
        $options = SamlOptions::of();

        self::assertSame(SamlOptions::PERSISTENT, $options->nameIdFormat);
        self::assertNull($options->subjectAttribute);
        self::assertFalse($options->emailTrusted, 'An address is trusted only on the operator\'s word.');
        self::assertTrue($options->signRequests);
        self::assertFalse($options->requireEncryption);
        self::assertTrue($options->requireGcm, 'AES-CBC refused unless turned off.');
        self::assertEquals($options, SamlOptions::fromArray($options->toArray()));
    }

    public function testAnUnusableOptionIsRefused(): void
    {
        $cases = [
            fn (): SamlOptions => SamlOptions::of(subjectAttribute: ''),
            fn (): SamlOptions => SamlOptions::of(nameIdFormat: 'email'),
        ];
        foreach ($cases as $case) {
            try {
                $case();
                self::fail('Accepted.');
            } catch (InvalidValue $refused) {
                self::assertNotSame('', $refused->getMessage());
            }
        }
    }

    public function testACertificateIsKnownByTheSha256OfItsDer(): void
    {
        $certificate = SamlCertificate::fromPem(Idp::rsa()['certificate'], null);

        $der = (string) base64_decode(Idp::der(Idp::rsa()['certificate']), true);
        self::assertSame(hash('sha256', $der), $certificate->fingerprint);
        $this->expectException(InvalidValue::class);
        SamlCertificate::fromPem('not a certificate', null);
    }

    public function testOneToThreeCertificatesAndHttpsOnly(): void
    {
        $certificate = SamlCertificate::fromPem(Idp::rsa()['certificate'], null);
        $sso = Url::fromString('https://idp.example/sso');
        $http = Url::fromString('http://idp.example/sso');
        $options = SamlOptions::of();
        foreach (
            [
                fn (): SamlSettings => SamlSettings::of(Idp::ENTITY_ID, $sso, [], null, SamlOptions::of()),
                fn (): SamlSettings
                    => SamlSettings::of(Idp::ENTITY_ID, $sso, array_fill(0, 4, $certificate), null, $options),
                fn (): SamlSettings => SamlSettings::of(Idp::ENTITY_ID, $http, [$certificate], null, $options),
                fn (): SamlSettings => SamlSettings::of('', $sso, [$certificate], null, SamlOptions::of()),
            ] as $case
        ) {
            try {
                $case();
                self::fail('Accepted.');
            } catch (InvalidValue $refused) {
                self::assertNotSame('', $refused->getMessage());
            }
        }
    }

    public function testASamlConnectionAndOnlyOneHasSamlSettings(): void
    {
        $saml = SamlSettings::of(
            Idp::ENTITY_ID,
            Url::fromString('https://idp.example/sso'),
            [SamlCertificate::fromPem(Idp::rsa()['certificate'], null)],
            null,
            SamlOptions::of(),
        );
        $now = new DateTimeImmutable('2026-03-04T09:00:00Z');
        $connection = Connection::samlProvider(ConnectionName::fromString('acme'), 'Acme', $saml, true, false, $now);

        self::assertTrue($connection->isExternal());
        self::assertSame(ConnectionStrategy::Saml, $connection->strategy);
        self::assertSame($saml, $connection->switched(false, null, 'Acme staff')->saml, 'Switching keeps them.');

        $this->expectException(InvalidValue::class);
        Connection::pool(ConnectionName::fromString('pool'), 'Pool', true, false, $now)->withSaml($saml);
    }
}
