<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Saml;

use Clavia\Adapter\Secondary\Saml\SimpleSamlServiceProvider;
use Clavia\Application\Port\Saml\SamlServiceProvider;
use ClaviaTest\Support\Contract\SamlServiceProviderContract;
use Clavia\Application\Port\Saml\ServiceProviderDescription;
use ClaviaTest\Support\Saml\TestIdentityProvider as Idp;
use DOMDocument;
use PHPUnit\Framework\TestCase;

/**
 * The adapter against genuine XML. No double runs this contract: like the passkey verifier's, it
 * feeds real signatures a double could only pass by being the adapter again (CLAUDE.md, "Known
 * issues"); use cases take {@see \ClaviaTest\Support\Fake\FakeSamlServiceProvider}.
 */
final class SimpleSamlServiceProviderTest extends TestCase
{
    use SamlServiceProviderContract;

    private const string SCHEMA = __DIR__ . '/../../../../../vendor/simplesamlphp/saml2/resources/schemas/'
        . 'saml-schema-metadata-2.0.xsd';

    /**
     * This server's metadata, with keys of both usages and its encryption methods, is valid against
     * the SAML metadata schema (SAML Metadata §2), whose imports are all local: nothing is fetched.
     */
    public function testThisServersMetadataIsValidAgainstTheSchema(): void
    {
        $signing = Idp::der(Idp::rsa()['certificate']) ?: self::fail('No DER.');
        $encryption = Idp::der(Idp::attacker()['certificate']) ?: self::fail('No DER.');
        $xml = (new SimpleSamlServiceProvider())->serviceProviderMetadata(new ServiceProviderDescription(
            Idp::SP_ENTITY_ID,
            Idp::ACS,
            Idp::PERSISTENT,
            [$signing],
            [$encryption],
        ));
        $document = new DOMDocument();
        self::assertTrue($xml !== '' && $document->loadXML($xml, LIBXML_NONET));

        libxml_use_internal_errors(true);
        $valid = $document->schemaValidate(self::SCHEMA, LIBXML_NONET);
        $errors = array_map(static fn (\LibXMLError $error): string => trim($error->message), libxml_get_errors());
        libxml_clear_errors();
        libxml_use_internal_errors(false);

        self::assertTrue($valid, implode("\n", $errors));
        self::assertStringContainsString('AuthnRequestsSigned="true"', $xml);
        self::assertStringContainsString('xmlenc11#aes256-gcm', $xml);
        self::assertStringNotContainsString('rsa-1_5', $xml);
    }

    #[\Override]
    protected function samlServiceProvider(): SamlServiceProvider
    {
        return new SimpleSamlServiceProvider();
    }
}
