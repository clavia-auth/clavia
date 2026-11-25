<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\DecryptionFailed;
use Clavia\Application\Port\Saml\AuthnRequestDetails;
use Clavia\Application\Port\Saml\ContentKeyDecrypter;
use Clavia\Application\Port\Saml\ExpectedResponse;
use Clavia\Application\Port\Saml\OaepDigest;
use Clavia\Application\Port\Saml\SamlIdentity;
use Clavia\Application\Port\Saml\SamlRefusal;
use Clavia\Application\Port\Saml\SamlRefused;
use Clavia\Application\Port\Saml\SamlServiceProvider;
use Clavia\Application\Port\Saml\ServiceProviderDescription;
use Clavia\Domain\Connection\Saml\SamlCertificate;
use Clavia\Domain\Connection\Saml\SamlRequestId;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Url;
use ClaviaTest\Support\Saml\TestIdentityProvider as Idp;
use DateTimeImmutable;
use DOMDocument;
use DOMElement;
use DOMXPath;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * The SAML service provider against genuine responses from {@see Idp} (docs/design/saml-connections.md
 * §8): a sign-in accepted, then every refusal that does not involve this server's own keys, one test
 * each, attacks included. Plain assertions only; encrypted ones come with the keys (slice 6).
 */
trait SamlServiceProviderContract
{
    abstract protected function samlServiceProvider(): SamlServiceProvider;

    #[Test]
    public function aSignedAssertionForThisRequestIsAccepted(): void
    {
        $identity = $this->consumed(Idp::response());

        self::assertInstanceOf(SamlIdentity::class, $identity);
        self::assertSame('a8f3c2d1-0b9e-4f7a-8c6d-5e4f3a2b1c0d', $identity->subject);
        self::assertSame(Idp::PERSISTENT, $identity->nameIdFormat);
        self::assertSame(['email' => ['ada@acme.example'], 'givenname' => ['Ada']], $identity->attributes);
        self::assertSame('_a1', $identity->assertionId);
        self::assertEquals(new DateTimeImmutable('2026-03-04T09:05:00Z'), $identity->validUntil);
        self::assertEquals(new DateTimeImmutable('2026-03-04T08:59:30Z'), $identity->authenticatedAt);
    }

    #[Test]
    public function theSubjectCanBeAnAttributeTheOperatorNames(): void
    {
        $response = Idp::response([
            'nameIdFormat' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
            'attributes' => ['objectidentifier' => ['5d1c']],
        ]);

        $identity = $this->consumed($response, subjectAttribute: 'objectidentifier');

        self::assertInstanceOf(SamlIdentity::class, $identity);
        self::assertSame('5d1c', $identity->subject);
    }

    #[Test]
    public function aCertificateBesideTheOneThatSignedIsTriedInTurn(): void
    {
        self::assertInstanceOf(
            SamlIdentity::class,
            $this->consumed(Idp::response(), [Idp::attacker()['certificate'], Idp::rsa()['certificate']]),
            'Rollover: the connection keeps up to three certificates.',
        );
    }

    /** @return iterable<string, array{0: array<string, mixed>, 1: SamlRefusal}> */
    public static function refusals(): iterable
    {
        yield 'an unsigned assertion' => [['signAssertion' => false], SamlRefusal::Signature];
        yield 'a signed response around an unsigned assertion' => [
            ['signAssertion' => false, 'signResponse' => true],
            SamlRefusal::Signature,
        ];
        yield 'a signature by another key' => [['key' => Idp::attacker()], SamlRefusal::Signature];
        yield 'another key, its certificate in KeyInfo' => [
            ['key' => Idp::attacker(), 'keyInfo' => Idp::attacker()['certificate']],
            SamlRefusal::Signature,
        ];
        yield 'an RSA-SHA1 signature' => [['algorithm' => Idp::RSA_SHA1], SamlRefusal::Signature];
        yield 'a SHA-1 digest' => [['digest' => Idp::SHA1], SamlRefusal::Signature];
        yield 'an ECDSA signature, which the library cannot read' => [
            ['key' => Idp::ec(), 'algorithm' => Idp::ECDSA_SHA256],
            SamlRefusal::Xml,
        ];
        yield 'a reference without exclusive canonicalisation' => [
            ['transforms' => ['http://www.w3.org/2000/09/xmldsig#enveloped-signature']],
            SamlRefusal::Signature,
        ];
        yield 'a comment in the NameID' => [['commentInNameId' => true], SamlRefusal::Xml];
        yield 'another Destination' => [['destination' => 'https://other.example/acs'], SamlRefusal::Destination];
        yield 'another Recipient' => [['recipient' => 'https://other.example/acs'], SamlRefusal::Destination];
        yield 'another Audience' => [['audience' => 'https://other.example/sp'], SamlRefusal::Audience];
        yield 'no Conditions' => [['conditions' => false], SamlRefusal::Audience];
        yield 'another Issuer on the assertion' => [['issuer' => 'https://other.example/idp'], SamlRefusal::Issuer];
        yield 'another Issuer on the response' => [
            ['responseIssuer' => 'https://other.example/idp'],
            SamlRefusal::Issuer,
        ];
        yield 'another request, on the response' => [
            ['inResponseTo' => '_' . str_repeat('b', 64)],
            SamlRefusal::InResponseTo,
        ];
        yield 'another request, in the confirmation' => [
            ['confirmationInResponseTo' => '_' . str_repeat('b', 64)],
            SamlRefusal::InResponseTo,
        ];
        yield 'conditions not yet valid past the skew' => [
            ['notBefore' => '2026-03-04T09:01:01Z'],
            SamlRefusal::Expired,
        ];
        yield 'conditions over at the skew' => [
            ['notBefore' => '2026-03-04T08:50:00Z', 'notOnOrAfter' => '2026-03-04T08:59:00Z'],
            SamlRefusal::Expired,
        ];
        yield 'a confirmation over at the skew' => [
            ['confirmationNotOnOrAfter' => '2026-03-04T08:59:00Z'],
            SamlRefusal::Expired,
        ];
        yield 'a failed Status' => [['status' => 'urn:oasis:names:tc:SAML:2.0:status:Responder'], SamlRefusal::Status];
        yield 'a transient subject' => [
            ['nameIdFormat' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'],
            SamlRefusal::Subject,
        ];
        yield 'an address as the subject' => [
            [
                'nameIdFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
                'nameId' => 'ada@acme.example',
            ],
            SamlRefusal::Subject,
        ];
        yield 'no AuthnStatement' => [['authnStatement' => false], SamlRefusal::Subject];
    }

    /** @param array<string, mixed> $options */
    #[Test]
    #[DataProvider('refusals')]
    public function aResponseIsRefused(array $options, SamlRefusal $reason): void
    {
        self::assertEquals(new SamlRefused($reason), $this->consumed(Idp::response($options)));
    }

    #[Test]
    public function theSkewIsSixtySecondsEitherWay(): void
    {
        self::assertInstanceOf(SamlIdentity::class, $this->consumed(Idp::response([
            'notBefore' => '2026-03-04T09:01:00Z',
            'notOnOrAfter' => '2026-03-04T09:05:00Z',
        ])), 'Valid from a minute ahead.');
        self::assertInstanceOf(SamlIdentity::class, $this->consumed(Idp::response([
            'notBefore' => '2026-03-04T08:50:00Z',
            'notOnOrAfter' => '2026-03-04T08:59:01Z',
            'confirmationNotOnOrAfter' => '2026-03-04T08:59:01Z',
        ])), 'Over 59 seconds ago.');
    }

    #[Test]
    public function aSecondAssertionBesideTheSignedOneIsRefused(): void
    {
        $document = self::document(Idp::xml());
        $xpath = self::xpath($document);
        $signed = $xpath->query('//saml:Assertion')->item(0);
        self::assertInstanceOf(DOMElement::class, $signed);
        $forged = self::document(Idp::xml(['signAssertion' => false, 'nameId' => 'admin']));
        $copy = $document->importNode(self::xpath($forged)->query('//saml:Assertion')->item(0) ?? $signed, true);
        self::assertInstanceOf(DOMElement::class, $copy);
        $copy->setAttribute('ID', '_forged');

        // Beside it, then wrapping it: the signed one moved inside the forged one.
        $beside = clone $document;
        $besideRoot = $beside->documentElement;
        self::assertInstanceOf(DOMElement::class, $besideRoot);
        $besideRoot->appendChild($beside->importNode($copy, true));
        self::assertEquals(
            new SamlRefused(SamlRefusal::Xml),
            $this->consumed(base64_encode((string) $beside->saveXML())),
        );

        $root = $document->documentElement;
        self::assertInstanceOf(DOMElement::class, $root);
        $root->replaceChild($copy, $signed);
        $copy->appendChild($signed);
        self::assertEquals(
            new SamlRefused(SamlRefusal::Xml),
            $this->consumed(base64_encode((string) $document->saveXML())),
        );
    }

    #[Test]
    public function aDoctypeIsRefused(): void
    {
        $xml = str_replace(
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>',
            Idp::xml(),
        );

        self::assertEquals(new SamlRefused(SamlRefusal::Xml), $this->consumed(base64_encode($xml)));
    }

    #[Test]
    public function oversizedOrUnreadableInputIsRefused(): void
    {
        $huge = Idp::response(['attributes' => ['filler' => [str_repeat('x', 270_000)]]]);

        self::assertEquals(new SamlRefused(SamlRefusal::Xml), $this->consumed($huge));
        self::assertEquals(new SamlRefused(SamlRefusal::Xml), $this->consumed('not base64!'));
        self::assertEquals(new SamlRefused(SamlRefusal::Xml), $this->consumed(base64_encode('<not-saml/>')));
    }

    #[Test]
    public function anAuthnRequestIsDeflatedAndAppendedToTheEndpoint(): void
    {
        $url = $this->samlServiceProvider()->authnRequestUrl(new AuthnRequestDetails(
            Url::fromString('https://idp.acme.example/saml/sso?tenant=7'),
            Idp::SP_ENTITY_ID,
            Url::fromString(Idp::ACS),
            SamlRequestId::fromString(Idp::REQUEST_ID),
            'handle-123',
            new DateTimeImmutable(Idp::NOW),
            Idp::PERSISTENT,
        ));

        self::assertStringStartsWith('https://idp.acme.example/saml/sso?tenant=7&SAMLRequest=', $url);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        self::assertSame('handle-123', $query['RelayState'] ?? null);
        $xml = gzinflate((string) base64_decode((string) ($query['SAMLRequest'] ?? ''), true));
        self::assertIsString($xml);
        $request = self::document($xml);
        $root = $request->documentElement;
        self::assertInstanceOf(DOMElement::class, $root);
        self::assertSame('AuthnRequest', $root->localName);
        self::assertSame(Idp::REQUEST_ID, $root->getAttribute('ID'));
        self::assertSame(Idp::ACS, $root->getAttribute('AssertionConsumerServiceURL'));
        self::assertSame('https://idp.acme.example/saml/sso?tenant=7', $root->getAttribute('Destination'));
        self::assertSame(Idp::SP_ENTITY_ID, self::xpath($request)->evaluate('string(saml:Issuer)', $root));
    }

    #[Test]
    public function anIdentityProvidersMetadataIsRead(): void
    {
        $metadata = $this->samlServiceProvider()->readMetadata(Idp::metadata([
            Idp::rsa()['certificate'],
            Idp::rsa()['certificate'],
        ]));

        self::assertSame(Idp::ENTITY_ID, $metadata->entityId);
        self::assertSame('https://idp.acme.example/saml/sso', $metadata->singleSignOnUrl->value);
        self::assertCount(1, $metadata->certificates, 'The same key is one certificate.');
        self::assertInstanceOf(SamlIdentity::class, $this->consumed(
            Idp::response(),
            array_map(static fn (SamlCertificate $certificate): string => $certificate->pem, $metadata->certificates),
        ));
        self::assertSame(
            hash('sha256', (string) base64_decode(Idp::der(Idp::rsa()['certificate']), true)),
            $metadata->certificates[0]->fingerprint,
        );
        self::assertNotNull($metadata->certificates[0]->notAfter);
    }

    /** @return iterable<string, array{0: string, 1: string, 2: string}> */
    public static function vendors(): iterable
    {
        yield 'Entra ID' => [
            'entra',
            'https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/',
            'https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/saml2',
        ];
        yield 'Okta' => [
            'okta',
            'http://www.okta.com/exk1a2b3c4d5e6f7g8h9',
            'https://acme.okta.com/app/acme_clavia_1/exk1a2b3c4d5e6f7g8h9/sso/saml',
        ];
        yield 'ADFS, an encryption key and an SP role beside' => [
            'adfs',
            'http://adfs.acme.example/adfs/services/trust',
            'https://adfs.acme.example/adfs/ls/',
        ];
        yield 'Keycloak, its entity in an aggregate' => [
            'keycloak',
            'https://keycloak.acme.example/realms/acme',
            'https://keycloak.acme.example/realms/acme/protocol/saml',
        ];
    }

    #[Test]
    #[DataProvider('vendors')]
    public function aVendorsMetadataIsRead(string $vendor, string $entityId, string $singleSignOn): void
    {
        $metadata = $this->samlServiceProvider()->readMetadata(Idp::vendorMetadata($vendor));

        self::assertSame($entityId, $metadata->entityId);
        self::assertSame($singleSignOn, $metadata->singleSignOnUrl->value);
        self::assertCount(1, $metadata->certificates, 'The signing key alone, once.');
        self::assertSame(Idp::rsa()['certificate'], $metadata->certificates[0]->pem);
    }

    #[Test]
    public function anAggregateOfSeveralEntitiesIsRefused(): void
    {
        $one = Idp::metadata([Idp::rsa()['certificate']]);
        $entity = substr($one, (int) strpos($one, '<EntityDescriptor'));
        $federation = '<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">' . $entity
            . str_replace(Idp::ENTITY_ID, 'https://other.example/idp', $entity) . '</EntitiesDescriptor>';

        $this->expectException(InvalidValue::class);
        $this->samlServiceProvider()->readMetadata($federation);
    }

    /** @return iterable<string, array{0: string}> */
    public static function unusableMetadata(): iterable
    {
        yield 'a DOCTYPE' => [str_replace(
            '<?xml version="1.0" encoding="utf-8"?>',
            '<?xml version="1.0" encoding="utf-8"?><!DOCTYPE m>',
            Idp::metadata([Idp::rsa()['certificate']]),
        )];
        yield 'no signing key' => [Idp::metadata()];
        yield 'POST sign-on only' => [Idp::metadata(
            [Idp::rsa()['certificate']],
            'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        )];
        yield 'an http sign-on URL' => [
            Idp::metadata([Idp::rsa()['certificate']], location: 'http://idp.acme.example/sso'),
        ];
        yield 'an EC certificate' => [Idp::metadata([Idp::ec()['certificate']])];
        yield 'an RSA key of 1024 bits' => [Idp::metadata([Idp::weak()['certificate']])];
        yield 'four certificates' => [Idp::metadata([
            Idp::rsa()['certificate'],
            Idp::attacker()['certificate'],
            self::otherRsa(1),
            self::otherRsa(2),
        ])];
        yield 'not metadata' => ['<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"/>'];
    }

    #[Test]
    #[DataProvider('unusableMetadata')]
    public function metadataThatCannotBeUsedIsRefused(string $document): void
    {
        $this->expectException(InvalidValue::class);
        $this->samlServiceProvider()->readMetadata($document);
    }

    #[Test]
    public function thisServersMetadataNamesItsEndpointAndWantsSignedAssertions(): void
    {
        $xml = $this->samlServiceProvider()->serviceProviderMetadata(new ServiceProviderDescription(
            Idp::SP_ENTITY_ID,
            Idp::ACS,
            Idp::PERSISTENT,
        ));
        $document = self::document($xml);
        $xpath = self::xpath($document);
        $xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');

        self::assertSame(Idp::SP_ENTITY_ID, $xpath->evaluate('string(/md:EntityDescriptor/@entityID)'));
        self::assertSame('true', $xpath->evaluate('string(//md:SPSSODescriptor/@WantAssertionsSigned)'));
        self::assertSame('false', $xpath->evaluate('string(//md:SPSSODescriptor/@AuthnRequestsSigned)'));
        self::assertSame(Idp::ACS, $xpath->evaluate('string(//md:AssertionConsumerService/@Location)'));
        self::assertSame(
            'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            $xpath->evaluate('string(//md:AssertionConsumerService/@Binding)'),
        );
    }

    /** @return iterable<string, array{0: array<string, mixed>}> */
    public static function encryptions(): iterable
    {
        yield 'AES-256-GCM, RSA-OAEP with SHA-1 (mgf1p)' => [[]];
        yield 'AES-128-GCM, RSA-OAEP 1.1 with SHA-256' => [[
            'cipher' => Idp::AES128_GCM,
            'transport' => Idp::RSA_OAEP,
            'oaepDigest' => 'sha256',
        ]];
        yield 'AES-256-CBC, ADFS\'s default' => [['cipher' => Idp::AES256_CBC]];
        yield 'no certificate named: each key tried' => [['nameRecipient' => false]];
    }

    /** @param array<string, mixed> $options */
    #[Test]
    #[DataProvider('encryptions')]
    public function anEncryptedAssertionIsDecryptedThenVerified(array $options): void
    {
        $identity = $this->consumed(Idp::response($options + ['encryptTo' => Idp::serviceProvider()['certificate']]));

        self::assertInstanceOf(SamlIdentity::class, $identity);
        self::assertSame('a8f3c2d1-0b9e-4f7a-8c6d-5e4f3a2b1c0d', $identity->subject);
    }

    /** @return iterable<string, array{0: array<string, mixed>, 1?: array{requireEncryption?: bool, requireGcm?: bool, decrypter?: bool}}> */
    public static function encryptionRefusals(): iterable
    {
        $to = ['encryptTo' => Idp::serviceProvider()['certificate']];
        yield 'RSA PKCS#1 v1.5 key transport' => [$to + ['transport' => Idp::RSA_1_5]];
        yield 'a tampered CBC ciphertext' => [$to + ['cipher' => Idp::AES256_CBC, 'tamper' => 'ciphertext']];
        yield 'a tampered GCM ciphertext' => [$to + ['tamper' => 'ciphertext']];
        yield 'a tampered GCM tag' => [$to + ['tamper' => 'tag']];
        yield 'a content key for another certificate' => [['encryptTo' => Idp::attacker()['certificate']]];
        yield 'AES-CBC when GCM is required' => [$to + ['cipher' => Idp::AES256_CBC], ['requireGcm' => true]];
        yield 'a plain assertion when encryption is required' => [[], ['requireEncryption' => true]];
        yield 'an encrypted assertion with no key to read it' => [$to, ['decrypter' => false]];
    }

    /**
     * @param array<string, mixed>                                                  $options
     * @param array{requireEncryption?: bool, requireGcm?: bool, decrypter?: bool} $requirements
     */
    #[Test]
    #[DataProvider('encryptionRefusals')]
    public function anEncryptedAssertionIsRefused(array $options, array $requirements = []): void
    {
        self::assertEquals(
            new SamlRefused(SamlRefusal::Decryption),
            $this->consumed(Idp::response($options), requirements: $requirements),
        );
    }

    #[Test]
    public function anEncryptedAssertionSignedByAnotherKeyIsStillRefusedForItsSignature(): void
    {
        $response = Idp::response(['key' => Idp::attacker(), 'encryptTo' => Idp::serviceProvider()['certificate']]);

        self::assertEquals(new SamlRefused(SamlRefusal::Signature), $this->consumed($response));
    }

    #[Test]
    public function aSignedRequestCarriesSigAlgAndASignatureOverTheQueryAsSent(): void
    {
        $key = Idp::serviceProvider();
        $url = $this->samlServiceProvider()->authnRequestUrl(
            new AuthnRequestDetails(
                Url::fromString('https://idp.acme.example/saml/sso'),
                Idp::SP_ENTITY_ID,
                Url::fromString(Idp::ACS),
                SamlRequestId::fromString(Idp::REQUEST_ID),
                'handle-123',
                new DateTimeImmutable(Idp::NOW),
            ),
            static function (string $data) use ($key): string {
                openssl_sign($data, $signature, $key['private'], OPENSSL_ALGO_SHA256);

                return $signature;
            },
        );

        // As an identity provider verifies it (Bindings §3.4.4.1): the query's octets up to the signature.
        $query = (string) parse_url($url, PHP_URL_QUERY);
        $signed = '/^(SAMLRequest=[^&]+&RelayState=[^&]+&SigAlg=[^&]+)&Signature=([^&]+)$/D';
        self::assertSame(1, preg_match($signed, $query, $parts));
        parse_str($query, $parameters);
        self::assertSame('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', $parameters['SigAlg'] ?? null);
        $signature = base64_decode(rawurldecode($parts[2]), true);
        self::assertIsString($signature);
        self::assertSame(1, openssl_verify($parts[1], $signature, $key['certificate'], OPENSSL_ALGO_SHA256));
    }

    /**
     * @param non-empty-list<non-empty-string>|null                                 $certificates
     * @param non-empty-string|null                                                 $subjectAttribute
     * @param array{requireEncryption?: bool, requireGcm?: bool, decrypter?: bool} $requirements
     */
    private function consumed(
        string $response,
        ?array $certificates = null,
        ?string $subjectAttribute = null,
        array $requirements = [],
    ): SamlIdentity|SamlRefused {
        $sp = Idp::serviceProvider();
        $decrypter = new ContentKeyDecrypter(
            [
                ['kid' => 'other', 'certificate' => Idp::der(Idp::rsa()['certificate']) ?: 'x'],
                ['kid' => 'sp-encryption', 'certificate' => Idp::der($sp['certificate']) ?: 'x'],
            ],
            static function (string $kid, string $wrapped, OaepDigest $digest) use ($sp): string {
                if ($kid !== 'sp-encryption') {
                    throw new DecryptionFailed('Not this key.');
                }
                $oaep = OPENSSL_PKCS1_OAEP_PADDING;
                $ok = @openssl_private_decrypt($wrapped, $key, $sp['private'], $oaep, $digest->value);

                return $ok ? $key : throw new DecryptionFailed('No.');
            },
        );

        return $this->samlServiceProvider()->consume($response, new ExpectedResponse(
            Idp::ENTITY_ID,
            $certificates ?? [Idp::rsa()['certificate']],
            Idp::SP_ENTITY_ID,
            Idp::ACS,
            SamlRequestId::fromString(Idp::REQUEST_ID),
            new DateTimeImmutable(Idp::NOW),
            $subjectAttribute,
            ($requirements['decrypter'] ?? true) ? $decrypter : null,
            $requirements['requireEncryption'] ?? false,
            $requirements['requireGcm'] ?? false,
        ));
    }

    /** @return non-empty-string */
    private static function otherRsa(int $n): string
    {
        $private = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        self::assertNotFalse($private);
        $csr = openssl_csr_new(['commonName' => 'Other ' . $n], $private);
        self::assertInstanceOf(\OpenSSLCertificateSigningRequest::class, $csr);
        $certificate = openssl_csr_sign($csr, null, $private, 30);
        self::assertNotFalse($certificate);
        openssl_x509_export($certificate, $pem);
        /** @var non-empty-string $pem */
        return $pem;
    }

    private static function document(string $xml): DOMDocument
    {
        $document = new DOMDocument();
        self::assertTrue($xml !== '' && $document->loadXML($xml));

        return $document;
    }

    private static function xpath(DOMDocument $document): DOMXPath
    {
        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
        $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');

        return $xpath;
    }
}
