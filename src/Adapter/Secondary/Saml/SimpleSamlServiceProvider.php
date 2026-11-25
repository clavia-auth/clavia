<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Saml;

use Clavia\Application\Port\Saml\AuthnRequestDetails;
use Clavia\Application\Port\Saml\ExpectedResponse;
use Clavia\Application\Port\Saml\IdentityProviderMetadata;
use Clavia\Application\Port\Saml\OaepDigest;
use Clavia\Application\Port\Saml\SamlIdentity;
use Clavia\Application\Port\Saml\SamlRefusal;
use Clavia\Application\Port\Saml\SamlRefused;
use Clavia\Application\Port\Saml\SamlServiceProvider;
use Clavia\Application\Port\Saml\ServiceProviderDescription;
use Clavia\Domain\Connection\Saml\SamlCertificate;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Url;
use Closure;
use DateTimeImmutable;
use DOMDocument;
use DOMElement;
use DOMNode;
use DOMXPath;
use Exception;
use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\samlp\Response;
use SimpleSAML\XMLSecurity\Alg\Encryption\AES;
use SimpleSAML\XMLSecurity\Key\SymmetricKey;
use SimpleSAML\XML\DOMDocumentFactory;
use SimpleSAML\XMLSecurity\Alg\Signature\RSA;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface;
use SimpleSAML\XMLSecurity\CryptoEncoding\PEM;
use SimpleSAML\XMLSecurity\Key\X509Certificate;
use Throwable;

/**
 * The SAML service provider on `simplesamlphp/saml2` and `simplesamlphp/xml-security`
 * (docs/design/saml-connections.md §2, §7). The libraries parse (no `DOCTYPE`, no network) and check
 * the signature, handing back the assertion rebuilt from the bytes the signature covers; this class
 * decides everything else, and reads that rebuilt assertion and nothing beside it.
 *
 * What it holds a response to, before any signature is checked:
 * - at most {@see MAX_RESPONSE_BYTES}, strict base64, no comment and no processing instruction
 *   anywhere (a comment in a `NameID` is how readers of the first text node were fooled);
 * - exactly one `saml:Assertion` in the whole document, a child of the response, and no encrypted
 *   one yet: one assertion leaves a wrapping attack nothing to swap;
 * - `Destination` this connection's endpoint, `Issuer` (when present) the identity provider,
 *   `InResponseTo` this request, `Status` success.
 *
 * The signature: on the assertion itself (a signed response around an unsigned assertion is refused),
 * exactly one reference, to the assertion's `ID`, transformed by enveloped-signature then exclusive
 * canonicalisation without comments, canonicalised so too; RSA over SHA-256, 384 or 512 and a digest
 * as strong (SHA-1 never, RFC 6931); verified only with the connection's certificates, never a key
 * the message carries (`KeyInfo` is ignored: `verify()` with no verifier would use it).
 *
 * RSA only: the library's object model refuses an ECDSA `SignatureMethod` (xml-security 2.3 and 3.1
 * alike), so an EC-signed assertion cannot be read, let alone verified. Entra ID, Okta, ADFS, Google
 * Workspace and Keycloak sign SAML with RSA; an EC certificate is refused at registration.
 *
 * Then, on the signed assertion (Profiles §4.1.4.2, §4.1.4.3, §4.1.4.5, with {@see SKEW_SECONDS} of
 * clock skew): `Issuer`; `Conditions` and their window; every `AudienceRestriction` naming this
 * service provider; a bearer `SubjectConfirmation` whose data names this endpoint and this request,
 * has a `NotOnOrAfter` still ahead and no `NotBefore`; an `AuthnStatement`; and a stable subject.
 */
final readonly class SimpleSamlServiceProvider implements SamlServiceProvider
{
    public const int MAX_RESPONSE_BYTES = 262_144;
    public const int MAX_METADATA_BYTES = 1_048_576;
    public const int SKEW_SECONDS = 60;
    public const int MAX_CERTIFICATES = 3;

    private const string NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
    private const string NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
    private const string NS_MD = 'urn:oasis:names:tc:SAML:2.0:metadata';
    private const string NS_DS = 'http://www.w3.org/2000/09/xmldsig#';

    private const string BINDING_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
    private const string BINDING_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
    private const string STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';
    private const string BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';
    private const string PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
    private const string ENTITY = 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity';

    private const string EXCLUSIVE_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    private const string ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    /** @var list<non-empty-string> */
    private const array RSA_ALGORITHMS = [
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
    ];

    /** @var list<non-empty-string> What this server decrypts, best first (§2): never `rsa-1_5`. */
    private const array ENCRYPTION_METHODS = [
        'http://www.w3.org/2009/xmlenc11#aes256-gcm',
        'http://www.w3.org/2009/xmlenc11#aes128-gcm',
        'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
        'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
        'http://www.w3.org/2009/xmlenc11#rsa-oaep',
        'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
    ];

    private const string NS_XENC = 'http://www.w3.org/2001/04/xmlenc#';
    private const string NS_XENC11 = 'http://www.w3.org/2009/xmlenc11#';
    private const string RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
    private const string RSA_OAEP = 'http://www.w3.org/2009/xmlenc11#rsa-oaep';
    private const string SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';
    private const string MGF1_SHA1 = 'http://www.w3.org/2009/xmlenc11#mgf1sha1';
    private const string MGF1_SHA256 = 'http://www.w3.org/2009/xmlenc11#mgf1sha256';

    /** @var list<non-empty-string> */
    private const array GCM = [
        'http://www.w3.org/2009/xmlenc11#aes128-gcm',
        'http://www.w3.org/2009/xmlenc11#aes256-gcm',
    ];

    /** @var list<non-empty-string> ADFS's default and older deployments': taken unless GCM is required. */
    private const array CBC = [
        'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
        'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
    ];

    /** @var array<non-empty-string, positive-int> */
    private const array KEY_BYTES = [
        'http://www.w3.org/2009/xmlenc11#aes128-gcm' => 16,
        'http://www.w3.org/2009/xmlenc11#aes256-gcm' => 32,
        'http://www.w3.org/2001/04/xmlenc#aes128-cbc' => 16,
        'http://www.w3.org/2001/04/xmlenc#aes256-cbc' => 32,
    ];

    /** @var list<non-empty-string> */
    private const array DIGESTS = [
        'http://www.w3.org/2001/04/xmlenc#sha256',
        'http://www.w3.org/2001/04/xmldsig-more#sha384',
        'http://www.w3.org/2001/04/xmlenc#sha512',
    ];

    #[\Override]
    public function authnRequestUrl(AuthnRequestDetails $request, ?Closure $sign = null): string
    {
        $document = new DOMDocument('1.0', 'UTF-8');
        $root = $document->createElementNS(self::NS_SAMLP, 'samlp:AuthnRequest');
        $document->appendChild($root);
        $root->setAttribute('ID', $request->id->value);
        $root->setAttribute('Version', '2.0');
        $root->setAttribute('IssueInstant', self::instant($request->issuedAt));
        $root->setAttribute('Destination', $request->singleSignOnUrl->value);
        $root->setAttribute('AssertionConsumerServiceURL', $request->assertionConsumerServiceUrl->value);
        $root->setAttribute('ProtocolBinding', self::BINDING_POST);
        $issuer = $document->createElementNS(self::NS_SAML, 'saml:Issuer');
        $issuer->appendChild($document->createTextNode($request->serviceProviderEntityId));
        $root->appendChild($issuer);
        if ($request->nameIdFormat !== null) {
            $policy = $document->createElementNS(self::NS_SAMLP, 'samlp:NameIDPolicy');
            $policy->setAttribute('Format', $request->nameIdFormat);
            $policy->setAttribute('AllowCreate', 'true');
            $root->appendChild($policy);
        }
        $xml = (string) $document->saveXML($root);
        $deflated = gzdeflate($xml);
        if ($deflated === false) {
            throw new \LogicException('An AuthnRequest did not deflate.');
        }

        // Bindings §3.4.4.1: the query is appended to the endpoint as registered, never rebuilt, and the
        // signature covers the three parameters exactly as they are sent, in that order.
        $url = $request->singleSignOnUrl->value;
        $query = 'SAMLRequest=' . rawurlencode(base64_encode($deflated))
            . '&RelayState=' . rawurlencode($request->relayState);
        if ($sign !== null) {
            $query .= '&SigAlg=' . rawurlencode(self::RSA_ALGORITHMS[0]);
            $query .= '&Signature=' . rawurlencode(base64_encode($sign($query)));
        }

        return $url . (str_contains($url, '?') ? '&' : '?') . $query;
    }

    #[\Override]
    public function consume(string $encodedResponse, ExpectedResponse $expected): SamlIdentity|SamlRefused
    {
        if (strlen($encodedResponse) > intdiv(self::MAX_RESPONSE_BYTES * 4, 3) + 4) {
            return self::refused(SamlRefusal::Xml);
        }
        $xml = base64_decode(preg_replace('/\s+/', '', $encodedResponse) ?? '', true);
        if ($xml === false || $xml === '' || strlen($xml) > self::MAX_RESPONSE_BYTES) {
            return self::refused(SamlRefusal::Xml);
        }
        try {
            $document = DOMDocumentFactory::fromString($xml);
        } catch (Throwable) {
            return self::refused(SamlRefusal::Xml);
        }
        $xpath = self::xpath($document);
        $root = $document->documentElement;
        if (
            ! $root instanceof DOMElement
            || $root->namespaceURI !== self::NS_SAMLP
            || $root->localName !== 'Response'
            || self::count($xpath, '//comment() | //processing-instruction()') > 0
            || self::count($xpath, '//saml:Assertion') + self::count($xpath, '//saml:EncryptedAssertion') !== 1
            || self::count($xpath, '/samlp:Response/saml:Assertion | /samlp:Response/saml:EncryptedAssertion') !== 1
        ) {
            return self::refused(SamlRefusal::Xml);
        }
        $encrypted = self::count($xpath, '/samlp:Response/saml:EncryptedAssertion') === 1;
        if (! $encrypted && $expected->requireEncryption) {
            return self::refused(SamlRefusal::Decryption);
        }

        try {
            Response::fromXML($root);
        } catch (Throwable) {
            return self::refused(SamlRefusal::Xml);
        }
        $refusal = self::envelopeRefusal($xpath, $root, $expected);
        if ($refusal !== null) {
            return self::refused($refusal);
        }

        if ($encrypted) {
            $plain = self::decrypted(self::element($xpath, '/samlp:Response/saml:EncryptedAssertion'), $expected);
            if ($plain === null) {
                return self::refused(SamlRefusal::Decryption);
            }
        } else {
            $plain = self::element($xpath, '/samlp:Response/saml:Assertion');
        }
        $assertion = self::verifiedAssertion($plain, $expected);
        if ($assertion === null) {
            return self::refused(SamlRefusal::Signature);
        }

        return self::identity($assertion, $expected);
    }

    #[\Override]
    public function readMetadata(string $document): IdentityProviderMetadata
    {
        if (strlen($document) > self::MAX_METADATA_BYTES) {
            throw new InvalidValue(sprintf('The metadata is at most %d bytes.', self::MAX_METADATA_BYTES));
        }
        try {
            $parsed = DOMDocumentFactory::fromString($document);
        } catch (Throwable) {
            throw new InvalidValue('The metadata is not an XML document this server reads (no DOCTYPE, no DTD).');
        }
        $root = $parsed->documentElement;
        $xpath = self::xpath($parsed);
        $aggregate = $root instanceof DOMElement && $root->namespaceURI === self::NS_MD
            && $root->localName === 'EntitiesDescriptor';
        if ($aggregate) {
            // Keycloak wraps its one entity in an aggregate; a federation's many are not one provider.
            $entities = self::elements($xpath, '//md:EntityDescriptor');
            $root = count($entities) === 1 ? $entities[0] : null;
        }
        if (
            ! $root instanceof DOMElement
            || $root->namespaceURI !== self::NS_MD
            || $root->localName !== 'EntityDescriptor'
        ) {
            throw new InvalidValue('The metadata is one EntityDescriptor: an aggregate of several is not read.');
        }
        $entityId = $root->getAttribute('entityID');
        if ($entityId === '' || strlen($entityId) > 1024) {
            throw new InvalidValue('The metadata names no entityID.');
        }
        $descriptors = array_values(array_filter(
            self::elements($xpath, 'md:IDPSSODescriptor', $root),
            static fn (DOMElement $d): bool => in_array(
                self::NS_SAMLP,
                preg_split('/\s+/', trim($d->getAttribute('protocolSupportEnumeration'))) ?: [],
                true,
            ),
        ));
        if (count($descriptors) !== 1) {
            throw new InvalidValue('The metadata holds no identity provider for SAML 2.0, or more than one.');
        }
        $descriptor = $descriptors[0];

        $singleSignOn = null;
        foreach (self::elements($xpath, 'md:SingleSignOnService', $descriptor) as $service) {
            if ($service->getAttribute('Binding') === self::BINDING_REDIRECT) {
                $singleSignOn = $service->getAttribute('Location');
                break;
            }
        }
        if ($singleSignOn === null) {
            throw new InvalidValue('The identity provider offers no HTTP-Redirect single sign-on service.');
        }
        try {
            $url = Url::fromString($singleSignOn);
        } catch (InvalidValue) {
            throw new InvalidValue('The single sign-on service is not a URL.');
        }
        if (! $url->isHttps()) {
            throw new InvalidValue('The single sign-on service is not an https URL.');
        }

        $certificates = [];
        foreach (self::elements($xpath, 'md:KeyDescriptor', $descriptor) as $key) {
            if (! in_array($key->getAttribute('use'), ['', 'signing'], true)) {
                continue;
            }
            foreach (self::elements($xpath, 'ds:KeyInfo/ds:X509Data/ds:X509Certificate', $key) as $certificate) {
                $pem = self::pem($certificate->textContent);
                $x509 = openssl_x509_parse($pem);
                /** @var mixed $seconds */
                $seconds = is_array($x509) ? ($x509['validTo_time_t'] ?? null) : null;
                $until = is_int($seconds) ? new \DateTimeImmutable('@' . $seconds) : null;
                $certificates[self::keyFingerprint($pem)] = SamlCertificate::fromPem($pem, $until);
            }
        }
        $certificates = array_values($certificates);
        if ($certificates === []) {
            throw new InvalidValue('The identity provider publishes no signing certificate.');
        }
        if (count($certificates) > self::MAX_CERTIFICATES) {
            throw new InvalidValue(sprintf('At most %d signing certificates are kept.', self::MAX_CERTIFICATES));
        }

        return new IdentityProviderMetadata($entityId, $url, $certificates);
    }

    #[\Override]
    public function serviceProviderMetadata(ServiceProviderDescription $description): string
    {
        $document = new DOMDocument('1.0', 'UTF-8');
        $document->formatOutput = true;
        $entity = $document->createElementNS(self::NS_MD, 'md:EntityDescriptor');
        $entity->setAttribute('entityID', $description->entityId);
        $document->appendChild($entity);
        $sp = $document->createElementNS(self::NS_MD, 'md:SPSSODescriptor');
        $sp->setAttribute('protocolSupportEnumeration', self::NS_SAMLP);
        $sp->setAttribute(
            'AuthnRequestsSigned',
            $description->signsRequests && $description->signingCertificates !== [] ? 'true' : 'false',
        );
        $sp->setAttribute('WantAssertionsSigned', 'true');
        $entity->appendChild($sp);
        $keys = ['signing' => $description->signingCertificates, 'encryption' => $description->encryptionCertificates];
        foreach ($keys as $use => $certificates) {
            foreach ($certificates as $certificate) {
                $key = $document->createElementNS(self::NS_MD, 'md:KeyDescriptor');
                $key->setAttribute('use', $use);
                $info = $document->createElementNS(self::NS_DS, 'ds:KeyInfo');
                $data = $document->createElementNS(self::NS_DS, 'ds:X509Data');
                $cert = $document->createElementNS(self::NS_DS, 'ds:X509Certificate');
                $cert->appendChild($document->createTextNode($certificate));
                $data->appendChild($cert);
                $info->appendChild($data);
                $key->appendChild($info);
                if ($use === 'encryption') {
                    // In order of preference (Metadata §2.4.1.1): GCM first, CBC for ADFS and its kind.
                    foreach (self::ENCRYPTION_METHODS as $algorithm) {
                        $method = $document->createElementNS(self::NS_MD, 'md:EncryptionMethod');
                        $method->setAttribute('Algorithm', $algorithm);
                        $key->appendChild($method);
                    }
                }
                $sp->appendChild($key);
            }
        }
        if ($description->nameIdFormat !== null) {
            $format = $document->createElementNS(self::NS_MD, 'md:NameIDFormat');
            $format->appendChild($document->createTextNode($description->nameIdFormat));
            $sp->appendChild($format);
        }
        $acs = $document->createElementNS(self::NS_MD, 'md:AssertionConsumerService');
        $acs->setAttribute('Binding', self::BINDING_POST);
        $acs->setAttribute('Location', $description->assertionConsumerServiceUrl);
        $acs->setAttribute('index', '0');
        $acs->setAttribute('isDefault', 'true');
        $sp->appendChild($acs);

        return (string) $document->saveXML();
    }

    /**
     * The assertion inside an `EncryptedAssertion` (SAML Core §2.3.4, XML Encryption 1.1), or null for
     * any failure at all, every one the same (§7, "No padding oracle"): the data encrypted with AES-GCM
     * or, unless the connection requires GCM, AES-CBC; its content key wrapped with RSA-OAEP, never
     * `rsa-1_5`, and unwrapped by this server's encryption key the `EncryptedKey` names by certificate,
     * or by each in turn. The plaintext is held to what a plain response is: one `saml:Assertion`, no
     * comment, no processing instruction. Its signature is checked afterwards, as for a plain one.
     */
    private static function decrypted(DOMElement $encrypted, ExpectedResponse $expected): ?DOMElement
    {
        $decrypter = $expected->decrypter;
        if ($decrypter === null || $decrypter->keys === []) {
            return null;
        }
        $document = $encrypted->ownerDocument;
        $xpath = self::xpath($document);
        $data = self::elements($xpath, 'xenc:EncryptedData', $encrypted);
        if (count($data) !== 1) {
            return null;
        }
        $methods = self::elements($xpath, 'xenc:EncryptionMethod', $data[0]);
        $cipher = count($methods) === 1 ? $methods[0]->getAttribute('Algorithm') : '';
        $allowed = $expected->requireGcm ? self::GCM : [...self::GCM, ...self::CBC];
        if (! in_array($cipher, $allowed, true)) {
            return null;
        }
        $keys = [
            ...self::elements($xpath, 'ds:KeyInfo/xenc:EncryptedKey', $data[0]),
            ...self::elements($xpath, 'xenc:EncryptedKey', $encrypted),
        ];
        if (count($keys) !== 1) {
            return null;
        }
        $digest = self::keyTransportDigest($xpath, $keys[0]);
        $wrapped = self::base64($xpath, 'xenc:CipherData/xenc:CipherValue', $keys[0]);
        $ciphertext = self::base64($xpath, 'xenc:CipherData/xenc:CipherValue', $data[0]);
        if ($digest === null || $wrapped === null || $ciphertext === null) {
            return null;
        }

        $named = array_map(
            static fn (DOMElement $c): string => (string) preg_replace('/\s+/', '', $c->textContent),
            self::elements($xpath, 'ds:KeyInfo/ds:X509Data/ds:X509Certificate', $keys[0]),
        );
        $candidates = array_values(array_filter(
            $decrypter->keys,
            static fn (array $key): bool => $named === [] || in_array($key['certificate'], $named, true),
        ));
        $contentKey = null;
        foreach ($candidates as $key) {
            $contentKey = $decrypter->contentKey($key['kid'], $wrapped, $digest);
            if ($contentKey !== null) {
                break;
            }
        }
        if ($contentKey === null || strlen($contentKey) !== self::KEY_BYTES[$cipher]) {
            return null;
        }
        try {
            $plaintext = (new AES(new SymmetricKey($contentKey), $cipher))->decrypt($ciphertext);
            $decrypted = DOMDocumentFactory::fromString($plaintext);
        } catch (Throwable) {
            return null;
        }
        $plainXpath = self::xpath($decrypted);
        $assertion = $decrypted->documentElement;
        if (
            ! $assertion instanceof DOMElement
            || $assertion->namespaceURI !== self::NS_SAML
            || $assertion->localName !== 'Assertion'
            || self::count($plainXpath, '//comment() | //processing-instruction()') > 0
            || self::count($plainXpath, '//saml:Assertion | //saml:EncryptedAssertion') !== 1
        ) {
            return null;
        }

        return $assertion;
    }

    /**
     * The OAEP digest of an `EncryptedKey`, when its key transport is one this server takes: XML
     * Encryption's `rsa-oaep-mgf1p` (SHA-1 throughout), or 1.1's `rsa-oaep` with SHA-1 and its default
     * MGF, or SHA-256 with MGF1 over SHA-256 (PHP's OpenSSL takes one digest for both). Never `rsa-1_5`.
     */
    private static function keyTransportDigest(DOMXPath $xpath, DOMElement $key): ?OaepDigest
    {
        $methods = self::elements($xpath, 'xenc:EncryptionMethod', $key);
        if (count($methods) !== 1) {
            return null;
        }
        $algorithm = $methods[0]->getAttribute('Algorithm');
        $digests = self::elements($xpath, 'ds:DigestMethod', $methods[0]);
        $digest = $digests === [] ? self::SHA1 : $digests[0]->getAttribute('Algorithm');
        $mgfs = self::elements($xpath, 'xenc11:MGF', $methods[0]);
        $mgf = $mgfs === [] ? null : $mgfs[0]->getAttribute('Algorithm');
        if (count($digests) > 1 || count($mgfs) > 1) {
            return null;
        }

        return match (true) {
            $algorithm === self::RSA_OAEP_MGF1P && $digest === self::SHA1 && $mgf === null => OaepDigest::Sha1,
            $algorithm === self::RSA_OAEP && $digest === self::SHA1
                && ($mgf === null || $mgf === self::MGF1_SHA1) => OaepDigest::Sha1,
            $algorithm === self::RSA_OAEP && $digest === self::DIGESTS[0] && $mgf === self::MGF1_SHA256
                => OaepDigest::Sha256,
            default => null,
        };
    }

    private static function base64(DOMXPath $xpath, string $query, DOMElement $context): ?string
    {
        $values = self::elements($xpath, $query, $context);
        if (count($values) !== 1) {
            return null;
        }
        $bytes = base64_decode((string) preg_replace('/\s+/', '', $values[0]->textContent), true);

        return $bytes === false || $bytes === '' ? null : $bytes;
    }

    /** The unsigned envelope's own fields (Profiles §4.1.4.2, §4.1.4.5). */
    private static function envelopeRefusal(
        DOMXPath $xpath,
        DOMElement $response,
        ExpectedResponse $expected,
    ): ?SamlRefusal {
        if ($response->getAttribute('Destination') !== $expected->assertionConsumerServiceUrl) {
            return SamlRefusal::Destination;
        }
        $issuers = self::elements($xpath, 'saml:Issuer', $response);
        if (
            count($issuers) > 1
            || ($issuers !== [] && ! self::isIssuer($issuers[0], $expected->identityProviderEntityId))
        ) {
            return SamlRefusal::Issuer;
        }
        if (! hash_equals($expected->inResponseTo->value, $response->getAttribute('InResponseTo'))) {
            return SamlRefusal::InResponseTo;
        }
        $codes = self::elements($xpath, 'samlp:Status/samlp:StatusCode', $response);
        if (count($codes) !== 1 || $codes[0]->getAttribute('Value') !== self::STATUS_SUCCESS) {
            return SamlRefusal::Status;
        }

        return null;
    }

    /**
     * The assertion rebuilt from what its signature covers, if it is signed as this server accepts by
     * a certificate of the connection; null otherwise.
     */
    private static function verifiedAssertion(DOMElement $inResponse, ExpectedResponse $expected): ?DOMElement
    {
        // On its own, so the library's same-document reference resolves to the assertion itself;
        // exclusive canonicalisation makes its bytes those it had inside the response.
        $own = new DOMDocument('1.0', 'UTF-8');
        $element = $own->importNode($inResponse, true);
        if (! $element instanceof DOMElement) {
            return null;
        }
        $own->appendChild($element);
        $xpath = self::xpath($own);
        $algorithm = self::acceptedSignatureAlgorithm($xpath, $element);
        if ($algorithm === null) {
            return null;
        }
        try {
            $assertion = Assertion::fromXML($element);
        } catch (Throwable) {
            return null;
        }

        foreach ($expected->certificates as $pem) {
            $verifier = self::verifier($algorithm, $pem);
            if ($verifier === null) {
                continue;
            }
            try {
                $verified = $assertion->verify($verifier);
            } catch (Throwable) {
                continue;
            }
            if ($verified instanceof Assertion) {
                $rebuilt = new DOMDocument('1.0', 'UTF-8');
                $rebuilt->appendChild($rebuilt->importNode($verified->toXML(), true));

                return $rebuilt->documentElement;
            }
        }

        return null;
    }

    /** The signature algorithm, when the signature's shape is one this server accepts; null otherwise. */
    private static function acceptedSignatureAlgorithm(DOMXPath $xpath, DOMElement $assertion): ?string
    {
        $signatures = self::elements($xpath, 'ds:Signature', $assertion);
        if (count($signatures) !== 1 || self::count($xpath, '//ds:Signature') !== 1) {
            return null;
        }
        $signedInfo = self::elements($xpath, 'ds:SignedInfo', $signatures[0]);
        if (count($signedInfo) !== 1) {
            return null;
        }
        $canonicalization = self::elements($xpath, 'ds:CanonicalizationMethod', $signedInfo[0]);
        $method = self::elements($xpath, 'ds:SignatureMethod', $signedInfo[0]);
        $references = self::elements($xpath, 'ds:Reference', $signedInfo[0]);
        if (
            count($canonicalization) !== 1
            || $canonicalization[0]->getAttribute('Algorithm') !== self::EXCLUSIVE_C14N
            || count($method) !== 1
            || count($references) !== 1
            || $references[0]->getAttribute('URI') !== '#' . $assertion->getAttribute('ID')
            || $assertion->getAttribute('ID') === ''
        ) {
            return null;
        }
        $transforms = array_map(
            static fn (DOMElement $t): string => $t->getAttribute('Algorithm'),
            self::elements($xpath, 'ds:Transforms/ds:Transform', $references[0]),
        );
        $digest = self::elements($xpath, 'ds:DigestMethod', $references[0]);
        if (
            $transforms !== [self::ENVELOPED, self::EXCLUSIVE_C14N]
            || count($digest) !== 1
            || ! in_array($digest[0]->getAttribute('Algorithm'), self::DIGESTS, true)
        ) {
            return null;
        }
        $algorithm = $method[0]->getAttribute('Algorithm');

        return in_array($algorithm, self::RSA_ALGORITHMS, true) ? $algorithm : null;
    }

    /** A verifier for the algorithm with the certificate's key; null when the key is not RSA. */
    private static function verifier(string $algorithm, string $pem): ?SignatureAlgorithmInterface
    {
        try {
            $key = (new X509Certificate(PEM::fromString($pem)))->getPublicKey();
            $details = openssl_pkey_get_details(openssl_pkey_get_public($key->getMaterial()) ?: throw new Exception());

            return is_array($details) && ($details['type'] ?? null) === OPENSSL_KEYTYPE_RSA
                ? new RSA($key, $algorithm)
                : null;
        } catch (Throwable) {
            return null;
        }
    }

    /** Everything read from the signed assertion, and only from it. */
    private static function identity(DOMElement $assertion, ExpectedResponse $expected): SamlIdentity|SamlRefused
    {
        $xpath = self::xpath($assertion->ownerDocument);
        $now = $expected->now;
        $issuers = self::elements($xpath, 'saml:Issuer', $assertion);
        if (count($issuers) !== 1 || ! self::isIssuer($issuers[0], $expected->identityProviderEntityId)) {
            return self::refused(SamlRefusal::Issuer);
        }

        $conditions = self::elements($xpath, 'saml:Conditions', $assertion);
        if (count($conditions) !== 1) {
            return self::refused(SamlRefusal::Audience);
        }
        try {
            $notBefore = self::time($conditions[0], 'NotBefore');
            $conditionsEnd = self::time($conditions[0], 'NotOnOrAfter');
        } catch (InvalidValue) {
            return self::refused(SamlRefusal::Xml);
        }
        if (
            ($notBefore !== null && $notBefore > self::ahead($now))
            || ($conditionsEnd !== null && $conditionsEnd <= self::behind($now))
        ) {
            return self::refused(SamlRefusal::Expired);
        }
        $restrictions = self::elements($xpath, 'saml:AudienceRestriction', $conditions[0]);
        if ($restrictions === []) {
            return self::refused(SamlRefusal::Audience);
        }
        foreach ($restrictions as $restriction) {
            $audiences = array_map(
                static fn (DOMElement $a): string => trim($a->textContent),
                self::elements($xpath, 'saml:Audience', $restriction),
            );
            if (! in_array($expected->serviceProviderEntityId, $audiences, true)) {
                // Core §2.5.1.4: every AudienceRestriction must hold.
                return self::refused(SamlRefusal::Audience);
            }
        }

        $subjects = self::elements($xpath, 'saml:Subject', $assertion);
        if (count($subjects) !== 1) {
            return self::refused(SamlRefusal::Subject);
        }
        $confirmation = self::bearerConfirmation($xpath, $subjects[0], $expected);
        if (! $confirmation instanceof DateTimeImmutable) {
            return self::refused($confirmation);
        }
        $statements = self::elements($xpath, 'saml:AuthnStatement', $assertion);
        if ($statements === []) {
            return self::refused(SamlRefusal::Subject);
        }
        try {
            $authenticatedAt = self::time($statements[0], 'AuthnInstant');
        } catch (InvalidValue) {
            return self::refused(SamlRefusal::Xml);
        }

        $attributes = [];
        foreach (self::elements($xpath, 'saml:AttributeStatement/saml:Attribute', $assertion) as $attribute) {
            $name = $attribute->getAttribute('Name');
            if ($name === '') {
                continue;
            }
            foreach (self::elements($xpath, 'saml:AttributeValue', $attribute) as $value) {
                if (self::count($xpath, '*', $value) === 0) {
                    $attributes[$name][] = $value->textContent;
                }
            }
            $attributes[$name] ??= [];
        }
        $nameIds = self::elements($xpath, 'saml:NameID', $subjects[0]);
        $nameId = count($nameIds) === 1 ? $nameIds[0]->textContent : null;
        $format = count($nameIds) === 1 && $nameIds[0]->hasAttribute('Format')
            ? $nameIds[0]->getAttribute('Format')
            : null;

        if ($expected->subjectAttribute === null) {
            // The persistent NameID: a transient one changes at every sign-in, an address changes hands.
            $subject = $format === self::PERSISTENT ? $nameId : null;
        } else {
            $values = $attributes[$expected->subjectAttribute] ?? [];
            $subject = count($values) === 1 ? $values[0] : null;
        }
        if ($subject === null || $subject === '' || strlen($subject) > 255) {
            return self::refused(SamlRefusal::Subject);
        }
        $id = $assertion->getAttribute('ID');
        if ($id === '') {
            return self::refused(SamlRefusal::Xml);
        }
        $validUntil = $conditionsEnd !== null && $conditionsEnd < $confirmation ? $conditionsEnd : $confirmation;

        return new SamlIdentity($subject, $nameId, $format, $attributes, $id, $validUntil, $authenticatedAt ?? $now);
    }

    /**
     * The `NotOnOrAfter` of a bearer confirmation for this endpoint and this request, still ahead and
     * with no `NotBefore` (Profiles §4.1.4.2); the reason when there is none.
     */
    private static function bearerConfirmation(
        DOMXPath $xpath,
        DOMElement $subject,
        ExpectedResponse $expected,
    ): DateTimeImmutable|SamlRefusal {
        $reason = SamlRefusal::Subject;
        foreach (self::elements($xpath, 'saml:SubjectConfirmation', $subject) as $confirmation) {
            if ($confirmation->getAttribute('Method') !== self::BEARER) {
                continue;
            }
            $data = self::elements($xpath, 'saml:SubjectConfirmationData', $confirmation);
            if (count($data) !== 1) {
                continue;
            }
            try {
                $end = self::time($data[0], 'NotOnOrAfter');
            } catch (InvalidValue) {
                return SamlRefusal::Xml;
            }
            if ($data[0]->getAttribute('Recipient') !== $expected->assertionConsumerServiceUrl) {
                $reason = SamlRefusal::Destination;
            } elseif (! hash_equals($expected->inResponseTo->value, $data[0]->getAttribute('InResponseTo'))) {
                $reason = SamlRefusal::InResponseTo;
            } elseif ($end === null || $end <= self::behind($expected->now) || $data[0]->hasAttribute('NotBefore')) {
                $reason = SamlRefusal::Expired;
            } else {
                return $end;
            }
        }

        return $reason;
    }

    private static function isIssuer(DOMElement $issuer, string $entityId): bool
    {
        $format = $issuer->getAttribute('Format');

        return ($format === '' || $format === self::ENTITY) && trim($issuer->textContent) === $entityId;
    }

    /** @throws InvalidValue */
    private static function time(DOMElement $element, string $attribute): ?DateTimeImmutable
    {
        if (! $element->hasAttribute($attribute)) {
            return null;
        }
        $value = $element->getAttribute($attribute);
        if (preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/D', $value) !== 1) {
            throw new InvalidValue('Not an xs:dateTime.');
        }
        try {
            return new DateTimeImmutable($value);
        } catch (Exception) {
            throw new InvalidValue('Not an xs:dateTime.');
        }
    }

    private static function ahead(DateTimeImmutable $now): DateTimeImmutable
    {
        return $now->modify(sprintf('+%d seconds', self::SKEW_SECONDS));
    }

    private static function behind(DateTimeImmutable $now): DateTimeImmutable
    {
        return $now->modify(sprintf('-%d seconds', self::SKEW_SECONDS));
    }

    /**
     * A certificate from metadata as PEM, if it holds a key this server verifies with.
     *
     * @return non-empty-string
     *
     * @throws InvalidValue
     */
    private static function pem(string $base64): string
    {
        $der = base64_decode(preg_replace('/\s+/', '', $base64) ?? '', true);
        if ($der === false || $der === '') {
            throw new InvalidValue('A signing certificate is not base64.');
        }
        $pem = "-----BEGIN CERTIFICATE-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END CERTIFICATE-----\n";
        $key = openssl_pkey_get_public($pem);
        $details = $key === false ? false : openssl_pkey_get_details($key);
        if (! is_array($details)) {
            throw new InvalidValue('A signing certificate cannot be read.');
        }
        $bits = $details['bits'] ?? 0;
        if (($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA || ! is_int($bits) || $bits < 2048) {
            throw new InvalidValue('A signing certificate holds an RSA key of 2048 bits or more.');
        }

        return $pem;
    }

    /** The key's own fingerprint: certificates for the same key are one. */
    private static function keyFingerprint(string $pem): string
    {
        $details = openssl_pkey_get_details(openssl_pkey_get_public($pem) ?: throw new \LogicException('Checked.'));

        /** @var mixed $key */
        $key = is_array($details) ? ($details['key'] ?? null) : null;

        return hash('sha256', is_string($key) ? $key : $pem);
    }

    private static function xpath(DOMDocument $document): DOMXPath
    {
        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('samlp', self::NS_SAMLP);
        $xpath->registerNamespace('saml', self::NS_SAML);
        $xpath->registerNamespace('md', self::NS_MD);
        $xpath->registerNamespace('ds', self::NS_DS);
        $xpath->registerNamespace('xenc', self::NS_XENC);
        $xpath->registerNamespace('xenc11', self::NS_XENC11);

        return $xpath;
    }

    private static function count(DOMXPath $xpath, string $query, ?DOMNode $context = null): int
    {
        $nodes = $xpath->query($query, $context);

        return $nodes === false ? 0 : $nodes->length;
    }

    /** @return list<DOMElement> */
    private static function elements(DOMXPath $xpath, string $query, ?DOMNode $context = null): array
    {
        $nodes = $xpath->query($query, $context);
        $elements = [];
        if ($nodes !== false) {
            /** @var DOMNode $node */
            foreach ($nodes as $node) {
                if ($node instanceof DOMElement) {
                    $elements[] = $node;
                }
            }
        }

        return $elements;
    }

    private static function element(DOMXPath $xpath, string $query): DOMElement
    {
        return self::elements($xpath, $query)[0] ?? throw new \LogicException('Counted before.');
    }

    private static function instant(DateTimeImmutable $instant): string
    {
        return $instant->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z');
    }

    private static function refused(SamlRefusal $reason): SamlRefused
    {
        return new SamlRefused($reason);
    }
}
