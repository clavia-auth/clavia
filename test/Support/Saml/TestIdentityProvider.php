<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Saml;

use DOMDocument;
use DOMElement;
use DOMXPath;
use LogicException;

/**
 * A SAML identity provider for tests: it builds `Response`s and signs them with real RSA and EC keys,
 * by hand (exclusive canonicalisation, enveloped signature, XML Signature 1.1), apart from the library
 * under test, so the adapter's contract checks genuine XML, as the passkey verifier's checks genuine
 * CBOR. Every option bends one thing a real identity provider, or an attacker, could send.
 */
final class TestIdentityProvider
{
    public const string ENTITY_ID = 'https://idp.acme.example/saml';
    public const string SP_ENTITY_ID = 'https://auth.clavia.test/auth/saml/acme';
    public const string ACS = 'https://auth.clavia.test/auth/saml/acme/acs';
    public const string NOW = '2026-03-04T09:00:00Z';
    public const string REQUEST_ID = '_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    public const string PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';

    public const string RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    public const string RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    public const string ECDSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256';
    public const string SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
    public const string SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';

    private const string NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
    private const string NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
    private const string NS_DS = 'http://www.w3.org/2000/09/xmldsig#';

    /** @var array<string, array{private: non-empty-string, certificate: non-empty-string}> */
    private static array $keys = [];

    /** @return array{private: non-empty-string, certificate: non-empty-string} RSA 2048, the connection's. */
    public static function rsa(): array
    {
        return self::key('rsa', ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    }

    /** @return array{private: non-empty-string, certificate: non-empty-string} EC P-256. */
    public static function ec(): array
    {
        return self::key('ec', ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    }

    /** @return array{private: non-empty-string, certificate: non-empty-string} Somebody else's RSA key. */
    public static function attacker(): array
    {
        return self::key('attacker', ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    }

    /** @return array{private: non-empty-string, certificate: non-empty-string} Too short to be trusted. */
    public static function weak(): array
    {
        return self::key('weak', ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 1024]);
    }

    /**
     * A response, base64 as POSTed. The defaults are a valid sign-in, signed with the RSA key.
     *
     * @param array<string, mixed> $o
     */
    public static function response(array $o = []): string
    {
        return base64_encode(self::xml($o));
    }

    /** @param array<string, mixed> $o */
    public static function xml(array $o = []): string
    {
        $o += [
            'destination' => self::ACS,
            'responseIssuer' => self::ENTITY_ID,
            'inResponseTo' => self::REQUEST_ID,
            'status' => 'urn:oasis:names:tc:SAML:2.0:status:Success',
            'issuer' => self::ENTITY_ID,
            'audience' => self::SP_ENTITY_ID,
            'recipient' => self::ACS,
            'confirmationInResponseTo' => self::REQUEST_ID,
            'notBefore' => '2026-03-04T08:59:00Z',
            'notOnOrAfter' => '2026-03-04T09:05:00Z',
            'confirmationNotOnOrAfter' => '2026-03-04T09:05:00Z',
            'nameId' => 'a8f3c2d1-0b9e-4f7a-8c6d-5e4f3a2b1c0d',
            'nameIdFormat' => self::PERSISTENT,
            'attributes' => ['email' => ['ada@acme.example'], 'givenname' => ['Ada']],
            'key' => self::rsa(),
            'algorithm' => self::RSA_SHA256,
            'digest' => self::SHA256,
            'keyInfo' => null,
            'signAssertion' => true,
            'signResponse' => false,
            'conditions' => true,
            'authnStatement' => true,
            'commentInNameId' => false,
            'transforms' => null,
        ];
        $e = static fn (mixed $v): string => htmlspecialchars((string) $v, ENT_XML1 | ENT_QUOTES, 'UTF-8');
        $attributes = '';
        /** @var array<string, list<string>> $given */
        $given = $o['attributes'];
        foreach ($given as $name => $values) {
            $attributes .= '<saml:Attribute Name="' . $e($name) . '">';
            foreach ($values as $value) {
                $attributes .= '<saml:AttributeValue>' . $e($value) . '</saml:AttributeValue>';
            }
            $attributes .= '</saml:Attribute>';
        }
        $nameId = $e($o['nameId']);
        if ($o['commentInNameId'] === true) {
            $nameId = 'admin@acme.example<!---->.evil.example';
        }
        $responseIssuer = $o['responseIssuer'] === null
            ? ''
            : '<saml:Issuer>' . $e($o['responseIssuer']) . '</saml:Issuer>';
        $conditions = $o['conditions'] !== true ? '' : '<saml:Conditions'
            . ($o['notBefore'] === null ? '' : ' NotBefore="' . $e($o['notBefore']) . '"')
            . ($o['notOnOrAfter'] === null ? '' : ' NotOnOrAfter="' . $e($o['notOnOrAfter']) . '"')
            . '><saml:AudienceRestriction><saml:Audience>' . $e($o['audience'])
            . '</saml:Audience></saml:AudienceRestriction></saml:Conditions>';
        $authn = $o['authnStatement'] !== true ? '' : '<saml:AuthnStatement AuthnInstant="2026-03-04T08:59:30Z" '
            . 'SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>'
            . 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
            . '</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>';

        $xml = '<?xml version="1.0" encoding="UTF-8"?>'
            . '<samlp:Response xmlns:samlp="' . self::NS_SAMLP . '" xmlns:saml="' . self::NS_SAML . '"'
            . ' ID="_r1" Version="2.0" IssueInstant="2026-03-04T09:00:00Z"'
            . ' Destination="' . $e($o['destination']) . '" InResponseTo="' . $e($o['inResponseTo']) . '">'
            . $responseIssuer
            . '<samlp:Status><samlp:StatusCode Value="' . $e($o['status']) . '"/></samlp:Status>'
            . '<saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-03-04T09:00:00Z">'
            . '<saml:Issuer>' . $e($o['issuer']) . '</saml:Issuer>'
            . '<saml:Subject><saml:NameID Format="' . $e($o['nameIdFormat']) . '">' . $nameId . '</saml:NameID>'
            . '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            . '<saml:SubjectConfirmationData NotOnOrAfter="' . $e($o['confirmationNotOnOrAfter']) . '"'
            . ' Recipient="' . $e($o['recipient']) . '" InResponseTo="' . $e($o['confirmationInResponseTo']) . '"/>'
            . '</saml:SubjectConfirmation></saml:Subject>'
            . $conditions
            . $authn
            . ($attributes === '' ? '' : '<saml:AttributeStatement>' . $attributes . '</saml:AttributeStatement>')
            . '</saml:Assertion>'
            . '</samlp:Response>';

        $document = new DOMDocument();
        $document->preserveWhiteSpace = true;
        if (! $document->loadXML($xml)) {
            throw new LogicException('The test identity provider wrote broken XML.');
        }
        $xpath = self::xpath($document);
        /** @var array{private: string, certificate: string} $key */
        $key = $o['key'];
        if ($o['signAssertion'] === true) {
            self::sign(self::first($xpath, '//saml:Assertion'), $key, $o);
        }
        if ($o['signResponse'] === true) {
            self::sign(self::first($xpath, '/samlp:Response'), $key, $o);
        }

        return (string) $document->saveXML();
    }

    /**
     * An enveloped signature on `$element`, placed after its `Issuer` (the schema's order).
     *
     * @param array{private: string, certificate: string} $key
     * @param array<string, mixed>                        $o
     */
    public static function sign(DOMElement $element, array $key, array $o = []): void
    {
        $o += ['algorithm' => self::RSA_SHA256, 'digest' => self::SHA256, 'keyInfo' => null, 'transforms' => null];
        $document = $element->ownerDocument;
        $digestName = $o['digest'] === self::SHA1 ? 'sha1' : 'sha256';
        /** @psalm-suppress WeakHash SHA-1 on purpose: the forged digest the adapter must refuse. */
        $digest = base64_encode(hash($digestName, (string) $element->C14N(true, false), true));

        $signature = $document->createElementNS(self::NS_DS, 'ds:Signature');
        $signedInfo = $document->createElementNS(self::NS_DS, 'ds:SignedInfo');
        $signature->appendChild($signedInfo);
        $c14n = $document->createElementNS(self::NS_DS, 'ds:CanonicalizationMethod');
        $c14n->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');
        $signedInfo->appendChild($c14n);
        $method = $document->createElementNS(self::NS_DS, 'ds:SignatureMethod');
        $method->setAttribute('Algorithm', (string) $o['algorithm']);
        $signedInfo->appendChild($method);
        $reference = $document->createElementNS(self::NS_DS, 'ds:Reference');
        $reference->setAttribute('URI', '#' . $element->getAttribute('ID'));
        $transforms = $document->createElementNS(self::NS_DS, 'ds:Transforms');
        /** @var list<string> $algorithms */
        $algorithms = $o['transforms'] ?? [
            'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
            'http://www.w3.org/2001/10/xml-exc-c14n#',
        ];
        foreach ($algorithms as $algorithm) {
            $transform = $document->createElementNS(self::NS_DS, 'ds:Transform');
            $transform->setAttribute('Algorithm', $algorithm);
            $transforms->appendChild($transform);
        }
        $reference->appendChild($transforms);
        $digestMethod = $document->createElementNS(self::NS_DS, 'ds:DigestMethod');
        $digestMethod->setAttribute('Algorithm', (string) $o['digest']);
        $reference->appendChild($digestMethod);
        $reference->appendChild($document->createElementNS(self::NS_DS, 'ds:DigestValue', $digest));
        $signedInfo->appendChild($reference);

        $issuer = null;
        /** @var \DOMNode $child */
        foreach ($element->childNodes as $child) {
            if ($child instanceof DOMElement && $child->localName === 'Issuer') {
                $issuer = $child;
                break;
            }
        }
        $element->insertBefore($signature, $issuer?->nextSibling ?? $element->firstChild);

        $input = (string) $signedInfo->C14N(true, false);
        $isEc = $o['algorithm'] === self::ECDSA_SHA256;
        $hash = $o['algorithm'] === self::RSA_SHA1 ? 'sha1' : 'sha256';
        if (! openssl_sign($input, $raw, $key['private'], $hash)) {
            throw new LogicException('The test identity provider could not sign.');
        }
        /** @var string $raw */
        $value = $isEc ? self::rawEcdsa($raw, 32) : $raw;
        $signature->appendChild($document->createElementNS(self::NS_DS, 'ds:SignatureValue', base64_encode($value)));
        if (is_string($o['keyInfo'])) {
            $info = $document->createElementNS(self::NS_DS, 'ds:KeyInfo');
            $data = $document->createElementNS(self::NS_DS, 'ds:X509Data');
            $data->appendChild($document->createElementNS(self::NS_DS, 'ds:X509Certificate', self::der($o['keyInfo'])));
            $info->appendChild($data);
            $signature->appendChild($info);
        }
    }

    /** The certificate's DER, base64, as metadata and `KeyInfo` carry it. */
    public static function der(string $pem): string
    {
        return preg_replace('/-----[^-]+-----|\s+/', '', $pem) ?? '';
    }

    /**
     * An identity provider's metadata, Entra-style, with the given signing certificates.
     *
     * @param list<string> $certificates PEM.
     */
    public static function metadata(
        array $certificates = [],
        string $binding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        string $location = 'https://idp.acme.example/saml/sso',
    ): string {
        $keys = '';
        /** @var string $certificate */
        foreach ($certificates as $certificate) {
            $keys .= '<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data>'
                . '<X509Certificate>' . self::der($certificate) . '</X509Certificate>'
                . '</X509Data></KeyInfo></KeyDescriptor>';
        }

        return '<?xml version="1.0" encoding="utf-8"?>'
            . '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="' . self::ENTITY_ID . '">'
            . '<!-- Published by the identity provider. -->'
            . '<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            . $keys
            . '<SingleSignOnService Binding="' . $binding . '" Location="' . htmlspecialchars($location) . '"/>'
            . '<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
            . 'Location="https://idp.acme.example/saml/post"/>'
            . '</IDPSSODescriptor></EntityDescriptor>';
    }

    private static function rawEcdsa(string $der, int $size): string
    {
        // SEQUENCE { INTEGER r, INTEGER s }, short lengths for P-256.
        $offset = 2;
        $parts = [];
        for ($i = 0; $i < 2; ++$i) {
            $length = ord($der[$offset + 1]);
            $parts[] = str_pad(ltrim(substr($der, $offset + 2, $length), "\x00"), $size, "\x00", STR_PAD_LEFT);
            $offset += 2 + $length;
        }

        return $parts[0] . $parts[1];
    }

    /**
     * @param array<string, int|string> $options
     *
     * @return array{private: non-empty-string, certificate: non-empty-string}
     */
    private static function key(string $name, array $options): array
    {
        if (! isset(self::$keys[$name])) {
            $private = openssl_pkey_new($options) ?: throw new LogicException('No key.');
            $csr = openssl_csr_new(['commonName' => 'Test IdP ' . $name], $private, ['digest_alg' => 'sha256']);
            if (! $csr instanceof \OpenSSLCertificateSigningRequest) {
                throw new LogicException('No request.');
            }
            $certificate = openssl_csr_sign($csr, null, $private, 3650, ['digest_alg' => 'sha256'])
                ?: throw new LogicException('No certificate.');
            openssl_pkey_export($private, $privatePem);
            openssl_x509_export($certificate, $certificatePem);
            if ($privatePem === '' || $certificatePem === '') {
                throw new LogicException('No PEM.');
            }
            self::$keys[$name] = ['private' => $privatePem, 'certificate' => $certificatePem];
        }

        return self::$keys[$name];
    }

    private static function xpath(DOMDocument $document): DOMXPath
    {
        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('samlp', self::NS_SAMLP);
        $xpath->registerNamespace('saml', self::NS_SAML);

        return $xpath;
    }

    private static function first(DOMXPath $xpath, string $query): DOMElement
    {
        $node = $xpath->query($query)->item(0);

        return $node instanceof DOMElement ? $node : throw new LogicException('No ' . $query);
    }
}
