<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Connection\Saml;

use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Url;

/**
 * One SAML identity provider (docs/design/saml-connections.md §4): its entity ID, its HTTP-Redirect
 * single sign-on URL and the one to three certificates its assertions are signed with, as read from
 * its metadata, the metadata URL to read them again from (or none), and the connection's options.
 */
final readonly class SamlSettings
{
    public const int MAX_CERTIFICATES = 3;

    /**
     * @param non-empty-string               $entityId
     * @param non-empty-list<SamlCertificate> $certificates
     */
    private function __construct(
        public string $entityId,
        public Url $singleSignOnUrl,
        public array $certificates,
        public ?Url $metadataUrl,
        public SamlOptions $options,
    ) {
    }

    /**
     * @param list<SamlCertificate> $certificates
     *
     * @throws InvalidValue
     */
    public static function of(
        string $entityId,
        Url $singleSignOnUrl,
        array $certificates,
        ?Url $metadataUrl,
        SamlOptions $options,
    ): self {
        if ($entityId === '' || strlen($entityId) > 1024) {
            throw new InvalidValue('An identity provider\'s entity ID is 1 to 1024 bytes.');
        }
        if (! $singleSignOnUrl->isHttps() || ($metadataUrl !== null && ! $metadataUrl->isHttps())) {
            throw new InvalidValue('The single sign-on and metadata URLs of a SAML connection are https.');
        }
        if ($certificates === [] || count($certificates) > self::MAX_CERTIFICATES) {
            throw new InvalidValue(
                sprintf('A SAML connection keeps 1 to %d signing certificates.', self::MAX_CERTIFICATES),
            );
        }

        return new self($entityId, $singleSignOnUrl, $certificates, $metadataUrl, $options);
    }

    /**
     * The same connection's provider as its metadata now says (a refresh); the options and the
     * metadata URL stay.
     *
     * @param list<SamlCertificate> $certificates
     *
     * @throws InvalidValue
     */
    public function withMetadata(string $entityId, Url $singleSignOnUrl, array $certificates): self
    {
        return self::of($entityId, $singleSignOnUrl, $certificates, $this->metadataUrl, $this->options);
    }

    /** @return non-empty-list<non-empty-string> */
    public function certificatePems(): array
    {
        return array_map(static fn (SamlCertificate $certificate): string => $certificate->pem, $this->certificates);
    }
}
