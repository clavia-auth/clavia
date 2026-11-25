<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Connections;

use Clavia\Application\Port\Saml\MetadataUnavailable;
use Clavia\Application\Port\Saml\SamlMetadataSource;
use Clavia\Application\Port\Saml\SamlServiceProvider;
use Clavia\Domain\Connection\Saml\SamlSettings;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Url;

/**
 * Turn what an operator gave into a SAML connection's settings (docs/design/saml-connections.md §5.2):
 * the identity provider's metadata, as a document or fetched from its URL now, at the keyboard, and
 * read by the service provider port, which holds it to the rules (one SAML 2.0 identity provider, an
 * https HTTP-Redirect sign-on service, one to three RSA signing certificates, no `DOCTYPE`).
 */
final readonly class SamlConfiguration
{
    public const string METADATA = '/saml/metadata';
    public const string METADATA_URL = '/saml/metadata_url';

    public function __construct(
        private SamlServiceProvider $saml,
        private SamlMetadataSource $source,
    ) {
    }

    /** @throws SamlMetadataRefused */
    public function settings(NewSamlConnection $new): SamlSettings
    {
        if (($new->metadata === null) === ($new->metadataUrl === null)) {
            throw new SamlMetadataRefused(
                self::METADATA,
                'A SAML connection is registered from its metadata: give saml.metadata or saml.metadata_url, '
                . 'one of them.',
            );
        }
        $url = null;
        if ($new->metadataUrl !== null) {
            try {
                $url = Url::fromString($new->metadataUrl);
            } catch (InvalidValue $malformed) {
                throw new SamlMetadataRefused(self::METADATA_URL, $malformed->getMessage(), $malformed);
            }
            if (! $url->isHttps()) {
                throw new SamlMetadataRefused(self::METADATA_URL, 'The metadata URL is https.');
            }
        }
        $pointer = $url === null ? self::METADATA : self::METADATA_URL;
        $document = $url === null ? (string) $new->metadata : $this->fetched($url);
        try {
            $metadata = $this->saml->readMetadata($document);

            return SamlSettings::of(
                $metadata->entityId,
                $metadata->singleSignOnUrl,
                $metadata->certificates,
                $url,
                $new->options,
            );
        } catch (InvalidValue $refused) {
            throw new SamlMetadataRefused($pointer, $refused->getMessage(), $refused);
        }
    }

    /**
     * The same connection's provider as its metadata URL says now.
     *
     * @throws SamlMetadataRefused
     * @throws \LogicException When it has no metadata URL: the caller checks.
     */
    public function refreshed(SamlSettings $saml): SamlSettings
    {
        $url = $saml->metadataUrl ?? throw new \LogicException('Registered from a document: nothing to fetch.');
        try {
            $metadata = $this->saml->readMetadata($this->fetched($url));

            return $saml->withMetadata($metadata->entityId, $metadata->singleSignOnUrl, $metadata->certificates);
        } catch (InvalidValue $refused) {
            throw new SamlMetadataRefused(self::METADATA_URL, $refused->getMessage(), $refused);
        }
    }

    /** @throws SamlMetadataRefused */
    private function fetched(Url $url): string
    {
        try {
            return $this->source->fetch($url);
        } catch (MetadataUnavailable $unavailable) {
            throw new SamlMetadataRefused(self::METADATA_URL, $unavailable->getMessage(), $unavailable);
        }
    }
}
