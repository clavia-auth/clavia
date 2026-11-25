<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Saml;

use Clavia\Adapter\Secondary\Http\OutboundUrlPolicy;
use Clavia\Adapter\Secondary\Http\OutboundUrlRefused;
use Clavia\Adapter\Secondary\IdentityProvider\ProviderHttp;
use Clavia\Application\Port\Saml\MetadataUnavailable;
use Clavia\Application\Port\Saml\SamlMetadataSource;
use Clavia\Domain\Shared\Url;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

/**
 * An identity provider's metadata over HTTPS (docs/design/saml-connections.md §5.2), as OpenID
 * Connect discovery is read: the URL held to `OutboundUrlPolicy` first (the client then connects to
 * the addresses it checked), no redirect followed, a 200 only, at most
 * {@see SimpleSamlServiceProvider::MAX_METADATA_BYTES} read.
 */
final readonly class HttpSamlMetadataSource implements SamlMetadataSource
{
    public function __construct(
        private ClientInterface $client,
        private RequestFactoryInterface $requests,
        private OutboundUrlPolicy $outbound,
    ) {
    }

    #[\Override]
    public function fetch(Url $url): string
    {
        try {
            $this->outbound->check($url->value, 'metadata URL');
        } catch (OutboundUrlRefused $refused) {
            throw new MetadataUnavailable($refused->getMessage(), 0, $refused);
        }
        try {
            $response = $this->client->sendRequest(
                $this->requests->createRequest('GET', $url->value)
                    ->withHeader('Accept', 'application/samlmetadata+xml, application/xml;q=0.9, text/xml;q=0.8')
                    ->withHeader('User-Agent', ProviderHttp::USER_AGENT),
            );
        } catch (ClientExceptionInterface) {
            throw new MetadataUnavailable('The metadata URL could not be reached.');
        }
        if ($response->getStatusCode() !== StatusCodeInterface::STATUS_OK) {
            throw new MetadataUnavailable(sprintf('The metadata URL answered %d.', $response->getStatusCode()));
        }
        $body = $response->getBody();
        $document = '';
        while (! $body->eof() && strlen($document) <= SimpleSamlServiceProvider::MAX_METADATA_BYTES) {
            $chunk = $body->read(65_536);
            if ($chunk === '') {
                break;
            }
            $document .= $chunk;
        }
        $body->close();
        if (strlen($document) > SimpleSamlServiceProvider::MAX_METADATA_BYTES) {
            throw new MetadataUnavailable(sprintf(
                'The metadata is over %d bytes.',
                SimpleSamlServiceProvider::MAX_METADATA_BYTES,
            ));
        }

        return $document;
    }
}
