<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\IdentityProvider;

use Clavia\Adapter\Secondary\Http\OutboundUrlPolicy;
use Clavia\Adapter\Secondary\Http\OutboundUrlRefused;
use Clavia\Application\Port\DiscoveredProvider;
use Clavia\Application\Port\DiscoveryFailed;
use Clavia\Application\Port\OidcDiscovery;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use JsonException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

/**
 * {@see OidcDiscovery} over any PSR-18 client.
 *
 * The document is an arbitrary server's answer, so it is trusted for nothing it could
 * not have been trusted with by the operator: its `issuer` must be the one asked for — the
 * check that stops a URL pointing at somebody else's metadata from being trusted for
 * tokens that claim to come from here — and the endpoints it names go through the same
 * outbound policy as the issuer did. Nothing it says is echoed back.
 */
final readonly class HttpOidcDiscovery implements OidcDiscovery
{
    private const array ENDPOINTS = ['authorization_endpoint', 'token_endpoint', 'jwks_uri'];

    public function __construct(
        private ClientInterface $client,
        private RequestFactoryInterface $requests,
        private OutboundUrlPolicy $outbound,
    ) {
    }

    #[\Override]
    public function discover(string $issuer): DiscoveredProvider
    {
        $this->allowed($issuer, 'issuer');
        $url = rtrim($issuer, '/') . '/.well-known/openid-configuration';

        try {
            $response = $this->client->sendRequest(
                $this->requests->createRequest(RequestMethodInterface::METHOD_GET, $url)
                    ->withHeader('Accept', 'application/json')
                    ->withHeader('User-Agent', ProviderHttp::USER_AGENT),
            );
        } catch (ClientExceptionInterface) {
            throw new DiscoveryFailed(sprintf('Could not fetch %s: it could not be reached.', $url));
        }
        if ($response->getStatusCode() !== StatusCodeInterface::STATUS_OK) {
            throw new DiscoveryFailed(sprintf('Could not fetch %s: it answered %d.', $url, $response->getStatusCode()));
        }

        try {
            /** @var mixed $document */
            $document = json_decode((string) $response->getBody(), true, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new DiscoveryFailed(sprintf('The discovery document at %s is not JSON.', $url));
        }
        if (! is_array($document) || ($document['issuer'] ?? null) !== $issuer) {
            throw new DiscoveryFailed(sprintf(
                "The discovery document at %s does not name '%s' as its issuer.",
                $url,
                $issuer,
            ));
        }

        $endpoints = [];
        foreach (self::ENDPOINTS as $field) {
            /** @var mixed $value */
            $value = $document[$field] ?? null;
            if (! is_string($value) || $value === '') {
                throw new DiscoveryFailed(sprintf("The discovery document is missing '%s'.", $field));
            }
            // The server will fetch two of these itself: the document does not get to aim them
            // anywhere the issuer could not have been aimed.
            $this->allowed($value, $field);
            $endpoints[$field] = $value;
        }

        return new DiscoveredProvider(
            $endpoints['authorization_endpoint'],
            $endpoints['token_endpoint'],
            $endpoints['jwks_uri'],
        );
    }

    /**
     * @throws DiscoveryFailed
     */
    private function allowed(string $url, string $what): void
    {
        try {
            $this->outbound->check($url, $what);
        } catch (OutboundUrlRefused $refused) {
            throw new DiscoveryFailed($refused->getMessage(), 0, $refused);
        }
    }
}
