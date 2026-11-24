<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Http;

use Clavia\Application\Port\BackChannelLogoutDelivery;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Shared\Url;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;

/**
 * A logout token posted as `application/x-www-form-urlencoded`, `logout_token=…`
 * (OIDC Back-Channel Logout 1.0 §2.5), over the server's one PSR-18 client.
 *
 * The URI is checked against the outbound policy here, at send time, and not only at
 * registration: what a name resolves to can change, and this server must not be steered
 * at its own network on its own account. The client then connects to the addresses that
 * check found ({@see PinCheckedAddresses}). Failures are logged with the client and the
 * reason — never the token — and go no further.
 */
final readonly class HttpBackChannelLogoutDelivery implements BackChannelLogoutDelivery
{
    public function __construct(
        private ClientInterface $http,
        private RequestFactoryInterface $requests,
        private StreamFactoryInterface $streams,
        private OutboundUrlPolicy $policy,
        private LoggerInterface $logger,
    ) {
    }

    #[\Override]
    public function deliver(ClientId $client, Url $uri, #[\SensitiveParameter] string $logoutToken): void
    {
        try {
            $this->policy->check($uri->value, 'back-channel logout URI');
        } catch (OutboundUrlRefused $refused) {
            $this->fail($client, $uri, $refused->getMessage());

            return;
        }

        $request = $this->requests->createRequest('POST', $uri->value)
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withHeader('User-Agent', 'Clavia')
            ->withBody($this->streams->createStream(
                http_build_query(['logout_token' => $logoutToken], '', '&', PHP_QUERY_RFC1738),
            ));

        try {
            $status = $this->http->sendRequest($request)->getStatusCode();
        } catch (ClientExceptionInterface $failure) {
            $this->fail($client, $uri, sprintf('it could not be reached (%s)', $failure::class));

            return;
        }

        // §2.8: 200 is success; anything else is the client's failure to accept it.
        if ($status < StatusCodeInterface::STATUS_OK || $status >= StatusCodeInterface::STATUS_MULTIPLE_CHOICES) {
            $this->fail($client, $uri, sprintf('it answered %d', $status));
        }
    }

    private function fail(ClientId $client, Url $uri, string $reason): void
    {
        $this->logger->warning('Back-channel logout to {uri} for client {client} failed: {reason}', [
            'uri' => $uri->value,
            'client' => $client->value,
            'reason' => $reason,
        ]);
    }
}
