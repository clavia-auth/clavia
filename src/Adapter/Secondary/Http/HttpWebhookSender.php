<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Http;

use Clavia\Application\Port\SendOutcome;
use Clavia\Application\Port\WebhookSender;
use Clavia\Domain\Shared\Url;
use Clavia\Domain\Webhook\DeliveryFailure;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * Posts a webhook delivery over PSR-18 (docs/design/webhooks.md §2):
 *
 * - the URL is held to `OutboundUrlPolicy` again first, so a name that now resolves somewhere
 *   private is a `refused_url`, not a connection made; the client then connects to the addresses
 *   the policy checked ({@see PinCheckedAddresses});
 * - no redirect is followed, and a 3xx is a failure like any status but a 2xx;
 * - the client is built not to read the answer's body (`stream`), and the body is closed unread: a
 *   receiver cannot make this server download or keep anything but its status.
 */
final readonly class HttpWebhookSender implements WebhookSender
{
    public function __construct(
        private ClientInterface $http,
        private RequestFactoryInterface $requests,
        private StreamFactoryInterface $streams,
        private OutboundUrlPolicy $policy,
    ) {
    }

    #[\Override]
    public function send(Url $url, array $headers, string $body): SendOutcome
    {
        $started = (int) hrtime(true);
        if ($this->policy->refusal($url->value, 'webhook endpoint') !== null) {
            return SendOutcome::unsent(DeliveryFailure::RefusedUrl, self::since($started));
        }

        $request = $this->requests->createRequest('POST', $url->value)
            ->withHeader('User-Agent', 'Clavia')
            ->withBody($this->streams->createStream($body));
        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        try {
            $response = $this->http->sendRequest($request);
        } catch (ClientExceptionInterface) {
            return SendOutcome::unsent(DeliveryFailure::Connection, self::since($started));
        }
        $response->getBody()->close();
        $status = $response->getStatusCode();
        $elapsed = self::since($started);

        return $status >= StatusCodeInterface::STATUS_OK && $status < StatusCodeInterface::STATUS_MULTIPLE_CHOICES
            ? SendOutcome::accepted($status, $elapsed)
            : SendOutcome::refused($status, $elapsed);
    }

    /** Milliseconds since `$started` (nanoseconds of `hrtime()`). */
    private static function since(int $started): int
    {
        return intdiv((int) hrtime(true) - $started, 1_000_000);
    }
}
