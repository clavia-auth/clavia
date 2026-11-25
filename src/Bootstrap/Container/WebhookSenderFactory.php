<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Secondary\Http\HttpWebhookSender;
use Clavia\Adapter\Secondary\Http\OutboundUrlPolicy;
use Clavia\Adapter\Secondary\Http\PinCheckedAddresses;
use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\RequestOptions;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * The webhook sender, on a client of its own: the shared one's timeouts, pinning and no redirects,
 * and `stream`, so a receiver's answer is never downloaded, only its status read
 * (docs/design/webhooks.md §2, "Timeouts").
 */
final class WebhookSenderFactory
{
    public function __invoke(ContainerInterface $container): HttpWebhookSender
    {
        /** @var OutboundUrlPolicy $policy */
        $policy = $container->get(OutboundUrlPolicy::class);
        /** @var RequestFactoryInterface $requests */
        $requests = $container->get(RequestFactoryInterface::class);
        /** @var StreamFactoryInterface $streams */
        $streams = $container->get(StreamFactoryInterface::class);
        $handlers = HandlerStack::create();
        $handlers->push(new PinCheckedAddresses($policy), 'pin-checked-addresses');

        return new HttpWebhookSender(
            new Client([
                'handler' => $handlers,
                RequestOptions::CONNECT_TIMEOUT => HttpClientFactory::CONNECT_TIMEOUT,
                RequestOptions::TIMEOUT => HttpClientFactory::TIMEOUT,
                RequestOptions::ALLOW_REDIRECTS => false,
                RequestOptions::HTTP_ERRORS => false,
                RequestOptions::STREAM => true,
            ]),
            $requests,
            $streams,
            $policy,
        );
    }
}
