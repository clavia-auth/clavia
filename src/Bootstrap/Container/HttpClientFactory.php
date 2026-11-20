<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use GuzzleHttp\Client;
use GuzzleHttp\RequestOptions;
use Psr\Container\ContainerInterface;
use Psr\Http\Client\ClientInterface;

/**
 * The PSR-18 client every outbound request goes through: Guzzle, and nothing outside
 * this factory knows it.
 *
 * Bounded, because a provider that hangs must not hold a PHP-FPM worker: a request
 * that cannot connect in a few seconds, or finish in ten, fails like any other refusal.
 * Redirects are not followed — an endpoint that answers with one is misconfigured, and
 * following it would send a client secret wherever the redirect pointed.
 */
final class HttpClientFactory
{
    public const float CONNECT_TIMEOUT = 5.0;

    public const float TIMEOUT = 10.0;

    public function __invoke(ContainerInterface $container): ClientInterface
    {
        return new Client([
            RequestOptions::CONNECT_TIMEOUT => self::CONNECT_TIMEOUT,
            RequestOptions::TIMEOUT => self::TIMEOUT,
            RequestOptions::ALLOW_REDIRECTS => false,
            RequestOptions::HTTP_ERRORS => false,
        ]);
    }
}
