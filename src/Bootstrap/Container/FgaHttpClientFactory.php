<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Configuration\Settings;
use GuzzleHttp\Client;
use GuzzleHttp\RequestOptions;
use Psr\Container\ContainerInterface;
use Psr\Http\Client\ClientInterface;

/**
 * The PSR-18 client OpenFGA, the decision engine, is called with
 * (docs/design/fine-grained-authorization.md §3).
 *
 * Not {@see HttpClientFactory}'s: that one refuses private addresses, because it fetches URLs
 * anybody registering an application may type in, and OpenFGA is on the private network beside
 * Clavia, at the address the operator names. Bounded by `CLAVIA_FGA_TIMEOUT`, connection
 * included, since a question nobody answers in time is answered by nobody: the caller fails
 * closed. No redirect is followed, so the preshared key goes nowhere else.
 */
final class FgaHttpClientFactory
{
    public const string SERVICE = 'clavia.http.fga';

    public function __invoke(ContainerInterface $container): ClientInterface
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        $timeout = (float) $settings->fgaTimeout;

        return new Client([
            RequestOptions::CONNECT_TIMEOUT => $timeout,
            RequestOptions::TIMEOUT => $timeout,
            RequestOptions::ALLOW_REDIRECTS => false,
            RequestOptions::HTTP_ERRORS => false,
        ]);
    }
}
