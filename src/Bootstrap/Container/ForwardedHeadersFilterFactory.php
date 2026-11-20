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
use Laminas\Diactoros\ServerRequestFilter\DoNotFilter;
use Laminas\Diactoros\ServerRequestFilter\FilterServerRequestInterface;
use Laminas\Diactoros\ServerRequestFilter\FilterUsingXForwardedHeaders;
use Psr\Container\ContainerInterface;

/**
 * Decides whose `X-Forwarded-Proto` the server believes.
 *
 * The scheme decides whether the server considers a request secure and what every URL
 * it builds starts with, so it is taken from a header only when the peer is a proxy the
 * operator named in `CLAVIA_TRUSTED_PROXIES`. With none named — the default — the
 * header is ignored outright and the scheme is whatever the web server reported over
 * FastCGI. Diactoros' own default (trust every private address) is deliberately not
 * used: a client on the same network could then choose its own scheme.
 *
 * Only the scheme is ever taken. The host is never read from a header — the issuer and
 * every host Clavia serves come from the settings.
 */
final class ForwardedHeadersFilterFactory
{
    public function __invoke(ContainerInterface $container): FilterServerRequestInterface
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        $headers = [FilterUsingXForwardedHeaders::HEADER_PROTO];

        // An entry of "*" is expanded by Diactoros to every IPv4 and IPv6 address.
        return $settings->trustedProxies === []
            ? new DoNotFilter()
            : FilterUsingXForwardedHeaders::trustProxies($settings->trustedProxies, $headers);
    }
}
