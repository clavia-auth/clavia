<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Bootstrap;

use Clavia\Bootstrap\Container\ForwardedHeadersFilterFactory;
use Clavia\Configuration\Settings;
use Laminas\Diactoros\ServerRequest;
use Laminas\ServiceManager\ServiceManager;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Whose `X-Forwarded-Proto` is believed. The scheme decides whether a request counts
 * as secure, so a client must never be able to choose it.
 */
final class ForwardedHeadersFilterTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function peers(): iterable
    {
        yield 'no proxy is trusted by default' => ['', '10.0.0.5', 'http'];
        yield 'not even loopback' => ['', '127.0.0.1', 'http'];
        yield 'a listed proxy is believed' => ['10.0.0.0/8', '10.0.0.5', 'https'];
        yield 'an unlisted peer is not' => ['10.0.0.0/8', '203.0.113.7', 'http'];
        yield 'a single address' => ['192.168.1.4', '192.168.1.4', 'https'];
        yield 'an IPv6 range' => ['fd00::/8', 'fd12::1', 'https'];
        yield 'the wildcard trusts any peer' => ['*', '203.0.113.7', 'https'];
    }

    #[DataProvider('peers')]
    public function testTheSchemeIsTakenOnlyFromATrustedProxy(string $trusted, string $peer, string $expected): void
    {
        $request = $this->filtered($trusted, $peer);

        self::assertSame($expected, $request->getUri()->getScheme());
    }

    public function testTheHostIsNeverTakenFromAHeader(): void
    {
        $request = $this->filtered('*', '10.0.0.5');

        self::assertSame('auth.acme.com', $request->getUri()->getHost());
    }

    private function filtered(string $trustedProxies, string $peer): ServerRequestInterface
    {
        $container = new ServiceManager(['services' => [
            Settings::class => Settings::fromEnvironment([
                'CLAVIA_ROOT_DOMAIN' => 'acme.com',
                'CLAVIA_TRUSTED_PROXIES' => $trustedProxies,
            ]),
        ]]);

        $filter = new ForwardedHeadersFilterFactory()($container);

        return $filter(new ServerRequest(
            serverParams: ['REMOTE_ADDR' => $peer],
            uri: 'http://auth.acme.com/oauth2/authorize',
            method: 'GET',
            headers: [
                'Host' => 'auth.acme.com',
                'X-Forwarded-Proto' => 'https',
                'X-Forwarded-Host' => 'evil.example',
                'X-Forwarded-Port' => '8443',
            ],
        ));
    }
}
