<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Http;

use Clavia\Adapter\Secondary\Http\OutboundUrlPolicy;
use Clavia\Adapter\Secondary\Http\OutboundUrlRefused;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The URLs an operator can make the server fetch: public https, and nothing that points
 * back into the network the server sits in — written as an address or resolved from a
 * name.
 */
final class OutboundUrlPolicyTest extends TestCase
{
    #[DataProvider('publicUrls')]
    public function testAPublicHttpsUrlIsAllowed(string $url, string $resolvesTo): void
    {
        $this->expectNotToPerformAssertions();

        $this->policy([$resolvesTo])->check($url, 'issuer');
    }

    /** @return iterable<string, array{string, string}> */
    public static function publicUrls(): iterable
    {
        yield 'a name resolving to a public IPv4 address' => ['https://idp.example/tenant', '93.184.216.34'];
        yield 'a name resolving to a public IPv6 address' => ['https://idp.example', '2606:2800:220:1::248'];
        yield 'a public IPv4 literal' => ['https://93.184.216.34/', '127.0.0.1'];
    }

    #[DataProvider('refusedUrls')]
    public function testAnythingElseIsRefusedWithoutSayingWhatItResolvedTo(string $url, string $resolvesTo): void
    {
        try {
            $this->policy([$resolvesTo])->check($url, 'issuer');
            self::fail(sprintf('%s was allowed.', $url));
        } catch (OutboundUrlRefused $refused) {
            self::assertStringStartsWith('The issuer must', $refused->getMessage());
            self::assertStringNotContainsString($resolvesTo, $refused->getMessage());
        }
    }

    /** @return iterable<string, array{string, string}> */
    public static function refusedUrls(): iterable
    {
        yield 'plain http' => ['http://idp.example', '93.184.216.34'];
        yield 'another scheme' => ['file:///etc/passwd', '93.184.216.34'];
        yield 'no host' => ['https:///path', '93.184.216.34'];
        yield 'not a URL' => ['idp.example', '93.184.216.34'];
        yield 'localhost' => ['https://localhost/', '93.184.216.34'];
        yield 'a .localhost name' => ['https://idp.localhost/', '93.184.216.34'];
        yield 'an .internal name' => ['https://metadata.google.internal/', '93.184.216.34'];
        yield 'loopback' => ['https://127.0.0.1/', '93.184.216.34'];
        yield 'IPv6 loopback' => ['https://[::1]/', '93.184.216.34'];
        yield 'a private address' => ['https://10.1.2.3/', '93.184.216.34'];
        yield 'the cloud metadata service' => ['https://169.254.169.254/', '93.184.216.34'];
        yield 'carrier-grade NAT' => ['https://100.64.0.1/', '93.184.216.34'];
        yield 'IPv6 unique-local' => ['https://[fd00::1]/', '93.184.216.34'];
        yield 'IPv6 link-local' => ['https://[fe80::1]/', '93.184.216.34'];
        yield 'a name resolving to a private address' => ['https://idp.example/', '192.168.1.10'];
        yield 'a name resolving to loopback' => ['https://idp.example/', '127.0.0.1'];
    }

    public function testANameResolvingToOnePrivateAddressAmongPublicOnesIsRefused(): void
    {
        $this->expectException(OutboundUrlRefused::class);

        $this->policy(['93.184.216.34', '10.0.0.1'])->check('https://idp.example', 'jwks_uri');
    }

    public function testDevelopmentMayReachPrivateAddressesButNeverOverPlainHttp(): void
    {
        $policy = new OutboundUrlPolicy(true, static fn (): array => ['127.0.0.1']);
        $policy->check('https://localhost:8443/', 'issuer');

        $this->expectException(OutboundUrlRefused::class);

        $policy->check('http://localhost:8080/', 'issuer');
    }

    /**
     * @param list<string> $addresses
     */
    private function policy(array $addresses): OutboundUrlPolicy
    {
        return new OutboundUrlPolicy(false, static fn (): array => $addresses);
    }
}
