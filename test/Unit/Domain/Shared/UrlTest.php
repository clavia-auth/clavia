<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Shared;

use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Url;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class UrlTest extends TestCase
{
    public function testItKeepsTheStringExactlyAsGiven(): void
    {
        $given = 'HTTPS://Client.Test:443/Callback/../cb?x=1';

        self::assertSame($given, Url::fromString($given)->toString());
        self::assertSame($given, Url::fromString($given)->value);
    }

    /**
     * Every pair here is "the same URL" to a normaliser. OAuth 2.1 §2.3.1 requires exact
     * string matching for redirect URIs, so to this class none of them are.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function equivalentLookingUrls(): iterable
    {
        yield 'a trailing slash' => ['https://client.test/cb', 'https://client.test/cb/'];
        yield 'host case' => ['https://client.test/cb', 'https://Client.test/cb'];
        yield 'scheme case' => ['https://client.test/cb', 'HTTPS://client.test/cb'];
        yield 'an explicit default port' => ['https://client.test/cb', 'https://client.test:443/cb'];
        yield 'a dot segment' => ['https://client.test/cb', 'https://client.test/a/../cb'];
        yield 'percent-encoding' => ['https://client.test/cb', 'https://client.test/%63b'];
        yield 'an empty query' => ['https://client.test/cb', 'https://client.test/cb?'];
        yield 'a query parameter' => ['https://client.test/cb', 'https://client.test/cb?next=/admin'];
    }

    #[DataProvider('equivalentLookingUrls')]
    public function testEqualityIsByteForByte(string $registered, string $presented): void
    {
        self::assertFalse(Url::fromString($registered)->equals(Url::fromString($presented)));
        self::assertTrue(Url::fromString($registered)->equals(Url::fromString($registered)));
    }

    public function testItAnswersQuestionsAboutItsParts(): void
    {
        $url = Url::fromString('HTTPS://Client.Test:8443/cb?x=1#frag');

        self::assertSame('https', $url->scheme());
        self::assertSame('client.test', $url->host());
        self::assertSame(8443, $url->port());
        self::assertSame('/cb', $url->path());
        self::assertTrue($url->hasQuery());
        self::assertTrue($url->hasFragment());
        self::assertTrue($url->isHttps());
        self::assertFalse($url->isLoopback());
    }

    public function testThePortDefaultsFromTheScheme(): void
    {
        self::assertSame(443, Url::fromString('https://client.test/cb')->port());
        self::assertSame(80, Url::fromString('http://localhost/cb')->port());
        self::assertNull(Url::fromString('com.example.app://callback')->port());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function origins(): iterable
    {
        yield 'https' => ['https://client.test/callback?x=1', 'https://client.test'];
        yield 'default port elided' => ['https://client.test:443/cb', 'https://client.test'];
        yield 'explicit port kept' => ['https://client.test:8443/cb', 'https://client.test:8443'];
        yield 'http default port elided' => ['http://localhost:80/cb', 'http://localhost'];
        yield 'case folded' => ['HTTPS://Client.Test/cb', 'https://client.test'];
        yield 'IPv6 literal' => ['http://[::1]:3000/cb', 'http://[::1]:3000'];
    }

    #[DataProvider('origins')]
    public function testTheOriginIsSchemeHostAndNonDefaultPort(string $url, string $origin): void
    {
        self::assertSame($origin, Url::fromString($url)->origin());
    }

    public function testLoopbackHostsAreRecognised(): void
    {
        self::assertTrue(Url::fromString('http://localhost:3000/cb')->isLoopback());
        self::assertTrue(Url::fromString('http://127.0.0.1:3000/cb')->isLoopback());
        self::assertTrue(Url::fromString('http://[::1]:3000/cb')->isLoopback());
        // A name that merely starts like one is not loopback.
        self::assertFalse(Url::fromString('http://localhost.evil.test/cb')->isLoopback());
        self::assertFalse(Url::fromString('http://127.0.0.1.evil.test/cb')->isLoopback());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function valuesThatAreNotAbsoluteUrls(): iterable
    {
        yield 'empty' => [''];
        yield 'a path' => ['/callback'];
        yield 'no scheme' => ['client.test/callback'];
        yield 'scheme-relative' => ['//client.test/callback'];
        yield 'no host' => ['https:///callback'];
        yield 'a scheme and nothing else' => ['https:'];
        yield 'a space' => ['https://client.test/call back'];
        yield 'a newline' => ["https://client.test/cb\n"];
        yield 'a NUL byte' => ["https://client.test/cb\0"];
        yield 'credentials' => ['https://client.test@evil.test/cb'];
        yield 'credentials with a password' => ['https://user:pass@client.test/cb'];
    }

    #[DataProvider('valuesThatAreNotAbsoluteUrls')]
    public function testOnlyAnAbsoluteUrlWithNoCredentialsIsAccepted(string $value): void
    {
        $this->expectException(InvalidValue::class);

        Url::fromString($value);
    }
}
