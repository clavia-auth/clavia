<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Http;

use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Fig\Http\Message\RequestMethodInterface;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\StreamFactory;
use Laminas\Diactoros\Uri;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

final class RequestParameterReaderTest extends TestCase
{
    public function testTheQueryIsDecoded(): void
    {
        $parameters = RequestParameterReader::query(
            $this->request('scope=openid+profile&redirect_uri=https%3A%2F%2Fapp.example%2Fcb%3Fx%3D1&state=a%20b'),
        );

        self::assertSame('openid profile', $parameters->get('scope'));
        self::assertSame('https://app.example/cb?x=1', $parameters->get('redirect_uri'));
        self::assertSame('a b', $parameters->get('state'));
    }

    public function testARepetitionInTheQueryIsKept(): void
    {
        // PHP's own $_GET keeps the last value and says nothing; that silence is how a
        // proxy and the application come to disagree on what a request asked for.
        $parameters = RequestParameterReader::query($this->request('redirect_uri=a&client_id=spa&redirect_uri=b'));

        self::assertTrue($parameters->isRepeated('redirect_uri'));
        self::assertSame(['redirect_uri'], $parameters->repeated());
    }

    public function testNamesAreNotRewrittenTheWayPhpDoes(): void
    {
        // $_GET would turn these into `a_b`, an array `scope`, and the integer key 123.
        $parameters = RequestParameterReader::query($this->request('a.b=1&scope[]=x&scope[]=y&123=n&123=m'));

        self::assertSame('1', $parameters->get('a.b'));
        self::assertNull($parameters->get('a_b'));
        self::assertNull($parameters->get('scope'));
        self::assertSame(['scope[]', '123'], $parameters->repeated());
    }

    public function testAParameterWithoutAValueIsAbsent(): void
    {
        $parameters = RequestParameterReader::query($this->request('state&scope=&&client_id=spa'));

        self::assertNull($parameters->get('state'));
        self::assertNull($parameters->get('scope'));
        self::assertSame('spa', $parameters->get('client_id'));
    }

    public function testAValueMayContainAnEqualsSign(): void
    {
        self::assertSame('a=b=c', RequestParameterReader::query($this->request('state=a=b=c'))->get('state'));
    }

    public function testAnEmptyQueryHasNoParameters(): void
    {
        self::assertSame([], RequestParameterReader::query($this->request(''))->repeated());
        self::assertNull(RequestParameterReader::query($this->request(''))->get(''));
    }

    public function testAFormBodyIsRead(): void
    {
        $parameters = RequestParameterReader::form(
            $this->request('', 'grant_type=authorization_code&code=a%2Bb', 'application/x-www-form-urlencoded'),
        );

        self::assertSame('authorization_code', $parameters->get('grant_type'));
        self::assertSame('a+b', $parameters->get('code'));
    }

    public function testTheMediaTypeMayCarryACharsetAndAnyCase(): void
    {
        $parameters = RequestParameterReader::form(
            $this->request('', 'code=abc', 'Application/X-WWW-Form-Urlencoded; charset=UTF-8'),
        );

        self::assertSame('abc', $parameters->get('code'));
    }

    public function testABodyOfAnotherMediaTypeIsNotAForm(): void
    {
        self::assertNull(
            RequestParameterReader::form($this->request('', '{"code":"abc"}', 'application/json'))->get('code'),
        );
        self::assertNull(RequestParameterReader::form($this->request('', 'code=abc', ''))->get('code'));
        self::assertNull(RequestParameterReader::form($this->request('', 'code=abc', 'text/plain'))->get('code'));
    }

    public function testTheFormReaderIgnoresTheQuery(): void
    {
        // RFC 6749 §3.2: token endpoint parameters travel in the body, never in the URI —
        // a code or a secret in a query string ends up in access logs.
        $parameters = RequestParameterReader::form(
            $this->request('code=from-query&client_secret=leaked', 'grant_type=x', 'application/x-www-form-urlencoded'),
        );

        self::assertNull($parameters->get('code'));
        self::assertNull($parameters->get('client_secret'));
    }

    public function testQueryAndFormTogetherMakeACrossSourceRepetitionVisible(): void
    {
        $parameters = RequestParameterReader::queryAndForm(
            $this->request(
                'client_id=spa&scope=openid',
                'client_id=other&state=xyz',
                'application/x-www-form-urlencoded',
            ),
        );

        self::assertTrue($parameters->isRepeated('client_id'));
        self::assertSame('openid', $parameters->get('scope'));
        self::assertSame('xyz', $parameters->get('state'));
    }

    private function request(string $query, string $body = '', string $contentType = ''): ServerRequestInterface
    {
        $request = new ServerRequest(
            uri: new Uri('https://auth.clavia.test/oauth2/authorize')->withQuery($query),
            method: $body === '' ? RequestMethodInterface::METHOD_GET : RequestMethodInterface::METHOD_POST,
            body: new StreamFactory()->createStream($body),
        );

        return $contentType === '' ? $request : $request->withHeader('Content-Type', $contentType);
    }
}
