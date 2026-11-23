<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\OAuth2;

use Clavia\Application\OAuth2\RequestParameters;
use Clavia\Domain\OAuth2\PushedAuthorizationRequest;
use PHPUnit\Framework\TestCase;

/**
 * The `request_uri` of a pushed request (RFC 9126 §2.2), and the parameters it keeps.
 */
final class PushedAuthorizationRequestTest extends TestCase
{
    private const string HANDLE = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ';

    public function testTheRequestUriIsAUrnNamingTheHandle(): void
    {
        $uri = PushedAuthorizationRequest::uriFor(self::HANDLE);

        self::assertSame('urn:ietf:params:oauth:request_uri:' . self::HANDLE, $uri);
        self::assertSame(self::HANDLE, PushedAuthorizationRequest::handleOf($uri));
    }

    public function testOnlyAUrnThisServerCouldHaveIssuedNamesAHandle(): void
    {
        self::assertNull(PushedAuthorizationRequest::handleOf('https://client.test/request.jwt'));
        self::assertNull(PushedAuthorizationRequest::handleOf('urn:ietf:params:oauth:request_uri:short'));
        // A trailing newline is not part of a handle.
        self::assertNull(PushedAuthorizationRequest::handleOf(PushedAuthorizationRequest::uriFor(self::HANDLE) . "\n"));
    }

    public function testParametersSurviveAsPairsRepetitionsAndAllDigitNamesIncluded(): void
    {
        $parameters = new RequestParameters(['scope' => ['a', 'b'], '42' => ['x'], 'state' => ['é']]);

        $pairs = $parameters->pairs();

        self::assertSame([['scope', 'a'], ['scope', 'b'], ['42', 'x'], ['state', 'é']], $pairs);
        self::assertSame($parameters->toQueryString(), RequestParameters::fromPairs($pairs)->toQueryString());
        self::assertSame(['scope'], RequestParameters::fromPairs($pairs)->repeated());
    }
}
