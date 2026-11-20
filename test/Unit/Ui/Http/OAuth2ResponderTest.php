<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Ui\Http;

use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Ui\Http\OAuth2\OAuth2Responder;
use Laminas\Diactoros\ResponseFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class OAuth2ResponderTest extends TestCase
{
    private const string ISSUER = 'https://auth.clavia.test';

    private OAuth2Responder $responder;

    #[\Override]
    protected function setUp(): void
    {
        $this->responder = new OAuth2Responder(new ResponseFactory(), self::ISSUER);
    }

    public function testASuccessIsJsonThatMustNotBeStored(): void
    {
        $response = $this->responder->success(
            ['token_type' => 'Bearer', 'access_token' => 'abc', 'expires_in' => 3600],
        );

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('application/json', $response->getHeaderLine('Content-Type'));
        // RFC 6749 §5.1.
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertSame('no-cache', $response->getHeaderLine('Pragma'));
        self::assertSame(
            '{"token_type":"Bearer","access_token":"abc","expires_in":3600}',
            (string) $response->getBody(),
        );
    }

    public function testAFailedClientAuthenticationAtTheTokenEndpointIs401WithAChallenge(): void
    {
        $response = $this->responder->tokenError(OAuth2Error::invalidClient('Client authentication failed.'));

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('Basic realm="https://auth.clavia.test"', $response->getHeaderLine('WWW-Authenticate'));
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertSame(
            '{"error":"invalid_client","error_description":"Client authentication failed."}',
            (string) $response->getBody(),
        );
    }

    #[DataProvider('otherErrors')]
    public function testEveryOtherTokenErrorIs400WithoutAChallenge(OAuth2Error $error, string $code): void
    {
        $response = $this->responder->tokenError($error);

        self::assertSame(400, $response->getStatusCode());
        self::assertFalse($response->hasHeader('WWW-Authenticate'));
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertSame(
            ['error' => $code, 'error_description' => 'why'],
            json_decode((string) $response->getBody(), true),
        );
    }

    /** @return iterable<string, array{OAuth2Error, string}> */
    public static function otherErrors(): iterable
    {
        yield 'invalid_request' => [OAuth2Error::invalidRequest('why'), 'invalid_request'];
        yield 'invalid_grant' => [OAuth2Error::invalidGrant('why'), 'invalid_grant'];
        yield 'unauthorized_client' => [OAuth2Error::unauthorizedClient('why'), 'unauthorized_client'];
        yield 'unsupported_grant_type' => [OAuth2Error::unsupportedGrantType('why'), 'unsupported_grant_type'];
        yield 'unsupported_response_type' => [
            OAuth2Error::unsupportedResponseType('why'),
            'unsupported_response_type',
        ];
        yield 'invalid_scope' => [OAuth2Error::invalidScope('why'), 'invalid_scope'];
    }

    public function testAnAuthorizationErrorShownInPlaceNeverChallengesTheBrowser(): void
    {
        $response = $this->responder->authorizationError(OAuth2Error::invalidClient('The client does not exist.'));

        // A Basic challenge here would make the browser ask the user for a client secret.
        self::assertSame(400, $response->getStatusCode());
        self::assertFalse($response->hasHeader('WWW-Authenticate'));
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertSame(
            ['error' => 'invalid_client', 'error_description' => 'The client does not exist.'],
            json_decode((string) $response->getBody(), true),
        );
    }

    public function testARedirectToTheClientCarriesTheParametersAndTheIssuer(): void
    {
        $response = $this->responder->redirectToClient(
            'https://app.example/cb',
            ['code' => 'a b+c', 'state' => 'x&y=z'],
        );

        self::assertSame(302, $response->getStatusCode());
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        // RFC 9207: `iss` lets a client talking to several servers tell who answered.
        self::assertSame(
            'https://app.example/cb?code=a%20b%2Bc&state=x%26y%3Dz&iss=https%3A%2F%2Fauth.clavia.test',
            $response->getHeaderLine('Location'),
        );
    }

    public function testAnAbsentParameterIsLeftOut(): void
    {
        $response = $this->responder->redirectToClient('https://app.example/cb', ['code' => 'abc', 'state' => null]);

        self::assertSame(
            'https://app.example/cb?code=abc&iss=https%3A%2F%2Fauth.clavia.test',
            $response->getHeaderLine('Location'),
        );
    }

    public function testTheQueryOfTheRegisteredUriIsKeptAsItIs(): void
    {
        $response = $this->responder->redirectToClient('https://app.example/cb?tenant=a%2Fb&x', ['code' => 'abc']);

        self::assertSame(
            'https://app.example/cb?tenant=a%2Fb&x&code=abc&iss=https%3A%2F%2Fauth.clavia.test',
            $response->getHeaderLine('Location'),
        );
    }

    public function testACallerCannotOverrideTheIssuer(): void
    {
        $response = $this->responder->redirectToClient('https://app.example/cb', ['iss' => 'https://evil.example']);

        self::assertSame(
            'https://app.example/cb?iss=https%3A%2F%2Fauth.clavia.test',
            $response->getHeaderLine('Location'),
        );
    }

    public function testARedirectWithinTheServerIsARelativeSeeOther(): void
    {
        $response = $this->responder->redirectWithinServer('/auth/login?state=abc');

        self::assertSame(303, $response->getStatusCode());
        self::assertSame('/auth/login?state=abc', $response->getHeaderLine('Location'));
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
    }
}
