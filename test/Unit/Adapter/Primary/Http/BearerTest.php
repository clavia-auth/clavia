<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Http;

use Clavia\Adapter\Primary\Http\Shared\BearerChallenger;
use Clavia\Adapter\Primary\Http\Shared\AccessTokenCredentials;
use Clavia\Application\OAuth2\ProtectedResource\TokenScheme;
use Clavia\Domain\OAuth2\BearerErrorCode;
use Clavia\Domain\OAuth2\BearerTokenError;
use Clavia\Domain\Shared\ScopeSet;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Bearer tokens presented to a protected resource, and the refusals (RFC 6750).
 */
final class BearerTest extends TestCase
{
    private const string REALM = 'https://auth.clavia.test';

    // ── Reading the token ───────────────────────────────────────────────────────

    public function testTheTokenIsReadFromTheAuthorizationHeader(): void
    {
        self::assertSame(
            'mF_9.B5f-4.1JqM',
            AccessTokenCredentials::fromRequest($this->request('Bearer mF_9.B5f-4.1JqM'))?->accessToken,
        );
        // The scheme is case-insensitive (RFC 9110 §11.1), and b64token allows trailing "=".
        self::assertSame(
            'abc+/==',
            AccessTokenCredentials::fromRequest($this->request('bearer abc+/=='))?->accessToken,
        );
    }

    public function testADpopTokenComesWithItsProofs(): void
    {
        // RFC 9449 §7.1: the `DPoP` scheme, and the proof in its own header.
        $credentials = AccessTokenCredentials::fromRequest(
            $this->request('DPoP mF_9.B5f-4.1JqM')->withHeader('DPoP', 'the.proof.jwt'),
        );

        self::assertNotNull($credentials);
        self::assertSame(TokenScheme::Dpop, $credentials->scheme);
        self::assertSame('mF_9.B5f-4.1JqM', $credentials->accessToken);
        self::assertSame(['the.proof.jwt'], $credentials->dpopProofs);
    }

    /**
     * @param list<string> $headers
     */
    #[DataProvider('noBearerCredentials')]
    public function testARequestWithoutBearerCredentialsHasNone(array $headers): void
    {
        self::assertNull(AccessTokenCredentials::fromRequest($this->request(...$headers)));
    }

    /** @return iterable<string, array{list<string>}> */
    public static function noBearerCredentials(): iterable
    {
        yield 'no header' => [[]];
        yield 'another scheme' => [['Basic ' . base64_encode('a:b')]];
        yield 'a scheme that only starts like it' => [['Bearerx abc']];
    }

    /**
     * @param list<string> $headers
     */
    #[DataProvider('malformed')]
    public function testAMalformedRequestIsAnInvalidRequest(array $headers, string $query = '', string $body = ''): void
    {
        try {
            AccessTokenCredentials::fromRequest($this->request(...$headers)->withUri(
                new ServerRequest()->getUri()->withQuery($query),
            )->withBody(new StreamFactory()->createStream($body)));
            self::fail('The request was accepted.');
        } catch (BearerTokenError $error) {
            self::assertSame(BearerErrorCode::InvalidRequest, $error->error);
        }
    }

    /** @return iterable<string, array{0: list<string>, 1?: string, 2?: string}> */
    public static function malformed(): iterable
    {
        yield 'no token' => [['Bearer']];
        yield 'nothing after the space' => [['Bearer ']];
        yield 'two tokens' => [['Bearer one two']];
        yield 'a character outside b64token' => [['Bearer abc!']];
        yield 'two Authorization headers' => [['Bearer one', 'Bearer two']];
        yield 'the token in the query as well' => [['Bearer abc'], 'access_token=abc'];
        yield 'the token in the body as well' => [['Bearer abc'], '', 'access_token=abc'];
    }

    // ── Refusing it ─────────────────────────────────────────────────────────────

    public function testNoCredentialsGetAChallengeWithoutAnErrorCode(): void
    {
        $response = $this->challenger()->missing();

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('Bearer realm="https://auth.clavia.test"', $response->getHeaderLine('WWW-Authenticate'));
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertSame('{}', (string) $response->getBody());
        self::assertStringStartsWith('application/json', $response->getHeaderLine('Content-Type'));
    }

    public function testEachRefusalHasItsStatusAndSaysWhyInTheChallengeAndTheBody(): void
    {
        $cases = [
            [BearerTokenError::invalidRequest('Malformed.'), 400],
            [BearerTokenError::invalidToken('Expired.'), 401],
            [BearerTokenError::insufficientScope(ScopeSet::fromString('openid'), 'Needs openid.'), 403],
        ];

        foreach ($cases as [$error, $status]) {
            $response = $this->challenger()->refuse($error);

            self::assertSame($status, $response->getStatusCode());
            self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
            self::assertStringStartsWith(
                sprintf(
                    'Bearer realm="%s", error="%s", error_description="%s"',
                    self::REALM,
                    $error->error->value,
                    $error->description,
                ),
                $response->getHeaderLine('WWW-Authenticate'),
            );
            self::assertSame(
                ['error' => $error->error->value, 'error_description' => $error->description],
                json_decode((string) $response->getBody(), true),
            );
        }
    }

    public function testInsufficientScopeNamesTheScopeNeeded(): void
    {
        $response = $this->challenger()->refuse(
            BearerTokenError::insufficientScope(ScopeSet::fromString('openid email'), 'More.'),
        );

        self::assertStringEndsWith(', scope="openid email"', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testQuotesInAChallengeAreEscaped(): void
    {
        $response = $this->challenger()->refuse(BearerTokenError::invalidToken('A "quoted" \\ word.'));

        self::assertStringContainsString(
            'error_description="A \\"quoted\\" \\\\ word."',
            $response->getHeaderLine('WWW-Authenticate'),
        );
    }

    private function challenger(): BearerChallenger
    {
        return new BearerChallenger(self::REALM);
    }

    private function request(string ...$authorization): ServerRequest
    {
        $request = new ServerRequest(method: 'POST', headers: ['Content-Type' => 'application/x-www-form-urlencoded']);

        return $authorization === [] ? $request : $request->withHeader('Authorization', $authorization);
    }
}
