<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Domain\Client\ClientRepository;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\OidcFixtures;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Pushed authorization requests (RFC 9126): the client pushes its request to `/oauth2/par` over
 * the back channel, and the browser carries only `client_id` and the `request_uri` it got.
 */
final class PushedAuthorizationRequestTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use OidcFixtures;

    private const string URN_PREFIX = 'urn:ietf:params:oauth:request_uri:';

    public function testDiscoveryNamesTheEndpoint(): void
    {
        $document = self::json($this->get('/.well-known/openid-configuration'));

        self::assertSame('https://auth.clavia.test/oauth2/par', $document['pushed_authorization_request_endpoint']);
        self::assertFalse($document['require_pushed_authorization_requests']);
    }

    public function testAPushedRequestIsAnsweredWithARequestUri(): void
    {
        $this->publicClient();

        $response = $this->push($this->authorizeParams($this->makePkcePair()[1]));

        self::assertSame(
            StatusCodeInterface::STATUS_CREATED,
            $response->getStatusCode(),
            (string) $response->getBody(),
        );
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        $body = self::json($response);
        self::assertIsString($body['request_uri']);
        self::assertStringStartsWith(self::URN_PREFIX, $body['request_uri']);
        self::assertSame(60, $body['expires_in']);
    }

    public function testTheBrowserCarriesOnlyTheReferenceAndGetsACode(): void
    {
        $this->user();
        $this->publicClient();
        $this->submitLogin();
        [$verifier, $challenge] = $this->makePkcePair();
        $requestUri = $this->pushedUri($this->authorizeParams($challenge, ['scope' => 'openid', 'state' => 'pushed']));

        $response = $this->byReference($requestUri);

        $query = self::locationQuery($response);
        self::assertSame('pushed', $query['state'] ?? null, 'The state is the pushed one.');
        $code = $this->extractCode($response);
        $tokens = self::json($this->post('/oauth2/token', $this->tokenRequest($code, $verifier)));
        self::assertIsString($tokens['id_token']);
    }

    public function testARequestUriYieldsOneCode(): void
    {
        $this->user();
        $this->publicClient();
        $this->submitLogin();
        $requestUri = $this->pushedUri($this->authorizeParams($this->makePkcePair()[1]));
        $by = ['client_id' => self::TEST_CLIENT_ID, 'request_uri' => $requestUri];

        $this->extractCode($this->get('/oauth2/authorize', $by));
        $again = $this->get('/oauth2/authorize', $by);

        self::assertSame(
            StatusCodeInterface::STATUS_BAD_REQUEST,
            $again->getStatusCode(),
            'Spent: there is no redirect URI to trust any more.',
        );
    }

    public function testTheQueryCannotChangeAPushedRequest(): void
    {
        // RFC 9126 §4: the pushed parameters are the request; anything else in the query is ignored.
        $this->user();
        $this->publicClient();
        $this->submitLogin();
        $requestUri = $this->pushedUri($this->authorizeParams($this->makePkcePair()[1], ['state' => 'pushed']));

        $response = $this->get('/oauth2/authorize', [
            'client_id' => self::TEST_CLIENT_ID,
            'request_uri' => $requestUri,
            'state' => 'tampered',
            'redirect_uri' => 'https://evil.test/cb',
        ]);

        self::assertStringStartsWith(self::TEST_REDIRECT_URI . '?', $response->getHeaderLine('Location'));
        self::assertSame('pushed', self::locationQuery($response)['state'] ?? null);
    }

    public function testASignInInBetweenKeepsTheRequestOutOfTheAddressBar(): void
    {
        $this->user();
        $this->publicClient();
        $requestUri = $this->pushedUri($this->authorizeParams($this->makePkcePair()[1], ['state' => 'pushed']));

        $toLogin = $this->get('/oauth2/authorize', ['client_id' => self::TEST_CLIENT_ID, 'request_uri' => $requestUri]);
        self::assertStringStartsWith('/auth/login?state=', $toLogin->getHeaderLine('Location'));
        parse_str((string) parse_url($toLogin->getHeaderLine('Location'), PHP_URL_QUERY), $login);
        $signedIn = $this->submitLogin(state: (string) $login['state']);

        // Back by reference, under a new request_uri: no pushed parameter in the URL.
        $back = $signedIn->getHeaderLine('Location');
        parse_str((string) parse_url($back, PHP_URL_QUERY), $resumed);
        self::assertSame(['client_id', 'request_uri'], array_keys($resumed));
        self::assertNotSame($requestUri, $resumed['request_uri']);
        self::assertSame('pushed', self::locationQuery($this->get($back))['state'] ?? null);
    }

    public function testAnotherClientCannotUseARequestUri(): void
    {
        $this->publicClient();
        $this->confidentialClient();
        $requestUri = $this->pushedUri($this->authorizeParams($this->makePkcePair()[1]));

        $response = $this->get('/oauth2/authorize', [
            'client_id' => self::TEST_CONFIDENTIAL_CLIENT_ID,
            'request_uri' => $requestUri,
        ]);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
    }

    public function testThePushIsValidatedAsTheAuthorizationEndpointWould(): void
    {
        $this->publicClient();

        $noPkce = $this->push($this->authorizeParams(null));
        $challenge = $this->makePkcePair()[1];
        $strangeRedirect = $this->push($this->authorizeParams($challenge, ['redirect_uri' => 'https://evil.test/cb']));
        $withRequestUri = $this->push($this->authorizeParams($challenge, ['request_uri' => self::URN_PREFIX . 'x']));

        self::assertSame('invalid_request', self::json($noPkce)['error']);
        self::assertSame('invalid_request', self::json($strangeRedirect)['error']);
        self::assertSame('invalid_request', self::json($withRequestUri)['error']);
    }

    public function testAConfidentialClientAuthenticatesAndItsSecretIsNotKept(): void
    {
        $this->user();
        $this->confidentialClient();
        $this->submitLogin();
        [$verifier, $challenge] = $this->makePkcePair();
        $params = $this->authorizeParams($challenge, ['client_id' => self::TEST_CONFIDENTIAL_CLIENT_ID]);

        $wrong = $this->post('/oauth2/par', $params + ['client_secret' => 'wrong']);
        $pushed = self::json($this->post('/oauth2/par', $params + ['client_secret' => self::TEST_CLIENT_SECRET]));

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $wrong->getStatusCode());
        self::assertIsString($pushed['request_uri']);
        $response = $this->get('/oauth2/authorize', [
            'client_id' => self::TEST_CONFIDENTIAL_CLIENT_ID,
            'request_uri' => $pushed['request_uri'],
        ]);
        self::assertStringNotContainsString(self::TEST_CLIENT_SECRET, $response->getHeaderLine('Location'));
        self::assertArrayHasKey('code', self::locationQuery($response));
    }

    public function testAClientRequiredToPushIsRefusedOtherwise(): void
    {
        $this->user();
        $client = $this->publicClient();
        $this->container()->get(ClientRepository::class)->save($client->withPushedAuthorizationRequestsRequired(true));
        $this->submitLogin();

        $plain = $this->get('/oauth2/authorize', $this->authorizeParams($this->makePkcePair()[1]));
        $pushed = $this->get('/oauth2/authorize', [
            'client_id' => self::TEST_CLIENT_ID,
            'request_uri' => $this->pushedUri($this->authorizeParams($this->makePkcePair()[1])),
        ]);

        self::assertSame('invalid_request', self::locationQuery($plain)['error'] ?? null);
        self::assertArrayHasKey('code', self::locationQuery($pushed));
    }

    public function testARequestUriThisServerDidNotIssueIsStillNotSupported(): void
    {
        $this->publicClient();

        $response = $this->get('/oauth2/authorize', $this->authorizeParams($this->makePkcePair()[1], [
            'request_uri' => 'https://client.test/request.jwt',
        ]));

        self::assertSame('request_uri_not_supported', self::locationQuery($response)['error'] ?? null);
    }

    private function byReference(string $requestUri): ResponseInterface
    {
        return $this->get('/oauth2/authorize', ['client_id' => self::TEST_CLIENT_ID, 'request_uri' => $requestUri]);
    }

    /**
     * @param array<string, string> $parameters
     */
    private function push(array $parameters): ResponseInterface
    {
        return $this->post('/oauth2/par', $parameters);
    }

    /**
     * @param array<string, string> $parameters
     */
    private function pushedUri(array $parameters): string
    {
        $response = $this->push($parameters);
        self::assertSame(
            StatusCodeInterface::STATUS_CREATED,
            $response->getStatusCode(),
            (string) $response->getBody(),
        );
        $uri = self::json($response)['request_uri'];
        self::assertIsString($uri);

        return $uri;
    }
}
