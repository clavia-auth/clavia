<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Domain\Client\BackChannelLogout;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Oidc\LogoutTokenClaims;
use Clavia\Domain\Shared\Url;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\FakeHttpClient;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\OidcFixtures;
use ClaviaTest\Support\TestEnvironment;
use Laminas\Diactoros\Response\EmptyResponse;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

/**
 * OpenID Connect Back-Channel Logout 1.0, ported from the Python suite's
 * `test_backchannel_logout.py`.
 *
 * Two halves. ID tokens carry `sid`, so a relying party can tie a later logout token to
 * the sign-in it belongs to; and every way a session is ended — the two logout endpoints,
 * an operator, deactivation, deletion — posts a logout token to each application that
 * signed in through it and registered a URI for it. The relying party is a fake wire
 * ({@see FakeHttpClient}) recording what it is sent.
 */
final class BackChannelLogoutTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use OidcFixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string SESSION_COOKIE = 'clavia_session';
    private const string LOGOUT_URI = 'https://client.test/oidc/backchannel-logout';
    private const string ISSUER = 'https://auth.' . TestEnvironment::ROOT_DOMAIN;

    private FakeHttpClient $rp;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->rp = new FakeHttpClient(static fn (): ResponseInterface => new EmptyResponse(200));
    }

    // ── sid ─────────────────────────────────────────────────────────────────────

    public function testTheIdTokenCarriesTheSessionIdentifier(): void
    {
        $this->publicClient();
        $tokens = $this->signInAndGetTokens();

        $session = $this->session($this->cookie(self::SESSION_COOKIE));
        self::assertNotNull($session);
        self::assertSame($session->sid, $this->idTokenClaims($tokens)['sid'] ?? null);
    }

    public function testTheSidIsNotTheCookieAndChangesWithTheSession(): void
    {
        $this->publicClient();
        $first = $this->idTokenClaims($this->signInAndGetTokens());
        $cookie = $this->cookie(self::SESSION_COOKIE);
        $this->post('/auth/logout');
        $second = $this->idTokenClaims($this->signInAndGetTokens());

        self::assertNotSame($first['sid'] ?? null, $second['sid'] ?? null);
        self::assertNotSame($cookie, $first['sid'] ?? null);
    }

    public function testNoSidWithoutABrowserSession(): void
    {
        // The development auto-login stands behind no session: there is nothing to name.
        $this->loggedIn();
        $this->publicClient();

        self::assertArrayNotHasKey('sid', $this->idTokenClaims($this->completeFlow('openid')));
    }

    public function testTheSessionRemembersWhichApplicationsSignedIn(): void
    {
        $this->publicClient();
        $this->user();
        $this->submitLogin();
        self::assertSame([], $this->session($this->cookie(self::SESSION_COOKIE))?->clients);

        $this->completeFlow('openid');

        $clients = $this->session($this->cookie(self::SESSION_COOKIE))->clients ?? [];
        self::assertSame([self::TEST_CLIENT_ID], array_map(static fn (ClientId $id): string => $id->value, $clients));
    }

    // ── The logout token ────────────────────────────────────────────────────────

    public function testLoggingOutPostsALogoutTokenToTheApplication(): void
    {
        $this->bootWithRelyingParty();
        $this->registered();
        $user = $this->user();
        /** @var mixed $sid */
        $sid = $this->idTokenClaims($this->signInAndGetTokens())['sid'] ?? null;

        $response = $this->post('/auth/logout');

        self::assertSame(303, $response->getStatusCode());
        self::assertSame([self::LOGOUT_URI], $this->deliveredTo());
        $request = $this->rp->requests[0];
        self::assertSame('POST', $request->getMethod());
        self::assertSame('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));

        $token = $this->verifiedIdToken($this->logoutTokens()[0]);
        self::assertSame(LogoutTokenClaims::TYPE, $token['header']['typ'] ?? null);
        self::assertNotEmpty($token['header']['kid'] ?? null);
        $claims = $token['claims'];
        self::assertSame(self::ISSUER, $claims['iss'] ?? null);
        self::assertSame(self::TEST_CLIENT_ID, $claims['aud'] ?? null);
        self::assertSame($user->id->value, $claims['sub'] ?? null);
        self::assertSame($sid, $claims['sid'] ?? null);
        self::assertSame([LogoutTokenClaims::EVENT => []], $claims['events'] ?? null);
        self::assertIsString($claims['jti'] ?? null);
        /** @var mixed $expires */
        $expires = $claims['exp'] ?? null;
        /** @var mixed $issued */
        $issued = $claims['iat'] ?? null;
        self::assertIsInt($expires);
        self::assertIsInt($issued);
        self::assertSame(120, $expires - $issued);
        // §2.6: the absence of a nonce is what tells a logout token from an ID token.
        self::assertArrayNotHasKey('nonce', $claims);
        // An empty object, as §2.4 has it — not an empty array.
        $events = '"events":{"' . LogoutTokenClaims::EVENT . '":{}}';
        self::assertStringContainsString($events, self::payloadOf($this->logoutTokens()[0]));
    }

    public function testEachLogoutTokenIsUnique(): void
    {
        $this->bootWithRelyingParty();
        $this->registered();
        $this->user();
        foreach ([1, 2] as $round) {
            $this->signInAndGetTokens();
            self::assertSame(303, $this->post('/auth/logout')->getStatusCode(), 'round ' . $round);
        }

        $claims = array_map(
            fn (string $token): array => $this->verifiedIdToken($token)['claims'],
            $this->logoutTokens(),
        );
        self::assertCount(2, $claims);
        [$first, $second] = [$claims[0] ?? [], $claims[1] ?? []];
        self::assertNotSame($first['jti'] ?? null, $second['jti'] ?? null);
        self::assertNotSame($first['sid'] ?? null, $second['sid'] ?? null);
    }

    public function testRpInitiatedLogoutTellsTheApplicationsToo(): void
    {
        $this->bootWithRelyingParty();
        $this->registered();
        $this->user();
        $tokens = $this->signInAndGetTokens();
        $idToken = $tokens['id_token'] ?? null;
        self::assertIsString($idToken);

        $response = $this->get('/oidc/logout', ['id_token_hint' => $idToken]);

        self::assertSame(303, $response->getStatusCode());
        self::assertCount(1, $this->logoutTokens());
        self::assertSame(
            $this->idTokenClaims($tokens)['sid'] ?? null,
            $this->verifiedIdToken($this->logoutTokens()[0])['claims']['sid'] ?? null,
        );
    }

    public function testAnApplicationWithoutAUriIsNotTold(): void
    {
        $this->bootWithRelyingParty();
        $this->publicClient();
        $this->user();
        $this->signInAndGetTokens();

        $this->post('/auth/logout');

        self::assertSame([], $this->rp->requests);
    }

    public function testAnApplicationThatDidNotSignInIsNotTold(): void
    {
        // Registration alone is not a session: only applications that received a code
        // through this session are told it ended.
        $this->bootWithRelyingParty();
        $this->registered();
        $this->user();
        $this->submitLogin();

        $this->post('/auth/logout');

        self::assertSame([], $this->rp->requests);
    }

    public function testASessionIsNotReportedTwice(): void
    {
        $this->bootWithRelyingParty();
        $this->registered();
        $this->user();
        $this->signInAndGetTokens();
        $cookie = $this->cookie(self::SESSION_COOKIE);
        $this->post('/auth/logout');
        self::assertCount(1, $this->rp->requests);
        self::assertNotNull($cookie);

        // The same cookie, presented again after the session ended.
        $this->setCookie(self::SESSION_COOKIE, $cookie);
        $this->post('/auth/logout');

        self::assertCount(1, $this->rp->requests);
    }

    public function testAFailingApplicationDoesNotBreakLogout(): void
    {
        $this->bootWithRelyingParty();
        $this->rp->answerWith(static function (): never {
            throw new class ('Connection refused.') extends RuntimeException implements ClientExceptionInterface {
            };
        });
        $this->registered();
        $this->user();
        $this->signInAndGetTokens();
        $sessionId = $this->cookie(self::SESSION_COOKIE);

        $response = $this->post('/auth/logout');

        self::assertSame(303, $response->getStatusCode());
        self::assertNull($this->session($sessionId));
        self::assertTrue($this->logger->hasRecordContaining('could not be reached'));
    }

    public function testAnErrorResponseIsTolerated(): void
    {
        $this->bootWithRelyingParty();
        $this->rp->answerWith(static fn (): ResponseInterface => new EmptyResponse(500));
        $this->registered();
        $this->user();
        $this->signInAndGetTokens();

        $response = $this->post('/auth/logout');

        self::assertSame(303, $response->getStatusCode());
        self::assertCount(1, $this->rp->requests);
        self::assertTrue($this->logger->hasRecordContaining('answered 500'));
    }

    public function testAPrivateAddressIsRefusedAtSendTime(): void
    {
        // What a name resolves to can change between registration and the day the token
        // is sent; here the registration is written around the check altogether.
        $this->bootWithRelyingParty();
        $this->registered('https://localhost/logout');
        $this->user();
        $this->signInAndGetTokens();

        $this->post('/auth/logout');

        self::assertSame([], $this->rp->requests);
        self::assertTrue($this->logger->hasRecordContaining('must not point at this server'));
    }

    // ── Registration ────────────────────────────────────────────────────────────

    public function testRegistrationCarriesTheUri(): void
    {
        $this->publicClient();
        $this->adminToken();

        $response = $this->api('PATCH', '/api/v1/clients/' . self::TEST_CLIENT_ID, [
            'backchannel_logout_uri' => self::LOGOUT_URI,
            'backchannel_logout_session_required' => true,
        ]);

        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame(self::LOGOUT_URI, self::json($response)['backchannel_logout_uri']);
        self::assertTrue(self::json($response)['backchannel_logout_session_required']);

        $cleared = $this->api('PATCH', '/api/v1/clients/' . self::TEST_CLIENT_ID, ['backchannel_logout_uri' => null]);
        self::assertSame(200, $cleared->getStatusCode(), (string) $cleared->getBody());
        self::assertNull(self::json($cleared)['backchannel_logout_uri']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function uris(): iterable
    {
        yield 'plaintext' => ['http://client.test/logout'];
        yield 'relative' => ['/logout'];
        yield 'a fragment' => ['https://client.test/logout#frag'];
        yield 'this host' => ['https://localhost/logout'];
        yield 'a private network' => ['https://10.0.0.5/logout'];
        yield 'cloud metadata' => ['https://169.254.169.254/latest/meta-data/'];
    }

    #[DataProvider('uris')]
    public function testRegistrationRefusesAUriThisServerMustNotPostTo(string $uri): void
    {
        $this->publicClient();
        $this->adminToken();

        $response = $this->api('PATCH', '/api/v1/clients/' . self::TEST_CLIENT_ID, ['backchannel_logout_uri' => $uri]);

        self::assertSame(422, $response->getStatusCode(), (string) $response->getBody());
    }

    public function testCreationChecksTheUriToo(): void
    {
        $this->adminToken();

        $response = $this->api('POST', '/api/v1/clients', [
            'name' => 'RP',
            'redirect_uris' => [self::TEST_REDIRECT_URI],
            'grant_types' => ['authorization_code'],
            'response_types' => ['code'],
            'backchannel_logout_uri' => 'https://127.0.0.1/logout',
        ]);

        self::assertSame(422, $response->getStatusCode(), (string) $response->getBody());
    }

    // ── Session management ──────────────────────────────────────────────────────

    public function testSessionsAreListedWithTheirApplications(): void
    {
        $client = $this->registered();
        $user = $this->user();
        $tokens = $this->signInAndGetTokens();
        $this->adminToken();

        $response = $this->api('GET', '/api/v1/users/' . $user->id->value . '/sessions');

        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        $sessions = self::json($response);
        self::assertCount(1, $sessions);
        $session = $sessions[0];
        self::assertIsArray($session);
        self::assertSame($this->idTokenClaims($tokens)['sid'] ?? null, $session['sid']);
        self::assertSame('password', $session['connection']);
        self::assertSame(['pwd'], $session['amr']);
        self::assertSame([['client_id' => self::TEST_CLIENT_ID, 'name' => $client->name]], $session['clients']);
    }

    public function testSignOutEverywhereEndsEverySessionAndTellsTheApplications(): void
    {
        $this->bootWithRelyingParty();
        $this->registered();
        $user = $this->user();
        $this->signInAndGetTokens();
        $first = $this->cookie(self::SESSION_COOKIE);
        $this->clearCookies();
        $this->signInAndGetTokens();
        $second = $this->cookie(self::SESSION_COOKIE);
        $this->adminToken();
        self::assertCount(2, self::json($this->api('GET', '/api/v1/users/' . $user->id->value . '/sessions')));

        $response = $this->api('DELETE', '/api/v1/users/' . $user->id->value . '/sessions');

        self::assertSame(204, $response->getStatusCode(), (string) $response->getBody());
        self::assertNull($this->session($first));
        self::assertNull($this->session($second));
        self::assertSame([], self::json($this->api('GET', '/api/v1/users/' . $user->id->value . '/sessions')));
        $sids = array_map(
            fn (string $token): mixed => $this->verifiedIdToken($token)['claims']['sid'] ?? null,
            $this->logoutTokens(),
        );
        self::assertCount(2, array_unique($sids));
    }

    public function testOneSessionCanBeEndedByItsSid(): void
    {
        $this->bootWithRelyingParty();
        $this->registered();
        $user = $this->user();
        $sid = $this->idTokenClaims($this->signInAndGetTokens())['sid'] ?? null;
        self::assertIsString($sid);
        $cookie = $this->cookie(self::SESSION_COOKIE);
        $this->adminToken();
        $path = '/api/v1/users/' . $user->id->value . '/sessions/' . $sid;

        $response = $this->api('DELETE', $path);

        self::assertSame(204, $response->getStatusCode(), (string) $response->getBody());
        self::assertNull($this->session($cookie));
        self::assertCount(1, $this->logoutTokens());
        self::assertSame(404, $this->api('DELETE', $path)->getStatusCode());
    }

    public function testDeactivatingAUserSignsThemOutEverywhere(): void
    {
        $this->bootWithRelyingParty();
        $this->registered();
        $user = $this->user();
        $this->signInAndGetTokens();
        $cookie = $this->cookie(self::SESSION_COOKIE);
        $this->adminToken();

        $response = $this->api('PATCH', '/api/v1/users/' . $user->id->value, ['is_active' => false]);

        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        self::assertNull($this->session($cookie));
        self::assertCount(1, $this->logoutTokens());
    }

    public function testDeletingAUserSignsThemOutEverywhere(): void
    {
        $this->bootWithRelyingParty();
        $this->registered();
        $user = $this->user();
        $this->signInAndGetTokens();
        $cookie = $this->cookie(self::SESSION_COOKIE);
        $this->adminToken();

        $response = $this->api('DELETE', '/api/v1/users/' . $user->id->value);

        self::assertSame(204, $response->getStatusCode(), (string) $response->getBody());
        self::assertNull($this->session($cookie));
        self::assertCount(1, $this->logoutTokens());
        self::assertSame($user->id->value, $this->verifiedIdToken($this->logoutTokens()[0])['claims']['sub'] ?? null);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    /**
     * Start the application with the fake relying party as the outbound wire.
     *
     * @param array<string, string> $environment
     */
    private function bootWithRelyingParty(array $environment = []): void
    {
        $this->boot($environment);
        $this->container()->setService(ClientInterface::class, $this->rp);
    }

    /** The public client, registered for back-channel logout — written straight to storage. */
    private function registered(string $uri = self::LOGOUT_URI): Client
    {
        $clients = $this->container()->get(ClientRepository::class);
        $client = $this->publicClient()->withBackChannelLogout(new BackChannelLogout(Url::fromString($uri)));
        $clients->save($client);

        return $client;
    }

    /**
     * Sign the test user in with a password, then run the authorization code flow.
     *
     * @return array<array-key, mixed>
     */
    private function signInAndGetTokens(): array
    {
        $this->user();
        $this->submitLogin();

        return $this->completeFlow('openid');
    }

    /**
     * @param array<array-key, mixed> $tokens
     *
     * @return array<string, mixed>
     */
    private function idTokenClaims(array $tokens): array
    {
        return $this->verifiedIdToken($tokens['id_token'] ?? null)['claims'];
    }

    /** @return list<string> Where each logout token went, in order. */
    private function deliveredTo(): array
    {
        return array_map(
            static fn (RequestInterface $request): string => (string) $request->getUri(),
            $this->rp->requests,
        );
    }

    /** @return list<string> */
    private function logoutTokens(): array
    {
        return array_map(
            static fn (RequestInterface $request): string => FakeHttpClient::form($request)['logout_token'] ?? '',
            $this->rp->requests,
        );
    }

    private static function payloadOf(string $jws): string
    {
        $parts = explode('.', $jws);

        return (string) base64_decode(strtr($parts[1] ?? '', '-_', '+/'), true);
    }
}
