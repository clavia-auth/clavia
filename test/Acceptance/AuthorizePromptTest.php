<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\OidcFixtures;
use ClaviaTest\Support\TestEnvironment;
use Psr\Http\Message\ResponseInterface;

/**
 * `prompt`, `max_age` and the request-object parameters at `/oauth2/authorize` (OpenID
 * Connect Core §3.1.2.1, §3.1.2.6, §6), and the `iss` response parameter (RFC 9207).
 *
 * Whether the person has to be seen again is decided once, by the authorization
 * endpoint: no session, a session the client cannot use, `prompt=login` or
 * `select_account`, a sign-in older than `max_age`. A sign-in satisfies what asked for it,
 * so the request the login page returns to no longer asks.
 */
final class AuthorizePromptTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use OidcFixtures;

    private const string ISSUER = 'https://auth.' . TestEnvironment::ROOT_DOMAIN;

    // ── RFC 9207 ────────────────────────────────────────────────────────────────

    public function testTheAuthorizationResponseNamesTheIssuer(): void
    {
        $this->signedIn();

        $params = self::redirectParams($this->authorize());

        self::assertSame(self::ISSUER, $params['iss'] ?? null);
        self::assertNotEmpty($params['code'] ?? null);
    }

    public function testErrorResponsesNameTheIssuerToo(): void
    {
        $this->signedIn();

        $params = self::redirectParams($this->authorize(['scope' => 'openid nonsense']));

        self::assertArrayHasKey('error', $params);
        self::assertSame(self::ISSUER, $params['iss'] ?? null);
    }

    // ── prompt=none ─────────────────────────────────────────────────────────────

    public function testPromptNoneWithoutASessionIsLoginRequired(): void
    {
        $this->publicClient();

        $params = self::redirectParams($this->authorize(['prompt' => 'none', 'state' => 's1']));

        self::assertSame('login_required', $params['error'] ?? null);
        self::assertSame('s1', $params['state'] ?? null);
    }

    public function testPromptNoneWithASessionIssuesACode(): void
    {
        $this->signedIn();

        self::assertNotSame('', $this->extractCode($this->authorize(['prompt' => 'none'])));
    }

    public function testPromptNoneWithASessionTooOldForMaxAgeIsLoginRequired(): void
    {
        $this->signedIn();

        $params = self::redirectParams($this->authorize(['prompt' => 'none', 'max_age' => '0']));

        self::assertSame('login_required', $params['error'] ?? null);
    }

    public function testPromptNoneCombinedWithAnotherValueIsInvalid(): void
    {
        $this->signedIn();

        $params = self::redirectParams($this->authorize(['prompt' => 'none login', 'state' => 's2']));

        self::assertSame('invalid_request', $params['error'] ?? null);
        self::assertSame('s2', $params['state'] ?? null);
    }

    // ── prompt=login, prompt=select_account, max_age ────────────────────────────

    public function testPromptLoginReauthenticatesASignedInUserExactlyOnce(): void
    {
        $this->signedIn();
        $before = $this->cookie('clavia_session');

        $response = $this->authorize(['prompt' => 'login']);

        self::assertSame(303, $response->getStatusCode());
        $back = $this->submitLogin(state: self::loginStateOf($response));
        self::assertSame(303, $back->getStatusCode());
        $next = $back->getHeaderLine('Location');
        self::assertStringStartsWith('/oauth2/authorize?', $next);
        self::assertStringNotContainsString('prompt=', $next);
        self::assertNotSame($before, $this->cookie('clavia_session'), 'A new session, not the old one.');
        self::assertNotSame('', $this->extractCode($this->follow($next)));
    }

    public function testPromptLoginKeepsTheOtherPromptValues(): void
    {
        $this->signedIn();

        $response = $this->authorize(['prompt' => 'login consent']);
        $next = $this->submitLogin(state: self::loginStateOf($response))->getHeaderLine('Location');

        self::assertSame('consent', self::queryOf($next)['prompt'] ?? null);
    }

    public function testPromptSelectAccountIsHonouredBySigningInAgain(): void
    {
        $this->signedIn();

        $response = $this->authorize(['prompt' => 'select_account']);

        self::assertSame(303, $response->getStatusCode());
        $next = $this->submitLogin(state: self::loginStateOf($response))->getHeaderLine('Location');
        self::assertStringNotContainsString('select_account', $next);
        self::assertNotSame('', $this->extractCode($this->follow($next)));
    }

    public function testMaxAgeWithinTheSessionAgePasses(): void
    {
        $this->signedIn();

        self::assertNotSame('', $this->extractCode($this->authorize(['max_age' => '3600'])));
    }

    public function testMaxAgeZeroAsksForASignInAndIsThenDropped(): void
    {
        $this->signedIn();

        $response = $this->authorize(['max_age' => '0']);

        self::assertSame(303, $response->getStatusCode());
        // max_age=0 is prompt=login by another name (§3.1.2.1), and goes like it.
        $next = $this->submitLogin(state: self::loginStateOf($response))->getHeaderLine('Location');
        self::assertArrayNotHasKey('max_age', self::queryOf($next));
        self::assertNotSame('', $this->extractCode($this->follow($next)));
    }

    public function testAPositiveMaxAgeSurvivesTheSignIn(): void
    {
        $clock = $this->freezeClock();
        $this->signedIn();
        $clock->advance(3600);

        $response = $this->authorize(['max_age' => '60']);

        self::assertSame(303, $response->getStatusCode(), 'An hour-old sign-in is too old for a minute.');
        $next = $this->submitLogin(state: self::loginStateOf($response))->getHeaderLine('Location');
        self::assertSame('60', self::queryOf($next)['max_age'] ?? null, 'A fresh sign-in satisfies it.');
        self::assertNotSame('', $this->extractCode($this->follow($next)));
    }

    public function testTheIdTokenSaysWhenThePersonSignedIn(): void
    {
        $this->signedIn();
        $session = $this->session($this->cookie('clavia_session'));
        self::assertNotNull($session);

        $tokens = $this->completeFlow('openid', ['max_age' => '3600']);

        self::assertSame(
            $session->authenticatedAt->getTimestamp(),
            $this->verifiedIdToken($tokens['id_token'] ?? null)['claims']['auth_time'] ?? null,
        );
    }

    public function testMaxAgeWithoutAKnownSignInTimeAsksForASignIn(): void
    {
        // The development auto-login has no sign-in time; max_age cannot be satisfied by a
        // time nobody knows.
        $this->loggedIn();
        $this->publicClient();

        self::assertSame(303, $this->authorize(['max_age' => '3600'])->getStatusCode());
    }

    public function testANegativeOrMalformedMaxAgeIsInvalid(): void
    {
        $this->signedIn();

        foreach (['-1', 'soon', '1.5'] as $bad) {
            $params = self::redirectParams($this->authorize(['max_age' => $bad]));
            self::assertSame('invalid_request', $params['error'] ?? null, $bad);
        }
    }

    public function testAnAnonymousRequestForASignInComesBackWithoutIt(): void
    {
        $this->publicClient();
        $this->user();

        $response = $this->authorize(['prompt' => 'login', 'max_age' => '0']);
        $next = $this->submitLogin(state: self::loginStateOf($response))->getHeaderLine('Location');

        self::assertArrayNotHasKey('prompt', self::queryOf($next));
        self::assertArrayNotHasKey('max_age', self::queryOf($next));
        self::assertNotSame('', $this->extractCode($this->follow($next)));
    }

    // ── Request objects ─────────────────────────────────────────────────────────

    public function testRequestObjectsAreRefusedWithTheDefinedErrors(): void
    {
        $this->signedIn();

        $byValue = self::redirectParams($this->authorize(['request' => 'eyJhbGciOiJub25lIn0.e30.', 'state' => 's3']));
        $byReference = self::redirectParams($this->authorize(['request_uri' => 'https://client.test/req']));

        self::assertSame('request_not_supported', $byValue['error'] ?? null);
        self::assertSame('s3', $byValue['state'] ?? null);
        self::assertSame('request_uri_not_supported', $byReference['error'] ?? null);
    }

    public function testARequestObjectIsRefusedEvenWithoutTheOtherParameters(): void
    {
        // A request object carries the parameters itself; their absence beside it is not
        // the error to report.
        $this->publicClient();

        $response = $this->get('/oauth2/authorize', [
            'client_id' => self::TEST_CLIENT_ID,
            'redirect_uri' => self::TEST_REDIRECT_URI,
            'request' => 'eyJhbGciOiJub25lIn0.e30.',
        ]);

        self::assertSame('request_not_supported', self::redirectParams($response)['error'] ?? null);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    /** The public client, and the test user signed in with a password. */
    private function signedIn(): void
    {
        $this->publicClient();
        $this->user();
        self::assertSame(303, $this->submitLogin()->getStatusCode());
    }

    /**
     * @param array<string, string|null> $overrides
     */
    private function authorize(array $overrides = []): ResponseInterface
    {
        [, $challenge] = $this->makePkcePair();

        return $this->get('/oauth2/authorize', $this->authorizeParams($challenge, $overrides));
    }

    /** Follow a local `Location` the way a browser does. */
    private function follow(string $location): ResponseInterface
    {
        return $this->get((string) parse_url($location, PHP_URL_PATH), self::queryOf($location));
    }

    /**
     * @return array<string, string>
     */
    private static function redirectParams(ResponseInterface $response): array
    {
        self::assertSame(302, $response->getStatusCode(), (string) $response->getBody());
        self::assertStringStartsWith(self::TEST_REDIRECT_URI, $response->getHeaderLine('Location'));

        return self::locationQuery($response);
    }

    private static function loginStateOf(ResponseInterface $response): string
    {
        self::assertStringStartsWith('/auth/login?', $response->getHeaderLine('Location'));
        $state = self::locationQuery($response)['state'] ?? null;
        self::assertIsString($state);

        return $state;
    }

    /**
     * @return array<string, string>
     */
    private static function queryOf(string $location): array
    {
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);

        /** @var array<string, string> $query */
        return $query;
    }
}
