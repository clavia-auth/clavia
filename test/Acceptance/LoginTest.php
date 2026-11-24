<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\RandomSource;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use DateTimeImmutable;
use Fig\Http\Message\StatusCodeInterface;

/**
 * The interactive login flow and the sessions it establishes.
 *
 * As with the PKCE suite, most of these correspond to an attack rather than a feature,
 * so a failure here is a security regression.
 */
final class LoginTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;

    private const string SESSION_COOKIE = 'clavia_session';

    // ------------------------------------------------------------------
    // The page itself
    // ------------------------------------------------------------------

    public function testLoginPageRendersWithCsrfToken(): void
    {
        $response = $this->get('/auth/login');

        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
        self::assertStringStartsWith('text/html', $response->getHeaderLine('Content-Type'));
        self::assertNotSame('', self::csrfTokenFrom($response));
        // Never cached: the page carries a CSRF token and may prefill an email.
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
    }

    public function testTheLoginPageRunsOnlyThisServersPasskeyModule(): void
    {
        $response = $this->get('/auth/login');

        $policy = $response->getHeaderLine('Content-Security-Policy');
        self::assertStringContainsString("default-src 'none'", $policy);
        // The passkey module, under Trusted Types with no policy: no inline script, no eval, no
        // other origin (docs/design/passkeys.md §8).
        self::assertStringContainsString("script-src 'self';", $policy);
        self::assertStringNotContainsString('unsafe', $policy);
        self::assertStringContainsString("require-trusted-types-for 'script'; trusted-types 'none'", $policy);
        self::assertStringContainsString("form-action 'self'", $policy);
        self::assertStringContainsString("frame-ancestors 'none'", $policy);
        $body = strtolower((string) $response->getBody());
        self::assertSame(1, substr_count($body, '<script'), 'The module and nothing else.');
        self::assertSame(1, preg_match('#<script type="module" src="([^"]+)"></script>#', $body, $module));
        self::assertSame('/auth/static/passkeys.js', html_entity_decode($module[1], ENT_QUOTES | ENT_HTML5));
        self::assertStringNotContainsString(' style=', (string) $response->getBody());
        self::assertSame('DENY', $response->getHeaderLine('X-Frame-Options'));
        self::assertSame('nosniff', $response->getHeaderLine('X-Content-Type-Options'));
    }

    public function testWithPasskeysOffTheLoginPageRunsNoScriptAtAll(): void
    {
        $this->boot(['CLAVIA_PASSKEYS_ENABLED' => 'false']);

        $response = $this->get('/auth/login');

        self::assertStringNotContainsString('script-src', $response->getHeaderLine('Content-Security-Policy'));
        self::assertStringNotContainsString('<script', strtolower((string) $response->getBody()));
    }

    public function testThemeToggleSetsACookieAndReturnsToThePage(): void
    {
        $response = $this->post('/auth/theme', ['theme' => 'dark', 'next' => '/auth/login?state=abc']);

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        self::assertSame('/auth/login?state=abc', $response->getHeaderLine('Location'));
        self::assertSame('dark', $this->cookie('clavia_theme'));

        $page = (string) $this->get('/auth/login')->getBody();
        self::assertStringContainsString('<html lang="en" data-theme="dark">', $page);
        self::assertStringContainsString('value="dark" aria-pressed="true"', $page);
        self::assertStringNotContainsString('value="auto" aria-pressed="true"', $page);
    }

    public function testThemeAutoClearsTheCookieAndFollowsTheSystem(): void
    {
        $this->setCookie('clavia_theme', 'light');

        $response = $this->post('/auth/theme', ['theme' => 'auto', 'next' => '/auth/login']);

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        self::assertNull($this->cookie('clavia_theme'));
        $page = (string) $this->get('/auth/login')->getBody();
        self::assertStringNotContainsString('data-theme', $page);
        self::assertStringContainsString('value="auto" aria-pressed="true"', $page);
    }

    public function testThemeToggleIgnoresUnknownValuesAndHostileNext(): void
    {
        $response = $this->post('/auth/theme', ['theme' => '<x>', 'next' => 'https://evil.test/']);

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        self::assertSame('/auth/login', $response->getHeaderLine('Location'));
        self::assertNull($this->cookie('clavia_theme'));
        self::assertStringNotContainsString('data-theme', (string) $this->get('/auth/login')->getBody());
    }

    public function testAForgedThemeCookieIsNotPrinted(): void
    {
        $this->setCookie('clavia_theme', 'dark"><b>x</b>');

        $page = (string) $this->get('/auth/login')->getBody();

        self::assertStringNotContainsString('data-theme', $page);
        self::assertStringNotContainsString('<b>x</b>', $page);
    }

    // ------------------------------------------------------------------
    // Happy path
    // ------------------------------------------------------------------

    public function testSuccessfulLoginEstablishesASession(): void
    {
        $user = $this->user();

        $response = $this->submitLogin();

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        $session = $this->session($this->cookie(self::SESSION_COOKIE));
        self::assertNotNull($session);
        self::assertTrue($session->userId->equals($user->id));
        self::assertSame(['pwd'], array_map(static fn ($method): string => $method->value, $session->methods));
    }

    public function testSessionCookieFlags(): void
    {
        $this->user();

        $header = self::setCookieHeader($this->submitLogin(), self::SESSION_COOKIE);

        self::assertNotNull($header);
        $lowered = strtolower($header);
        self::assertStringContainsString('httponly', $lowered);
        self::assertStringContainsString('secure', $lowered);
        self::assertStringContainsString('samesite=lax', $lowered);
        self::assertStringContainsString('path=/', $lowered);
        self::assertStringContainsString('max-age=604800', $lowered);
        // No Domain attribute: the cookie is the auth origin's alone, never shared with
        // another subdomain of the deployment.
        self::assertStringNotContainsString('domain=', $lowered);
    }

    public function testSessionIdIsNotStoredInPlaintext(): void
    {
        $this->user();
        $this->submitLogin();
        $sessionId = $this->cookie(self::SESSION_COOKIE) ?? '';

        $keys = TestStorage::redis()->keys('session:*');

        self::assertIsArray($keys);
        self::assertNotSame([], $keys, 'the session was not stored');
        foreach ($keys as $key) {
            self::assertStringNotContainsString($sessionId, $key);
        }
    }

    public function testLogoutDestroysTheSession(): void
    {
        $this->user();
        $this->submitLogin();
        $sessionId = $this->cookie(self::SESSION_COOKIE);
        self::assertNotNull($this->session($sessionId));

        $response = $this->post('/auth/logout');

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        self::assertSame('/auth/login', $response->getHeaderLine('Location'));
        self::assertNull($this->session($sessionId));
        self::assertNull($this->cookie(self::SESSION_COOKIE));
    }

    public function testLogoutRejectsGet(): void
    {
        $this->user();
        $this->submitLogin();
        $sessionId = $this->cookie(self::SESSION_COOKIE);

        $response = $this->get('/auth/logout');

        self::assertSame(StatusCodeInterface::STATUS_METHOD_NOT_ALLOWED, $response->getStatusCode());
        self::assertSame('POST', $response->getHeaderLine('Allow'));
        self::assertNotNull($this->session($sessionId));
    }

    public function testLogoutRedirectsToARegisteredClientOrigin(): void
    {
        $this->user();
        $this->publicClient();
        $this->submitLogin();

        $response = $this->request(
            'POST',
            '/auth/logout?' . http_build_query(['next' => 'https://client.test/signed-out']),
        );

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        self::assertSame('https://client.test/signed-out', $response->getHeaderLine('Location'));
    }

    public function testLogoutIgnoresAnUnregisteredNext(): void
    {
        $this->user();
        $this->publicClient();
        $this->submitLogin();

        $untrusted = ['https://evil.test/phish', 'http://client.test/plain-http', 'https://client.test.evil.test/'];
        foreach ($untrusted as $next) {
            $response = $this->request('POST', '/auth/logout?' . http_build_query(['next' => $next]));

            self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
            self::assertSame('/auth/login', $response->getHeaderLine('Location'), $next);
        }
    }

    // ------------------------------------------------------------------
    // Credential handling
    // ------------------------------------------------------------------

    public function testWrongPasswordIsRejected(): void
    {
        $this->user();

        $response = $this->submitLogin(password: 'not-the-password');

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $response->getStatusCode());
        self::assertNull($this->cookie(self::SESSION_COOKIE));
    }

    public function testUnknownAccountGivesTheSameResponseAsAWrongPassword(): void
    {
        $this->user();

        $wrongPassword = $this->submitLogin(password: 'not-the-password');
        $unknownAccount = $this->submitLogin(email: 'nobody@clavia.dev');

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $wrongPassword->getStatusCode());
        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $unknownAccount->getStatusCode());
        self::assertStringContainsString('Incorrect email or password.', (string) $wrongPassword->getBody());
        self::assertStringContainsString('Incorrect email or password.', (string) $unknownAccount->getBody());
    }

    public function testInactiveUserCannotLogIn(): void
    {
        $this->deactivate($this->user());

        $response = $this->submitLogin();

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $response->getStatusCode());
        self::assertStringContainsString('Incorrect email or password.', (string) $response->getBody());
        self::assertNull($this->cookie(self::SESSION_COOKIE));
    }

    /**
     * An account that signs in elsewhere has nothing to verify; an empty password must
     * not match an absent hash.
     */
    public function testAccountWithoutAPasswordCannotLogInWithOne(): void
    {
        /** @var UserRepository $users */
        $users = $this->container()->get(UserRepository::class);
        /** @var RandomSource $random */
        $random = $this->container()->get(RandomSource::class);
        $users->save(User::register(UserId::generate($random), 'sso@clavia.dev', null, new DateTimeImmutable()));

        $response = $this->submitLogin(email: 'sso@clavia.dev', password: '');

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $response->getStatusCode());
        self::assertNull($this->cookie(self::SESSION_COOKIE));
    }

    /** A session is re-checked against the account on every use, not just at sign-in. */
    public function testDeactivatingAUserInvalidatesTheirLiveSession(): void
    {
        $user = $this->user();
        $this->publicClient();
        $this->submitLogin();
        self::assertNotNull($this->cookie(self::SESSION_COOKIE));

        $this->deactivate($user);
        [, $challenge] = $this->makePkcePair();
        $response = $this->get('/oauth2/authorize', $this->authorizeParams($challenge));

        // Treated as "not signed in" rather than authorizing on a dead account.
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        self::assertStringStartsWith('/auth/login?', $response->getHeaderLine('Location'));
    }

    public function testAHostileEmailIsEscapedWhenTheFormIsShownAgain(): void
    {
        $this->user();

        $response = $this->submitLogin(email: '"><script>alert(1)</script>', password: 'x');

        $body = (string) $response->getBody();
        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $response->getStatusCode());
        self::assertStringNotContainsString('<script>', $body);
        self::assertStringContainsString(
            'value="&quot;&gt;&lt;script&gt;alert&#x28;1&#x29;&lt;&#x2F;script&gt;"',
            $body,
        );
    }

    // ------------------------------------------------------------------
    // CSRF and session fixation
    // ------------------------------------------------------------------

    public function testLoginWithoutCsrfTokenIsRejected(): void
    {
        $this->user();

        $response = $this->post(
            '/auth/login',
            ['email' => self::TEST_USER_EMAIL, 'password' => self::TEST_USER_PASSWORD],
        );

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertStringContainsString('Your session expired. Please try again.', (string) $response->getBody());
        self::assertNull($this->cookie(self::SESSION_COOKIE));
    }

    public function testLoginWithMismatchedCsrfTokenIsRejected(): void
    {
        $this->user();

        $response = $this->submitLogin(csrfToken: 'not-the-token-in-the-cookie');

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertNull($this->cookie(self::SESSION_COOKIE));
    }

    public function testALoginPostThatIsNotAFormIsRejected(): void
    {
        $this->user();
        $token = self::csrfTokenFrom($this->get('/auth/login'));

        $response = $this->request(
            'POST',
            '/auth/login',
            ['Content-Type' => 'application/json'],
            body: (string) json_encode([
                'email' => self::TEST_USER_EMAIL,
                'password' => self::TEST_USER_PASSWORD,
                'csrf_token' => $token,
            ]),
        );

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertNull($this->cookie(self::SESSION_COOKIE));
    }

    /**
     * Session fixation: an identifier the browser already holds must not survive
     * authentication — whoever planted it must not end up holding a valid session.
     */
    public function testLoginRotatesTheSessionIdentifier(): void
    {
        $this->user();
        $this->submitLogin();
        $first = $this->cookie(self::SESSION_COOKIE);
        self::assertNotNull($this->session($first));

        // Signing in again while presenting the first cookie — through an authorization
        // request, the only reason a signed-in browser is shown the form at all.
        $this->submitLogin(nextUrl: '/oauth2/authorize?x=y');
        $second = $this->cookie(self::SESSION_COOKIE);

        self::assertNotNull($first);
        self::assertNotNull($second);
        self::assertNotSame($first, $second);
        self::assertNull($this->session($first));
        self::assertNotNull($this->session($second));
    }

    public function testAPlantedSessionIdentifierIsNotAdopted(): void
    {
        $this->user();
        $this->setCookie(self::SESSION_COOKIE, 'chosen-by-the-attacker');

        $this->submitLogin();

        self::assertNotSame('chosen-by-the-attacker', $this->cookie(self::SESSION_COOKIE));
        self::assertNull($this->session('chosen-by-the-attacker'));
    }

    // ------------------------------------------------------------------
    // Session lifetimes
    // ------------------------------------------------------------------

    /** The absolute ceiling is not extended by activity. */
    public function testSessionPastItsAbsoluteLifetimeIsGoneEvenIfUsed(): void
    {
        $clock = $this->freezeClock();
        $this->user();
        $this->submitLogin();
        $sessionId = $this->cookie(self::SESSION_COOKIE);

        // Used every six hours for a week — never idle long enough to expire that way.
        for ($use = 1; $use < 28; $use++) {
            $clock->advance(6 * 3600);
            self::assertNotNull($this->session($sessionId), sprintf('use %d', $use));
        }

        // Exactly seven days after signing in.
        $clock->advance(6 * 3600);

        self::assertNull($this->session($sessionId));
    }

    /** Storage holds a session for the idle window, and each use starts the window over. */
    public function testASessionLivesForTheIdleWindowAndEachUseRenewsIt(): void
    {
        $this->user();
        $this->submitLogin();
        $sessionId = (string) $this->cookie(self::SESSION_COOKIE);
        $key = 'session:' . hash('sha256', $sessionId);

        self::assertGreaterThan(28800 - 5, TestStorage::redis()->ttl($key));

        TestStorage::redis()->expire($key, 60);
        $this->get('/auth/login');

        self::assertGreaterThan(28800 - 5, TestStorage::redis()->ttl($key));
    }

    // ------------------------------------------------------------------
    // Open redirect
    // ------------------------------------------------------------------

    /** The target after sign-in is re-validated even though it comes from our own store. */
    public function testNextCannotSendTheUserOffSite(): void
    {
        $this->user();

        foreach (
            [
                'https://evil.test/steal',
                '//evil.test',
                '/\\evil.test',
                'javascript:alert(1)',
                "/ok\r\nLocation: https://evil.test",
            ] as $hostile
        ) {
            $response = $this->submitLogin(nextUrl: $hostile);

            self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
            $location = $response->getHeaderLine('Location');
            self::assertStringNotContainsString('evil.test', $location);
            self::assertStringStartsNotWith('javascript:', $location);
            $this->post('/auth/logout');
        }
    }

    public function testNextPreservesALocalTarget(): void
    {
        $this->user();

        $response = $this->submitLogin(nextUrl: '/oauth2/authorize?response_type=code');

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        self::assertSame('/oauth2/authorize?response_type=code', $response->getHeaderLine('Location'));
    }

    /** The handle is forgotten once a sign-in succeeds, like a spent code. */
    public function testLoginStateIsSingleUse(): void
    {
        $this->user();
        $state = $this->storeLoginState('/oauth2/authorize?response_type=code');

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $this->submitLogin(state: $state)->getStatusCode());
        self::assertNull($this->loginState($state));
    }

    /**
     * A wrong password re-renders the form with the same handle, so the person is not
     * sent back to the application to start over.
     */
    public function testFailedLoginKeepsTheLoginState(): void
    {
        $this->user();
        $state = $this->storeLoginState('/oauth2/authorize?response_type=code');

        $response = $this->submitLogin(password: 'wrong', state: $state);

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $response->getStatusCode());
        self::assertStringContainsString(sprintf('name="state" value="%s"', $state), (string) $response->getBody());
        self::assertNotNull($this->loginState($state));
    }

    // ------------------------------------------------------------------
    // Throttling
    // ------------------------------------------------------------------

    public function testRepeatedFailuresLockTheAccountOut(): void
    {
        $this->boot(['CLAVIA_LOGIN_MAX_ATTEMPTS' => '3']);
        $this->user();

        for ($attempt = 0; $attempt < 3; $attempt++) {
            self::assertSame(
                StatusCodeInterface::STATUS_UNAUTHORIZED,
                $this->submitLogin(password: 'wrong')->getStatusCode(),
            );
        }

        // The correct password is refused too: the endpoint has stopped answering rather
        // than remaining an unlimited password oracle.
        $response = $this->submitLogin();
        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $response->getStatusCode());
        self::assertStringContainsString('Incorrect email or password.', (string) $response->getBody());
        self::assertNull($this->cookie(self::SESSION_COOKIE));
    }

    public function testSuccessfulLoginClearsTheFailureCounter(): void
    {
        $this->boot(['CLAVIA_LOGIN_MAX_ATTEMPTS' => '3']);
        $this->user();

        self::assertSame(
            StatusCodeInterface::STATUS_UNAUTHORIZED,
            $this->submitLogin(password: 'wrong')->getStatusCode(),
        );
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $this->submitLogin()->getStatusCode());
        $this->post('/auth/logout');

        // Two more failures would have tripped the limit had the counter survived.
        self::assertSame(
            StatusCodeInterface::STATUS_UNAUTHORIZED,
            $this->submitLogin(password: 'wrong')->getStatusCode(),
        );
        self::assertSame(
            StatusCodeInterface::STATUS_UNAUTHORIZED,
            $this->submitLogin(password: 'wrong')->getStatusCode(),
        );
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $this->submitLogin()->getStatusCode());
    }

    public function testTheFailureCountersHoldNeitherAnEmailNorAnAddress(): void
    {
        $this->user();
        $this->submitLogin(password: 'wrong');

        $keys = TestStorage::redis()->keys('login-attempts:*');

        self::assertIsArray($keys);
        self::assertCount(2, $keys);
        self::assertStringNotContainsString('clavia.dev', implode('|', $keys));
        self::assertStringNotContainsString('203.0.113.7', implode('|', $keys));
    }

    // ------------------------------------------------------------------
    // The whole journey
    // ------------------------------------------------------------------

    public function testUnauthenticatedAuthorizeRedirectsToLogin(): void
    {
        $this->user();
        $this->publicClient();
        [, $challenge] = $this->makePkcePair();

        $response = $this->get('/oauth2/authorize', $this->authorizeParams($challenge));

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        $location = $response->getHeaderLine('Location');
        self::assertStringStartsWith('/auth/login?', $location);
        // The authorization request itself is kept server-side: only an opaque handle
        // travels through the URL.
        self::assertStringNotContainsString('code_challenge', $location);
        self::assertStringNotContainsString('client_id', $location);

        $pending = $this->loginState(self::locationQuery($response)['state']);
        self::assertNotNull($pending);
        self::assertStringStartsWith('/oauth2/authorize?', $pending->nextUrl);
        self::assertStringContainsString('code_challenge', $pending->nextUrl);
    }

    /** An unknown client is refused outright, not used to lure a sign-in. */
    public function testInvalidAuthorizeRequestNeverReachesTheLoginPage(): void
    {
        $this->user();
        $this->publicClient();
        [, $challenge] = $this->makePkcePair();

        $response = $this->get(
            '/oauth2/authorize',
            $this->authorizeParams($challenge, ['client_id' => 'no-such-client']),
        );

        self::assertStringNotContainsString('/auth/login', $response->getHeaderLine('Location'));
    }

    /** Sign in at the login page, come back, and complete the PKCE exchange. */
    public function testLoginThenAuthorizeThenToken(): void
    {
        $this->user();
        $this->publicClient();
        [$verifier, $challenge] = $this->makePkcePair();

        // 1. No session: the authorization endpoint sends the browser to sign in.
        $first = $this->get('/oauth2/authorize', $this->authorizeParams($challenge));
        $state = self::locationQuery($first)['state'];
        $nextUrl = $this->loginState($state)?->nextUrl;
        self::assertNotNull($nextUrl);

        // 2. Sign in with the handle the page's hidden field carries: back to the request.
        $login = $this->submitLogin(state: $state);
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $login->getStatusCode());
        self::assertSame($nextUrl, $login->getHeaderLine('Location'));

        // 3. Follow it, now carrying the session cookie: a code is issued.
        $code = $this->extractCode($this->request('GET', $nextUrl));

        // 4. Exchange it.
        $token = $this->post('/oauth2/token', $this->tokenRequest($code, $verifier));

        self::assertSame(StatusCodeInterface::STATUS_OK, $token->getStatusCode(), (string) $token->getBody());
        self::assertIsString(self::json($token)['access_token']);
    }

    /**
     * A prefetch, a second tab or the back button must not invalidate an open form: the
     * token is the browser's, and a second render reuses it.
     */
    public function testCsrfTokenSurvivesASecondPageLoad(): void
    {
        $this->user();
        $first = $this->get('/auth/login');
        $second = $this->get('/auth/login');
        self::assertSame(self::csrfTokenFrom($first), self::csrfTokenFrom($second));

        $response = $this->post('/auth/login', [
            'csrf_token' => self::csrfTokenFrom($first),
            'email' => self::TEST_USER_EMAIL,
            'password' => self::TEST_USER_PASSWORD,
        ]);

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
    }

    /**
     * Two `clavia_csrf` cookies — the current one and a stale one at another path — both
     * reach the server; the form's token may match either, and the stale one is cleared.
     */
    public function testAStaleSecondCsrfCookieDoesNotLockThePersonOut(): void
    {
        $this->user();
        $current = self::csrfTokenFrom($this->get('/auth/login'));
        $both = sprintf('clavia_csrf=%s; clavia_csrf=stale-from-another-path', $current);

        $response = $this->post(
            '/auth/login',
            ['csrf_token' => $current, 'email' => self::TEST_USER_EMAIL, 'password' => self::TEST_USER_PASSWORD],
            headers: ['Cookie' => $both],
        );
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());

        // A render that sees both keeps the current one and clears the other.
        $rendered = $this->request('GET', '/auth/login', ['Cookie' => $both]);
        self::assertSame($current, self::csrfTokenFrom($rendered));
        $deletions = array_filter(
            self::setCookieHeaders($rendered, 'clavia_csrf'),
            static fn (string $header): bool => str_contains($header, 'Max-Age=0') && str_contains($header, 'Path=/;'),
        );
        self::assertNotSame([], $deletions, implode("\n", $rendered->getHeader('Set-Cookie')));
    }

    /**
     * The handle can expire while the tab sits open; a correct password must still end
     * somewhere legible — signed in, and told to go back to the application.
     */
    public function testSigningInWithAnExpiredStateLandsSomewhereThatSaysSo(): void
    {
        $this->user();

        $response = $this->submitLogin(state: 'expired-or-forged');
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        self::assertSame('/auth/login', $response->getHeaderLine('Location'));

        $landing = $this->get('/auth/login');
        $body = (string) $landing->getBody();
        self::assertSame(StatusCodeInterface::STATUS_OK, $landing->getStatusCode());
        self::assertStringContainsString('You are signed in', $body);
        self::assertStringContainsString(self::TEST_USER_EMAIL, $body);
        self::assertStringNotContainsString('name="password"', $body);
    }

    /** With a `state`, the page is part of a flow: show the form as asked. */
    public function testASignedInVisitorWithAnAuthorizationRequestStillGetsTheForm(): void
    {
        $this->user();
        $this->publicClient();
        $this->submitLogin();
        $state = $this->storeLoginState('/oauth2/authorize?x=y', self::TEST_CLIENT_ID);

        $page = $this->get('/auth/login', ['state' => $state]);

        self::assertStringContainsString('name="password"', (string) $page->getBody());
    }

    /**
     * Chromium applies `form-action` to a submission's whole redirect chain, and a
     * successful sign-in ends at the application's redirect URI. The page for an
     * authorization request therefore names that origin; a page for none does not.
     */
    public function testLoginPageLetsASubmitEndAtTheApplication(): void
    {
        $this->publicClient();
        [, $challenge] = $this->makePkcePair();
        $state = self::locationQuery($this->get('/oauth2/authorize', $this->authorizeParams($challenge)))['state'];

        $withApplication = $this->get('/auth/login', ['state' => $state]);
        self::assertStringContainsString(
            "form-action 'self' https://client.test;",
            $withApplication->getHeaderLine('Content-Security-Policy'),
        );

        $without = $this->get('/auth/login');
        self::assertStringContainsString("form-action 'self';", $without->getHeaderLine('Content-Security-Policy'));
    }

    public function testAFailedSubmitKeepsTheApplicationOriginInThePolicy(): void
    {
        $this->user();
        $this->publicClient();
        $state = $this->storeLoginState('/oauth2/authorize?x=y', self::TEST_CLIENT_ID);

        $response = $this->submitLogin(password: 'wrong', state: $state);

        self::assertStringContainsString(
            "form-action 'self' https://client.test;",
            $response->getHeaderLine('Content-Security-Policy'),
        );
    }

    private function deactivate(User $user): void
    {
        /** @var UserRepository $users */
        $users = $this->container()->get(UserRepository::class);
        $user->deactivate(new DateTimeImmutable());
        $users->save($user);
    }
}
