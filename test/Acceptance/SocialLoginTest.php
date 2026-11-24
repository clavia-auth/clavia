<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Secondary\IdentityProvider\GitHubIdentityProvider;
use Clavia\Adapter\Secondary\IdentityProvider\GoogleIdentityProvider;
use Clavia\Application\Authentication\Mfa\TotpSeeds;
use Clavia\Domain\Authentication\Mfa\MfaFactor;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Mfa\Totp;
use Clavia\Domain\Authentication\Mfa\TotpSecret;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\RandomSource;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\FakeHttpClient;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\OidcFixtures;
use ClaviaTest\Support\TestStorage;
use Fig\Http\Message\StatusCodeInterface;
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Signing in through an external provider, end to end — Clavia as an OAuth 2.0 client.
 *
 * The real Google and GitHub adapters run against a fake wire ({@see FakeHttpClient}):
 * what the provider says about the person is each test's input, and what Clavia does
 * with it is the subject. Nothing here talks to Google or GitHub.
 */
final class SocialLoginTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use OidcFixtures;

    private const string SESSION_COOKIE = 'clavia_session';
    private const string STATE_COOKIE = 'clavia_external_state';
    private const string CALLBACK = 'https://auth.clavia.test/auth/social/google/callback';

    private FakeHttpClient $wire;

    /** What the fake Google's userinfo answers. @var array<string, mixed> */
    private array $claims = ['sub' => 'g-123', 'email' => 'ada@clavia.dev', 'email_verified' => true];

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->wire = new FakeHttpClient($this->google(...));
    }

    // ------------------------------------------------------------------
    // Starting
    // ------------------------------------------------------------------

    public function testAnUnconfiguredProviderIsA404LikeAnUnknownOne(): void
    {
        $this->bootWithProviders([]);

        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $this->get('/auth/social/google')->getStatusCode());
        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $this->get('/auth/social/nope')->getStatusCode());
        self::assertSame(
            StatusCodeInterface::STATUS_NOT_FOUND,
            $this->get('/auth/social/google/callback', ['code' => 'c', 'state' => 's'])->getStatusCode(),
        );
        self::assertStringNotContainsString('Continue with', (string) $this->get('/auth/login')->getBody());
    }

    public function testTheLoginPageOffersEachConfiguredProvider(): void
    {
        $this->bootWithProviders(['google', 'github']);

        $page = html_entity_decode((string) $this->get('/auth/login')->getBody());

        self::assertStringContainsString('href="/auth/social/google"', $page);
        self::assertStringContainsString('Continue with Google', $page);
        self::assertStringContainsString('Continue with GitHub', $page);
        // By connection name.
        self::assertLessThan(strpos($page, 'Continue with Google'), strpos($page, 'Continue with GitHub'));
    }

    public function testStartingSendsStatePkceAndAPairingCookie(): void
    {
        $this->bootWithProviders(['google']);

        $response = $this->get('/auth/social/google');

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        $location = $response->getHeaderLine('Location');
        self::assertStringStartsWith(GoogleIdentityProvider::AUTHORIZATION_ENDPOINT . '?', $location);
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);
        self::assertSame('google-client', $query['client_id']);
        self::assertSame(self::CALLBACK, $query['redirect_uri']);
        self::assertSame('S256', $query['code_challenge_method']);
        self::assertIsString($query['code_challenge']);
        self::assertSame($query['state'], $this->cookie(self::STATE_COOKIE));
        $cookie = (string) self::setCookieHeader($response, self::STATE_COOKIE);
        self::assertStringContainsString('HttpOnly', $cookie);
        self::assertStringContainsString('Path=/auth', $cookie);
        self::assertStringContainsString('SameSite=Lax', $cookie);
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
    }

    // ------------------------------------------------------------------
    // Completing
    // ------------------------------------------------------------------

    public function testAFirstSignInCreatesAVerifiedPasswordLessAccount(): void
    {
        $this->bootWithProviders(['google']);

        $response = $this->finish($this->start());

        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $response->getStatusCode(),
            (string) $response->getBody(),
        );
        self::assertSame('/auth/login', $response->getHeaderLine('Location'));
        $session = $this->session($this->cookie(self::SESSION_COOKIE));
        self::assertNotNull($session);
        self::assertSame(['ext'], array_map(static fn ($method): string => $method->value, $session->methods));
        $user = $this->users()->find($session->userId);
        self::assertNotNull($user);
        self::assertSame('ada@clavia.dev', $user->email);
        self::assertTrue($user->isEmailVerified());
        self::assertNull($user->passwordHash());
        self::assertSame('google', $user->connection->value, 'The account belongs to the connection that made it.');
        self::assertSame('google', $session->connection->value);
        self::assertSame([['google', 'g-123']], $this->identities());
        // The code was exchanged server side, with the secret and the PKCE verifier.
        $exchange = FakeHttpClient::form($this->wire->requests[0]);
        self::assertSame('google-secret', $exchange['client_secret']);
        self::assertSame('provider-code', $exchange['code']);
        self::assertSame(self::CALLBACK, $exchange['redirect_uri']);
        self::assertNotSame('', $exchange['code_verifier']);
        self::assertNull($this->cookie(self::STATE_COOKIE));
    }

    public function testTheIdentityIsMatchedBySubjectNotByEmail(): void
    {
        $this->bootWithProviders(['google']);
        $this->finish($this->start());
        $first = $this->session($this->cookie(self::SESSION_COOKIE))?->userId;
        $this->post('/auth/logout');

        // Same subject, a new address at the provider: the same account, its address untouched.
        $this->claims['email'] = 'ada.new@clavia.dev';
        $this->finish($this->start());

        $again = $this->session($this->cookie(self::SESSION_COOKIE))?->userId;
        self::assertNotNull($first);
        self::assertTrue($again?->equals($first));
        self::assertSame('ada@clavia.dev', $this->users()->find($first)?->email);
        self::assertCount(1, $this->identities());
    }

    public function testASecondSubjectWithTheSameVerifiedAddressJoinsTheAccount(): void
    {
        $this->bootWithProviders(['google']);
        $this->finish($this->start());
        $first = $this->session($this->cookie(self::SESSION_COOKIE))?->userId;
        $this->post('/auth/logout');

        $this->claims['sub'] = 'g-999';
        $this->finish($this->start());

        self::assertNotNull($first);
        self::assertTrue($this->session($this->cookie(self::SESSION_COOKIE))?->userId->equals($first));
        self::assertSame([['google', 'g-123'], ['google', 'g-999']], $this->identities());
    }

    public function testAVerifiedAddressLinksToTheExistingLocalAccount(): void
    {
        $this->bootWithProviders(['google']);
        $user = $this->user();
        $this->claims['email'] = strtoupper(self::TEST_USER_EMAIL);

        $this->finish($this->start());

        self::assertTrue($this->session($this->cookie(self::SESSION_COOKIE))?->userId->equals($user->id));
        self::assertTrue($this->users()->find($user->id)?->isEmailVerified());
        $this->post('/auth/logout');
        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $this->submitLogin()->getStatusCode(),
            'The password still works alongside.',
        );
    }

    public function testAnUnverifiedAddressLinksNothingAndCreatesNothing(): void
    {
        $this->bootWithProviders(['google']);
        $this->user();
        $this->claims = ['sub' => 'g-123', 'email' => self::TEST_USER_EMAIL, 'email_verified' => false];

        $response = $this->finish($this->start());

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertStringContainsString('no verified email', (string) $response->getBody());
        self::assertNull($this->cookie(self::SESSION_COOKIE));
        self::assertSame([], $this->identities());
        self::assertSame(1, TestStorage::database()->fetchValue('SELECT count(*) FROM users'), 'Nothing squatted.');
    }

    public function testLinkingByAddressCanBeSwitchedOff(): void
    {
        $this->bootWithProviders(['google'], ['CLAVIA_SOCIAL_AUTO_LINK' => 'false']);
        $this->user();
        $this->claims['email'] = self::TEST_USER_EMAIL;

        $response = $this->finish($this->start());

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertStringContainsString('Sign in with your password', (string) $response->getBody());
        self::assertNull($this->cookie(self::SESSION_COOKIE));
    }

    // ------------------------------------------------------------------
    // What the callback refuses
    // ------------------------------------------------------------------

    public function testACallbackWithoutThePairingCookieIsRefused(): void
    {
        // Login CSRF: an attacker starts a sign-in, then makes the victim's browser finish it.
        $this->bootWithProviders(['google']);
        $state = $this->start();
        $this->clearCookies();

        $response = $this->finish($state);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertStringContainsString('did not start in this browser', (string) $response->getBody());
        self::assertNull($this->cookie(self::SESSION_COOKIE));
        self::assertSame([], $this->wire->requests, 'Nothing was exchanged.');
    }

    public function testTheStateIsSingleUse(): void
    {
        $this->bootWithProviders(['google']);
        $state = $this->start();
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $this->finish($state)->getStatusCode());
        $this->post('/auth/logout');
        $this->setCookie(self::STATE_COOKIE, $state, '/auth');

        $replay = $this->finish($state);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $replay->getStatusCode());
        self::assertStringContainsString('expired', (string) $replay->getBody());
    }

    public function testTheProvidersErrorIsNotEchoed(): void
    {
        $this->bootWithProviders(['google']);
        $state = $this->start();

        $response = $this->get('/auth/social/google/callback', [
            'error' => '<img src=x onerror=alert(1)>',
            'error_description' => 'Click here: https://evil.example',
            'state' => $state,
        ]);

        $body = (string) $response->getBody();
        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertStringNotContainsString('onerror', $body);
        self::assertStringNotContainsString('evil.example', $body);
        self::assertStringContainsString('Sign-in with Google was cancelled or failed.', $body);
        // The page is the login page as if reached directly: nothing points back here.
        self::assertStringNotContainsString('/auth/social/google/callback', $body);
        self::assertNull($this->cookie(self::STATE_COOKIE));
    }

    public function testAFailedExchangeIsReportedGenericallyAndLogged(): void
    {
        $this->bootWithProviders(['google']);
        $this->wire->answerWith(
            static fn (): ResponseInterface => new JsonResponse(
                ['error' => 'server_error'],
                StatusCodeInterface::STATUS_INTERNAL_SERVER_ERROR,
            ),
        );

        $response = $this->finish($this->start());

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertStringContainsString('Could not complete sign-in with Google.', (string) $response->getBody());
        self::assertTrue($this->logger->hasRecordContaining('answered 500'));
    }

    // ------------------------------------------------------------------
    // With the rest of the sign-in
    // ------------------------------------------------------------------

    public function testTheSignInReturnsToTheAuthorizationRequest(): void
    {
        $this->bootWithProviders(['google']);
        $this->publicClient();
        [, $challenge] = $this->makePkcePair();
        $authorize = $this->get('/oauth2/authorize', $this->authorizeParams($challenge));
        $loginHandle = self::locationQuery($authorize)['state'] ?? null;
        self::assertIsString($loginHandle);
        self::assertStringContainsString(
            'href="/auth/social/google?state=' . $loginHandle . '"',
            html_entity_decode((string) $this->get('/auth/login', ['state' => $loginHandle])->getBody()),
        );

        $response = $this->finish($this->start($loginHandle));

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        self::assertStringStartsWith('/oauth2/authorize?', $response->getHeaderLine('Location'));
        self::assertStringContainsString('code_challenge', $response->getHeaderLine('Location'));
        self::assertNull($this->loginState($loginHandle), 'The login page handle is spent.');
    }

    public function testTheSignInStillAsksForAConfirmedSecondFactor(): void
    {
        $this->bootWithProviders(['google']);
        $user = $this->user();
        $this->confirmSecondFactor($user);
        $this->claims['email'] = self::TEST_USER_EMAIL;

        $response = $this->finish($this->start());

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        self::assertSame('/auth/mfa', $response->getHeaderLine('Location'));
        self::assertNotNull($this->cookie('clavia_mfa'));
        self::assertNull($this->cookie(self::SESSION_COOKIE));
    }

    public function testTheIdTokenReportsAnExternalSignIn(): void
    {
        $this->bootWithProviders(['google']);
        $this->publicClient();
        $this->finish($this->start());

        $token = $this->completeFlow('openid');

        self::assertSame(['ext'], $this->verifiedIdToken($token['id_token'] ?? null)['claims']['amr'] ?? null);
    }

    public function testAPasswordSignInStillReportsPwd(): void
    {
        $this->bootWithProviders(['google']);
        $this->publicClient();
        $this->user();
        $this->submitLogin();

        $token = $this->completeFlow('openid');

        self::assertSame(['pwd'], $this->verifiedIdToken($token['id_token'] ?? null)['claims']['amr'] ?? null);
    }

    public function testGitHubSignsInWithThePrimaryVerifiedAddress(): void
    {
        $this->bootWithProviders(['github']);
        $this->wire->answerWith(FakeHttpClient::routes([
            GitHubIdentityProvider::TOKEN_ENDPOINT => new JsonResponse(['access_token' => 'gh-token']),
            GitHubIdentityProvider::USER_ENDPOINT => new JsonResponse(['id' => 4242, 'email' => null]),
            GitHubIdentityProvider::EMAILS_ENDPOINT => new JsonResponse([
                ['email' => 'old@clavia.dev', 'primary' => false, 'verified' => true],
                ['email' => 'me@clavia.dev', 'primary' => true, 'verified' => true],
            ]),
        ]));
        $start = $this->get('/auth/social/github');
        parse_str((string) parse_url($start->getHeaderLine('Location'), PHP_URL_QUERY), $query);
        $state = $query['state'] ?? null;
        self::assertIsString($state);

        $response = $this->get('/auth/social/github/callback', ['code' => 'c', 'state' => $state]);

        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $response->getStatusCode(),
            (string) $response->getBody(),
        );
        self::assertSame([['github', '4242']], $this->identities());
        self::assertNotNull($this->users()->findByEmail(ConnectionName::fromString('github'), 'me@clavia.dev'));
    }

    // ------------------------------------------------------------------

    /**
     * @param list<'google'|'github'> $providers
     * @param array<string, string>   $environment
     */
    private function bootWithProviders(array $providers, array $environment = []): void
    {
        foreach ($providers as $provider) {
            $prefix = 'CLAVIA_' . strtoupper($provider);
            $environment[$prefix . '_CLIENT_ID'] = $provider . '-client';
            $environment[$prefix . '_CLIENT_SECRET'] = $provider . '-secret';
        }
        $this->boot($environment);
        $this->container()->setService(ClientInterface::class, $this->wire);
    }

    /** Begin a Google sign-in and return the `state` the provider would echo. */
    private function start(?string $loginHandle = null): string
    {
        $response = $this->get('/auth/social/google', $loginHandle === null ? [] : ['state' => $loginHandle]);
        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $response->getStatusCode(),
            (string) $response->getBody(),
        );
        parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $query);
        $state = $query['state'] ?? null;
        self::assertIsString($state);

        return $state;
    }

    private function finish(string $state, string $code = 'provider-code'): ResponseInterface
    {
        return $this->get('/auth/social/google/callback', ['code' => $code, 'state' => $state]);
    }

    /** Google's token and userinfo endpoints, answering with {@see self::$claims}. */
    private function google(RequestInterface $request): ResponseInterface
    {
        $authorised = $request->getHeaderLine('Authorization') === 'Bearer provider-token';

        return FakeHttpClient::routes([
            GoogleIdentityProvider::TOKEN_ENDPOINT => new JsonResponse(['access_token' => 'provider-token']),
            GoogleIdentityProvider::USERINFO_ENDPOINT => $authorised
                ? new JsonResponse($this->claims)
                : new JsonResponse([], StatusCodeInterface::STATUS_UNAUTHORIZED),
        ])($request);
    }

    private function users(): UserRepository
    {
        return $this->container()->get(UserRepository::class);
    }

    /** @return list<array{string, string}> Every linked `(provider, subject)`, in order. */
    private function identities(): array
    {
        /** @var list<array{provider: string, subject: string}> $rows */
        $rows = TestStorage::database()->fetchAll(
            'SELECT provider, subject FROM external_identities ORDER BY provider, subject',
        );

        return array_map(static fn (array $row): array => [$row['provider'], $row['subject']], $rows);
    }

    private function confirmSecondFactor(User $user): void
    {
        /** @var TotpSeeds $seeds */
        $seeds = $this->container()->get(TotpSeeds::class);
        /** @var RandomSource $random */
        $random = $this->container()->get(RandomSource::class);
        $secret = TotpSecret::generate($random);
        $now = new \DateTimeImmutable();
        $factor = MfaFactor::stage($user->id, $seeds->seal($user->id, $secret), $now);
        self::assertTrue($factor->accept($secret, Totp::codeAt($secret, $now), $now));
        $factor->confirm($now);
        $this->container()->get(MfaFactorRepository::class)->save($factor);
    }
}
