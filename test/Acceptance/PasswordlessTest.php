<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Application\Authentication\Mfa\TotpSeeds;
use Clavia\Application\Port\Mailer;
use Clavia\Application\Port\MailOutbox;
use Clavia\Application\Port\OutgoingMail;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\LocalPath;
use Clavia\Domain\Authentication\Mfa\MfaFactor;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Mfa\Totp;
use Clavia\Domain\Authentication\Mfa\TotpSecret;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\RecordingMailer;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\OidcFixtures;
use Psr\Http\Message\ResponseInterface;

/**
 * Passwordless sign-in — a one-time code or a sign-in link sent by email — ported from the
 * Python suite's `test_passwordless.py`.
 *
 * The test environment's mail backend is the console one: every message lands in the
 * development outbox, where each test reads the code or the link as a person would read
 * their email.
 */
final class PasswordlessTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use OidcFixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string EMAIL = 'ada@clavia.dev';
    private const string SESSION_COOKIE = 'clavia_session';
    private const string CODE_COOKIE = 'clavia_passwordless';

    // ── What the login page offers ──────────────────────────────────────────────

    public function testTheLoginPageOffersACodeAndALink(): void
    {
        $page = (string) $this->get('/auth/login')->getBody();

        self::assertStringContainsString('action="/auth/passwordless/start"', $page);
        self::assertStringContainsString('Email me a code', $page);
        self::assertStringContainsString('Email me a sign-in link', $page);
        self::assertStringContainsString('id="passwordless-email"', $page, 'Not the password form\'s field id.');
    }

    public function testNotOfferedWhenTheServerCannotSendEmail(): void
    {
        $this->boot(['CLAVIA_EMAIL_BACKEND' => 'none']);

        self::assertStringNotContainsString('Email me a code', (string) $this->get('/auth/login')->getBody());
        $refused = $this->start();
        self::assertSame(400, $refused->getStatusCode());
        self::assertStringContainsString('not available for this application', (string) $refused->getBody());
    }

    public function testNotOfferedToAnApplicationThatDisablesIt(): void
    {
        $this->publicClient();
        $this->restrictTo(ConnectionName::DEFAULT_POOL);
        $state = $this->loginStateForTheClient();

        self::assertStringNotContainsString(
            'Email me a code',
            (string) $this->get('/auth/login', ['state' => $state])->getBody(),
        );
        $refused = $this->start(state: $state);
        self::assertSame(400, $refused->getStatusCode());
        self::assertStringContainsString('not available for this application', (string) $refused->getBody());
        self::assertSame([], $this->outbox()->recent(10), 'Refused, not merely hidden: nothing was sent.');
    }

    // ── A code ──────────────────────────────────────────────────────────────────

    public function testACodeSignsInAndCreatesTheAccount(): void
    {
        $started = $this->start();

        self::assertSame(303, $started->getStatusCode(), (string) $started->getBody());
        self::assertSame('/auth/passwordless/code', $started->getHeaderLine('Location'));
        self::assertNotNull($this->cookie(self::CODE_COOKIE, '/auth'));
        $page = $this->get('/auth/passwordless/code');
        self::assertSame(200, $page->getStatusCode());
        self::assertStringContainsString('Check your email', (string) $page->getBody());
        self::assertStringContainsString(self::EMAIL, (string) $page->getBody());
        $mail = $this->lastMail();
        self::assertSame(self::EMAIL, $mail->to);
        self::assertStringContainsString('sign-in code', $mail->subject);

        $signedIn = $this->submitCode(self::codeIn($mail));

        self::assertSame(303, $signedIn->getStatusCode(), (string) $signedIn->getBody());
        // Nothing to return to: the login page, which says who is signed in.
        self::assertSame(LocalPath::DEFAULT, $signedIn->getHeaderLine('Location'));
        $account = $this->users()->findByEmail(ConnectionName::email(), self::EMAIL);
        self::assertNotNull($account);
        self::assertNull($account->passwordHash());
        self::assertTrue($account->isEmailVerified());
        $session = $this->session($this->cookie(self::SESSION_COOKIE));
        self::assertNotNull($session);
        self::assertTrue($session->userId->equals($account->id));
        self::assertSame('email', $session->connection->value);
        self::assertSame([AuthenticationMethod::OneTimePassword], $session->methods);
        self::assertNull($this->cookie(self::CODE_COOKIE, '/auth'), 'The challenge cookie is cleared.');
    }

    public function testASecondSignInReusesTheAccount(): void
    {
        $this->start();
        $this->submitCode(self::codeIn($this->lastMail()));
        $first = $this->users()->findByEmail(ConnectionName::email(), self::EMAIL);
        $this->clearCookies();

        $this->start(strtoupper(self::EMAIL));
        $this->submitCode(self::codeIn($this->lastMail()));

        self::assertNotNull($first);
        self::assertTrue($this->session($this->cookie(self::SESSION_COOKIE))?->userId->equals($first->id));
        self::assertSame(1, $this->users()->countIn(ConnectionName::email()));
    }

    public function testTypedCodesTolerateSpaces(): void
    {
        $this->start();
        $code = self::codeIn($this->lastMail());

        $signedIn = $this->submitCode(' ' . substr($code, 0, 3) . ' ' . substr($code, 3) . ' ');

        self::assertSame(303, $signedIn->getStatusCode());
        self::assertNotNull($this->cookie(self::SESSION_COOKIE));
    }

    public function testAWrongCodeIsRefusedAndABudgetEndsTheChallenge(): void
    {
        $this->boot(['CLAVIA_PASSWORDLESS_MAX_ATTEMPTS' => '3']);
        $this->start();
        $code = self::codeIn($this->lastMail());
        $wrong = $code === '000000' ? '111111' : '000000';

        foreach ([1, 2] as $attempt) {
            $refused = $this->submitCode($wrong);
            self::assertSame(401, $refused->getStatusCode(), 'attempt ' . $attempt);
            self::assertStringContainsString('not valid', (string) $refused->getBody());
        }
        $ended = $this->submitCode($wrong);
        self::assertSame(303, $ended->getStatusCode());
        self::assertSame('/auth/login', $ended->getHeaderLine('Location'));

        $dead = $this->submitCode($code);
        self::assertSame(303, $dead->getStatusCode());
        self::assertSame('/auth/login', $dead->getHeaderLine('Location'));
        self::assertNull($this->cookie(self::SESSION_COOKIE));
    }

    public function testACodeOnlyWorksInTheBrowserThatAsked(): void
    {
        $this->start();
        $code = self::codeIn($this->lastMail());
        $handle = $this->cookie(self::CODE_COOKIE, '/auth');
        self::assertNotNull($handle);

        $this->clearCookies();
        $elsewhere = $this->submitCode($code);

        self::assertSame(303, $elsewhere->getStatusCode());
        self::assertSame('/auth/login', $elsewhere->getHeaderLine('Location'));
        self::assertNull($this->cookie(self::SESSION_COOKIE));

        $this->setCookie(self::CODE_COOKIE, $handle, '/auth');
        self::assertSame(303, $this->submitCode($code)->getStatusCode());
        self::assertNotNull($this->cookie(self::SESSION_COOKIE), 'Still alive where it was asked.');
    }

    public function testACodeIsSingleUse(): void
    {
        $this->start();
        $code = self::codeIn($this->lastMail());
        $handle = $this->cookie(self::CODE_COOKIE, '/auth');
        self::assertNotNull($handle);
        $this->submitCode($code);
        self::assertNotNull($this->cookie(self::SESSION_COOKIE));

        $this->clearCookies();
        $this->setCookie(self::CODE_COOKIE, $handle, '/auth');
        $again = $this->submitCode($code);

        self::assertSame('/auth/login', $again->getHeaderLine('Location'));
        self::assertNull($this->cookie(self::SESSION_COOKIE));
    }

    public function testTheCodePageWithoutAChallengeSendsBackToTheLoginPage(): void
    {
        $response = $this->get('/auth/passwordless/code');

        self::assertSame(303, $response->getStatusCode());
        self::assertSame('/auth/login', $response->getHeaderLine('Location'));
    }

    // ── A link ──────────────────────────────────────────────────────────────────

    public function testALinkSignsInFromAnyBrowser(): void
    {
        $sent = $this->start(mode: 'link');
        self::assertSame(200, $sent->getStatusCode(), (string) $sent->getBody());
        self::assertStringContainsString('Check your email', (string) $sent->getBody());
        $mail = $this->lastMail();
        self::assertStringContainsString('Sign in to', $mail->subject);
        $token = self::tokenIn($mail);

        $this->clearCookies();
        $signedIn = $this->confirmLink($token);

        self::assertSame(303, $signedIn->getStatusCode(), (string) $signedIn->getBody());
        $session = $this->session($this->cookie(self::SESSION_COOKIE));
        self::assertSame('email', $session?->connection->value);
        self::assertSame([AuthenticationMethod::OneTimePassword], $session->methods ?? null);
    }

    public function testOpeningTheLinkDoesNotSpendIt(): void
    {
        $this->start(mode: 'link');
        $token = self::tokenIn($this->lastMail());

        $opened = $this->get('/auth/passwordless/verify', ['token' => $token]);
        $openedAgain = $this->get('/auth/passwordless/verify', ['token' => $token]);

        self::assertSame(200, $opened->getStatusCode());
        self::assertStringContainsString(self::EMAIL, (string) $openedAgain->getBody());
        self::assertStringContainsString('>Sign in</button>', (string) $openedAgain->getBody());
        self::assertNull($this->cookie(self::SESSION_COOKIE));
        self::assertSame(303, $this->confirmLink($token)->getStatusCode(), 'A preview spent nothing.');
    }

    public function testALinkIsSingleUse(): void
    {
        $this->start(mode: 'link');
        $token = self::tokenIn($this->lastMail());
        self::assertSame(303, $this->confirmLink($token)->getStatusCode());

        $this->clearCookies();
        $again = $this->post('/auth/passwordless/verify', [
            'token' => $token,
            'csrf_token' => self::csrfTokenFrom($this->get('/auth/login')),
        ]);

        self::assertSame(400, $again->getStatusCode());
        self::assertStringContainsString('not valid or has expired', (string) $again->getBody());
        self::assertSame(400, $this->get('/auth/passwordless/verify', ['token' => $token])->getStatusCode());
    }

    public function testAnUnknownLinkIsRefused(): void
    {
        $response = $this->get('/auth/passwordless/verify', ['token' => 'no-such-link']);

        self::assertSame(400, $response->getStatusCode());
        self::assertStringContainsString('not valid or has expired', (string) $response->getBody());
        self::assertSame(400, $this->get('/auth/passwordless/verify')->getStatusCode());
    }

    public function testTheCodeBrowsersHandleIsNoLink(): void
    {
        $this->start();
        $handle = $this->cookie(self::CODE_COOKIE, '/auth');
        self::assertNotNull($handle);

        $response = $this->get('/auth/passwordless/verify', ['token' => $handle]);

        self::assertSame(400, $response->getStatusCode(), 'Holding the cookie is not having read the code.');
    }

    // ── Limits and refusals ─────────────────────────────────────────────────────

    public function testSendsAreRateLimited(): void
    {
        $this->boot(['CLAVIA_PASSWORDLESS_SEND_LIMIT' => '2']);

        self::assertSame(303, $this->start()->getStatusCode());
        self::assertSame(200, $this->start(mode: 'link')->getStatusCode());
        $third = $this->start();

        self::assertSame(429, $third->getStatusCode());
        self::assertStringContainsString('Too many', (string) $third->getBody());
        self::assertCount(2, $this->outbox()->recent(10));
    }

    public function testGarbageIsRefusedWithoutSending(): void
    {
        $badAddress = $this->start('not-an-email');
        $badMode = $this->start(mode: 'pigeon');

        self::assertSame(400, $badAddress->getStatusCode());
        self::assertStringContainsString('Enter the email address', (string) $badAddress->getBody());
        self::assertSame(400, $badMode->getStatusCode());
        self::assertSame([], $this->outbox()->recent(10));
    }

    public function testAFormWithoutItsCsrfTokenSendsNothing(): void
    {
        $this->get('/auth/login');

        $response = $this->post('/auth/passwordless/start', ['email' => self::EMAIL, 'mode' => 'code']);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame([], $this->outbox()->recent(10));
    }

    public function testMailThatCannotLeaveIsSaidPlainly(): void
    {
        $this->boot();
        $this->container()->setService(Mailer::class, new RecordingMailer(failing: true));

        $response = $this->start();

        self::assertSame(503, $response->getStatusCode());
        self::assertStringContainsString('not available right now', (string) $response->getBody());
        self::assertNull($this->cookie(self::CODE_COOKIE, '/auth'));
    }

    public function testAPasswordAccountWithTheSameAddressIsADifferentAccount(): void
    {
        $passwordAccount = $this->user();

        $this->start(self::TEST_USER_EMAIL);
        $this->submitCode(self::codeIn($this->lastMail()));

        $mailboxAccount = $this->users()->findByEmail(ConnectionName::email(), self::TEST_USER_EMAIL);
        self::assertNotNull($mailboxAccount);
        self::assertFalse($mailboxAccount->id->equals($passwordAccount->id));
        self::assertTrue($this->session($this->cookie(self::SESSION_COOKIE))?->userId->equals($mailboxAccount->id));
    }

    public function testADisabledAccountCannotSignIn(): void
    {
        $this->start();
        $this->submitCode(self::codeIn($this->lastMail()));
        $this->clearCookies();
        $account = $this->users()->findByEmail(ConnectionName::email(), self::EMAIL);
        self::assertNotNull($account);
        $account->deactivate($this->container()->get(Clock::class)->now());
        $this->users()->save($account);

        $this->start();
        $response = $this->submitCode(self::codeIn($this->lastMail()));

        self::assertSame(403, $response->getStatusCode());
        self::assertStringContainsString('disabled', (string) $response->getBody());
        self::assertNull($this->cookie(self::SESSION_COOKIE));
    }

    // ── With the rest of the sign-in ────────────────────────────────────────────

    public function testPasswordlessCompletesAnAuthorizationRequest(): void
    {
        $this->publicClient();
        $state = $this->loginStateForTheClient();

        $this->start(state: $state);
        $signedIn = $this->submitCode(self::codeIn($this->lastMail()));

        self::assertSame(303, $signedIn->getStatusCode());
        self::assertStringStartsWith('/oauth2/authorize?', $signedIn->getHeaderLine('Location'));
        self::assertNull($this->loginState($state), 'The login page handle is spent.');
        $back = $this->get('/oauth2/authorize', self::locationQuery($signedIn));
        self::assertNotSame('', $this->extractCode($back));
    }

    public function testTheIdTokenReportsAOneTimePassword(): void
    {
        $this->publicClient();
        $this->start();
        $this->submitCode(self::codeIn($this->lastMail()));

        $token = $this->completeFlow('openid email');
        $claims = $this->verifiedIdToken($token['id_token'] ?? null)['claims'];

        self::assertSame(['otp'], $claims['amr'] ?? null);
        self::assertSame(self::EMAIL, $claims['email'] ?? null);
        self::assertTrue($claims['email_verified'] ?? null);
    }

    public function testASecondFactorStillApplies(): void
    {
        $this->start();
        $this->submitCode(self::codeIn($this->lastMail()));
        $account = $this->users()->findByEmail(ConnectionName::email(), self::EMAIL);
        self::assertNotNull($account);
        $this->confirmSecondFactor($account);
        $this->clearCookies();

        $this->start(mode: 'link');
        $response = $this->confirmLink(self::tokenIn($this->lastMail()));

        self::assertSame(303, $response->getStatusCode());
        self::assertSame('/auth/mfa', $response->getHeaderLine('Location'));
        self::assertNotNull($this->cookie('clavia_mfa', '/auth'));
        self::assertNull($this->cookie(self::SESSION_COOKIE));
    }

    // ── Administration ──────────────────────────────────────────────────────────

    public function testTheEmailConnectionIsBuiltIn(): void
    {
        $this->adminToken();

        $email = self::json($this->api('GET', '/api/v1/connections/email'));
        self::assertSame('passwordless', $email['strategy']);
        self::assertTrue($email['usable']);
        self::assertSame(409, $this->api('DELETE', '/api/v1/connections/email')->getStatusCode());
        self::assertSame(422, $this->api('POST', '/api/v1/connections', [
            'name' => 'sms',
            'display_name' => 'SMS',
            'strategy' => 'passwordless',
        ])->getStatusCode());

        $this->boot(['CLAVIA_EMAIL_BACKEND' => 'none']);
        $this->adminToken();
        $email = self::json($this->api('GET', '/api/v1/connections/email'));
        self::assertFalse($email['configured']);
        self::assertFalse($email['usable']);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    /** Fill in the login page's email form and press one of its two buttons. */
    private function start(string $email = self::EMAIL, string $mode = 'code', ?string $state = null): ResponseInterface
    {
        $page = $this->get('/auth/login', $state === null ? [] : ['state' => $state]);

        return $this->post('/auth/passwordless/start', [
            'email' => $email,
            'mode' => $mode,
            'csrf_token' => self::csrfTokenFrom($page),
            'state' => $state ?? '',
        ]);
    }

    private function submitCode(string $code): ResponseInterface
    {
        return $this->post('/auth/passwordless/code', [
            'code' => $code,
            'csrf_token' => self::csrfTokenFrom($this->get('/auth/login')),
        ]);
    }

    /** Open the link, then press "Sign in" on the page it opens on. */
    private function confirmLink(string $token): ResponseInterface
    {
        $page = $this->get('/auth/passwordless/verify', ['token' => $token]);
        self::assertSame(200, $page->getStatusCode(), (string) $page->getBody());

        return $this->post(
            '/auth/passwordless/verify',
            ['token' => $token, 'csrf_token' => self::csrfTokenFrom($page)],
        );
    }

    private function outbox(): MailOutbox
    {
        return $this->container()->get(MailOutbox::class);
    }

    private function lastMail(): OutgoingMail
    {
        $mail = $this->outbox()->recent(1)[0] ?? null;
        self::assertNotNull($mail, 'Nothing was sent.');

        return $mail;
    }

    private static function codeIn(OutgoingMail $mail): string
    {
        self::assertSame(1, preg_match('/\b(\d{6})\b/', $mail->text, $match), $mail->text);

        return $match[1];
    }

    private static function tokenIn(OutgoingMail $mail): string
    {
        $link = '~https://auth\.clavia\.test/auth/passwordless/verify\?token=([A-Za-z0-9_-]+)~';
        self::assertSame(1, preg_match($link, $mail->text, $match), $mail->text);

        return $match[1];
    }

    private function users(): UserRepository
    {
        return $this->container()->get(UserRepository::class);
    }

    private function restrictTo(string ...$names): void
    {
        $clients = $this->container()->get(ClientRepository::class);
        $client = $clients->find(ClientId::fromString(self::TEST_CLIENT_ID));
        self::assertNotNull($client);
        $clients->save($client->withConnections(array_values(array_map(ConnectionName::fromString(...), $names))));
    }

    /** Start an authorization request with nobody signed in; the login page's handle. */
    private function loginStateForTheClient(): string
    {
        [, $challenge] = $this->makePkcePair();
        $response = $this->get('/oauth2/authorize', $this->authorizeParams($challenge));
        self::assertSame(303, $response->getStatusCode(), (string) $response->getBody());
        $state = self::locationQuery($response)['state'] ?? null;
        self::assertIsString($state);

        return $state;
    }

    private function confirmSecondFactor(User $user): void
    {
        /** @var TotpSeeds $seeds */
        $seeds = $this->container()->get(TotpSeeds::class);
        $secret = TotpSecret::generate($this->container()->get(RandomSource::class));
        $now = new \DateTimeImmutable();
        $factor = MfaFactor::stage($user->id, $seeds->seal($user->id, $secret), $now);
        self::assertTrue($factor->accept($secret, Totp::codeAt($secret, $now), $now));
        $factor->confirm($now);
        $this->container()->get(MfaFactorRepository::class)->save($factor);
    }
}
