<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Port\MailOutbox;
use Clavia\Application\Port\OutgoingMail;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Audit\AuditLog;
use Clavia\Domain\Audit\AuditQuery;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\PageRequest;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Self-service accounts: signing up, proving an address, choosing a new password
 * (docs/design/self-service-accounts.md).
 *
 * The test environment's mail backend is the console one: every message lands in the
 * development outbox, where each test reads its link as a person would read their email.
 */
final class SelfServiceAccountsTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string EMAIL = 'grace@clavia.dev';

    private const string PASSWORD = 'correct horse battery';

    private const string SESSION_COOKIE = 'clavia_session';

    // ── Sign-up ─────────────────────────────────────────────────────────────────

    public function testNoPoolTakesSignUpsUntilAnOperatorOpensOne(): void
    {
        self::assertStringNotContainsString('Create an account', (string) $this->get('/auth/login')->getBody());
        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $this->get('/auth/signup')->getStatusCode());
        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $this->signUp()->getStatusCode());
        self::assertNull($this->account());
    }

    public function testSigningUpWhereAVerifiedAddressIsRequiredSendsALinkAndSignsNobodyIn(): void
    {
        $this->openSignUp(requireVerifiedEmail: true);
        self::assertStringContainsString('Create an account', (string) $this->get('/auth/login')->getBody());

        $response = $this->signUp();

        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode(), (string) $response->getBody());
        self::assertStringContainsString('Check your email', (string) $response->getBody());
        self::assertNull($this->cookie(self::SESSION_COOKIE));
        $account = $this->account();
        self::assertNotNull($account);
        self::assertFalse($account->isEmailVerified());
        self::assertSame(ConnectionName::DEFAULT_POOL, $account->connection->value);
        $mail = $this->lastMail();
        self::assertSame(self::EMAIL, $mail->to);
        self::assertStringContainsString('/auth/verify-email?token=', $mail->text);
        self::assertSame(1, $this->audited(AuditEventType::UserSignedUp));
    }

    public function testAnUnverifiedAccountIsSentANewLinkUntilItConfirmsThenSignsIn(): void
    {
        $this->openSignUp(requireVerifiedEmail: true);
        $this->signUp();
        $this->clearCookies();

        $refused = $this->signIn();
        self::assertSame(StatusCodeInterface::STATUS_OK, $refused->getStatusCode());
        self::assertStringContainsString('we sent it a new link', (string) $refused->getBody());
        self::assertNull($this->cookie(self::SESSION_COOKIE));

        $confirmed = $this->followVerificationLink($this->lastMail());
        self::assertSame(StatusCodeInterface::STATUS_OK, $confirmed->getStatusCode(), (string) $confirmed->getBody());
        self::assertStringContainsString('is confirmed', (string) $confirmed->getBody());
        self::assertTrue($this->account()?->isEmailVerified());
        self::assertNull($this->cookie(self::SESSION_COOKIE), 'Confirming an address signs nobody in.');
        self::assertSame(1, $this->audited(AuditEventType::UserEmailVerified));

        $signedIn = $this->signIn();
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $signedIn->getStatusCode());
        self::assertNotNull($this->session($this->cookie(self::SESSION_COOKIE)));
    }

    public function testATakenAddressGetsTheSameAnswerAndItsOwnerANotice(): void
    {
        $this->openSignUp(requireVerifiedEmail: true);
        $this->signUp();
        $first = $this->account();
        $this->clearCookies();

        $again = $this->signUp(password: 'another long password');

        self::assertSame(StatusCodeInterface::STATUS_OK, $again->getStatusCode());
        self::assertStringContainsString('Check your email', (string) $again->getBody());
        self::assertSame($first?->id->toString(), $this->account()?->id->toString(), 'No second account.');
        self::assertStringContainsString('already has one', $this->lastMail()->text);
        self::assertStringNotContainsString('token=', $this->lastMail()->text, 'A notice carries no link.');
    }

    public function testAPoolWithoutVerificationSignsTheNewAccountInAndResumesTheRequest(): void
    {
        $this->openSignUp(requireVerifiedEmail: false);
        $this->publicClient();
        $state = $this->loginStateForTheClient();

        $response = $this->signUp(state: $state);

        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $response->getStatusCode(),
            (string) $response->getBody(),
        );
        self::assertStringStartsWith('/oauth2/authorize?', $response->getHeaderLine('Location'));
        self::assertNotNull($this->session($this->cookie(self::SESSION_COOKIE)));
        self::assertStringContainsString('/auth/verify-email?token=', $this->lastMail()->text);
    }

    public function testAPoolWithoutVerificationSaysAnAddressIsTaken(): void
    {
        $this->openSignUp(requireVerifiedEmail: false);
        $this->signUp();
        $this->clearCookies();

        $again = $this->signUp();

        self::assertSame(StatusCodeInterface::STATUS_CONFLICT, $again->getStatusCode());
        self::assertStringContainsString('already has an account', (string) $again->getBody());
    }

    public function testAPasswordThePolicyRefusesKeepsTheFormAndCreatesNothing(): void
    {
        $this->openSignUp(requireVerifiedEmail: true);

        $response = $this->signUp(password: 'short');

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertStringContainsString('at least 8 characters', (string) $response->getBody());
        // The address is kept, escaped for the attribute it fills.
        self::assertStringContainsString('value="grace&#x40;clavia.dev"', (string) $response->getBody());
        self::assertNull($this->account());
    }

    public function testSignUpsAreLimitedPerClientAddress(): void
    {
        $this->boot(['CLAVIA_SIGN_UP_LIMIT' => '1']);
        $this->openSignUp(requireVerifiedEmail: true);
        $this->signUp();

        $second = $this->signUp('someone.else@clavia.dev');

        self::assertSame(StatusCodeInterface::STATUS_TOO_MANY_REQUESTS, $second->getStatusCode());
        self::assertNull($this->account('someone.else@clavia.dev'));
    }

    public function testSignUpNeedingMailIsNotOfferedWithoutIt(): void
    {
        $this->boot(['CLAVIA_EMAIL_BACKEND' => 'none']);
        $this->openSignUp(requireVerifiedEmail: true);

        self::assertStringNotContainsString('Create an account', (string) $this->get('/auth/login')->getBody());
        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $this->signUp()->getStatusCode());
    }

    // ── Verification links ──────────────────────────────────────────────────────

    public function testOpeningAVerificationLinkSpendsNothingAndConfirmingWorksOnce(): void
    {
        $this->openSignUp(requireVerifiedEmail: true);
        $this->signUp();
        $link = self::linkIn($this->lastMail());

        // A mail scanner fetches the URL; the link survives it.
        self::assertSame(StatusCodeInterface::STATUS_OK, $this->get($link)->getStatusCode());
        self::assertSame(StatusCodeInterface::STATUS_OK, $this->get($link)->getStatusCode());
        $page = $this->get($link);
        self::assertStringContainsString('Confirm my address', (string) $page->getBody());

        $form = ['token' => self::tokenOf($link), 'csrf_token' => self::csrfTokenFrom($page)];
        self::assertSame(StatusCodeInterface::STATUS_OK, $this->post('/auth/verify-email', $form)->getStatusCode());
        self::assertSame(
            StatusCodeInterface::STATUS_BAD_REQUEST,
            $this->post('/auth/verify-email', $form)->getStatusCode(),
        );
    }

    public function testAnUnknownLinkIsRefused(): void
    {
        $response = $this->get('/auth/verify-email', ['token' => 'not-a-token']);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertStringContainsString('not valid any more', (string) $response->getBody());
    }

    // ── Password reset ──────────────────────────────────────────────────────────

    public function testTheLoginPageOffersAResetOnlyWhenMailCanBeSent(): void
    {
        self::assertStringContainsString('Forgot your password?', (string) $this->get('/auth/login')->getBody());

        $this->boot(['CLAVIA_EMAIL_BACKEND' => 'none']);

        self::assertStringNotContainsString('Forgot your password?', (string) $this->get('/auth/login')->getBody());
        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $this->forgot()->getStatusCode());
    }

    public function testAKnownAndAnUnknownAddressGetTheSameAnswer(): void
    {
        $this->existingAccount();
        $before = count($this->outbox()->recent(50));

        $known = $this->forgot();
        $unknown = $this->forgot('nobody@clavia.dev');

        self::assertSame(StatusCodeInterface::STATUS_OK, $known->getStatusCode());
        self::assertSame(StatusCodeInterface::STATUS_OK, $unknown->getStatusCode());
        self::assertStringContainsString('If ', (string) $unknown->getBody());
        self::assertCount(
            $before + 1,
            $this->outbox()->recent(50),
            'Nothing is mailed to an address without an account.',
        );
        self::assertSame(self::EMAIL, $this->lastMail()->to);
    }

    public function testAResetSetsThePasswordVerifiesTheAddressAndEndsEverySession(): void
    {
        $this->existingAccount();
        $this->signIn();
        $sessionId = $this->cookie(self::SESSION_COOKIE);
        self::assertNotNull($this->session($sessionId));
        $this->forgot();
        $link = self::linkIn($this->lastMail());

        $form = $this->get($link);
        self::assertStringContainsString('Choose a new password', (string) $form->getBody());
        $changed = $this->post('/auth/password/reset', [
            'token' => self::tokenOf($link),
            'password' => 'a brand new passphrase',
            'csrf_token' => self::csrfTokenFrom($form),
        ]);

        self::assertSame(StatusCodeInterface::STATUS_OK, $changed->getStatusCode(), (string) $changed->getBody());
        self::assertStringContainsString('Password changed', (string) $changed->getBody());
        self::assertNull($this->session($sessionId), 'Every session ended.');
        self::assertTrue($this->account()?->isEmailVerified());
        self::assertSame(1, $this->audited(AuditEventType::UserPasswordReset));
        $this->clearCookies();
        self::assertSame(
            StatusCodeInterface::STATUS_UNAUTHORIZED,
            $this->signIn()->getStatusCode(),
            'The old password is gone.',
        );
        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $this->signIn(password: 'a brand new passphrase')->getStatusCode(),
        );
    }

    public function testARefusedPasswordKeepsTheLink(): void
    {
        $this->existingAccount();
        $this->forgot();
        $link = self::linkIn($this->lastMail());
        $form = $this->get($link);

        $refused = $this->post('/auth/password/reset', [
            'token' => self::tokenOf($link),
            'password' => 'short',
            'csrf_token' => self::csrfTokenFrom($form),
        ]);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $refused->getStatusCode());
        self::assertStringContainsString('at least 8 characters', (string) $refused->getBody());
        self::assertSame(StatusCodeInterface::STATUS_OK, $this->get($link)->getStatusCode(), 'The link is still good.');
    }

    public function testAResetLinkDiesOnceThePasswordChanges(): void
    {
        $this->existingAccount();
        $this->forgot();
        $first = self::linkIn($this->lastMail());
        $this->forgot();
        $second = self::linkIn($this->lastMail());
        $form = $this->get($first);
        $this->post('/auth/password/reset', [
            'token' => self::tokenOf($first),
            'password' => 'a brand new passphrase',
            'csrf_token' => self::csrfTokenFrom($form),
        ]);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $this->get($second)->getStatusCode());
    }

    // ── Management API ──────────────────────────────────────────────────────────

    public function testOperatorsOpenAPoolToSignUpsFromTheManagementApi(): void
    {
        $this->adminToken();

        $changed = $this->api(RequestMethodInterface::METHOD_PATCH, '/api/v1/connections/password', [
            'allow_sign_up' => true,
            'require_verified_email' => true,
        ]);

        self::assertSame(StatusCodeInterface::STATUS_OK, $changed->getStatusCode(), (string) $changed->getBody());
        self::assertTrue(self::json($changed)['allow_sign_up']);
        self::assertTrue(self::json($changed)['require_verified_email']);
        self::assertStringContainsString('Create an account', (string) $this->get('/auth/login')->getBody());
    }

    public function testOnlyAPoolTakesSignUps(): void
    {
        $this->adminToken();

        $refused = $this->api(
            RequestMethodInterface::METHOD_PATCH,
            '/api/v1/connections/google',
            ['allow_sign_up' => true],
        );

        self::assertSame(
            StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY,
            $refused->getStatusCode(),
            (string) $refused->getBody(),
        );
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    private function openSignUp(bool $requireVerifiedEmail): void
    {
        $connections = $this->container()->get(ConnectionRepository::class);
        $pool = $connections->find(ConnectionName::defaultPool());
        self::assertNotNull($pool);
        $connections->save($pool->switched(null, null, null, true, $requireVerifiedEmail));
    }

    private function signUp(
        string $email = self::EMAIL,
        string $password = self::PASSWORD,
        ?string $state = null,
    ): ResponseInterface {
        $page = $this->get('/auth/login', $state === null ? [] : ['state' => $state]);

        return $this->post('/auth/signup', [
            'email' => $email,
            'password' => $password,
            'csrf_token' => self::csrfTokenFrom($page),
            'state' => $state ?? '',
        ]);
    }

    private function signIn(string $password = self::PASSWORD): ResponseInterface
    {
        return $this->post('/auth/login', [
            'email' => self::EMAIL,
            'password' => $password,
            'csrf_token' => self::csrfTokenFrom($this->get('/auth/login')),
            'state' => '',
        ]);
    }

    private function forgot(string $email = self::EMAIL): ResponseInterface
    {
        return $this->post('/auth/password/forgot', [
            'email' => $email,
            'csrf_token' => self::csrfTokenFrom($this->get('/auth/password/forgot')),
            'state' => '',
        ]);
    }

    /** Open the link, then press "Confirm my address" on the page it opens on. */
    private function followVerificationLink(OutgoingMail $mail): ResponseInterface
    {
        $link = self::linkIn($mail);

        return $this->post('/auth/verify-email', [
            'token' => self::tokenOf($link),
            'csrf_token' => self::csrfTokenFrom($this->get($link)),
        ]);
    }

    private function existingAccount(): void
    {
        $this->openSignUp(requireVerifiedEmail: false);
        $this->signUp();
        $this->clearCookies();
    }

    private function account(string $email = self::EMAIL): ?User
    {
        return $this->container()->get(UserRepository::class)->findByEmail(ConnectionName::defaultPool(), $email);
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

    /** The link's path and query, as the browser would request it from this server. */
    private static function linkIn(OutgoingMail $mail): string
    {
        self::assertSame(1, preg_match('#https://[^/\s]+(/auth/[a-z/-]+\?token=[A-Za-z0-9_-]+)#', $mail->text, $match));

        return $match[1];
    }

    private static function tokenOf(string $link): string
    {
        parse_str((string) parse_url($link, PHP_URL_QUERY), $query);
        $token = $query['token'] ?? null;
        self::assertIsString($token);

        return $token;
    }

    private function audited(AuditEventType $type): int
    {
        return $this->container()->get(AuditLog::class)->page(
            new AuditQuery(types: [$type]),
            PageRequest::of(1, 50),
        )->total;
    }

    /** Start an authorization request with nobody signed in; the login page's handle. */
    private function loginStateForTheClient(): string
    {
        [, $challenge] = $this->makePkcePair();
        $response = $this->get('/oauth2/authorize', $this->authorizeParams($challenge));
        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $response->getStatusCode(),
            (string) $response->getBody(),
        );
        $state = self::locationQuery($response)['state'] ?? null;
        self::assertIsString($state);

        return $state;
    }
}
