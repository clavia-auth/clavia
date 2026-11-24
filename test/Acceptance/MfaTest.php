<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Secondary\Redis\Keys;
use Clavia\Application\Port\DecryptionFailed;
use Clavia\Application\Port\SecretCipher;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Mfa\RecoveryCodeRepository;
use Clavia\Domain\Authentication\Mfa\Totp;
use Clavia\Domain\Authentication\Mfa\TotpSecret;
use Clavia\Domain\Identity\UserRepository;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use DateTimeImmutable;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Multi-factor authentication through the pages: enrollment, the second step of a
 * sign-in, recovery codes, turning it off, and the operator's reset.
 *
 * The property under test throughout is that a correct password is not a session once
 * a factor is enrolled, and that a code is spent when it is used. The clock is frozen,
 * so the codes the test computes are the codes the server expects.
 */
final class MfaTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string SESSION_COOKIE = 'clavia_session';
    private const string MFA_COOKIE = 'clavia_mfa';

    private FrozenClock $clock;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->clock = $this->freezeClock();
    }

    // ------------------------------------------------------------------
    // Enrollment
    // ------------------------------------------------------------------

    public function testEnrollmentNeedsASessionAndComesBackToItAfterSigningIn(): void
    {
        $this->user();

        $response = $this->get('/auth/mfa/enroll');

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        self::assertStringStartsWith('/auth/login?state=', $response->getHeaderLine('Location'));
        $state = self::locationQuery($response)['state'] ?? null;
        self::assertIsString($state);
        self::assertSame('/auth/mfa/enroll', $this->loginState($state)?->nextUrl);

        $signedIn = $this->submitLogin(state: $state);
        self::assertSame('/auth/mfa/enroll', $signedIn->getHeaderLine('Location'));
    }

    public function testEnrollmentConfirmsOnlyWithACorrectCodeAndKeepsTheSameSeed(): void
    {
        $user = $this->user();
        $this->submitLogin();
        $setUp = $this->beginEnrollment();
        $secret = self::secretFrom($setUp);

        $wrong = $this->post('/auth/mfa/enroll/confirm', [
            'code' => self::wrongCodeFor($secret, $this->clock->now()),
            'csrf_token' => self::csrfTokenFrom($setUp),
        ]);

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $wrong->getStatusCode());
        self::assertStringContainsString('That code is not valid.', (string) $wrong->getBody());
        // The same seed again, so the account already added to the app stays valid.
        self::assertSame($secret, self::secretFrom($wrong));
        self::assertFalse($this->factors()->find($user->id)?->isConfirmed() ?? false);
    }

    public function testTheSeedIsSealedForItsAccountAndNeverStoredInTheClear(): void
    {
        $user = $this->user();
        $secret = $this->enroll();

        $factor = $this->factors()->find($user->id);

        self::assertNotNull($factor);
        self::assertTrue($factor->isConfirmed());
        self::assertStringNotContainsString($secret->base32(), $factor->sealedSecret);
        /** @var SecretCipher $cipher */
        $cipher = $this->container()->get(SecretCipher::class);
        self::assertSame(
            $secret->base32(),
            $cipher->decrypt($factor->sealedSecret, 'user:' . $user->id->value . ':totp'),
        );

        $this->expectException(DecryptionFailed::class);
        $cipher->decrypt($factor->sealedSecret, 'user:00000000-0000-4000-8000-000000000000:totp');
    }

    public function testTheSetUpPageHasNoScriptAndDrawsTheQrCodeInline(): void
    {
        $this->user();
        $this->submitLogin();

        $setUp = $this->beginEnrollment();
        $body = (string) $setUp->getBody();

        self::assertStringNotContainsString('<script', strtolower($body));
        self::assertStringContainsString('<svg', $body);
        self::assertStringContainsString('fill="currentColor"', $body);
        self::assertStringNotContainsString('style=', $body);
        // The provisioning URI, issuer and account included, travels in the QR code only.
        self::assertStringNotContainsString('otpauth', $body);
        self::assertStringContainsString("default-src 'none'", $setUp->getHeaderLine('Content-Security-Policy'));
        self::assertSame('no-store', $setUp->getHeaderLine('Cache-Control'));
    }

    public function testWithoutAnEncryptionKeyTheSetUpSaysSoAndStoresNothing(): void
    {
        $this->boot(['CLAVIA_SECRET_ENCRYPTION_KEY' => '']);
        $this->clock = $this->freezeClock();
        $user = $this->user();
        $this->submitLogin();
        $settings = $this->get('/auth/mfa/enroll');

        $response = $this->post('/auth/mfa/enroll', ['csrf_token' => self::csrfTokenFrom($settings)]);

        self::assertSame(StatusCodeInterface::STATUS_SERVICE_UNAVAILABLE, $response->getStatusCode());
        self::assertStringContainsString(
            'CLAVIA_SECRET_ENCRYPTION_KEY is not configured',
            (string) $response->getBody(),
        );
        self::assertNull($this->factors()->find($user->id));
    }

    public function testAConfirmedFactorCannotBeReplacedWithoutTurningItOff(): void
    {
        $user = $this->user();
        $secret = $this->enroll();
        $settings = $this->get('/auth/mfa/enroll');

        $response = $this->post('/auth/mfa/enroll', ['csrf_token' => self::csrfTokenFrom($settings)]);

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        self::assertSame('/auth/mfa/enroll', $response->getHeaderLine('Location'));
        self::assertSame(
            $secret->base32(),
            $this->container()->get(SecretCipher::class)->decrypt(
                (string) $this->factors()->find($user->id)?->sealedSecret,
                'user:' . $user->id->value . ':totp',
            ),
        );
    }

    public function testAFormWithoutItsCsrfTokenChangesNothing(): void
    {
        $user = $this->user();
        $this->enroll();

        $response = $this->post('/auth/mfa/disable', ['csrf_token' => 'forged']);

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        self::assertTrue($this->factors()->find($user->id)?->isConfirmed() ?? false);
    }

    // ------------------------------------------------------------------
    // The second step of a sign-in
    // ------------------------------------------------------------------

    public function testAPasswordAloneNoLongerSignsIn(): void
    {
        $this->user();
        $this->enroll();
        $this->post('/auth/logout');

        $response = $this->submitLogin();

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        self::assertSame('/auth/mfa', $response->getHeaderLine('Location'));
        self::assertNotNull($this->cookie(self::MFA_COOKIE));
        self::assertNull($this->cookie(self::SESSION_COOKIE));
        $cookie = (string) self::setCookieHeader($response, self::MFA_COOKIE);
        self::assertStringContainsString('Path=/auth', $cookie);
        self::assertStringContainsString('HttpOnly', $cookie);
        self::assertStringContainsString('Max-Age=300', $cookie);
    }

    public function testACorrectCodeFinishesTheSignInWithTheMethodsUsed(): void
    {
        $user = $this->user();
        $secret = $this->enroll();
        $this->post('/auth/logout');
        $this->submitLogin(nextUrl: '/oauth2/authorize?x=1');
        // Confirming spent the current step; the app rolls over to the next one.
        $this->clock->advance(Totp::PERIOD);

        $response = $this->answer(Totp::codeAt($secret, $this->clock->now()));

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        self::assertSame('/oauth2/authorize?x=1', $response->getHeaderLine('Location'));
        $session = $this->session($this->cookie(self::SESSION_COOKIE));
        self::assertNotNull($session);
        self::assertTrue($session->userId->equals($user->id));
        self::assertSame(['pwd', 'otp', 'mfa'], self::methods($session->methods));
        self::assertNull($this->cookie(self::MFA_COOKIE));
    }

    public function testACodeIsSingleUse(): void
    {
        $this->user();
        $secret = $this->enroll();
        $this->post('/auth/logout');

        // The step the confirmation spent is refused, though the code is genuine.
        $this->submitLogin();
        self::assertSame(
            StatusCodeInterface::STATUS_UNAUTHORIZED,
            $this->answer(Totp::codeAt($secret, $this->clock->now()))->getStatusCode(),
        );

        $this->clock->advance(Totp::PERIOD);
        $code = Totp::codeAt($secret, $this->clock->now());
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $this->answer($code)->getStatusCode());
        $this->post('/auth/logout');

        $this->submitLogin();
        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $this->answer($code)->getStatusCode());
    }

    public function testACodeFromTheAdjacentStepIsAcceptedAndOneFurtherIsNot(): void
    {
        $this->user();
        $secret = $this->enroll();
        $this->post('/auth/logout');
        $this->clock->advance(3 * Totp::PERIOD);

        $this->submitLogin();
        $tooOld = Totp::codeAt($secret, $this->clock->now()->modify('-' . (2 * Totp::PERIOD) . ' seconds'));
        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $this->answer($tooOld)->getStatusCode());

        $previous = Totp::codeAt($secret, $this->clock->now()->modify('-' . Totp::PERIOD . ' seconds'));
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $this->answer($previous)->getStatusCode());
    }

    public function testWrongCodesExhaustTheChallenge(): void
    {
        $this->boot(['CLAVIA_MFA_MAX_ATTEMPTS' => '3']);
        $this->clock = $this->freezeClock();
        $this->user();
        $secret = $this->enroll();
        $this->post('/auth/logout');
        $this->submitLogin();
        $wrong = self::wrongCodeFor($secret, $this->clock->now());

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $this->answer($wrong)->getStatusCode());
        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $this->answer($wrong)->getStatusCode());
        $last = $this->answer($wrong);

        // Third strike: back to the password, the challenge gone.
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $last->getStatusCode());
        self::assertSame('/auth/login', $last->getHeaderLine('Location'));
        self::assertNull($this->cookie(self::MFA_COOKIE));
        $this->clock->advance(Totp::PERIOD);
        $this->setCookie(self::MFA_COOKIE, 'replayed', '/auth');
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $this->get('/auth/mfa')->getStatusCode());
    }

    public function testARecoveryCodeSignsInOnceInAnyCase(): void
    {
        $user = $this->user();
        $this->submitLogin();
        $setUp = $this->beginEnrollment();
        $secret = TotpSecret::fromBase32(self::secretFrom($setUp));
        $confirmed = $this->post('/auth/mfa/enroll/confirm', [
            'code' => Totp::codeAt($secret, $this->clock->now()),
            'csrf_token' => self::csrfTokenFrom($setUp),
        ]);
        $codes = self::recoveryCodesFrom($confirmed);
        self::assertCount(10, $codes);
        self::assertCount(10, array_unique($codes));
        $this->post('/auth/logout');

        $this->submitLogin();
        $first = $this->answer(strtoupper($codes[0]));
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $first->getStatusCode());
        $session = $this->session($this->cookie(self::SESSION_COOKIE));
        self::assertSame(['pwd', 'mfa'], self::methods($session?->methods ?? []));
        $this->post('/auth/logout');

        $this->submitLogin();
        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $this->answer($codes[0])->getStatusCode());
        self::assertSame(9, $this->recoveryCodes()->unusedCount($user->id));
        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $this->answer(str_replace('-', '', $codes[1]))->getStatusCode(),
        );
        self::assertStringContainsString('8 unused recovery codes', (string) $this->get('/auth/mfa/enroll')->getBody());
    }

    public function testTheChallengeWithoutItsCookieGoesBackToTheLogin(): void
    {
        $response = $this->get('/auth/mfa');

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        self::assertSame('/auth/login', $response->getHeaderLine('Location'));
    }

    public function testAnExpiredChallengeGoesBackToTheLogin(): void
    {
        $this->user();
        $secret = $this->enroll();
        $this->post('/auth/logout');
        $this->submitLogin();
        $page = $this->get('/auth/mfa');

        // Redis keeps time on its own: let the entry lapse as its TTL would.
        $this->clock->advance(Totp::PERIOD);
        TestStorage::redis()->del(Keys::forSecret('mfa-challenge', (string) $this->cookie(self::MFA_COOKIE)));
        $response = $this->post('/auth/mfa', [
            'code' => Totp::codeAt($secret, $this->clock->now()),
            'csrf_token' => self::csrfTokenFrom($page),
        ]);

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        self::assertSame('/auth/login', $response->getHeaderLine('Location'));
        self::assertNull($this->cookie(self::SESSION_COOKIE));
        self::assertNull($this->cookie(self::MFA_COOKIE));
    }

    public function testTheChallengeFormIsRefusedWithoutItsCsrfToken(): void
    {
        $this->user();
        $secret = $this->enroll();
        $this->post('/auth/logout');
        $this->submitLogin();
        $this->clock->advance(Totp::PERIOD);

        $response = $this->post('/auth/mfa', ['code' => Totp::codeAt($secret, $this->clock->now())]);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertNull($this->cookie(self::SESSION_COOKIE));
    }

    public function testADeactivatedUserCannotFinishTheSecondStep(): void
    {
        $user = $this->user();
        $secret = $this->enroll();
        $this->post('/auth/logout');
        $this->submitLogin();
        $user->deactivate(new DateTimeImmutable());
        $this->container()->get(UserRepository::class)->save($user);
        $this->clock->advance(Totp::PERIOD);

        $response = $this->answer(Totp::codeAt($secret, $this->clock->now()));

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $response->getStatusCode());
        self::assertNull($this->cookie(self::SESSION_COOKIE));
    }

    public function testTurningItOffRemovesTheFactorAndTheCodes(): void
    {
        $user = $this->user();
        $this->enroll();
        $settings = $this->get('/auth/mfa/enroll');
        self::assertStringContainsString('>On<', (string) $settings->getBody());

        $response = $this->post('/auth/mfa/disable', ['csrf_token' => self::csrfTokenFrom($settings)]);

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        self::assertNull($this->factors()->find($user->id));
        self::assertSame(0, $this->recoveryCodes()->unusedCount($user->id));
        self::assertStringContainsString('>Off<', (string) $this->get('/auth/mfa/enroll')->getBody());
        $this->post('/auth/logout');
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $this->submitLogin()->getStatusCode());
        self::assertNotNull($this->cookie(self::SESSION_COOKIE));
    }

    // ------------------------------------------------------------------
    // Management API
    // ------------------------------------------------------------------

    public function testAnOperatorCanResetAUserLockedOut(): void
    {
        $user = $this->user();
        $this->enroll();
        $this->post('/auth/logout');
        $this->adminToken();
        $path = '/api/v1/users/' . $user->id->value;

        self::assertTrue(self::document($this->api('GET', $path))['mfa_enrolled']);
        self::assertSame(StatusCodeInterface::STATUS_NO_CONTENT, $this->api('DELETE', $path . '/mfa')->getStatusCode());
        self::assertFalse(self::document($this->api('GET', $path))['mfa_enrolled']);
        // Idempotent: the caller asked for it to be off, and it is off.
        self::assertSame(StatusCodeInterface::STATUS_NO_CONTENT, $this->api('DELETE', $path . '/mfa')->getStatusCode());
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $this->submitLogin()->getStatusCode());
        self::assertNotNull($this->cookie(self::SESSION_COOKIE));
    }

    public function testResettingNeedsTheUpdateScopeAndAKnownUser(): void
    {
        $user = $this->user();
        $this->adminToken(['read:users']);

        self::assertSame(
            StatusCodeInterface::STATUS_FORBIDDEN,
            $this->api('DELETE', '/api/v1/users/' . $user->id->value . '/mfa')->getStatusCode(),
        );

        $this->adminToken();
        self::assertSame(
            StatusCodeInterface::STATUS_NOT_FOUND,
            $this->api('DELETE', '/api/v1/users/00000000-0000-4000-8000-000000000000/mfa')->getStatusCode(),
        );
    }

    // ------------------------------------------------------------------

    /** Sign in, turn two-factor authentication on through the pages, and return the seed. */
    private function enroll(): TotpSecret
    {
        $this->submitLogin();
        $settings = $this->get('/auth/mfa/enroll');
        self::assertSame(StatusCodeInterface::STATUS_OK, $settings->getStatusCode());
        self::assertStringContainsString('>Off<', (string) $settings->getBody());

        $setUp = $this->beginEnrollment($settings);
        $secret = TotpSecret::fromBase32(self::secretFrom($setUp));

        $confirmed = $this->post('/auth/mfa/enroll/confirm', [
            'code' => Totp::codeAt($secret, $this->clock->now()),
            'csrf_token' => self::csrfTokenFrom($setUp),
        ]);
        self::assertSame(StatusCodeInterface::STATUS_OK, $confirmed->getStatusCode(), (string) $confirmed->getBody());
        self::assertStringContainsString('Recovery codes', (string) $confirmed->getBody());

        return $secret;
    }

    private function beginEnrollment(?ResponseInterface $settings = null): ResponseInterface
    {
        $settings ??= $this->get('/auth/mfa/enroll');
        $setUp = $this->post('/auth/mfa/enroll', ['csrf_token' => self::csrfTokenFrom($settings)]);
        self::assertSame(StatusCodeInterface::STATUS_OK, $setUp->getStatusCode(), (string) $setUp->getBody());

        return $setUp;
    }

    /** Fetch the second-step form and post a code with its CSRF token. */
    private function answer(string $code): ResponseInterface
    {
        $page = $this->get('/auth/mfa');
        self::assertSame(StatusCodeInterface::STATUS_OK, $page->getStatusCode());

        return $this->post('/auth/mfa', ['code' => $code, 'csrf_token' => self::csrfTokenFrom($page)]);
    }

    private function factors(): MfaFactorRepository
    {
        return $this->container()->get(MfaFactorRepository::class);
    }

    private function recoveryCodes(): RecoveryCodeRepository
    {
        return $this->container()->get(RecoveryCodeRepository::class);
    }

    private static function secretFrom(ResponseInterface $page): string
    {
        self::assertSame(1, preg_match('#<p class="secret">([A-Z2-7]+)</p>#', (string) $page->getBody(), $match));

        return $match[1];
    }

    /**
     * @return list<string>
     */
    private static function recoveryCodesFrom(ResponseInterface $page): array
    {
        preg_match_all('#<li>([a-z2-9]{4}-[a-z2-9]{4}-[a-z2-9]{4})</li>#', (string) $page->getBody(), $matches);

        return $matches[1];
    }

    /** Six digits no step in the accepted window produces. */
    private static function wrongCodeFor(TotpSecret|string $secret, DateTimeImmutable $at): string
    {
        $secret = is_string($secret) ? TotpSecret::fromBase32($secret) : $secret;
        $valid = array_map(
            static fn (int $offset): string => Totp::codeAt($secret, $at->modify($offset . ' seconds')),
            [-Totp::PERIOD, 0, Totp::PERIOD],
        );
        for ($candidate = 0;; $candidate++) {
            $code = sprintf('%06d', $candidate);
            if (! in_array($code, $valid, true)) {
                return $code;
            }
        }
    }

    /**
     * @param list<AuthenticationMethod> $methods
     *
     * @return list<string>
     */
    private static function methods(array $methods): array
    {
        return array_map(static fn (AuthenticationMethod $method): string => $method->value, $methods);
    }
}
