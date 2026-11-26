<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Application\Port\PasskeyVerifier;
use Clavia\Domain\Audit\AuditEvent;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Audit\AuditLog;
use Clavia\Domain\Audit\AuditQuery;
use Clavia\Domain\Authentication\Mfa\RecoveryCode;
use Clavia\Domain\Authentication\Mfa\RecoveryCodeRepository;
use Clavia\Domain\Authentication\Passkey\CoseAlgorithm;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\PasskeyId;
use Clavia\Domain\Authentication\Passkey\PasskeyName;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use Clavia\Domain\Authentication\Passkey\WebAuthnPurpose;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Shared\Base64Url;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\PageRequest;
use Clavia\Domain\Shared\RandomSource;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\SoftwareAuthenticator;
use DateTimeImmutable;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * A passkey as the second factor of a sign-in (docs/design/passkeys.md §6.3), through the real
 * pipeline: a password, then the passkey, with every refusal counted as a wrong code is.
 *
 * The browser's part is played by a {@see SoftwareAuthenticator} that reads the options from the
 * page as `passkeys.js` does.
 */
final class PasskeySecondFactorTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;

    private const string SESSION_COOKIE = 'clavia_session';

    private const string MFA_COOKIE = 'clavia_mfa';

    private FrozenClock $clock;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->clock = $this->freezeClock();
    }

    public function testAnAccountWithAPasskeyIsAskedForItAfterItsPassword(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $this->passkeyOf($this->user(), $authenticator);

        $signIn = $this->submitLogin(nextUrl: '/oauth2/authorize?next');

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $signIn->getStatusCode());
        self::assertSame('/auth/mfa', $signIn->getHeaderLine('Location'));
        self::assertNull($this->cookie(self::SESSION_COOKIE), 'No session before the second factor.');
        $page = $this->get('/auth/mfa');
        self::assertSame(StatusCodeInterface::STATUS_OK, $page->getStatusCode());
        self::assertStringContainsString('Use a passkey', (string) $page->getBody());
        // No authenticator app: the code the page asks for is a recovery code.
        self::assertStringContainsString('Recovery code', (string) $page->getBody());
        self::assertStringContainsString("script-src 'self'", $page->getHeaderLine('Content-Security-Policy'));
        $options = self::optionsOf($page);
        self::assertSame('auth.clavia.test', $options['rpId']);
        self::assertSame('preferred', $options['userVerification']);
        self::assertSame(
            [Base64Url::encode($authenticator->credentialId)],
            array_column($options['allowCredentials'], 'id'),
        );
    }

    public function testTheRightPasskeyFinishesTheSignInAndItsMethodsAreInAmr(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::EdDSA);
        $user = $this->user();
        $passkey = $this->passkeyOf($user, $authenticator);
        $this->submitLogin(nextUrl: '/auth/after');

        $answered = $this->answerWithPasskey($authenticator, $user, signCount: 4);

        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $answered->getStatusCode(),
            (string) $answered->getBody(),
        );
        self::assertSame('/auth/after', $answered->getHeaderLine('Location'));
        $session = $this->session($this->cookie(self::SESSION_COOKIE));
        self::assertNotNull($session);
        self::assertSame(['pwd', 'hwk', 'mfa'], array_map(static fn ($m): string => $m->value, $session->methods));
        self::assertNull($this->cookie(self::MFA_COOKIE));
        self::assertSame(4, $this->passkeys()->one($passkey->id)?->signCount);
        self::assertNotNull($this->passkeys()->one($passkey->id)?->lastUsedAt);
    }

    public function testASyncedPasskeyUsedWithoutVerificationSaysSo(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256, synced: true);
        $user = $this->user();
        $this->passkeyOf($user, $authenticator);
        $this->submitLogin(nextUrl: '/auth/after');

        $this->answerWithPasskey($authenticator, $user, signCount: 0, userVerified: false);

        $session = $this->session($this->cookie(self::SESSION_COOKIE));
        self::assertSame(
            ['pwd', 'swk', 'user', 'mfa'],
            array_map(static fn ($m): string => $m->value, $session?->methods ?? []),
        );
    }

    public function testAPasskeyOfAnotherAccountIsRefusedAndCounted(): void
    {
        $user = $this->user();
        $this->passkeyOf($user, SoftwareAuthenticator::generate(CoseAlgorithm::ES256));
        $stranger = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $this->submitLogin();

        $refused = $this->answerWithPasskey($stranger, $user);

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $refused->getStatusCode());
        self::assertStringContainsString('That passkey did not work', (string) $refused->getBody());
        self::assertNull($this->cookie(self::SESSION_COOKIE));
        $failed = $this->audited(AuditEventType::SignInFailed);
        self::assertCount(1, $failed);
        self::assertSame('unknown_passkey', $failed[0]->details['reason'] ?? null);
    }

    public function testAResponseThatDoesNotVerifyIsRefused(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $user = $this->user();
        $this->passkeyOf($user, $authenticator);
        $this->submitLogin();

        $refused = $this->answerWithPasskey($authenticator, $user, origin: 'https://evil.example');

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $refused->getStatusCode());
        self::assertSame(
            'wrong_second_factor',
            $this->audited(AuditEventType::SignInFailed)[0]->details['reason'] ?? null,
        );
    }

    public function testACounterThatWentBackIsRefusedAuditedAndLeavesThePasskey(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $user = $this->user();
        $passkey = $this->passkeyOf($user, $authenticator, signCount: 10);
        $this->submitLogin();

        $refused = $this->answerWithPasskey($authenticator, $user, signCount: 3);

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $refused->getStatusCode());
        $regressed = $this->audited(AuditEventType::PasskeyCounterRegressed);
        self::assertCount(1, $regressed);
        self::assertSame(10, $regressed[0]->details['stored'] ?? null);
        self::assertSame(3, $regressed[0]->details['presented'] ?? null);
        self::assertSame(10, $this->passkeys()->one($passkey->id)?->signCount);
    }

    public function testFailuresUseUpTheChallengeLikeWrongCodes(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $user = $this->user();
        $this->passkeyOf($user, $authenticator);
        $this->submitLogin();

        for ($attempt = 1; $attempt < 5; $attempt++) {
            $refused = $this->answerWithPasskey($authenticator, $user, origin: 'https://evil.example');
            self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $refused->getStatusCode());
        }
        $last = $this->answerWithPasskey($authenticator, $user, origin: 'https://evil.example');

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $last->getStatusCode());
        self::assertSame('/auth/login', $last->getHeaderLine('Location'));
    }

    public function testACeremonyAnswersOnce(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $user = $this->user();
        $this->passkeyOf($user, $authenticator);
        $this->submitLogin();
        $page = $this->get('/auth/mfa');
        $ceremony = $this->cookie('clavia_webauthn');
        $form = [
            'credential' => $authenticator->authenticate($this->challengeFrom($page, $user), $this->rp(), $user->id),
            'csrf_token' => self::csrfTokenFrom($page),
        ];
        // Refused once (by origin), the ceremony is spent: the same cookie cannot be answered again.
        $this->post('/auth/mfa/passkey', [
            'credential' => $authenticator->authenticate(
                $this->challengeFrom($page, $user),
                $this->rp(),
                $user->id,
                origin: 'https://evil.example',
            ),
            'csrf_token' => self::csrfTokenFrom($page),
        ]);

        $replayed = $this->request(RequestMethodInterface::METHOD_POST, '/auth/mfa/passkey', [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Cookie' => implode('; ', [
                self::MFA_COOKIE . '=' . ($this->cookie(self::MFA_COOKIE) ?? ''),
                'clavia_csrf=' . ($this->cookie('clavia_csrf') ?? ''),
                'clavia_webauthn=' . ($ceremony ?? ''),
            ]),
        ], body: http_build_query($form));

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $replayed->getStatusCode());
        self::assertNull($this->cookie(self::SESSION_COOKIE));
    }

    public function testARecoveryCodeAnswersForAnAccountWhoseOnlySecondFactorIsAPasskey(): void
    {
        $user = $this->user();
        $this->passkeyOf($user, SoftwareAuthenticator::generate(CoseAlgorithm::ES256));
        $this->container()->get(RecoveryCodeRepository::class)->replaceAll(
            $user->id,
            [RecoveryCode::digest('abcd-efgh-jkmn')],
            $this->clock->now(),
        );
        $this->submitLogin(nextUrl: '/auth/after');
        $page = $this->get('/auth/mfa');

        $answered = $this->post('/auth/mfa', ['code' => 'abcd-efgh-jkmn', 'csrf_token' => self::csrfTokenFrom($page)]);

        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $answered->getStatusCode(),
            (string) $answered->getBody(),
        );
        self::assertSame(['pwd', 'mfa'], array_map(
            static fn ($m): string => $m->value,
            $this->session($this->cookie(self::SESSION_COOKIE))?->methods ?? [],
        ));
    }

    public function testWithPasskeysOffAPasskeyAsksForNothing(): void
    {
        $this->boot(['CLAVIA_PASSKEYS_ENABLED' => 'false']);
        $this->clock = $this->freezeClock();
        $user = $this->user();
        $this->passkeyOf($user, SoftwareAuthenticator::generate(CoseAlgorithm::ES256));

        $signIn = $this->submitLogin(nextUrl: '/auth/after');

        self::assertSame('/auth/after', $signIn->getHeaderLine('Location'));
        self::assertNotNull($this->session($this->cookie(self::SESSION_COOKIE)));
    }

    public function testTheTwoFactorSettingsShowThePasskeys(): void
    {
        $user = $this->user();
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $this->passkeyOf($user, $authenticator);
        $this->submitLogin();
        $this->answerWithPasskey($authenticator, $user);

        $settings = (string) $this->get('/auth/mfa/enroll')->getBody();

        self::assertStringContainsString('On, with a passkey', $settings);
        self::assertStringContainsString('You have 1 passkey.', $settings);
        self::assertStringContainsString('action="/auth/passkeys"', $settings);
    }

    // ── What the tests above are made of ──────────────────────────────────────────────────────

    /** Read the options from the second-factor page, sign them, post them: what `passkeys.js` does. */
    private function answerWithPasskey(
        SoftwareAuthenticator $authenticator,
        User $user,
        int $signCount = 1,
        bool $userVerified = true,
        ?string $origin = null,
    ): ResponseInterface {
        $page = $this->get('/auth/mfa');
        self::assertSame(StatusCodeInterface::STATUS_OK, $page->getStatusCode(), (string) $page->getBody());

        return $this->post('/auth/mfa/passkey', [
            'credential' => $authenticator->authenticate(
                $this->challengeFrom($page, $user),
                $this->rp(),
                $user->id,
                signCount: $signCount,
                origin: $origin,
                userVerified: $userVerified,
            ),
            'csrf_token' => self::csrfTokenFrom($page),
        ]);
    }

    /**
     * @return array{rpId: string, userVerification: string, challenge: string,
     *     allowCredentials: list<array{id: string}>}
     */
    private static function optionsOf(ResponseInterface $page): array
    {
        self::assertSame(1, preg_match('#data-webauthn-get="([^"]+)"#', (string) $page->getBody(), $match));
        /** @var array{rpId: string, userVerification: string, challenge: string,
         *     allowCredentials: list<array{id: string}>} $options */
        $options = json_decode(html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5), true, flags: JSON_THROW_ON_ERROR);

        return $options;
    }

    private function challengeFrom(ResponseInterface $page, User $user): WebAuthnChallenge
    {
        return WebAuthnChallenge::reconstitute(
            Base64Url::decode(self::optionsOf($page)['challenge']),
            WebAuthnPurpose::SecondFactor,
            $user->id,
            Digest::of('unused by the authenticator'),
            new DateTimeImmutable('+5 minutes'),
        );
    }

    /** A passkey of this authenticator on the account, as a registration would have made it. */
    private function passkeyOf(User $user, SoftwareAuthenticator $authenticator, int $signCount = 0): Passkey
    {
        $rp = $this->rp();
        $registration = WebAuthnChallenge::forRegistration(
            $this->container()->get(RandomSource::class),
            $user->id,
            $this->clock->now(),
            300,
        );
        $verified = $this->container()->get(PasskeyVerifier::class)->verifyRegistration(
            $authenticator->register($registration, $rp, signCount: $signCount),
            $registration,
            $rp,
        );
        $passkey = Passkey::register(
            PasskeyId::generate($this->container()->get(RandomSource::class)),
            $user->id,
            $verified->credentialId,
            $verified->publicKey,
            $verified->algorithm,
            $verified->signCount,
            $verified->transports,
            $verified->aaguid,
            $verified->backupEligible,
            $verified->backedUp,
            PasskeyName::fromString('Key'),
            $this->clock->now(),
        );
        $this->passkeys()->save($passkey);

        return $passkey;
    }

    private function passkeys(): PasskeyRepository
    {
        return $this->container()->get(PasskeyRepository::class);
    }

    private function rp(): RelyingParty
    {
        return $this->container()->get(RelyingParty::class);
    }

    /** @return list<AuditEvent> */
    private function audited(AuditEventType $type): array
    {
        return $this->container()->get(AuditLog::class)->page(
            new AuditQuery(types: [$type]),
            PageRequest::of(1, 50),
        )->items;
    }
}
