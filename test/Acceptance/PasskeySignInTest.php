<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Primary\Http\Auth\LoginPages;
use Clavia\Application\Port\PasskeyVerifier;
use Clavia\Domain\Audit\AuditEvent;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Audit\AuditLog;
use Clavia\Domain\Audit\AuditQuery;
use Clavia\Domain\Authentication\Passkey\CoseAlgorithm;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\PasskeyId;
use Clavia\Domain\Authentication\Passkey\PasskeyName;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use Clavia\Domain\Authentication\Passkey\WebAuthnPurpose;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Base64Url;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\PageRequest;
use Clavia\Domain\Shared\RandomSource;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\SeededRandomSource;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\SoftwareAuthenticator;
use DateTimeImmutable;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Signing in with a passkey and nothing else (docs/design/passkeys.md §6.2): no address typed —
 * the passkey says whose account it is — and the same refusals as a password sign-in.
 *
 * The browser's part is played by a {@see SoftwareAuthenticator} that reads the options from the
 * login page as `passkeys.js` does, and answers as a discoverable credential would: naming its
 * owner by the user handle.
 */
final class PasskeySignInTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;

    private const string SESSION_COOKIE = 'clavia_session';

    private FrozenClock $clock;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->clock = $this->freezeClock();
    }

    public function testTheLoginPageOffersAPasskeyInTheAutofillAndBehindAButton(): void
    {
        $page = $this->get('/auth/login', ['state' => $this->storeLoginState('/oauth2/authorize?x')]);

        $body = (string) $page->getBody();
        self::assertStringContainsString('Sign in with a passkey', $body);
        self::assertStringContainsString('data-webauthn-conditional', $body);
        self::assertStringContainsString('autocomplete="username&#x20;webauthn"', $body);
        self::assertNotNull($this->cookie('clavia_webauthn'));
        $options = self::optionsOf($page);
        self::assertSame([], $options['allowCredentials'], 'Any discoverable passkey: the account is not known yet.');
        self::assertSame('required', $options['userVerification']);
        self::assertSame('auth.clavia.test', $options['rpId']);
    }

    public function testAPasskeySignsInWithoutAnAddressAndCountsAsMultiFactor(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256, synced: true);
        $user = $this->user();
        $this->passkeyOf($user, $authenticator);
        $state = $this->storeLoginState('/oauth2/authorize?resume');

        $signedIn = $this->signInWithPasskey($authenticator, $state, $user->id);

        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $signedIn->getStatusCode(),
            (string) $signedIn->getBody(),
        );
        self::assertSame('/oauth2/authorize?resume', $signedIn->getHeaderLine('Location'));
        self::assertSame(['swk', 'mfa'], $this->methods());
        self::assertNull($this->loginState($state), 'The handle has done its job.');
        self::assertNull($this->cookie('clavia_webauthn'));
    }

    public function testAPageReachedDirectlySignsInToo(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::EdDSA);
        $user = $this->user();
        $this->passkeyOf($user, $authenticator);

        $signedIn = $this->signInWithPasskey($authenticator, null, $user->id);

        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $signedIn->getStatusCode(),
            (string) $signedIn->getBody(),
        );
        self::assertSame(['hwk', 'mfa'], $this->methods());
    }

    public function testWithoutUserVerificationThePasskeyIsRefused(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $user = $this->user();
        $this->passkeyOf($user, $authenticator);

        $refused = $this->signInWithPasskey($authenticator, null, $user->id, userVerified: false);

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $refused->getStatusCode());
        self::assertNull($this->cookie(self::SESSION_COOKIE));
    }

    public function testWhenAPasskeyIsNotEnoughTheSecondFactorFollows(): void
    {
        $this->boot(['CLAVIA_PASSKEY_SATISFIES_MFA' => 'false']);
        $this->clock = $this->freezeClock();
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $user = $this->user();
        $this->passkeyOf($user, $authenticator);

        $signIn = $this->signInWithPasskey($authenticator, null, $user->id);

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $signIn->getStatusCode());
        self::assertSame('/auth/mfa', $signIn->getHeaderLine('Location'));
        self::assertNull($this->cookie(self::SESSION_COOKIE));
        self::assertNotNull($this->cookie('clavia_mfa'));
    }

    public function testAfterAPasskeyAPasskeyCannotBeTheSecondFactor(): void
    {
        $this->boot(['CLAVIA_PASSKEY_SATISFIES_MFA' => 'false']);
        $this->clock = $this->freezeClock();
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $user = $this->user();
        $this->passkeyOf($user, $authenticator);
        $this->signInWithPasskey($authenticator, null, $user->id);

        $page = $this->get('/auth/mfa');
        self::assertStringNotContainsString('data-webauthn-get', (string) $page->getBody());
        // Posted anyway, with a ceremony of the login page's kind, the same passkey is refused.
        $login = $this->get('/auth/login');
        $again = $this->post('/auth/mfa/passkey', [
            'credential' => $authenticator->authenticate($this->challengeFrom($login), $this->rp(), $user->id),
            'csrf_token' => self::csrfTokenFrom($page),
        ]);

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $again->getStatusCode());
        self::assertNull($this->cookie(self::SESSION_COOKIE));
    }

    /**
     * Every refusal is the wrong password's answer: one message, one status, a fresh form.
     *
     * @return iterable<string, array{string}>
     */
    public static function refusals(): iterable
    {
        yield 'a passkey Clavia does not know' => ['unknown'];
        yield 'a response that does not verify' => ['tampered'];
        yield 'a user handle that is not the owner' => ['other-owner'];
        yield 'no user handle at all' => ['no-handle'];
        yield 'a deactivated account' => ['deactivated'];
        yield 'an application that does not let the account in' => ['connection'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('refusals')]
    public function testARefusalLooksLikeAWrongPassword(string $case): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $user = $this->user();
        $this->passkeyOf($user, $authenticator);
        $state = null;
        $handle = $user->id;
        $answering = $authenticator;
        $origin = null;
        match ($case) {
            'unknown' => $answering = SoftwareAuthenticator::generate(CoseAlgorithm::ES256),
            'tampered' => $origin = 'https://evil.example',
            'other-owner' => $handle = UserId::generate(new SeededRandomSource(42)),
            'no-handle' => $handle = null,
            'deactivated' => $this->deactivate($user),
            'connection' => $state = $this->stateForAnApplicationWithoutThePool(),
            default => null,
        };

        $refused = $this->signInWithPasskey($answering, $state, $handle, origin: $origin);

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $refused->getStatusCode(), $case);
        self::assertStringContainsString(LoginPages::INVALID_CREDENTIALS, (string) $refused->getBody());
        self::assertStringContainsString('data-webauthn-get', (string) $refused->getBody(), 'A fresh ceremony.');
        self::assertNull($this->cookie(self::SESSION_COOKIE));
        self::assertCount(1, $this->audited(AuditEventType::SignInFailed), $case);
    }

    public function testTheReasonIsKeptForTheTrail(): void
    {
        $this->signInWithPasskey(SoftwareAuthenticator::generate(CoseAlgorithm::ES256), null, null);

        $failed = $this->audited(AuditEventType::SignInFailed);
        self::assertSame('unknown_passkey', $failed[0]->details['reason'] ?? null);
        self::assertNull($failed[0]->details['method'] ?? null, 'Of a passkey Clavia does not know, nothing is told.');
    }

    public function testACeremonyAnswersOnce(): void
    {
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $user = $this->user();
        $this->passkeyOf($user, $authenticator);
        $page = $this->get('/auth/login');
        $ceremony = $this->cookie('clavia_webauthn');
        $form = [
            'credential' => $authenticator->authenticate($this->challengeFrom($page), $this->rp(), $user->id),
            'state' => '',
            'csrf_token' => self::csrfTokenFrom($page),
        ];
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $this->post('/auth/passkey', $form)->getStatusCode());
        $this->clearCookies();

        $replayed = $this->request('POST', '/auth/passkey', [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Cookie' => 'clavia_webauthn=' . ($ceremony ?? '') . '; clavia_csrf=' . $form['csrf_token'],
        ], body: http_build_query($form));

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $replayed->getStatusCode());
    }

    public function testTheClientAddressIsThrottled(): void
    {
        $this->boot(['CLAVIA_LOGIN_MAX_ATTEMPTS' => '2']);
        $this->clock = $this->freezeClock();
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $user = $this->user();
        $this->passkeyOf($user, $authenticator);
        $stranger = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $this->signInWithPasskey($stranger, null, null);
        $this->signInWithPasskey($stranger, null, null);

        $genuine = $this->signInWithPasskey($authenticator, null, $user->id);

        self::assertSame(
            StatusCodeInterface::STATUS_UNAUTHORIZED,
            $genuine->getStatusCode(),
            'Throttled before the passkey is looked at.',
        );
        self::assertContains('throttled', array_map(
            static fn (AuditEvent $event): mixed => $event->details['reason'] ?? null,
            $this->audited(AuditEventType::SignInFailed),
        ));
    }

    public function testThePasskeySignInDoesNotExistWithPasskeysOff(): void
    {
        $this->boot(['CLAVIA_PASSKEYS_ENABLED' => 'false']);

        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $this->post('/auth/passkey', [])->getStatusCode());
        self::assertStringNotContainsString('data-webauthn', (string) $this->get('/auth/login')->getBody());
    }

    // ── What the tests above are made of ──────────────────────────────────────────────────────

    /** Read the options from the login page, sign them, post them: what `passkeys.js` does. */
    private function signInWithPasskey(
        SoftwareAuthenticator $authenticator,
        ?string $state,
        ?UserId $userHandle,
        bool $userVerified = true,
        ?string $origin = null,
    ): ResponseInterface {
        $page = $this->get('/auth/login', $state === null ? [] : ['state' => $state]);
        self::assertSame(StatusCodeInterface::STATUS_OK, $page->getStatusCode());

        return $this->post('/auth/passkey', [
            'credential' => $authenticator->authenticate(
                $this->challengeFrom($page),
                $this->rp(),
                $userHandle,
                origin: $origin,
                userVerified: $userVerified,
            ),
            'state' => $state ?? '',
            'csrf_token' => self::csrfTokenFrom($page),
        ]);
    }

    /**
     * @return array{rpId: string, userVerification: string, challenge: string, allowCredentials: list<mixed>}
     */
    private static function optionsOf(ResponseInterface $page): array
    {
        self::assertSame(1, preg_match('#data-webauthn-get="([^"]+)"#', (string) $page->getBody(), $match));
        /** @var array{rpId: string, userVerification: string, challenge: string, allowCredentials: list<mixed>} $o */
        $o = json_decode(html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5), true, flags: JSON_THROW_ON_ERROR);

        return $o;
    }

    private function challengeFrom(ResponseInterface $page): WebAuthnChallenge
    {
        return WebAuthnChallenge::reconstitute(
            Base64Url::decode(self::optionsOf($page)['challenge']),
            WebAuthnPurpose::SignIn,
            null,
            Digest::of('unused by the authenticator'),
            new DateTimeImmutable('+5 minutes'),
        );
    }

    /** @return list<string> */
    private function methods(): array
    {
        return array_map(
            static fn ($method): string => $method->value,
            $this->session($this->cookie(self::SESSION_COOKIE))?->methods ?? [],
        );
    }

    private function passkeyOf(User $user, SoftwareAuthenticator $authenticator): Passkey
    {
        $rp = $this->rp();
        $registration = WebAuthnChallenge::forRegistration(
            $this->container()->get(RandomSource::class),
            $user->id,
            $this->clock->now(),
            300,
        );
        $verified = $this->container()->get(PasskeyVerifier::class)->verifyRegistration(
            $authenticator->register($registration, $rp),
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
        $this->container()->get(PasskeyRepository::class)->save($passkey);

        return $passkey;
    }

    private function deactivate(User $user): void
    {
        $user->deactivate($this->clock->now());
        $this->container()->get(UserRepository::class)->save($user);
    }

    /** A login state for an application that lets nobody in through the default pool. */
    private function stateForAnApplicationWithoutThePool(): string
    {
        $client = $this->publicClient();
        $this->container()->get(ClientRepository::class)->save(
            $client->withConnections([ConnectionName::fromString('email')]),
        );

        return $this->storeLoginState('/oauth2/authorize?x', ClientId::fromString(self::TEST_CLIENT_ID)->value);
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
