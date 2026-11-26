<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Domain\Audit\AuditEvent;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Audit\AuditLog;
use Clavia\Domain\Audit\AuditQuery;
use Clavia\Domain\Authentication\Mfa\RecoveryCodeRepository;
use Clavia\Domain\Authentication\Passkey\CoseAlgorithm;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use Clavia\Domain\Authentication\Passkey\WebAuthnPurpose;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Shared\Base64Url;
use Clavia\Domain\Shared\PageRequest;
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
 * Registering, renaming and removing passkeys from the account page (docs/design/passkeys.md
 * §6.1, §6.4), through the real pipeline.
 *
 * The browser's part is played by a {@see SoftwareAuthenticator}: it reads the options from the
 * page as `passkeys.js` would, makes a genuine credential, and the form posts it. Everything the
 * server decides is checked as a browser would meet it: the status, the page, the cookies.
 */
final class PasskeyRegistrationTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;

    private const string CEREMONY_COOKIE = 'clavia_webauthn';

    private FrozenClock $clock;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->clock = $this->freezeClock();
    }

    public function testThePageNeedsASessionAndComesBackAfterSigningIn(): void
    {
        $this->user();

        $response = $this->get('/auth/passkeys');

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        $state = self::locationQuery($response)['state'] ?? null;
        self::assertIsString($state);
        self::assertSame('/auth/passkeys', $this->loginState($state)?->nextUrl);
        self::assertSame('/auth/passkeys', $this->submitLogin(state: $state)->getHeaderLine('Location'));
    }

    public function testAGenuinePasskeyIsRegisteredWithRecoveryCodesWhenItIsTheFirstSecondFactor(): void
    {
        $user = $this->user();
        $this->submitLogin();

        $created = $this->registerPasskey(SoftwareAuthenticator::generate(CoseAlgorithm::ES256), 'Work laptop');

        self::assertSame(StatusCodeInterface::STATUS_OK, $created->getStatusCode(), (string) $created->getBody());
        self::assertStringContainsString('Your passkey is ready', (string) $created->getBody());
        self::assertSame(10, preg_match_all('#<li>[^<]+</li>#', (string) $created->getBody()));
        self::assertSame(10, $this->container()->get(RecoveryCodeRepository::class)->unusedCount($user->id));
        $passkeys = $this->passkeysOf($user);
        self::assertCount(1, $passkeys);
        self::assertSame('Work laptop', $passkeys[0]->name->value);
        self::assertNull($this->cookie(self::CEREMONY_COOKIE), 'The ceremony cookie is spent.');
        $registered = $this->audited(AuditEventType::PasskeyRegistered);
        self::assertCount(1, $registered);
        self::assertSame('Work laptop', $registered[0]->details['name'] ?? null);

        $list = $this->get('/auth/passkeys');
        self::assertStringContainsString('Work laptop', (string) $list->getBody());
        self::assertStringContainsString('On one device', (string) $list->getBody());
    }

    public function testASecondPasskeyBringsNoNewCodesAndAnUnnamedOneIsNamedForItsDate(): void
    {
        $user = $this->user();
        $this->submitLogin();
        $this->registerPasskey(SoftwareAuthenticator::generate(CoseAlgorithm::EdDSA), 'First');
        // A second later: passkeys are listed oldest first, and two made at one instant have no order.
        $this->clock->advance(1);

        $second = $this->registerPasskey(SoftwareAuthenticator::generate(CoseAlgorithm::RS256, synced: true), '');

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $second->getStatusCode(), (string) $second->getBody());
        self::assertSame('/auth/passkeys', $second->getHeaderLine('Location'));
        $passkeys = $this->passkeysOf($user);
        self::assertCount(2, $passkeys);
        self::assertSame('Passkey added 15 Jan 2026', $passkeys[1]->name->value);
        self::assertTrue($passkeys[1]->isSynced());
        $list = (string) $this->get('/auth/passkeys')->getBody();
        self::assertStringContainsString('Synced across your devices', $list);
    }

    public function testTheOptionsNameTheAccountByItsHandleAndExcludeItsPasskeys(): void
    {
        $user = $this->user();
        $this->submitLogin();
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $this->registerPasskey($authenticator, 'First');

        $options = self::optionsOf($this->beginRegistration());

        self::assertSame('auth.clavia.test', $options['rp']['id']);
        self::assertSame(Base64Url::encode($user->id->toBytes()), $options['user']['id']);
        self::assertSame(self::TEST_USER_EMAIL, $options['user']['name']);
        self::assertSame([-8, -7, -257], array_column($options['pubKeyCredParams'], 'alg'));
        self::assertSame(
            [Base64Url::encode($authenticator->credentialId)],
            array_column($options['excludeCredentials'], 'id'),
        );
        self::assertSame('required', $options['authenticatorSelection']['residentKey']);
        self::assertSame('required', $options['authenticatorSelection']['userVerification']);
        self::assertSame('none', $options['attestation']);
        self::assertSame(300000, $options['timeout']);
    }

    public function testOnlyThePageThatMakesAPasskeyRunsScriptAndItRunsNothingElse(): void
    {
        $this->user();
        $this->submitLogin();

        $list = $this->get('/auth/passkeys');
        $create = $this->beginRegistration();

        self::assertStringNotContainsString('script-src', $list->getHeaderLine('Content-Security-Policy'));
        self::assertStringNotContainsString('<script', (string) $list->getBody());
        $policy = $create->getHeaderLine('Content-Security-Policy');
        self::assertStringContainsString("script-src 'self'", $policy);
        self::assertStringContainsString("require-trusted-types-for 'script'", $policy);
        self::assertStringContainsString("trusted-types 'none'", $policy);
        self::assertStringContainsString("default-src 'none'", $policy);
        self::assertSame(
            1,
            preg_match_all('#<script\b#', (string) $create->getBody()),
            'One script, the module, and no inline one.',
        );
        $module = '#<script type="module" src="([^"]+)"></script>#';
        self::assertSame(1, preg_match($module, (string) $create->getBody(), $src));
        self::assertSame('/auth/static/passkeys.js', html_entity_decode($src[1], ENT_QUOTES | ENT_HTML5));
        self::assertSame(
            'publickey-credentials-create=(self), publickey-credentials-get=(self)',
            $create->getHeaderLine('Permissions-Policy'),
        );
    }

    public function testAResponseThatDoesNotVerifyIsRefusedAndAddsNothing(): void
    {
        $user = $this->user();
        $this->submitLogin();
        $page = $this->beginRegistration();
        $challenge = $this->challengeFrom($page, $user);

        $refused = $this->post('/auth/passkeys', [
            'credential' => SoftwareAuthenticator::generate(CoseAlgorithm::ES256)->register(
                $challenge,
                $this->rp(),
                origin: 'https://evil.example',
            ),
            'name' => 'Phished',
            'csrf_token' => self::csrfTokenFrom($page),
        ]);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $refused->getStatusCode());
        self::assertStringContainsString('That did not work.', (string) $refused->getBody());
        self::assertSame([], $this->passkeysOf($user));
        self::assertSame([], $this->audited(AuditEventType::PasskeyRegistered));
    }

    public function testACeremonyAnswersOnceEvenWithAGenuineResponse(): void
    {
        $user = $this->user();
        $this->submitLogin();
        $page = $this->beginRegistration();
        $handle = $this->cookie(self::CEREMONY_COOKIE);
        self::assertNotNull($handle);
        $form = [
            'credential' => SoftwareAuthenticator::generate(CoseAlgorithm::ES256)->register(
                $this->challengeFrom($page, $user),
                $this->rp(),
            ),
            'name' => 'Once',
            'csrf_token' => self::csrfTokenFrom($page),
        ];
        $this->post('/auth/passkeys', $form);

        // The same answer again, as if the browser had kept the ceremony's cookie.
        $replayed = $this->request(RequestMethodInterface::METHOD_POST, '/auth/passkeys', [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Cookie' => implode('; ', [
                'clavia_session=' . ($this->cookie('clavia_session') ?? ''),
                'clavia_csrf=' . ($this->cookie('clavia_csrf') ?? ''),
                self::CEREMONY_COOKIE . '=' . $handle,
            ]),
        ], body: http_build_query($form));

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $replayed->getStatusCode());
        self::assertCount(1, $this->passkeysOf($user));
    }

    public function testACeremonyExpiresAfterItsLifetime(): void
    {
        $user = $this->user();
        $this->submitLogin();
        $page = $this->beginRegistration();
        $credential = SoftwareAuthenticator::generate(CoseAlgorithm::ES256)->register(
            $this->challengeFrom($page, $user),
            $this->rp(),
        );

        $this->clock->advance(301);
        $late = $this->post('/auth/passkeys', [
            'credential' => $credential,
            'name' => 'Late',
            'csrf_token' => self::csrfTokenFrom($page),
        ]);

        self::assertNotSame(StatusCodeInterface::STATUS_OK, $late->getStatusCode());
        self::assertSame([], $this->passkeysOf($user));
    }

    public function testThePasskeyAlreadyRegisteredIsRefusedAsSuch(): void
    {
        $user = $this->user();
        $this->submitLogin();
        $authenticator = SoftwareAuthenticator::generate(CoseAlgorithm::ES256);
        $this->registerPasskey($authenticator, 'First');

        $again = $this->registerPasskey($authenticator, 'Again');

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $again->getStatusCode());
        self::assertStringContainsString('already registered', (string) $again->getBody());
        self::assertCount(1, $this->passkeysOf($user));
    }

    public function testAddingAPasskeyNeedsARecentSignIn(): void
    {
        $user = $this->user();
        $this->submitLogin();
        $this->clock->advance(601);

        $begin = $this->post('/auth/passkeys/new', ['csrf_token' => self::csrfTokenFrom($this->get('/auth/passkeys'))]);

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $begin->getStatusCode());
        self::assertStringStartsWith('/auth/login?state=', $begin->getHeaderLine('Location'));
        $state = self::locationQuery($begin)['state'] ?? '';
        self::assertSame('/auth/passkeys', $this->submitLogin(state: $state)->getHeaderLine('Location'));
        self::assertSame(
            StatusCodeInterface::STATUS_OK,
            $this->beginRegistration()->getStatusCode(),
            'Signed in again, it works.',
        );
        self::assertSame([], $this->passkeysOf($user));
    }

    public function testAPostWithoutItsCsrfTokenChangesNothing(): void
    {
        $user = $this->user();
        $this->submitLogin();
        // The login page opened a sign-in ceremony of its own: whatever the cookie holds now.
        $before = $this->cookie(self::CEREMONY_COOKIE);

        $begin = $this->post('/auth/passkeys/new', []);

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $begin->getStatusCode());
        self::assertSame('/auth/passkeys', $begin->getHeaderLine('Location'));
        self::assertSame($before, $this->cookie(self::CEREMONY_COOKIE), 'No registration ceremony was opened.');
        self::assertSame([], $this->passkeysOf($user));
    }

    public function testTheLimitStopsTheNextPasskey(): void
    {
        $this->boot(['CLAVIA_PASSKEY_MAX_PER_USER' => '1']);
        $this->clock = $this->freezeClock();
        $user = $this->user();
        $this->submitLogin();
        $this->registerPasskey(SoftwareAuthenticator::generate(CoseAlgorithm::ES256), 'Only');

        $begin = $this->post('/auth/passkeys/new', ['csrf_token' => self::csrfTokenFrom($this->get('/auth/passkeys'))]);

        self::assertSame(StatusCodeInterface::STATUS_CONFLICT, $begin->getStatusCode());
        self::assertStringContainsString('as many as it may', (string) $begin->getBody());
        self::assertCount(1, $this->passkeysOf($user));
    }

    public function testAPasskeyIsRenamedAndRemovedByItsOwnerOnly(): void
    {
        $user = $this->user();
        $this->submitLogin();
        $this->registerPasskey(SoftwareAuthenticator::generate(CoseAlgorithm::ES256), 'Old name');
        $passkey = $this->passkeysOf($user)[0];
        $csrf = self::csrfTokenFrom($this->get('/auth/passkeys'));

        $renamed = $this->post('/auth/passkeys/' . $passkey->id->value . '/name', [
            'name' => 'New name',
            'csrf_token' => $csrf,
        ]);
        $badName = $this->post('/auth/passkeys/' . $passkey->id->value . '/name', [
            'name' => "  \n ",
            'csrf_token' => $csrf,
        ]);
        $unknown = $this->post('/auth/passkeys/00000000-0000-4000-8000-000000000009/remove', ['csrf_token' => $csrf]);
        $malformed = $this->post('/auth/passkeys/not-an-id/remove', ['csrf_token' => $csrf]);

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $renamed->getStatusCode());
        self::assertSame('New name', $this->passkeysOf($user)[0]->name->value);
        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $badName->getStatusCode());
        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $unknown->getStatusCode());
        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $malformed->getStatusCode());

        $removed = $this->post('/auth/passkeys/' . $passkey->id->value . '/remove', ['csrf_token' => $csrf]);

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $removed->getStatusCode());
        self::assertSame([], $this->passkeysOf($user));
        self::assertCount(1, $this->audited(AuditEventType::PasskeyRenamed));
        self::assertCount(1, $this->audited(AuditEventType::PasskeyRemoved));
    }

    public function testWithPasskeysOffThePagesDoNotExist(): void
    {
        $this->boot(['CLAVIA_PASSKEYS_ENABLED' => 'false']);
        $this->user();
        $this->submitLogin();

        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $this->get('/auth/passkeys')->getStatusCode());
    }

    // ── What the tests above are made of ──────────────────────────────────────────────────────

    /** Open a ceremony, make the credential, post it: what a person and `passkeys.js` do together. */
    private function registerPasskey(SoftwareAuthenticator $authenticator, string $name): ResponseInterface
    {
        $page = $this->beginRegistration();

        return $this->post('/auth/passkeys', [
            'credential' => $authenticator->register($this->challengeFrom($page, $this->user()), $this->rp()),
            'name' => $name,
            'csrf_token' => self::csrfTokenFrom($page),
        ]);
    }

    private function beginRegistration(): ResponseInterface
    {
        $page = $this->post('/auth/passkeys/new', ['csrf_token' => self::csrfTokenFrom($this->get('/auth/passkeys'))]);
        self::assertSame(StatusCodeInterface::STATUS_OK, $page->getStatusCode(), (string) $page->getBody());

        return $page;
    }

    /**
     * The options the page carries, as `passkeys.js` reads them from its form.
     *
     * @return array{rp: array{id: string}, user: array{id: string, name: string}, challenge: string,
     *     pubKeyCredParams: list<array{alg: int}>, excludeCredentials: list<array{id: string}>,
     *     authenticatorSelection: array{residentKey: string, userVerification: string},
     *     attestation: string, timeout: int}
     */
    private static function optionsOf(ResponseInterface $page): array
    {
        self::assertSame(1, preg_match('#data-webauthn-create="([^"]+)"#', (string) $page->getBody(), $match));
        /** @var array{rp: array{id: string}, user: array{id: string, name: string}, challenge: string,
         *     pubKeyCredParams: list<array{alg: int}>, excludeCredentials: list<array{id: string}>,
         *     authenticatorSelection: array{residentKey: string, userVerification: string},
         *     attestation: string, timeout: int} $options */
        $options = json_decode(html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5), true, flags: JSON_THROW_ON_ERROR);

        return $options;
    }

    /** The challenge the page asks the browser to sign, as the authenticator needs it. */
    private function challengeFrom(ResponseInterface $page, User $user): WebAuthnChallenge
    {
        return WebAuthnChallenge::reconstitute(
            Base64Url::decode(self::optionsOf($page)['challenge']),
            WebAuthnPurpose::Registration,
            $user->id,
            null,
            new DateTimeImmutable('+5 minutes'),
        );
    }

    private function rp(): RelyingParty
    {
        return $this->container()->get(RelyingParty::class);
    }

    /** @return list<Passkey> */
    private function passkeysOf(User $user): array
    {
        return $this->container()->get(PasskeyRepository::class)->ofUser($user->id);
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
