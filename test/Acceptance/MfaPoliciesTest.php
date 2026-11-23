<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Application\Port\MailOutbox;
use Clavia\Domain\Authentication\Mfa\Totp;
use Clavia\Domain\Authentication\Mfa\TotpSecret;
use Clavia\Domain\Authentication\MfaPolicy;
use Clavia\Domain\Authentication\Passkey\CoseAlgorithm;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use Clavia\Domain\Authentication\Passkey\WebAuthnPurpose;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Base64Url;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\OidcFixtures;
use ClaviaTest\Support\SoftwareAuthenticator;
use DateTimeImmutable;
use Psr\Http\Message\ResponseInterface;

/**
 * MFA policies on applications and APIs, and enrolment on the way (docs/design/mfa-policies.md,
 * slice 3): a `required` application or API takes nobody in on one factor; a signed-in person
 * steps up, or — with no second factor and a verified address — sets one up and goes on.
 */
final class MfaPoliciesTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use MachineFixtures;
    use ManagementFixtures;
    use OidcFixtures;

    private const string MFA = 'http://schemas.openid.net/pape/policies/2007/06/multi-factor';

    private const string SESSION_COOKIE = 'clavia_session';

    private FrozenClock $clock;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->clock = $this->freezeClock();
    }

    // ── The Management API ──────────────────────────────────────────────────────

    public function testOperatorsSetThePolicyOnApplicationsAndApis(): void
    {
        $this->adminToken();

        $client = $this->api('POST', '/api/v1/clients', [
            'name' => 'Payroll',
            'redirect_uris' => ['https://payroll.test/cb'],
            'grant_types' => ['authorization_code'],
            'response_types' => ['code'],
            'mfa_policy' => 'required',
        ]);
        self::assertSame(201, $client->getStatusCode(), (string) $client->getBody());
        self::assertSame('required', self::document($client)['mfa_policy']);
        $path = '/api/v1/clients/' . rawurlencode((string) self::document($client)['client_id']);
        $patched = $this->api('PATCH', $path, ['mfa_policy' => 'optional']);
        self::assertSame('optional', self::document($patched)['mfa_policy']);
        self::assertSame(422, $this->api('PATCH', $path, ['mfa_policy' => 'sometimes'])->getStatusCode());

        $api = $this->api('POST', '/api/v1/resource-servers', ['identifier' => 'https://payroll.test/api/']);
        self::assertSame('optional', self::document($api)['mfa_policy']);
        $apiPath = '/api/v1/resource-servers/' . (string) self::document($api)['id'];
        $patchedApi = $this->api('PATCH', $apiPath, ['mfa_policy' => 'required']);
        self::assertSame('required', self::document($patchedApi)['mfa_policy']);
    }

    // ── Applications requiring MFA ──────────────────────────────────────────────

    public function testATwoFactorSignInIsLetInAsBefore(): void
    {
        $this->requiringClient();
        $secret = $this->appEnrolled();
        $this->post('/auth/logout');
        $this->submitLogin();
        $this->clock->advance(Totp::PERIOD);
        $page = $this->get('/auth/mfa');
        $this->post('/auth/mfa', [
            'code' => Totp::codeAt($secret, $this->clock->now()),
            'csrf_token' => self::csrfTokenFrom($page),
        ]);

        $idToken = $this->completeFlow('openid')['id_token'];

        self::assertIsString($idToken);
        self::assertSame(self::MFA, $this->verifiedIdToken($idToken)['claims']['acr']);
    }

    public function testAOneFactorSessionStepsUp(): void
    {
        $this->requiringClient();
        $this->appEnrolled();

        $response = $this->authorize();

        self::assertSame('/auth/mfa', $response->getHeaderLine('Location'));
    }

    public function testSomeoneWithNoSecondFactorSetsOneUpAndGoesOn(): void
    {
        $this->requiringClient();
        $this->verifiedUser();
        $this->submitLogin();
        $before = $this->session($this->cookie(self::SESSION_COOKIE));
        self::assertNotNull($before);
        [$verifier, $challenge] = $this->makePkcePair();

        $sent = $this->get('/oauth2/authorize', $this->authorizeParams($challenge, ['scope' => 'openid']));
        self::assertStringStartsWith('/auth/mfa/enroll?state=', $sent->getHeaderLine('Location'));
        $settings = $this->get($sent->getHeaderLine('Location'));
        self::assertStringContainsString(
            'Test public client requires two-factor authentication',
            (string) $settings->getBody(),
        );

        $setUp = $this->post('/auth/mfa/enroll', [
            'csrf_token' => self::csrfTokenFrom($settings),
            'state' => self::stateIn($settings),
        ]);
        self::assertSame(1, preg_match('#<p class="secret">([A-Z2-7]+)</p>#', (string) $setUp->getBody(), $match));
        $codes = $this->post('/auth/mfa/enroll/confirm', [
            'code' => Totp::codeAt(TotpSecret::fromBase32($match[1]), $this->clock->now()),
            'csrf_token' => self::csrfTokenFrom($setUp),
            'state' => self::stateIn($setUp),
        ]);
        self::assertSame(200, $codes->getStatusCode(), (string) $codes->getBody());

        // Confirming the app raised the session: the same sid, now with two factors.
        $after = $this->session($this->cookie(self::SESSION_COOKIE));
        self::assertNotNull($after);
        self::assertSame($before->sid, $after->sid);
        self::assertSame(['pwd', 'otp', 'mfa'], array_map(static fn ($m): string => $m->value, $after->methods));
        // And the owner is told.
        $mail = $this->container()->get(MailOutbox::class)->recent(1)[0] ?? null;
        self::assertNotNull($mail);
        self::assertSame(self::TEST_USER_EMAIL, $mail->to);
        self::assertStringContainsString('Two-factor authentication was turned on', $mail->subject);

        // Continue goes back to the request, which now gets its code.
        $continued = $this->post('/auth/mfa/enroll/continue', [
            'csrf_token' => self::csrfTokenFrom($codes),
            'state' => self::stateIn($codes),
        ]);
        self::assertStringStartsWith('/oauth2/authorize?', $continued->getHeaderLine('Location'));
        $code = $this->extractCode($this->get($continued->getHeaderLine('Location')));
        $tokens = self::json($this->post('/oauth2/token', $this->tokenRequest($code, $verifier)));
        self::assertIsString($tokens['id_token']);
        self::assertSame(self::MFA, $this->verifiedIdToken($tokens['id_token'])['claims']['acr']);
    }

    public function testAPasskeyCanBeSetUpOnTheWayInstead(): void
    {
        $this->requiringClient();
        $user = $this->verifiedUser();
        $this->submitLogin();
        $sent = $this->authorize();
        $settings = $this->get($sent->getHeaderLine('Location'));
        self::assertStringContainsString('Add a passkey instead', (string) $settings->getBody());

        $page = $this->post('/auth/passkeys/new', [
            'csrf_token' => self::csrfTokenFrom($settings),
            'state' => self::stateIn($settings),
        ]);
        self::assertSame(200, $page->getStatusCode(), (string) $page->getBody());
        self::assertSame(1, preg_match('#data-webauthn-create="([^"]+)"#', (string) $page->getBody(), $m));
        /** @var array{challenge: string} $options */
        $options = json_decode(html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5), true, flags: JSON_THROW_ON_ERROR);
        $codes = $this->post('/auth/passkeys', [
            'credential' => SoftwareAuthenticator::generate(CoseAlgorithm::ES256)->register(
                WebAuthnChallenge::reconstitute(
                    Base64Url::decode($options['challenge']),
                    WebAuthnPurpose::Registration,
                    $user->id,
                    null,
                    new DateTimeImmutable('+5 minutes'),
                ),
                $this->container()->get(RelyingParty::class),
            ),
            'name' => 'Laptop',
            'csrf_token' => self::csrfTokenFrom($page),
            'state' => self::stateIn($page),
        ]);
        self::assertSame(200, $codes->getStatusCode(), (string) $codes->getBody());

        // Back to the request, where the step-up asks for the passkey just made.
        $continued = $this->post('/auth/mfa/enroll/continue', [
            'csrf_token' => self::csrfTokenFrom($codes),
            'state' => self::stateIn($codes),
        ]);
        $again = $this->get($continued->getHeaderLine('Location'));
        self::assertSame('/auth/mfa', $again->getHeaderLine('Location'));
    }

    public function testEnrollingOutsideARequestRaisesNothingAndMailsNothing(): void
    {
        // Only on the way does the app's first code count as a second factor.
        $this->verifiedUser();
        $this->appEnrolled();

        $session = $this->session($this->cookie(self::SESSION_COOKIE));
        self::assertNotNull($session);
        self::assertSame(['pwd'], array_map(static fn ($m): string => $m->value, $session->methods));
        self::assertSame([], $this->container()->get(MailOutbox::class)->recent(5));
    }

    public function testAnUnverifiedAddressCannotSetOneUpOnTheWay(): void
    {
        // Trust on first use needs somewhere to send the notice.
        $this->requiringClient();
        $this->user();
        $this->submitLogin();

        self::assertSame(
            'unmet_authentication_requirements',
            self::locationQuery($this->authorize())['error'] ?? null,
        );
    }

    // ── APIs requiring MFA ──────────────────────────────────────────────────────

    public function testAnApiRequiringMfaRequiresItOfEveryApplication(): void
    {
        $this->publicClient();
        $api = $this->machineApi();
        $this->container()->get(ResourceServerRepository::class)->save($api->requiringMfa(MfaPolicy::Required));
        $this->appEnrolled();

        $forTheApi = $this->authorize(['scope' => 'openid api:read', 'audience' => self::TEST_M2M_AUDIENCE]);
        $forNoApi = $this->authorize();

        self::assertSame('/auth/mfa', $forTheApi->getHeaderLine('Location'));
        self::assertArrayHasKey('code', self::locationQuery($forNoApi));
    }

    public function testRefreshTokensIssuedBeforeThePolicyKeepWorking(): void
    {
        $this->refreshingClient();
        $this->user();
        $this->submitLogin();
        $refresh = $this->completeFlow('openid')['refresh_token'] ?? null;
        self::assertIsString($refresh);
        $this->requireMfaOf(self::TEST_CLIENT_ID);

        $refreshed = $this->post('/oauth2/token', [
            'grant_type' => 'refresh_token',
            'client_id' => self::TEST_CLIENT_ID,
            'refresh_token' => $refresh,
        ]);

        self::assertSame(200, $refreshed->getStatusCode(), (string) $refreshed->getBody());
    }

    // ── The device flow ─────────────────────────────────────────────────────────

    public function testTheDevicePageStepsUpToo(): void
    {
        $client = $this->container()->get(ClientRepository::class);
        $device = Client::register(
            ClientId::fromString('tv-app'),
            'Living room TV',
            ClientType::Public,
            ClientAuthMethod::None,
            null,
            [],
            [GrantType::DeviceCode],
            [],
            new DateTimeImmutable(),
            connections: [ConnectionName::defaultPool()],
            mfaPolicy: MfaPolicy::Required,
        );
        $client->save($device);
        $this->appEnrolled();
        $started = self::json($this->post('/oauth2/device/code', ['client_id' => 'tv-app', 'scope' => 'openid']));
        self::assertIsString($started['user_code']);
        $review = $this->get('/auth/device', ['user_code' => $started['user_code']]);

        $allowed = $this->post('/auth/device', [
            'user_code' => $started['user_code'],
            'decision' => 'allow',
            'csrf_token' => self::csrfTokenFrom($review),
        ]);

        self::assertSame('/auth/mfa', $allowed->getHeaderLine('Location'));
    }

    // ── What the tests above are made of ────────────────────────────────────────

    /** The test's public client, requiring more than one factor. */
    private function requiringClient(): void
    {
        $this->publicClient();
        $this->requireMfaOf(self::TEST_CLIENT_ID);
    }

    private function requireMfaOf(string $clientId): void
    {
        $clients = $this->container()->get(ClientRepository::class);
        $client = $clients->find(ClientId::fromString($clientId));
        self::assertNotNull($client);
        $clients->save($client->requiringMfa(MfaPolicy::Required));
    }

    private function verifiedUser(): User
    {
        $user = $this->user();
        $user->recordEmailVerification(true, $this->clock->now());
        $this->container()->get(UserRepository::class)->save($user);

        return $user;
    }

    /** Sign in with a password, then turn an authenticator app on: a one-factor session with a factor. */
    private function appEnrolled(): TotpSecret
    {
        $this->user();
        $this->submitLogin();
        $settings = $this->get('/auth/mfa/enroll');
        $setUp = $this->post('/auth/mfa/enroll', ['csrf_token' => self::csrfTokenFrom($settings)]);
        self::assertSame(1, preg_match('#<p class="secret">([A-Z2-7]+)</p>#', (string) $setUp->getBody(), $match));
        $secret = TotpSecret::fromBase32($match[1]);
        $this->post('/auth/mfa/enroll/confirm', [
            'code' => Totp::codeAt($secret, $this->clock->now()),
            'csrf_token' => self::csrfTokenFrom($setUp),
        ]);

        return $secret;
    }

    /**
     * @param array<string, string|null> $overrides
     */
    private function authorize(array $overrides = []): ResponseInterface
    {
        return $this->get('/oauth2/authorize', $this->authorizeParams($this->makePkcePair()[1], $overrides));
    }

    /** The held request's handle, as a page's forms carry it. */
    private static function stateIn(ResponseInterface $page): string
    {
        self::assertSame(1, preg_match('#name="state" value="([^"]+)"#', (string) $page->getBody(), $match));

        return html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5);
    }
}
