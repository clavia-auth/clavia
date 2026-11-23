<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Domain\Authentication\Mfa\Totp;
use Clavia\Domain\Authentication\Mfa\TotpSecret;
use Clavia\Domain\ResourceServer\AccessTokenFormat;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\OidcFixtures;
use Psr\Http\Message\ResponseInterface;

/**
 * Authentication levels in tokens (docs/design/mfa-policies.md, slice 1): the `acr` of a
 * sign-in and its `auth_time`, in the ID token (OIDC Core §2), the JWT access token and
 * introspection (RFC 9470 §6), refresh included, and the values discovery lists.
 */
final class AuthenticationLevelsTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use MachineFixtures;
    use OidcFixtures;

    private const string MFA = 'http://schemas.openid.net/pape/policies/2007/06/multi-factor';

    private FrozenClock $clock;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->clock = $this->freezeClock();
    }

    public function testDiscoveryListsTheLevelsWeakestFirst(): void
    {
        $document = self::json($this->get('/.well-known/openid-configuration'));

        // No `phrh`: without attestation, a key's hardware is only its own word.
        self::assertSame([self::MFA, 'phr'], $document['acr_values_supported']);
        self::assertIsArray($document['claims_supported']);
        self::assertContains('acr', $document['claims_supported']);
    }

    public function testAPasswordAloneIsNoLevel(): void
    {
        $this->user();
        $this->refreshingClient();
        $this->submitLogin();

        $idToken = $this->completeFlow('openid')['id_token'];
        self::assertIsString($idToken);
        $claims = $this->verifiedIdToken($idToken)['claims'];

        self::assertSame(['pwd'], $claims['amr']);
        self::assertArrayNotHasKey('acr', $claims);
    }

    public function testATwoFactorSignInIsReportedOnEveryToken(): void
    {
        $this->user();
        $this->refreshingClient();
        $this->container()->get(ResourceServerRepository::class)
            ->save($this->machineApi()->issuingAccessTokensAs(AccessTokenFormat::Jwt));
        $this->signInWithAnApp();
        $signedInAt = $this->clock->now()->getTimestamp();
        $this->clock->advance(120);

        $tokens = $this->completeFlow('openid api:read', ['audience' => self::TEST_M2M_AUDIENCE]);

        self::assertIsString($tokens['id_token']);
        $idToken = $this->verifiedIdToken($tokens['id_token'])['claims'];
        self::assertSame(self::MFA, $idToken['acr']);
        self::assertSame($signedInAt, $idToken['auth_time']);

        self::assertIsString($tokens['access_token']);
        $accessToken = $this->verifiedJwt($tokens['access_token'])['claims'];
        self::assertSame(self::MFA, $accessToken['acr']);
        self::assertSame($signedInAt, $accessToken['auth_time']);

        $introspected = self::json($this->introspect($tokens['access_token']));
        self::assertSame(self::MFA, $introspected['acr']);
        self::assertSame($signedInAt, $introspected['auth_time']);

        // RFC 9470 §6.1: a refreshed token keeps the sign-in that started its family.
        $this->clock->advance(600);
        self::assertIsString($tokens['refresh_token']);
        $refreshed = self::json($this->post('/oauth2/token', [
            'grant_type' => 'refresh_token',
            'client_id' => self::TEST_CLIENT_ID,
            'refresh_token' => $tokens['refresh_token'],
        ]));
        self::assertIsString($refreshed['access_token']);
        $again = $this->verifiedJwt($refreshed['access_token'])['claims'];
        self::assertSame(self::MFA, $again['acr']);
        self::assertSame($signedInAt, $again['auth_time']);
        self::assertSame(self::MFA, self::json($this->introspect($refreshed['access_token']))['acr']);
    }

    public function testAMachineTokenSaysNothingOfASignIn(): void
    {
        $this->machineApi();
        $token = self::json($this->requestMachineToken())['access_token'];
        self::assertIsString($token);

        $introspected = self::json($this->introspect($token));

        self::assertTrue($introspected['active']);
        self::assertArrayNotHasKey('acr', $introspected);
        self::assertArrayNotHasKey('auth_time', $introspected);
    }

    /** Turn an authenticator app on, sign out, and sign in again with a password and the app. */
    private function signInWithAnApp(): void
    {
        $this->submitLogin();
        $settings = $this->get('/auth/mfa/enroll');
        $setUp = $this->post('/auth/mfa/enroll', ['csrf_token' => self::csrfTokenFrom($settings)]);
        self::assertSame(1, preg_match('#<p class="secret">([A-Z2-7]+)</p>#', (string) $setUp->getBody(), $match));
        $secret = TotpSecret::fromBase32($match[1]);
        $this->post('/auth/mfa/enroll/confirm', [
            'code' => Totp::codeAt($secret, $this->clock->now()),
            'csrf_token' => self::csrfTokenFrom($setUp),
        ]);
        $this->post('/auth/logout');

        $this->submitLogin();
        // Confirming spent the current step.
        $this->clock->advance(Totp::PERIOD);
        $page = $this->get('/auth/mfa');
        $done = $this->post('/auth/mfa', [
            'code' => Totp::codeAt($secret, $this->clock->now()),
            'csrf_token' => self::csrfTokenFrom($page),
        ]);
        self::assertSame(303, $done->getStatusCode(), (string) $done->getBody());
    }

    private function introspect(string $token): ResponseInterface
    {
        return $this->post(
            '/oauth2/introspect',
            ['token' => $token],
            basicAuth: [self::TEST_M2M_CLIENT_ID, self::TEST_M2M_SECRET],
        );
    }
}
