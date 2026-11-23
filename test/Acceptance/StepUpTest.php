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
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Mfa\Totp;
use Clavia\Domain\Authentication\Mfa\TotpSecret;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\UserRepository;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\OidcFixtures;
use ClaviaTest\Support\TestStorage;
use Psr\Http\Message\ResponseInterface;

/**
 * `acr_values` and step-up (docs/design/mfa-policies.md, slice 2): a request asking for a
 * stronger sign-in than the session has sends the person for one more factor, and their
 * session is raised in place — the same `sid`, a new identifier, the same absolute expiry —
 * without signing in again from scratch. Every refusal of §5.1 is here.
 */
final class StepUpTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use OidcFixtures;

    private const string MFA = 'http://schemas.openid.net/pape/policies/2007/06/multi-factor';

    private const string SESSION_COOKIE = 'clavia_session';

    private FrozenClock $clock;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->clock = $this->freezeClock();
        $this->user();
        $this->publicClient();
    }

    public function testASessionThatMeetsTheRequestGetsItsCodeAndTheLevelInTheIdToken(): void
    {
        $secret = $this->signedInWithAnAppEnrolled();
        $this->post('/auth/logout');
        $this->signInWithPasswordAndApp($secret);

        $idToken = $this->completeFlow('openid', ['acr_values' => self::MFA])['id_token'];

        self::assertIsString($idToken);
        self::assertSame(self::MFA, $this->verifiedIdToken($idToken)['claims']['acr']);
    }

    public function testASessionThatFallsShortStepsUpWithoutSigningInAgain(): void
    {
        $secret = $this->signedInWithAnAppEnrolled();
        $before = $this->session($this->cookie(self::SESSION_COOKIE));
        self::assertNotNull($before);
        [$verifier, $challenge] = $this->makePkcePair();

        $asked = $this->get('/oauth2/authorize', $this->authorizeParams($challenge, [
            'scope' => 'openid',
            'acr_values' => self::MFA,
        ]));

        self::assertSame(303, $asked->getStatusCode(), (string) $asked->getBody());
        self::assertSame('/auth/mfa', $asked->getHeaderLine('Location'));
        $page = $this->get('/auth/mfa');
        self::assertStringContainsString('Test public client needs one more step', (string) $page->getBody());
        // No password field anywhere: the person is not signing in again.
        self::assertStringNotContainsString('type="password"', (string) $page->getBody());

        $this->clock->advance(Totp::PERIOD);
        $answered = $this->post('/auth/mfa', [
            'code' => Totp::codeAt($secret, $this->clock->now()),
            'csrf_token' => self::csrfTokenFrom($page),
        ]);
        self::assertSame(303, $answered->getStatusCode(), (string) $answered->getBody());
        self::assertStringStartsWith('/oauth2/authorize?', $answered->getHeaderLine('Location'));

        // The same session, raised: same sid and expiry, new identifier, the factor added.
        $after = $this->session($this->cookie(self::SESSION_COOKIE));
        self::assertNotNull($after);
        self::assertSame($before->sid, $after->sid);
        self::assertEquals($before->expiresAt, $after->expiresAt);
        self::assertSame(['pwd', 'otp', 'mfa'], array_map(static fn ($m): string => $m->value, $after->methods));
        self::assertEquals($this->clock->now(), $after->authenticatedAt);
        self::assertSame(1, $this->audited(AuditEventType::SessionSteppedUp));

        // The request, resumed, now gets its code, and the ID token says how.
        $code = $this->extractCode($this->get($answered->getHeaderLine('Location')));
        $tokens = self::json($this->post('/oauth2/token', $this->tokenRequest($code, $verifier)));
        self::assertIsString($tokens['id_token']);
        $claims = $this->verifiedIdToken($tokens['id_token'])['claims'];
        self::assertSame(self::MFA, $claims['acr']);
        self::assertSame($before->sid, $claims['sid']);
    }

    public function testTheOldIdentifierOpensNothingAfterAStepUp(): void
    {
        $secret = $this->signedInWithAnAppEnrolled();
        $old = $this->cookie(self::SESSION_COOKIE);

        $this->stepUpWith($secret);

        self::assertNotSame($old, $this->cookie(self::SESSION_COOKIE));
        self::assertNull($this->session($old));
    }

    public function testPromptNoneIsTold(): void
    {
        $this->signedInWithAnAppEnrolled();

        $response = $this->authorize([
            'acr_values' => self::MFA,
            'prompt' => 'none',
        ]);

        self::assertSame('interaction_required', self::locationQuery($response)['error'] ?? null);
    }

    public function testALevelNoFactorTheyHoldReachesIsUnmet(): void
    {
        // An authenticator app cannot make a password phishing-resistant: only a passkey can.
        $this->signedInWithAnAppEnrolled();

        $response = $this->authorize(['acr_values' => 'phr']);

        self::assertSame(302, $response->getStatusCode());
        self::assertSame('unmet_authentication_requirements', self::locationQuery($response)['error'] ?? null);
        self::assertSame('test-state-value', self::locationQuery($response)['state'] ?? null);
    }

    public function testSomeoneWithNoSecondFactorIsUnmetUntilEnrolmentOnTheWayExists(): void
    {
        $this->submitLogin();

        $response = $this->authorize(['acr_values' => self::MFA]);

        self::assertSame('unmet_authentication_requirements', self::locationQuery($response)['error'] ?? null);
    }

    public function testOnlyUnknownValuesAskForNothingAndAnEmptyOneIsInvalid(): void
    {
        $this->submitLogin();

        $unknown = $this->authorize(['acr_values' => 'urn:other:gold']);
        $empty = $this->authorize(['acr_values' => ' ']);

        self::assertArrayHasKey('code', self::locationQuery($unknown));
        self::assertSame('invalid_request', self::locationQuery($empty)['error'] ?? null);
    }

    public function testAStepUpCannotBeFinishedWithAnotherSession(): void
    {
        $secret = $this->signedInWithAnAppEnrolled();
        $page = $this->openStepUp();
        // Another session of the same person in this browser by the time the answer comes
        // (another tab signed in anew): not the one the step-up was opened for.
        $user = $this->container()->get(UserRepository::class)->findByEmail(
            ConnectionName::defaultPool(),
            self::TEST_USER_EMAIL,
        );
        self::assertNotNull($user);
        $otherId = $this->container()->get(Sessions::class)->establish(
            $user->id,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            null,
        );
        $this->setCookie(self::SESSION_COOKIE, $otherId);
        $other = $this->session($otherId);
        $this->clock->advance(Totp::PERIOD);

        $this->post('/auth/mfa', [
            'code' => Totp::codeAt($secret, $this->clock->now()),
            'csrf_token' => self::csrfTokenFrom($page),
        ]);

        self::assertNotNull($other);
        $still = $this->session($otherId);
        self::assertNotNull($still);
        self::assertSame(['pwd'], array_map(static fn ($m): string => $m->value, $still->methods));
        self::assertSame(0, $this->audited(AuditEventType::SessionSteppedUp));
    }

    /**
     * An authorization request with a fresh PKCE challenge.
     *
     * @param array<string, string|null> $overrides
     */
    private function authorize(array $overrides): ResponseInterface
    {
        return $this->get('/oauth2/authorize', $this->authorizeParams($this->makePkcePair()[1], $overrides));
    }

    /** Sign in with a password, then turn an authenticator app on: a one-factor session. */
    private function signedInWithAnAppEnrolled(): TotpSecret
    {
        $this->submitLogin();
        $settings = $this->get('/auth/mfa/enroll');
        $setUp = $this->post('/auth/mfa/enroll', ['csrf_token' => self::csrfTokenFrom($settings)]);
        self::assertSame(1, preg_match('#<p class="secret">([A-Z2-7]+)</p>#', (string) $setUp->getBody(), $match));
        $secret = TotpSecret::fromBase32($match[1]);
        $confirmed = $this->post('/auth/mfa/enroll/confirm', [
            'code' => Totp::codeAt($secret, $this->clock->now()),
            'csrf_token' => self::csrfTokenFrom($setUp),
        ]);
        self::assertSame(200, $confirmed->getStatusCode());

        return $secret;
    }

    private function signInWithPasswordAndApp(TotpSecret $secret): void
    {
        $this->submitLogin();
        $this->clock->advance(Totp::PERIOD);
        $page = $this->get('/auth/mfa');
        $this->post('/auth/mfa', [
            'code' => Totp::codeAt($secret, $this->clock->now()),
            'csrf_token' => self::csrfTokenFrom($page),
        ]);
    }

    private function openStepUp(): ResponseInterface
    {
        $asked = $this->authorize(['acr_values' => self::MFA]);
        self::assertSame('/auth/mfa', $asked->getHeaderLine('Location'));

        return $this->get('/auth/mfa');
    }

    private function stepUpWith(TotpSecret $secret): void
    {
        $page = $this->openStepUp();
        $this->clock->advance(Totp::PERIOD);
        $answered = $this->post('/auth/mfa', [
            'code' => Totp::codeAt($secret, $this->clock->now()),
            'csrf_token' => self::csrfTokenFrom($page),
        ]);
        self::assertSame(303, $answered->getStatusCode());
    }

    private function audited(AuditEventType $type): int
    {
        return (int) TestStorage::database()->fetchValue(
            'SELECT count(*) FROM audit_events WHERE type = :type',
            ['type' => $type->value],
        );
    }
}
