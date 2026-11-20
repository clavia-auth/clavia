<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Application\Port\PasswordHasher;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Base64Url;
use Clavia\Domain\Shared\RandomSource;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\OidcFixtures;
use DateTimeImmutable;
use Psr\Http\Message\ResponseInterface;

/**
 * OpenID Connect RP-Initiated Logout 1.0: an application signs its person out at
 * `/oidc/logout`.
 *
 * A request that ends a session is forgeable from any page, so the property under test
 * throughout is that a session ends at once only with a genuine `id_token_hint` for
 * its own person — and otherwise only once the person confirms on this server's page.
 */
final class RpLogoutTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use OidcFixtures;

    private const string SESSION_COOKIE = 'clavia_session';

    public function testDiscoveryAdvertisesTheEndpoint(): void
    {
        $document = self::json($this->get('/.well-known/openid-configuration'));

        self::assertSame('https://auth.clavia.test/oidc/logout', $document['end_session_endpoint'] ?? null);
    }

    public function testAHintForTheSessionsPersonEndsItAndReturnsToTheRegisteredUriWithState(): void
    {
        $idToken = $this->signInAndGetIdToken();
        $sessionId = $this->cookie(self::SESSION_COOKIE);

        $response = $this->logout([
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => self::TEST_POST_LOGOUT_REDIRECT_URI,
            'state' => 'af0ifjsldkj',
        ]);

        self::assertSame(303, $response->getStatusCode());
        self::assertSame(
            self::TEST_POST_LOGOUT_REDIRECT_URI . '?state=af0ifjsldkj',
            $response->getHeaderLine('Location'),
        );
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertNull($this->session($sessionId));
        self::assertNull($this->cookie(self::SESSION_COOKIE));
    }

    public function testWithoutAHintThePersonIsAskedAndTheSessionSurvivesUntilTheyConfirm(): void
    {
        // The forced-logout defence: an <img src="/oidc/logout"> proves nothing.
        $this->signInAndGetIdToken();
        $sessionId = $this->cookie(self::SESSION_COOKIE);

        $page = $this->logout([
            'client_id' => self::TEST_CLIENT_ID,
            'post_logout_redirect_uri' => self::TEST_POST_LOGOUT_REDIRECT_URI,
            'state' => 'xyz',
        ]);

        self::assertSame(200, $page->getStatusCode());
        $body = (string) $page->getBody();
        self::assertStringContainsString('Test public client', $body);
        self::assertStringContainsString('action="/oidc/logout"', $body);
        self::assertStringContainsString(
            "form-action 'self' https://client.test",
            $page->getHeaderLine('Content-Security-Policy'),
        );
        self::assertNotNull($this->session($sessionId));

        $confirmed = $this->post('/oidc/logout', self::hiddenFields($body));

        self::assertSame(303, $confirmed->getStatusCode());
        self::assertSame(self::TEST_POST_LOGOUT_REDIRECT_URI . '?state=xyz', $confirmed->getHeaderLine('Location'));
        self::assertNull($this->session($sessionId));
    }

    public function testAHintForAnotherPersonDoesNotEndThisSession(): void
    {
        $adasToken = $this->signInAndGetIdToken();
        $this->post('/auth/logout');
        $this->secondUser('bob@clavia.dev');
        $this->submitLogin(email: 'bob@clavia.dev');
        $sessionId = $this->cookie(self::SESSION_COOKIE);

        $response = $this->logout(['id_token_hint' => $adasToken]);

        self::assertSame(200, $response->getStatusCode(), 'The person is asked instead.');
        self::assertNotNull($this->session($sessionId));
    }

    public function testAForgedHintIsNoProof(): void
    {
        $idToken = $this->signInAndGetIdToken();
        $sessionId = $this->cookie(self::SESSION_COOKIE);
        [$header, $claims, $signature] = explode('.', $idToken);
        $otherClaims = Base64Url::encode('{"iss":"https://auth.clavia.test","sub":"x"}');
        $forgeries = [
            'alg none' => 'eyJhbGciOiJub25lIn0.' . $claims . '.',
            'claims altered' => $header . '.' . $otherClaims . '.' . $signature,
            'not a JWS' => 'not-a-token',
        ];

        foreach ($forgeries as $name => $hint) {
            self::assertSame(200, $this->logout(['id_token_hint' => $hint])->getStatusCode(), $name);
            self::assertNotNull($this->session($sessionId), $name);
        }
    }

    public function testAnExpiredHintStillProvesWhoAsks(): void
    {
        $clock = $this->freezeClock();
        $idToken = $this->signInAndGetIdToken();
        $sessionId = $this->cookie(self::SESSION_COOKIE);
        $clock->advance(2 * 3600);

        $response = $this->logout(['id_token_hint' => $idToken]);

        self::assertSame(303, $response->getStatusCode());
        self::assertNull($this->session($sessionId));
    }

    public function testAnUnregisteredRedirectIsNotFollowed(): void
    {
        $idToken = $this->signInAndGetIdToken();

        $unregistered = ['https://evil.test/phish', 'https://client.test/callback', 'https://client.test/signed-out/'];

        foreach ($unregistered as $uri) {
            $response = $this->logout(['id_token_hint' => $idToken, 'post_logout_redirect_uri' => $uri]);

            self::assertSame(303, $response->getStatusCode());
            self::assertSame('/auth/login', $response->getHeaderLine('Location'), $uri);
        }
    }

    public function testAClientIdThatContradictsTheHintVoidsBoth(): void
    {
        $idToken = $this->signInAndGetIdToken();
        $this->confidentialClient();
        $sessionId = $this->cookie(self::SESSION_COOKIE);

        $response = $this->logout([
            'id_token_hint' => $idToken,
            'client_id' => self::TEST_CONFIDENTIAL_CLIENT_ID,
            'post_logout_redirect_uri' => self::TEST_POST_LOGOUT_REDIRECT_URI,
        ]);

        self::assertSame(200, $response->getStatusCode());
        self::assertNotNull($this->session($sessionId));
        self::assertStringNotContainsString('client.test', (string) $response->getBody());
    }

    public function testWithNoSessionTheBrowserIsSimplySentBack(): void
    {
        $this->publicClient();

        $response = $this->logout([
            'client_id' => self::TEST_CLIENT_ID,
            'post_logout_redirect_uri' => self::TEST_POST_LOGOUT_REDIRECT_URI,
        ]);

        self::assertSame(303, $response->getStatusCode());
        self::assertSame(self::TEST_POST_LOGOUT_REDIRECT_URI, $response->getHeaderLine('Location'));
        self::assertSame([], self::setCookieHeaders($response, self::SESSION_COOKIE));
    }

    public function testTheEndpointAnswersAFormPostToo(): void
    {
        $idToken = $this->signInAndGetIdToken();
        $sessionId = $this->cookie(self::SESSION_COOKIE);

        $response = $this->post('/oidc/logout', [
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => self::TEST_POST_LOGOUT_REDIRECT_URI,
        ]);

        self::assertSame(303, $response->getStatusCode());
        self::assertSame(self::TEST_POST_LOGOUT_REDIRECT_URI, $response->getHeaderLine('Location'));
        self::assertNull($this->session($sessionId));
    }

    public function testAConfirmationCannotBeGivenByALink(): void
    {
        $this->signInAndGetIdToken();
        $sessionId = $this->cookie(self::SESSION_COOKIE);

        self::assertSame(200, $this->logout(['confirmed' => 'yes'])->getStatusCode());
        self::assertNotNull($this->session($sessionId));
    }

    // ------------------------------------------------------------------

    private function signInAndGetIdToken(): string
    {
        $this->user();
        $this->publicClient();
        $this->submitLogin();
        $idToken = $this->completeFlow('openid')['id_token'] ?? null;
        self::assertIsString($idToken);

        return $idToken;
    }

    /**
     * @param array<string, string> $query
     */
    private function logout(array $query): ResponseInterface
    {
        return $this->get('/oidc/logout', $query);
    }

    /**
     * The hidden fields of the confirmation form, as the browser would post them.
     *
     * @return array<string, string>
     */
    private static function hiddenFields(string $page): array
    {
        preg_match_all('/<input type="hidden" name="([^"]+)" value="([^"]*)">/', $page, $matches, PREG_SET_ORDER);
        $fields = [];
        foreach ($matches as [, $name, $value]) {
            $fields[html_entity_decode($name)] = html_entity_decode($value);
        }

        return $fields;
    }

    private function secondUser(string $email): User
    {
        /** @var UserRepository $users */
        $users = $this->container()->get(UserRepository::class);
        /** @var PasswordHasher $hasher */
        $hasher = $this->container()->get(PasswordHasher::class);
        /** @var RandomSource $random */
        $random = $this->container()->get(RandomSource::class);
        $user = User::register(
            UserId::generate($random),
            $email,
            $hasher->hash(self::TEST_USER_PASSWORD),
            new DateTimeImmutable(),
        );
        $users->save($user);

        return $user;
    }
}
