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
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\Url;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * `ui_locales` (OpenID Connect Core §3.1.2.1, docs/design/translated-sign-in-pages.md §5.2): the language
 * an application asks for is the language of every page its request goes through, before the browser's.
 * Each browser here asks for English.
 */
final class UiLocalesTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;

    private const string THIRD_PARTY_CLIENT_ID = 'tpc_test-third-party';

    private FrozenClock $clock;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->clock = $this->freezeClock();
    }

    public function testDiscoveryNamesTheLanguagesOffered(): void
    {
        $document = self::json($this->get('/.well-known/openid-configuration'));

        self::assertSame(['en', 'fr'], $document['ui_locales_supported']);
    }

    public function testTheLoginPageSpeaksTheLanguageTheApplicationAskedFor(): void
    {
        $this->publicClient();

        $page = $this->page($this->authorize(['ui_locales' => 'de fr-CA en']));

        self::assertSame('fr', $page->getHeaderLine('Content-Language'), 'German is not offered; fr-CA is fr.');
        self::assertStringContainsString('<title>Connexion · Clavia</title>', (string) $page->getBody());
    }

    public function testWithoutAnOfferedOneTheBrowserDecides(): void
    {
        $this->publicClient();

        foreach (['de', 'not/a/tag', ''] as $asked) {
            $page = $this->page($this->authorize(['ui_locales' => $asked]));

            self::assertSame(StatusCodeInterface::STATUS_OK, $page->getStatusCode(), $asked);
            self::assertSame('en', $page->getHeaderLine('Content-Language'), $asked);
        }
    }

    public function testARefusedPasswordIsInThatLanguageToo(): void
    {
        $this->user();
        $this->publicClient();
        $login = $this->page($this->authorize(['ui_locales' => 'fr']));

        $refused = $this->post('/auth/login', [
            'email' => self::TEST_USER_EMAIL,
            'password' => 'not the password',
            'csrf_token' => self::csrfTokenFrom($login),
            'state' => self::stateOf($login),
        ], headers: ['Accept-Language' => 'en']);

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $refused->getStatusCode());
        self::assertStringContainsString('Adresse e-mail ou mot de passe incorrect.', (string) $refused->getBody());
    }

    public function testThePushedRequestsLanguageIsTheOneUsed(): void
    {
        $this->publicClient();
        $pushed = $this->post('/oauth2/par', $this->authorizeParams($this->makePkcePair()[1], ['ui_locales' => 'fr']));
        self::assertSame(StatusCodeInterface::STATUS_CREATED, $pushed->getStatusCode(), (string) $pushed->getBody());
        $requestUri = self::json($pushed)['request_uri'];
        self::assertIsString($requestUri);

        $page = $this->page(
            $this->get('/oauth2/authorize', ['client_id' => self::TEST_CLIENT_ID, 'request_uri' => $requestUri]),
        );

        self::assertSame('fr', $page->getHeaderLine('Content-Language'));
    }

    public function testTheSecondFactorKeepsIt(): void
    {
        $this->user();
        $this->publicClient();
        $secret = $this->enrol();
        $this->post('/auth/logout');
        $login = $this->page($this->authorize(['ui_locales' => 'fr']));
        $state = self::stateOf($login);

        $signedIn = $this->post('/auth/login', [
            'email' => self::TEST_USER_EMAIL,
            'password' => self::TEST_USER_PASSWORD,
            'csrf_token' => self::csrfTokenFrom($login),
            'state' => $state,
        ], headers: ['Accept-Language' => 'en']);
        self::assertSame('/auth/mfa', $signedIn->getHeaderLine('Location'));
        $challenge = $this->inEnglishBrowser('/auth/mfa');

        self::assertSame('fr', $challenge->getHeaderLine('Content-Language'));
        self::assertStringContainsString(
            "Consultez votre application d'authentification",
            html_entity_decode((string) $challenge->getBody()),
        );
        $this->clock->advance(Totp::PERIOD);
        $wrong = $this->post('/auth/mfa', [
            'code' => Totp::codeAt($secret, $this->clock->now()) === '000000' ? '111111' : '000000',
            'csrf_token' => self::csrfTokenFrom($challenge),
        ], headers: ['Accept-Language' => 'en']);
        self::assertSame('fr', $wrong->getHeaderLine('Content-Language'), 'A refused code too.');
    }

    public function testTheConsentScreenKeepsIt(): void
    {
        $this->loggedIn();
        $this->thirdPartyClient();

        $asked = $this->authorize(['client_id' => self::THIRD_PARTY_CLIENT_ID, 'ui_locales' => 'fr']);
        self::assertStringStartsWith('/auth/consent?state=', $asked->getHeaderLine('Location'));
        $screen = $this->inEnglishBrowser($asked->getHeaderLine('Location'));

        self::assertSame(StatusCodeInterface::STATUS_OK, $screen->getStatusCode());
        self::assertSame('fr', $screen->getHeaderLine('Content-Language'));
        self::assertStringContainsString("Autoriser l'accès ?", html_entity_decode((string) $screen->getBody()));
    }

    /** @param array<string, string|null> $overrides */
    private function authorize(array $overrides = []): ResponseInterface
    {
        return $this->get('/oauth2/authorize', $this->authorizeParams($this->makePkcePair()[1], $overrides));
    }

    /** Follow the authorization endpoint to the page it sends the browser to. */
    private function page(ResponseInterface $redirect): ResponseInterface
    {
        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $redirect->getStatusCode(),
            (string) $redirect->getBody(),
        );

        return $this->inEnglishBrowser($redirect->getHeaderLine('Location'));
    }

    private function inEnglishBrowser(string $path): ResponseInterface
    {
        return $this->request(
            RequestMethodInterface::METHOD_GET,
            $path,
            ['Accept' => 'text/html', 'Accept-Language' => 'en'],
        );
    }

    private static function stateOf(ResponseInterface $login): string
    {
        self::assertSame(1, preg_match('/name="state" value="([^"]+)"/', (string) $login->getBody(), $match));

        return html_entity_decode($match[1]);
    }

    private function enrol(): TotpSecret
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
        self::assertSame(StatusCodeInterface::STATUS_OK, $confirmed->getStatusCode());

        return $secret;
    }

    private function thirdPartyClient(): void
    {
        $this->container()->get(ClientRepository::class)->save(Client::register(
            ClientId::fromString(self::THIRD_PARTY_CLIENT_ID),
            'Partner Analytics',
            ClientType::Public,
            ClientAuthMethod::None,
            null,
            [Url::fromString(self::TEST_REDIRECT_URI)],
            [GrantType::AuthorizationCode],
            [ResponseType::Code],
            $this->container()->get(Clock::class)->now(),
        ));
    }
}
