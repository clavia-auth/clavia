<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\OAuth2Fixtures;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * The language switcher (docs/design/translated-sign-in-pages.md §5.4): the person's choice outranks the
 * application's `ui_locales` and the browser's `Accept-Language`, on every page. Each browser here asks
 * for English.
 */
final class LanguageSwitcherTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;

    private const string COOKIE = 'clavia_language';

    public function testEveryPageOffersEachLanguageNamedInItself(): void
    {
        $page = (string) $this->page('/auth/login')->getBody();

        self::assertStringContainsString('<form class="toggle" method="post" action="/auth/language"', $page);
        self::assertMatchesRegularExpression(
            '#<link rel="stylesheet" href="&\#x2F;auth&\#x2F;static&\#x2F;auth.css&\#x3F;v&\#x3D;[0-9a-f]{12}">#',
            $page,
            'Versioned, so the switcher never meets a stylesheet cached before it.',
        );
        self::assertStringContainsString('<input type="hidden" name="return_to" value="&#x2F;auth&#x2F;login">', $page);
        self::assertStringContainsString(
            '<button type="submit" name="language" value="en" lang="en" aria-pressed="true">English</button>',
            $page,
        );
        self::assertStringContainsString(
            '<button type="submit" name="language" value="fr" lang="fr">Français</button>',
            $page,
        );
    }

    public function testChoosingALanguageRemembersItAndGoesBack(): void
    {
        $response = $this->post('/auth/language', ['language' => 'fr', 'return_to' => '/auth/login?state=abc']);

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        self::assertSame('/auth/login?state=abc', $response->getHeaderLine('Location'));
        $cookie = (string) self::setCookieHeader($response, self::COOKIE);
        self::assertStringStartsWith('clavia_language=fr;', $cookie);
        self::assertStringContainsString('Max-Age=31536000', $cookie);
        self::assertStringContainsString('Path=/;', $cookie . ';');
        self::assertStringContainsString('HttpOnly', $cookie);
        self::assertStringContainsString('SameSite=Lax', $cookie);
        self::assertStringNotContainsString('Domain', $cookie);

        $page = $this->page('/auth/login');
        self::assertSame('fr', $page->getHeaderLine('Content-Language'));
        self::assertStringContainsString('value="fr" lang="fr" aria-pressed="true"', (string) $page->getBody());
    }

    public function testTheChoiceOutranksWhatTheApplicationAskedFor(): void
    {
        $this->publicClient();
        $this->setCookie(self::COOKIE, 'en');

        $parameters = $this->authorizeParams($this->makePkcePair()[1], ['ui_locales' => 'fr']);
        $asked = $this->get('/oauth2/authorize', $parameters);
        $page = $this->page($asked->getHeaderLine('Location'));

        self::assertSame('en', $page->getHeaderLine('Content-Language'));
    }

    public function testThePagesOutsideTheSignInFollowItToo(): void
    {
        $this->setCookie(self::COOKIE, 'fr');

        $refused = $this->page('/oauth2/authorize?client_id=no-such-client&response_type=code');

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $refused->getStatusCode());
        self::assertSame('fr', $refused->getHeaderLine('Content-Language'));
    }

    public function testAnythingButAnOfferedLanguageChangesNothing(): void
    {
        $this->setCookie(self::COOKIE, 'fr');

        foreach (['de', 'FR', 'fr-CA', '<x>', ''] as $language) {
            $response = $this->post('/auth/language', ['language' => $language, 'return_to' => 'https://evil.test/']);

            self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode(), $language);
            self::assertSame('/auth/login', $response->getHeaderLine('Location'), 'Never off this origin.');
            self::assertNull(self::setCookieHeader($response, self::COOKIE), $language);
        }
        self::assertSame('fr', $this->page('/auth/login')->getHeaderLine('Content-Language'));
    }

    public function testAForgedCookieIsPassedOver(): void
    {
        $this->setCookie(self::COOKIE, 'de"><b>x</b>');

        $page = $this->page('/auth/login');

        self::assertSame('en', $page->getHeaderLine('Content-Language'));
        self::assertStringNotContainsString('<b>x</b>', (string) $page->getBody());
    }

    private function page(string $path): ResponseInterface
    {
        return $this->request(
            RequestMethodInterface::METHOD_GET,
            $path,
            ['Accept' => 'text/html', 'Accept-Language' => 'en'],
        );
    }
}
