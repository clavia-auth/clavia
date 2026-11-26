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
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * The pages in the browser's language (#181, docs/design/translated-sign-in-pages.md §5.1): what
 * `Accept-Language` prefers among the offered languages, said in `<html lang>` and `Content-Language`
 * (RFC 9110 §8.5); the default otherwise. The login page and the error pages first.
 */
final class TranslatedPagesTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;

    public function testTheLoginPageIsInTheBrowsersLanguage(): void
    {
        $page = $this->page('/auth/login', 'fr-CA,fr;q=0.9,en;q=0.5');

        self::assertSame(StatusCodeInterface::STATUS_OK, $page->getStatusCode());
        self::assertSame('fr', $page->getHeaderLine('Content-Language'));
        $body = (string) $page->getBody();
        self::assertStringContainsString('<html lang="fr"', $body);
        self::assertStringContainsString('<title>Connexion · Clavia</title>', $body);
        self::assertStringContainsString('Se connecter', $body);
        self::assertStringContainsString('Mot de passe', $body);
        self::assertStringContainsString('Sécurisé par', $body);
        self::assertStringNotContainsString('Sign in', $body);
    }

    public function testWithoutAnOfferedLanguageThePageIsInTheDefaultOne(): void
    {
        foreach (['', 'de-DE, it;q=0.8', '*'] as $header) {
            $page = $this->page('/auth/login', $header);

            self::assertSame('en', $page->getHeaderLine('Content-Language'), $header);
            self::assertStringContainsString('<html lang="en"', (string) $page->getBody(), $header);
            self::assertStringContainsString('<button type="submit">Sign in</button>', (string) $page->getBody());
        }
    }

    public function testARefusedSignInIsInTheBrowsersLanguage(): void
    {
        $this->user();
        $form = $this->page('/auth/login', 'fr');

        $refused = $this->post('/auth/login', [
            'email' => self::TEST_USER_EMAIL,
            'password' => 'not the password',
            'csrf_token' => self::csrfTokenFrom($form),
            'state' => '',
        ], headers: ['Accept-Language' => 'fr']);

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $refused->getStatusCode());
        self::assertStringContainsString('Adresse e-mail ou mot de passe incorrect.', (string) $refused->getBody());
    }

    public function testAnErrorPageIsInTheBrowsersLanguage(): void
    {
        $missing = $this->page('/auth/nothing-here', 'fr');

        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $missing->getStatusCode());
        self::assertSame('fr', $missing->getHeaderLine('Content-Language'));
        self::assertStringContainsString('Page introuvable', (string) $missing->getBody());
        self::assertStringContainsString(
            "Il n'y a rien à cette adresse.",
            html_entity_decode((string) $missing->getBody()),
        );
    }

    /**
     * A refused authorization request: its explanation in the browser's language, the server's technical
     * description kept in English and marked so, for the application's developer.
     */
    public function testARefusedAuthorizationKeepsItsTechnicalDetailInEnglish(): void
    {
        $refused = $this->page('/oauth2/authorize?client_id=no-such-client&response_type=code', 'fr');

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $refused->getStatusCode());
        $body = html_entity_decode((string) $refused->getBody());
        self::assertStringContainsString('Cette connexion ne peut pas continuer', $body);
        self::assertStringContainsString('Détails pour le développeur', $body);
        self::assertStringContainsString('<p class="hint" lang="en">', $body);
    }

    private function page(string $path, string $acceptLanguage): ResponseInterface
    {
        $headers = ['Accept' => 'text/html'];
        if ($acceptLanguage !== '') {
            $headers['Accept-Language'] = $acceptLanguage;
        }

        return $this->request(RequestMethodInterface::METHOD_GET, $path, $headers);
    }
}
