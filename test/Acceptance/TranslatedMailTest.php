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
use Clavia\Application\Port\RenderedMail;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionRepository;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;

/**
 * Each mail in the language of the person it concerns (#184, docs/design/translated-sign-in-pages.md
 * §5.3): the page's when a person caused it, the account's profile `locale` when an operator did, the
 * default otherwise.
 */
final class TranslatedMailTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string FRENCH = 'fr-FR,fr;q=0.9';

    public function testASignUpsVerificationIsInThePagesLanguage(): void
    {
        $this->openSignUp();

        $this->signUp('grace@clavia.dev', self::FRENCH);

        $mail = $this->lastMail();
        self::assertSame('Confirmez votre adresse e-mail pour clavia.test', $mail->subject);
        self::assertStringContainsString('Ouvrez ce lien pour confirmer', $mail->text);
        self::assertStringContainsString('expire dans 24 heures', $mail->text);
        self::assertStringContainsString('/auth/verify-email?token=', $mail->text);
    }

    public function testWithoutAPreferenceTheMailIsInTheDefaultLanguage(): void
    {
        $this->openSignUp();

        $this->signUp('grace@clavia.dev', 'de-DE');

        $mail = $this->lastMail();
        self::assertSame('Confirm your email address for clavia.test', $mail->subject);
        self::assertStringContainsString('expires in 24 hours', $mail->text);
    }

    public function testAResetAskedForInFrenchIsInFrench(): void
    {
        $this->user();
        $form = $this->request(
            RequestMethodInterface::METHOD_GET,
            '/auth/password/forgot',
            ['Accept-Language' => self::FRENCH],
        );

        $this->post('/auth/password/forgot', [
            'email' => self::TEST_USER_EMAIL,
            'csrf_token' => self::csrfTokenFrom($form),
            'state' => '',
        ], headers: ['Accept-Language' => self::FRENCH]);

        $mail = $this->lastMail();
        self::assertSame('Choisissez un nouveau mot de passe pour clavia.test', $mail->subject);
        self::assertStringContainsString('vous déconnecte partout', $mail->text);
    }

    public function testASignInCodeIsInThePagesLanguage(): void
    {
        $page = $this->request(RequestMethodInterface::METHOD_GET, '/auth/login', ['Accept-Language' => self::FRENCH]);

        $this->post('/auth/passwordless/start', [
            'email' => 'ada@clavia.dev',
            'mode' => 'code',
            'csrf_token' => self::csrfTokenFrom($page),
            'state' => '',
        ], headers: ['Accept-Language' => self::FRENCH]);

        $mail = $this->lastMail();
        self::assertSame('Votre code de connexion pour clavia.test', $mail->subject);
        self::assertMatchesRegularExpression('/^Votre code de connexion est \d{6}$/m', $mail->text);
        self::assertStringContainsString('expire dans 10 minutes', $mail->text);
    }

    /** Nobody's page is involved in an operator's request: the account's profile says the language. */
    public function testAnOperatorsInvitationFollowsTheAccountsProfile(): void
    {
        $this->adminToken();
        $cases = ['marie@clavia.dev' => 'fr', 'hans@clavia.dev' => 'de', 'lin@clavia.dev' => null];

        foreach ($cases as $email => $locale) {
            $created = $this->api(
                RequestMethodInterface::METHOD_POST,
                '/api/v1/users',
                $locale === null ? ['email' => $email] : ['email' => $email, 'locale' => $locale],
            );
            $body = (string) $created->getBody();
            self::assertSame(StatusCodeInterface::STATUS_CREATED, $created->getStatusCode(), $body);
            $id = (string) self::document($created)['id'];

            $sent = $this->api(RequestMethodInterface::METHOD_POST, '/api/v1/users/' . $id . '/password-reset');

            self::assertSame(StatusCodeInterface::STATUS_ACCEPTED, $sent->getStatusCode(), (string) $sent->getBody());
            self::assertSame(
                $locale === 'fr' ? 'Vous êtes invité sur clavia.test' : 'You have been invited to clavia.test',
                $this->lastMail()->subject,
                $email,
            );
        }
    }

    private function openSignUp(): void
    {
        $connections = $this->container()->get(ConnectionRepository::class);
        $pool = $connections->find(ConnectionName::defaultPool());
        self::assertNotNull($pool);
        $connections->save($pool->switched(null, null, null, true, true));
    }

    private function signUp(string $email, string $acceptLanguage): void
    {
        $headers = ['Accept-Language' => $acceptLanguage];
        $page = $this->request(RequestMethodInterface::METHOD_GET, '/auth/login', $headers);

        $this->post('/auth/signup', [
            'email' => $email,
            'password' => 'correct horse battery',
            'csrf_token' => self::csrfTokenFrom($page),
            'state' => '',
        ], headers: ['Accept-Language' => $acceptLanguage]);
    }

    private function lastMail(): RenderedMail
    {
        $mail = $this->container()->get(MailOutbox::class)->recent(1)[0] ?? null;
        self::assertNotNull($mail, 'Nothing was sent.');

        return $mail;
    }
}
