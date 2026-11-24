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
use Clavia\Application\Port\OutgoingMail;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Domain\Audit\ActorKind;
use Clavia\Domain\Audit\AuditEvent;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Audit\AuditLog;
use Clavia\Domain\Audit\AuditQuery;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\PageRequest;
use Clavia\Domain\Shared\RandomSource;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * `POST /api/v1/users/{user_id}/password-reset`: an operator mails a person the link to
 * choose a password — an invitation for an account that has none, a reset for one that has.
 *
 * The mail backend is the console one, so each test reads the link from the development
 * outbox as the person would read their email, and follows it on the sign-in host.
 */
final class ManagementPasswordLinkTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string EMAIL = 'grace@clavia.dev';

    private const string PASSWORD = 'correct horse battery';

    public function testAnAccountWithAPasswordIsSentAReset(): void
    {
        $user = $this->account(self::PASSWORD);
        $this->adminToken();

        $response = $this->sendLink($user);

        self::assertSame(
            StatusCodeInterface::STATUS_ACCEPTED,
            $response->getStatusCode(),
            (string) $response->getBody(),
        );
        self::assertSame(['kind' => 'reset'], self::document($response));
        $mail = $this->lastMail();
        self::assertSame(self::EMAIL, $mail->to);
        self::assertStringContainsString('Choose a new password', $mail->subject);
        self::assertStringContainsString('/auth/password/reset?token=', $mail->text);
    }

    public function testAnAccountWithoutAPasswordIsInvitedAndCanChooseOne(): void
    {
        $user = $this->account(null);
        $this->adminToken();

        $response = $this->sendLink($user);

        self::assertSame(
            StatusCodeInterface::STATUS_ACCEPTED,
            $response->getStatusCode(),
            (string) $response->getBody(),
        );
        self::assertSame(['kind' => 'invitation'], self::document($response));
        $mail = $this->lastMail();
        self::assertStringContainsString('invited', $mail->subject);
        self::assertSame(
            StatusCodeInterface::STATUS_UNAUTHORIZED,
            $this->signIn(self::PASSWORD)->getStatusCode(),
            'There is no password yet.',
        );

        $link = self::linkIn($mail);
        $form = $this->get($link);
        self::assertStringContainsString('Choose a new password', (string) $form->getBody());
        $changed = $this->post('/auth/password/reset', [
            'token' => self::tokenOf($link),
            'password' => self::PASSWORD,
            'csrf_token' => self::csrfTokenFrom($form),
        ]);

        self::assertSame(StatusCodeInterface::STATUS_OK, $changed->getStatusCode(), (string) $changed->getBody());
        self::assertTrue($this->reload($user)->isEmailVerified(), 'Following the link proves the address.');
        $this->clearCookies();
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $this->signIn(self::PASSWORD)->getStatusCode());
    }

    public function testAnAccountCreatedThroughTheApiWithoutAPasswordIsInvitedAndSignsIn(): void
    {
        $this->adminToken();
        $created = $this->api('POST', '/api/v1/users', ['email' => self::EMAIL]);
        self::assertSame(StatusCodeInterface::STATUS_CREATED, $created->getStatusCode(), (string) $created->getBody());
        $id = self::document($created)['id'];
        self::assertIsString($id);
        self::assertSame(
            StatusCodeInterface::STATUS_UNAUTHORIZED,
            $this->signIn(self::PASSWORD)->getStatusCode(),
            'There is no password yet.',
        );

        $invited = $this->api('POST', '/api/v1/users/' . $id . '/password-reset');

        self::assertSame(StatusCodeInterface::STATUS_ACCEPTED, $invited->getStatusCode(), (string) $invited->getBody());
        self::assertSame(['kind' => 'invitation'], self::document($invited));
        $link = self::linkIn($this->lastMail());
        $form = $this->get($link);
        $changed = $this->post('/auth/password/reset', [
            'token' => self::tokenOf($link),
            'password' => self::PASSWORD,
            'csrf_token' => self::csrfTokenFrom($form),
        ]);
        self::assertSame(StatusCodeInterface::STATUS_OK, $changed->getStatusCode(), (string) $changed->getBody());
        self::assertTrue(self::document($this->api('GET', '/api/v1/users/' . $id))['has_password']);
        $this->clearCookies();
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $this->signIn(self::PASSWORD)->getStatusCode());
    }

    public function testTheLinkDiesOnceThePasswordIsChosen(): void
    {
        $user = $this->account(null);
        $this->adminToken();
        $this->sendLink($user);
        $link = self::linkIn($this->lastMail());
        $form = $this->get($link);
        $this->post('/auth/password/reset', [
            'token' => self::tokenOf($link),
            'password' => self::PASSWORD,
            'csrf_token' => self::csrfTokenFrom($form),
        ]);

        $again = $this->get($link);

        self::assertStringContainsString('not valid any more', (string) $again->getBody());
    }

    public function testTheOperatorIsTheActorAndNoLinkIsRecorded(): void
    {
        $user = $this->account(null);
        $this->adminToken();

        $this->sendLink($user);

        $events = $this->audited(AuditEventType::UserPasswordLinkSent);
        self::assertCount(1, $events);
        $event = $events[0];
        self::assertSame(ActorKind::Application, $event->actor->kind);
        self::assertSame(self::TEST_M2M_CLIENT_ID, $event->actor->clientId?->value);
        self::assertSame($user->id->toString(), $event->target?->id);
        self::assertSame(['kind' => 'invitation'], $event->details);
    }

    public function testItNeedsItsOwnScope(): void
    {
        $user = $this->account(self::PASSWORD);
        $this->adminToken(['read:users', 'update:users', 'create:users']);

        $response = $this->sendLink($user);

        self::assertSame(StatusCodeInterface::STATUS_FORBIDDEN, $response->getStatusCode());
        self::assertCount(0, $this->outbox()->recent(10));
    }

    public function testAnUnknownUserIsNotFound(): void
    {
        $this->adminToken();

        $response = $this->api('POST', '/api/v1/users/6f1c8a52-1b1e-4c8e-9d38-0f2b3d7c9e10/password-reset');

        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $response->getStatusCode());
        self::assertCount(0, $this->outbox()->recent(10));
    }

    public function testADeactivatedAccountIsRefusedAndNothingIsMailed(): void
    {
        $user = $this->account(self::PASSWORD, active: false);
        $this->adminToken();

        $response = $this->sendLink($user);

        self::assertSame(StatusCodeInterface::STATUS_CONFLICT, $response->getStatusCode());
        self::assertCount(0, $this->outbox()->recent(10));
        self::assertCount(0, $this->audited(AuditEventType::UserPasswordLinkSent));
    }

    public function testAnAccountThroughAProviderHasNoPasswordToChoose(): void
    {
        $user = User::registerFromProvider(
            UserId::generate($this->container()->get(RandomSource::class)),
            self::EMAIL,
            ConnectionName::fromString('google'),
            $this->container()->get(Clock::class)->now(),
        );
        $this->container()->get(UserRepository::class)->save($user);
        $this->adminToken();

        $response = $this->sendLink($user);

        self::assertSame(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, $response->getStatusCode());
        self::assertCount(0, $this->outbox()->recent(10));
    }

    public function testTheSendLimitAnswersTooManyRequests(): void
    {
        $this->boot(['CLAVIA_ACCOUNT_EMAIL_SEND_LIMIT' => '2']);
        $user = $this->account(self::PASSWORD);
        $this->adminToken();

        self::assertSame(StatusCodeInterface::STATUS_ACCEPTED, $this->sendLink($user)->getStatusCode());
        self::assertSame(StatusCodeInterface::STATUS_ACCEPTED, $this->sendLink($user)->getStatusCode());
        $response = $this->sendLink($user);

        self::assertSame(StatusCodeInterface::STATUS_TOO_MANY_REQUESTS, $response->getStatusCode());
        self::assertCount(2, $this->outbox()->recent(10));
        self::assertCount(2, $this->audited(AuditEventType::UserPasswordLinkSent));
    }

    public function testADeploymentWithoutMailAnswersServiceUnavailable(): void
    {
        $this->boot(['CLAVIA_EMAIL_BACKEND' => 'none']);
        $user = $this->account(self::PASSWORD);
        $this->adminToken();

        $response = $this->sendLink($user);

        self::assertSame(StatusCodeInterface::STATUS_SERVICE_UNAVAILABLE, $response->getStatusCode());
        self::assertCount(0, $this->audited(AuditEventType::UserPasswordLinkSent));
    }

    private function sendLink(User $user): ResponseInterface
    {
        return $this->api('POST', '/api/v1/users/' . $user->id->toString() . '/password-reset');
    }

    private function account(?string $password, bool $active = true): User
    {
        $random = $this->container()->get(RandomSource::class);
        $clock = $this->container()->get(Clock::class);
        $hash = $password === null
            ? null
            : $this->container()->get(PasswordHasher::class)->hash($password);
        $user = User::register(UserId::generate($random), self::EMAIL, $hash, $clock->now());
        if (! $active) {
            $user->deactivate($clock->now());
        }
        $this->container()->get(UserRepository::class)->save($user);

        return $user;
    }

    private function reload(User $user): User
    {
        $found = $this->container()->get(UserRepository::class)->find($user->id);
        self::assertNotNull($found);

        return $found;
    }

    private function signIn(string $password): ResponseInterface
    {
        return $this->post('/auth/login', [
            'email' => self::EMAIL,
            'password' => $password,
            'csrf_token' => self::csrfTokenFrom($this->get('/auth/login')),
            'state' => '',
        ]);
    }

    private function outbox(): MailOutbox
    {
        return $this->container()->get(MailOutbox::class);
    }

    private function lastMail(): OutgoingMail
    {
        $mail = $this->outbox()->recent(1)[0] ?? null;
        self::assertNotNull($mail, 'Nothing was sent.');

        return $mail;
    }

    /** The link's path and query, as the browser would request it from this server. */
    private static function linkIn(OutgoingMail $mail): string
    {
        self::assertSame(1, preg_match('#https://[^/\s]+(/auth/[a-z/-]+\?token=[A-Za-z0-9_-]+)#', $mail->text, $match));

        return $match[1];
    }

    private static function tokenOf(string $link): string
    {
        parse_str((string) parse_url($link, PHP_URL_QUERY), $query);
        $token = $query['token'] ?? null;
        self::assertIsString($token);

        return $token;
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
