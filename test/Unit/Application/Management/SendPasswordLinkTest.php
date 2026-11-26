<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Management;

use Clavia\Application\Authentication\Account\AccountMail;
use Clavia\Application\Authentication\Account\SendAccountLink;
use Clavia\Application\Authentication\EmailSendLimit;
use Clavia\Application\Management\Conflict;
use Clavia\Application\Management\NotFound;
use Clavia\Application\Management\Users\PasswordLinkRefused;
use Clavia\Application\Management\Users\PasswordLinkSent;
use Clavia\Application\Management\Users\SendPasswordLink;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\Event\PasswordLinkSent as PasswordLinkSentEvent;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAccountLinkStore;
use ClaviaTest\Support\Fake\InMemoryAttemptCounter;
use ClaviaTest\Support\Fake\InMemoryConnectionRepository;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\RecordingMailer;
use ClaviaTest\Support\Fake\SeededRandomSource;
use ClaviaTest\Support\TestMail;
use PHPUnit\Framework\TestCase;

/**
 * An operator mailing an account the link to choose a password: an invitation for an
 * account that has none, a reset for one that has, refused where no link could work.
 */
final class SendPasswordLinkTest extends TestCase
{
    private FrozenClock $clock;

    private InMemoryUserRepository $users;

    private InMemoryAccountLinkStore $links;

    private InMemoryDomainEvents $events;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->users = new InMemoryUserRepository();
        $this->links = new InMemoryAccountLinkStore($this->clock);
        $this->events = new InMemoryDomainEvents();
    }

    public function testAnAccountWithoutAPasswordIsInvited(): void
    {
        $mailer = new RecordingMailer();
        $user = $this->account(passwordHash: null);

        $outcome = $this->send($mailer)($user->id, '192.0.2.1');

        self::assertEquals(new PasswordLinkSent(invitation: true), $outcome);
        self::assertStringContainsString('invited', (string) $mailer->lastRendered()?->subject);
        self::assertStringContainsString('/auth/password/reset?token=', (string) $mailer->lastRendered()?->text);
        self::assertCount(1, $this->links->tokens());
        $recorded = $this->events->ofType(PasswordLinkSentEvent::class);
        self::assertCount(1, $recorded);
        self::assertTrue($recorded[0]->invitation);
        self::assertTrue($recorded[0]->userId->equals($user->id));
    }

    public function testAnAccountWithAPasswordIsSentAReset(): void
    {
        $mailer = new RecordingMailer();
        $user = $this->account(passwordHash: '$2y$12$hash');

        $outcome = $this->send($mailer)($user->id, '192.0.2.1');

        self::assertEquals(new PasswordLinkSent(invitation: false), $outcome);
        self::assertStringContainsString('new password', (string) $mailer->lastRendered()?->subject);
        self::assertFalse($this->events->ofType(PasswordLinkSentEvent::class)[0]->invitation);
    }

    public function testTheMailGoesToTheAccountsOwnAddress(): void
    {
        $mailer = new RecordingMailer();
        $user = $this->account();

        $this->send($mailer)($user->id, '192.0.2.1');

        self::assertSame('jane@example.com', $mailer->last()?->to);
    }

    public function testAnUnknownAccountIsNotFound(): void
    {
        $this->expectException(NotFound::class);

        $this->send(new RecordingMailer())(UserId::generate(new SeededRandomSource(9)), '192.0.2.1');
    }

    public function testADeactivatedAccountIsRefusedAndNothingIsMailed(): void
    {
        $mailer = new RecordingMailer();
        $user = $this->account();
        $user->deactivate($this->clock->now());
        $this->users->save($user);

        try {
            $this->send($mailer)($user->id, '192.0.2.1');
            self::fail('A deactivated account was mailed a link.');
        } catch (Conflict) {
            self::assertSame([], $mailer->sent);
            self::assertSame([], $this->links->tokens());
            self::assertSame([], $this->events->ofType(PasswordLinkSentEvent::class));
        }
    }

    public function testAnAccountOutsideAPoolHasNoPasswordToChoose(): void
    {
        $user = User::registerFromProvider(
            UserId::generate(new SeededRandomSource(3)),
            'jane@example.com',
            ConnectionName::fromString('google'),
            $this->clock->now(),
        );
        $this->users->save($user);

        $this->expectException(InvalidValue::class);

        $this->send(new RecordingMailer())($user->id, '192.0.2.1');
    }

    public function testADeploymentWithoutMailRefusesBeforeOpeningALink(): void
    {
        $user = $this->account();

        $outcome = $this->send(new RecordingMailer(canSend: false))($user->id, '192.0.2.1');

        self::assertSame(PasswordLinkRefused::MailUnavailable, $outcome);
        self::assertSame([], $this->links->tokens());
        self::assertSame([], $this->events->ofType(PasswordLinkSentEvent::class));
    }

    public function testAMailServerThatRefusesClosesTheLinkAgainAndRecordsNothing(): void
    {
        $mailer = new RecordingMailer(failing: true);
        $user = $this->account();

        $outcome = $this->send($mailer)($user->id, '192.0.2.1');

        self::assertSame(PasswordLinkRefused::MailUnavailable, $outcome);
        self::assertSame([], $this->links->tokens());
        self::assertSame([], $this->events->ofType(PasswordLinkSentEvent::class));
    }

    public function testTheSendLimitStopsTheMailAndRecordsNothing(): void
    {
        $mailer = new RecordingMailer();
        $user = $this->account();
        $send = $this->send($mailer, limit: 1);

        self::assertInstanceOf(PasswordLinkSent::class, $send($user->id, '192.0.2.1'));
        $outcome = $send($user->id, '192.0.2.1');

        self::assertSame(PasswordLinkRefused::LimitReached, $outcome);
        self::assertCount(1, $mailer->sent);
        self::assertCount(1, $this->events->ofType(PasswordLinkSentEvent::class));
    }

    /** @param positive-int $limit */
    private function send(RecordingMailer $mailer, int $limit = 5): SendPasswordLink
    {
        return new SendPasswordLink(
            $this->users,
            new InMemoryConnectionRepository(),
            new SendAccountLink(
                $this->links,
                new EmailSendLimit(new InMemoryAttemptCounter($this->clock), $limit, 'account'),
                $mailer,
                new AccountMail('clavia.test', 'https://auth.clavia.test', 86400, 1800),
                new SecretGenerator(new SeededRandomSource(7)),
                86400,
                1800,
                TestMail::languages(),
            ),
            $mailer,
            $this->events,
        );
    }

    private function account(?string $passwordHash = '$2y$12$hash'): User
    {
        $user = User::register(
            UserId::generate(new SeededRandomSource(5)),
            'jane@example.com',
            $passwordHash,
            $this->clock->now(),
        );
        $this->users->save($user);

        return $user;
    }
}
