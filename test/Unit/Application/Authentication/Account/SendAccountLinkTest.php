<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Authentication\Account;

use Clavia\Application\Authentication\Account\AccountMail;
use Clavia\Application\Authentication\Account\Delivery;
use Clavia\Application\Authentication\Account\SendAccountLink;
use Clavia\Application\Authentication\EmailSendLimit;
use Clavia\Domain\Identity\AccountLinkPurpose;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAccountLinkStore;
use ClaviaTest\Support\Fake\InMemoryAttemptCounter;
use ClaviaTest\Support\Fake\RecordingMailer;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;

final class SendAccountLinkTest extends TestCase
{
    private FrozenClock $clock;

    private InMemoryAccountLinkStore $links;

    private RecordingMailer $mailer;

    private SendAccountLink $send;

    private User $user;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->links = new InMemoryAccountLinkStore($this->clock);
        $this->mailer = new RecordingMailer();
        $this->send = new SendAccountLink(
            $this->links,
            new EmailSendLimit(new InMemoryAttemptCounter($this->clock), 2, 'account'),
            $this->mailer,
            new AccountMail('clavia.test', 'https://auth.clavia.test', 86400, 1800),
            new SecretGenerator(new SeededRandomSource(7)),
            86400,
            1800,
        );
        $this->user = User::register(
            UserId::fromString('6f1d6f0e-6b2a-4c9e-9d8a-3b1f2c4d5e6f'),
            'jane@example.com',
            '$2y$12$hash',
            $this->clock->now(),
        );
    }

    public function testAVerificationLinkIsOpenedAndMailed(): void
    {
        self::assertTrue($this->send->verification($this->user, 'login-state', '192.0.2.1'));

        $token = $this->links->tokens()[0] ?? '';
        self::assertSame(AccountLinkPurpose::VerifyEmail, $this->links->find($token)?->purpose);
        self::assertStringContainsString('/auth/verify-email?token=' . $token, (string) $this->mailer->last()?->text);
        self::assertStringContainsString('24 hours', (string) $this->mailer->last()?->text);
    }

    public function testAResetLinkLivesItsOwnLifetime(): void
    {
        $this->send->reset($this->user, null, '192.0.2.1');
        $token = $this->links->tokens()[0] ?? '';

        $this->clock->advance(1799);
        self::assertNotNull($this->links->find($token));
        $this->clock->advance(1);
        self::assertNull($this->links->find($token));
    }

    public function testTheLimitStopsTheThirdMailToOneAddress(): void
    {
        self::assertTrue($this->send->verification($this->user, null, '192.0.2.1'));
        self::assertTrue($this->send->reset($this->user, null, '192.0.2.2'));

        self::assertFalse($this->send->verification($this->user, null, '192.0.2.3'));
        self::assertCount(2, $this->mailer->sent);
        self::assertCount(2, $this->links->tokens(), 'A refused send opens no link.');
    }

    public function testALinkWhoseMailCannotLeaveIsClosedAgain(): void
    {
        $this->mailer->failing = true;

        self::assertFalse($this->send->reset($this->user, null, '192.0.2.1'));
        self::assertSame([], $this->links->tokens());
    }

    public function testTheTakenAddressNoticeCarriesNoLink(): void
    {
        self::assertTrue($this->send->addressTaken('jane@example.com', '192.0.2.1'));

        self::assertSame([], $this->links->tokens());
        self::assertStringNotContainsString('token=', (string) $this->mailer->last()?->text);
        self::assertStringContainsString('/auth/password/forgot', (string) $this->mailer->last()?->text);
    }

    public function testAnOperatorsLinkToAnAccountWithNoPasswordIsAnInvitation(): void
    {
        $user = User::register($this->user->id, 'jane@example.com', null, $this->clock->now());

        self::assertSame(Delivery::Sent, $this->send->passwordLink($user, '192.0.2.1'));

        $token = $this->links->tokens()[0] ?? '';
        self::assertSame(AccountLinkPurpose::ResetPassword, $this->links->find($token)?->purpose);
        self::assertStringContainsString('invited', (string) $this->mailer->last()?->subject);
        self::assertStringContainsString('/auth/password/reset?token=' . $token, (string) $this->mailer->last()?->text);
    }

    public function testAnOperatorsLinkToAnAccountWithAPasswordIsAReset(): void
    {
        self::assertSame(Delivery::Sent, $this->send->passwordLink($this->user, '192.0.2.1'));

        self::assertStringContainsString('new password', (string) $this->mailer->last()?->subject);
    }

    public function testTheDeliveryTellsALimitFromAMailServerThatRefused(): void
    {
        self::assertSame(Delivery::Sent, $this->send->passwordLink($this->user, '192.0.2.1'));
        self::assertSame(Delivery::Sent, $this->send->passwordLink($this->user, '192.0.2.1'));
        self::assertSame(Delivery::LimitReached, $this->send->passwordLink($this->user, '192.0.2.1'));
        self::assertCount(2, $this->links->tokens());

        $this->mailer->failing = true;
        $other = User::register(
            UserId::fromString('0b5f6a4e-1c2d-4e3f-8a9b-7c6d5e4f3a2b'),
            'other@example.com',
            '$2y$12$hash',
            $this->clock->now(),
        );

        self::assertSame(Delivery::MailUnavailable, $this->send->passwordLink($other, '198.51.100.7'));
        self::assertCount(2, $this->links->tokens(), 'The link that could not be mailed was closed again.');
    }
}
