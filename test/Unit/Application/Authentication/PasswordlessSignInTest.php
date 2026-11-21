<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Authentication;

use Clavia\Application\Authentication\Passwordless\AnswerPasswordlessCode;
use Clavia\Application\Authentication\Passwordless\DescribePasswordlessChallenge;
use Clavia\Application\Authentication\Passwordless\FinishPasswordlessSignIn;
use Clavia\Application\Authentication\Passwordless\FollowPasswordlessLink;
use Clavia\Application\Authentication\Passwordless\PasswordlessCodeRejected;
use Clavia\Application\Authentication\Passwordless\PasswordlessCodeSent;
use Clavia\Application\Authentication\Passwordless\PasswordlessFailure;
use Clavia\Application\Authentication\Passwordless\PasswordlessLinkSent;
use Clavia\Application\Authentication\Passwordless\PasswordlessRefused;
use Clavia\Application\Authentication\Passwordless\PasswordlessSendLimit;
use Clavia\Application\Authentication\Passwordless\PasswordlessStart;
use Clavia\Application\Authentication\Passwordless\SignInMail;
use Clavia\Application\Authentication\Passwordless\StartPasswordlessSignIn;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Authentication\SignIn\CompleteFirstFactor;
use Clavia\Application\Authentication\SignIn\SignedIn;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\LoginState;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Clients;
use ClaviaTest\Support\Fake\FakeIdentityProviders;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAttemptCounter;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemoryConnectionRepository;
use ClaviaTest\Support\Fake\InMemoryLoginStateStore;
use ClaviaTest\Support\Fake\InMemoryMfaChallengeStore;
use ClaviaTest\Support\Fake\InMemoryMfaFactorRepository;
use ClaviaTest\Support\Fake\InMemoryPasswordlessChallengeStore;
use ClaviaTest\Support\Fake\InMemorySessionStore;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\RecordingMailer;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;

/**
 * The passwordless use cases together, on fakes: what is sent, what is parked, what
 * answers it, and what comes of it.
 */
final class PasswordlessSignInTest extends TestCase
{
    private FrozenClock $clock;
    private RecordingMailer $mailer;
    private InMemoryPasswordlessChallengeStore $challenges;
    private InMemoryLoginStateStore $loginStates;
    private InMemoryClientRepository $clients;
    private InMemoryUserRepository $users;
    private Sessions $sessions;
    private StartPasswordlessSignIn $start;
    private AnswerPasswordlessCode $answer;
    private FollowPasswordlessLink $follow;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->mailer = new RecordingMailer();
        $this->challenges = new InMemoryPasswordlessChallengeStore($this->clock);
        $this->loginStates = new InMemoryLoginStateStore($this->clock);
        $this->clients = new InMemoryClientRepository();
        $this->clients->save(Clients::public('spa'));
        $this->users = new InMemoryUserRepository();
        $secrets = new SecretGenerator(new SeededRandomSource(1));
        $this->sessions = new Sessions(new InMemorySessionStore($this->clock), $secrets, $this->clock, 28800, 604800);
        $access = new ConnectionAccess(
            new InMemoryConnectionRepository($this->clients),
            new FakeIdentityProviders(),
            $this->mailer,
        );
        $describe = new DescribePasswordlessChallenge($this->challenges, $this->clients);
        $finish = new FinishPasswordlessSignIn(
            $access,
            $this->clients,
            $this->users,
            $this->loginStates,
            new CompleteFirstFactor(
                $this->sessions,
                new InMemoryMfaFactorRepository(new InMemoryTransactionManager()),
                new InMemoryMfaChallengeStore($this->clock),
                $secrets,
                300,
            ),
            new SeededRandomSource(2),
            $this->clock,
        );

        $this->start = new StartPasswordlessSignIn(
            $access,
            $this->clients,
            $this->loginStates,
            $this->challenges,
            new PasswordlessSendLimit(new InMemoryAttemptCounter($this->clock), 2),
            $this->mailer,
            new SignInMail('acme.com', 'https://auth.acme.com', 600, 900),
            $describe,
            $secrets,
            new SeededRandomSource(3),
            600,
            900,
        );
        $this->answer = new AnswerPasswordlessCode($this->challenges, $describe, $finish, 3);
        $this->follow = new FollowPasswordlessLink($this->challenges, $finish);
    }

    public function testACodeIsSentAndAnsweredOnceInTheBrowserThatAsked(): void
    {
        $this->loginStates->put('login', new LoginState('/oauth2/authorize?x=y', ClientId::fromString('spa')));

        $sent = $this->startWith(' Jane@Example.com ', 'code', 'login');

        self::assertInstanceOf(PasswordlessCodeSent::class, $sent);
        self::assertSame('jane@example.com', $sent->prompt->email);
        self::assertSame(['https://app.example'], $sent->prompt->formOrigins);
        $mail = $this->mailer->last();
        self::assertSame('jane@example.com', $mail?->to);
        self::assertSame('Your sign-in code for acme.com', $mail?->subject);
        self::assertStringContainsString('expires in 10 minutes', $mail?->text ?? '');

        $signedIn = ($this->answer)($sent->handle, $this->code(), null);

        self::assertInstanceOf(SignedIn::class, $signedIn);
        self::assertSame('/oauth2/authorize?x=y', $signedIn->nextUrl);
        $session = $this->sessions->resolve($signedIn->sessionId);
        self::assertSame([AuthenticationMethod::OneTimePassword], $session?->methods);
        self::assertTrue($session?->connection->equals(ConnectionName::email()));
        self::assertNull($this->loginStates->get('login'), 'The login page handle is spent.');
        $user = $this->users->findByEmail(ConnectionName::email(), 'jane@example.com');
        self::assertNotNull($user);
        self::assertTrue($user->isEmailVerified());
        self::assertNull($user->passwordHash());

        self::assertEquals(
            new PasswordlessRefused(PasswordlessFailure::Expired),
            ($this->answer)($sent->handle, $this->code(), null),
            'A code signs in once.',
        );
    }

    public function testWrongCodesSpendTheBudgetAndTheLastOneEndsTheChallenge(): void
    {
        $sent = $this->startWith('jane@example.com', 'code');
        self::assertInstanceOf(PasswordlessCodeSent::class, $sent);

        self::assertInstanceOf(PasswordlessCodeRejected::class, ($this->answer)($sent->handle, '000000', null));
        self::assertInstanceOf(PasswordlessCodeRejected::class, ($this->answer)($sent->handle, 'nonsense', null));
        self::assertEquals(
            new PasswordlessRefused(PasswordlessFailure::Expired),
            ($this->answer)($sent->handle, '000000', null),
        );
        self::assertEquals(
            new PasswordlessRefused(PasswordlessFailure::Expired),
            ($this->answer)($sent->handle, $this->code(), null),
            'The right code is dead with its challenge.',
        );
    }

    public function testALinkIsSpentOnlyAsALinkAndACodeHandleIsNoLink(): void
    {
        $link = $this->startWith('jane@example.com', 'link');
        self::assertInstanceOf(PasswordlessLinkSent::class, $link);
        $token = $this->token();

        $code = $this->startWith('ada@example.com', 'code');
        self::assertInstanceOf(PasswordlessCodeSent::class, $code);
        self::assertEquals(
            new PasswordlessRefused(PasswordlessFailure::InvalidLink),
            ($this->follow)($code->handle, null),
            'Holding the cookie is not having read the code.',
        );
        self::assertEquals(
            new PasswordlessRefused(PasswordlessFailure::Expired),
            ($this->answer)($token, '123456', null),
            'A link answers no code.',
        );

        self::assertInstanceOf(SignedIn::class, ($this->follow)($token, null));
        self::assertEquals(new PasswordlessRefused(PasswordlessFailure::InvalidLink), ($this->follow)($token, null));
    }

    public function testNothingIsSentForABadRequestOrAnApplicationWithoutEmail(): void
    {
        $this->clients->save(Clients::public('spa')->withConnections([ConnectionName::defaultPool()]));
        $this->loginStates->put('login', new LoginState('/oauth2/authorize?x=y', ClientId::fromString('spa')));

        self::assertEquals(self::refused(PasswordlessFailure::InvalidRequest), $this->startWith('nope', 'code'));
        self::assertEquals(self::refused(PasswordlessFailure::InvalidRequest), $this->startWith('a@b.c', 'sms'));
        self::assertEquals(
            self::refused(PasswordlessFailure::NotAvailable),
            $this->startWith('jane@example.com', 'code', 'login'),
        );
        self::assertSame([], $this->mailer->sent);
    }

    public function testTheSendLimitCountsPerAddressAndPerSource(): void
    {
        self::assertInstanceOf(PasswordlessLinkSent::class, $this->startWith('jane@example.com', 'link'));
        self::assertInstanceOf(PasswordlessLinkSent::class, $this->startWith('JANE@example.com', 'link'));
        self::assertEquals(
            self::refused(PasswordlessFailure::TooManyEmails),
            $this->startWith('jane@example.com', 'link'),
        );
        self::assertEquals(
            self::refused(PasswordlessFailure::TooManyEmails),
            $this->startWith('ada@example.com', 'link'),
            'The same source, another mailbox.',
        );
        self::assertInstanceOf(
            PasswordlessLinkSent::class,
            $this->startWith('ada@example.com', 'link', clientAddress: '198.51.100.9'),
        );

        $this->clock->advance(PasswordlessSendLimit::WINDOW_SECONDS + 1);
        self::assertInstanceOf(PasswordlessLinkSent::class, $this->startWith('jane@example.com', 'link'));
    }

    public function testAMessageThatCannotBeSentLeavesNothingPending(): void
    {
        $this->mailer->failing = true;

        self::assertEquals(
            self::refused(PasswordlessFailure::MailUnavailable),
            $this->startWith('jane@example.com', 'link'),
        );

        $this->mailer->failing = false;
        $this->startWith('ada@example.com', 'link');
        self::assertCount(1, $this->mailer->sent);
    }

    public function testADisabledAccountIsNotSignedIn(): void
    {
        $user = User::registerFromProvider(
            UserId::generate(new SeededRandomSource(9)),
            'jane@example.com',
            ConnectionName::email(),
            $this->clock->now(),
        );
        $user->deactivate($this->clock->now());
        $this->users->save($user);
        $this->startWith('jane@example.com', 'link');

        self::assertEquals(self::refused(PasswordlessFailure::AccountDisabled), ($this->follow)($this->token(), null));
    }

    public function testAnAccountWhoseAddressAnOperatorCapitalizedIsStillFound(): void
    {
        $user = User::registerFromProvider(
            UserId::generate(new SeededRandomSource(9)),
            'Jane@Example.com',
            ConnectionName::email(),
            $this->clock->now(),
        );
        $this->users->save($user);
        $this->startWith('jane@example.com', 'link');

        $signedIn = ($this->follow)($this->token(), null);

        self::assertInstanceOf(SignedIn::class, $signedIn);
        self::assertTrue($this->sessions->resolve($signedIn->sessionId)?->userId->equals($user->id));
    }

    private function startWith(
        string $email,
        string $mode,
        ?string $loginState = null,
        string $clientAddress = '203.0.113.7',
    ): PasswordlessCodeSent|PasswordlessLinkSent|PasswordlessRefused {
        return ($this->start)(new PasswordlessStart($email, $mode, $clientAddress, $loginState));
    }

    private static function refused(PasswordlessFailure $reason): PasswordlessRefused
    {
        return new PasswordlessRefused($reason);
    }

    /** The six digits in the last message. */
    private function code(): string
    {
        self::assertSame(1, preg_match('/\b(\d{6})\b/', $this->mailer->last()?->text ?? '', $match));

        return $match[1];
    }

    /** The link's secret in the last message. */
    private function token(): string
    {
        $link = '~^https://auth\.acme\.com/auth/passwordless/verify\?token=([A-Za-z0-9_-]+)$~m';
        self::assertSame(1, preg_match($link, $this->mailer->last()?->text ?? '', $match));

        return $match[1];
    }
}
