<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\SessionStore;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\UserId;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see SessionStore} must do. Expiry is asserted by each implementation's own
 * test: how time passes is not the same for an array and for Redis.
 */
trait SessionStoreContract
{
    abstract protected function sessions(): SessionStore;

    #[Test]
    public function aSavedSessionIsReadBackWhole(): void
    {
        $session = $this->aSession();
        $this->sessions()->save('session-1', $session, 600);

        $stored = $this->sessions()->find('session-1');

        self::assertNotNull($stored);
        self::assertTrue($stored->userId->equals($session->userId));
        self::assertEquals($session->authenticatedAt, $stored->authenticatedAt);
        self::assertEquals($session->expiresAt, $stored->expiresAt);
        self::assertSame([AuthenticationMethod::Password], $stored->methods);
        self::assertSame('the-sid', $stored->sid);
    }

    #[Test]
    public function anUnknownOrEmptyIdentifierIsNull(): void
    {
        $this->sessions()->save('session-1', $this->aSession(), 600);

        self::assertNull($this->sessions()->find('session-2'));
        self::assertNull($this->sessions()->find(''));
        self::assertNull($this->sessions()->find('*'));
    }

    #[Test]
    public function aDeletedSessionIsGoneAndOnlyThatOne(): void
    {
        $this->sessions()->save('session-1', $this->aSession(), 600);
        $this->sessions()->save('session-2', $this->aSession(), 600);

        $this->sessions()->delete('session-1');
        $this->sessions()->delete('never-there');
        $this->sessions()->delete('');

        self::assertNull($this->sessions()->find('session-1'));
        self::assertNotNull($this->sessions()->find('session-2'));
    }

    #[Test]
    public function extendingAMissingSessionCreatesNothing(): void
    {
        $this->sessions()->extend('never-there', 600);
        $this->sessions()->extend('', 600);

        self::assertNull($this->sessions()->find('never-there'));
    }

    #[Test]
    public function savingAgainReplacesTheSession(): void
    {
        $this->sessions()->save('session-1', $this->aSession(), 600);
        $replacement = Session::establish(
            UserId::generate(new SeededRandomSource(9)),
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            'another-sid',
            new DateTimeImmutable('2026-01-16T10:00:00Z'),
            3600,
        );

        $this->sessions()->save('session-1', $replacement, 600);

        self::assertSame('another-sid', $this->sessions()->find('session-1')?->sid);
    }

    #[Test]
    public function theApplicationsThatSignedInAreKeptWithTheSession(): void
    {
        $session = $this->aSession();
        $this->sessions()->save('session-1', $session, 600);
        self::assertSame([], $this->sessions()->find('session-1')?->clients);

        $this->sessions()->recordClient($session->userId, 'the-sid', ClientId::fromString('spa'));
        $this->sessions()->recordClient($session->userId, 'the-sid', ClientId::fromString('admin'));
        $this->sessions()->recordClient($session->userId, 'the-sid', ClientId::fromString('spa'));

        self::assertSame(['admin', 'spa'], self::clientIds($this->sessions()->find('session-1')));
        self::assertSame(['admin', 'spa'], self::clientIds($this->sessions()->ofUser($session->userId)[0] ?? null));
    }

    #[Test]
    public function aClientIsRecordedOnlyOnTheAccountsOwnLiveSession(): void
    {
        $session = $this->aSession();
        $this->sessions()->save('session-1', $session, 600);

        $stranger = UserId::generate(new SeededRandomSource(5));
        $this->sessions()->recordClient($stranger, 'the-sid', ClientId::fromString('x'));
        $this->sessions()->recordClient($session->userId, 'another-sid', ClientId::fromString('x'));
        $this->sessions()->recordClient($session->userId, '', ClientId::fromString('x'));
        self::assertSame([], $this->sessions()->find('session-1')?->clients);

        $this->sessions()->delete('session-1');
        $this->sessions()->recordClient($session->userId, 'the-sid', ClientId::fromString('spa'));
        $this->sessions()->save('session-1', $session, 600);
        self::assertSame([], $this->sessions()->find('session-1')?->clients, 'A new session starts with none.');
    }

    #[Test]
    public function anAccountsSessionsAreListedOldestFirstAndEndedTogetherOrBySid(): void
    {
        $userId = $this->aSession()->userId;
        $this->sessions()->save('later', $this->sessionOf($userId, 'sid-later', '2026-01-15T12:00:00Z'), 600);
        $this->sessions()->save('earlier', $this->sessionOf($userId, 'sid-earlier', '2026-01-15T09:00:00Z'), 600);
        $this->sessions()->save('third', $this->sessionOf($userId, 'sid-third', '2026-01-15T13:00:00Z'), 600);
        $stranger = UserId::generate(new SeededRandomSource(5));
        $this->sessions()->save('stranger', $this->sessionOf($stranger, 's', null), 600);
        $this->sessions()->delete('third');

        self::assertSame(['sid-earlier', 'sid-later'], self::sids($this->sessions()->ofUser($userId)));

        self::assertSame(['sid-later'], self::sids($this->sessions()->endOfUser($userId, 'sid-later')));
        self::assertSame([], $this->sessions()->endOfUser($userId, 'sid-later'), 'Already ended.');
        self::assertNull($this->sessions()->find('later'));
        self::assertNotNull($this->sessions()->find('earlier'));

        self::assertSame(['sid-earlier'], self::sids($this->sessions()->endOfUser($userId)));
        self::assertNull($this->sessions()->find('earlier'));
        self::assertSame([], $this->sessions()->ofUser($userId));
        self::assertNotNull($this->sessions()->find('stranger'), 'Someone else\'s session is left alone.');
    }

    #[Test]
    public function aReplacedSessionIsNoLongerItsFormerOwners(): void
    {
        $first = $this->aSession();
        $this->sessions()->save('session-1', $first, 600);
        $stranger = UserId::generate(new SeededRandomSource(5));
        $this->sessions()->save('session-1', $this->sessionOf($stranger, 's', null), 600);

        self::assertSame([], $this->sessions()->ofUser($first->userId));
        self::assertSame([], $this->sessions()->endOfUser($first->userId));
        self::assertNotNull($this->sessions()->find('session-1'));
    }

    /**
     * @param non-empty-string $sid
     */
    private function sessionOf(UserId $userId, string $sid, ?string $at): Session
    {
        return Session::establish(
            $userId,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            $sid,
            new DateTimeImmutable($at ?? '2026-01-15T10:00:00Z'),
            604800,
        );
    }

    /**
     * @param list<Session> $sessions
     *
     * @return list<string>
     */
    private static function sids(array $sessions): array
    {
        return array_map(static fn (Session $session): string => $session->sid, $sessions);
    }

    /** @return list<string>|null */
    private static function clientIds(?Session $session): ?array
    {
        return $session === null
            ? null
            : array_map(static fn (ClientId $client): string => $client->value, $session->clients);
    }

    private function aSession(): Session
    {
        return Session::establish(
            UserId::generate(new SeededRandomSource(1)),
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            'the-sid',
            new DateTimeImmutable('2026-01-15T10:00:00.123456Z'),
            604800,
        );
    }
}
