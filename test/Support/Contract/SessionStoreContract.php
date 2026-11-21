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
