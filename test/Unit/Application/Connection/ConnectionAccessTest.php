<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Connection;

use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Connection\UsableConnection;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionName;
use ClaviaTest\Support\Clients;
use ClaviaTest\Support\Fake\FakeIdentityProvider;
use ClaviaTest\Support\Fake\FakeIdentityProviders;
use ClaviaTest\Support\Fake\InMemoryConnectionRepository;
use ClaviaTest\Support\Fake\RecordingMailer;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

/**
 * The three switches combined: a connection's own, whether it can work, and the
 * application's list — or, for a third party, the domain flag.
 */
final class ConnectionAccessTest extends TestCase
{
    private InMemoryConnectionRepository $connections;
    private ConnectionAccess $access;
    private RecordingMailer $mailer;

    #[\Override]
    protected function setUp(): void
    {
        $this->connections = new InMemoryConnectionRepository();
        $this->mailer = new RecordingMailer();
        // Google is configured; GitHub is not.
        $this->access = new ConnectionAccess(
            $this->connections,
            new FakeIdentityProviders(new FakeIdentityProvider('google')),
            $this->mailer,
        );
        $this->connections->add(Connection::pool(
            ConnectionName::fromString('staff'),
            'Staff',
            true,
            false,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        ));
    }

    public function testAConnectionIsUsableWhenSwitchedOnAndAbleToWork(): void
    {
        self::assertSame(['email', 'google', 'password', 'staff'], self::names($this->access->usable()));
        $github = $this->find('github');
        self::assertFalse($this->access->isUsable($github));
        self::assertFalse($this->access->isConfigured($github));

        $this->switchOff('google');

        self::assertSame(['email', 'password', 'staff'], self::names($this->access->usable()));
        self::assertTrue($this->access->isConfigured($this->find('google')), 'Off, but it would work.');
        self::assertTrue($this->access->isConfigured($this->find('staff')));
    }

    public function testWithoutAnApplicationEveryUsableConnectionIsAvailable(): void
    {
        self::assertSame(['email', 'google', 'password', 'staff'], self::names($this->access->available(null)));
        self::assertSame(['password', 'staff'], self::values($this->access->pools(null)), 'Email is no pool.');
    }

    public function testThePasswordlessConnectionWorksOnlyWhileMailCanBeSent(): void
    {
        $email = $this->find('email');
        self::assertTrue($this->access->isUsable($email));
        self::assertNull($this->access->usable()[0]->provider, 'Signed in here, not at a provider.');
        self::assertNull($this->access->external(ConnectionName::email()), 'Not external.');

        $withoutMail = new ConnectionAccess(
            $this->connections,
            new FakeIdentityProviders(new FakeIdentityProvider('google')),
            new RecordingMailer(false),
        );

        self::assertFalse($withoutMail->isUsable($email));
        self::assertFalse($withoutMail->isConfigured($email));
        self::assertFalse($withoutMail->allows(null, ConnectionName::email()));
        self::assertSame(['google', 'password', 'staff'], self::names($withoutMail->usable()));
    }

    public function testAFirstPartyApplicationGetsItsOwnListAndNothingElse(): void
    {
        $client = $this->firstParty([ConnectionName::fromString('google'), ConnectionName::fromString('staff')]);

        self::assertSame(['google', 'staff'], self::names($this->access->available($client)));
        self::assertSame(['staff'], self::values($this->access->pools($client)));
        self::assertFalse(
            $this->access->allows($client, ConnectionName::defaultPool()),
            'The default pool is a domain connection, which a first-party list does not take in.',
        );
    }

    public function testAThirdPartyApplicationGetsTheDomainConnections(): void
    {
        $client = Clients::public('tpc_aaaaaaaaaaaaaaaaaaaaaa');
        $staff = $this->find('staff');

        self::assertSame(['password'], self::names($this->access->available($client)));

        $this->connections->save($staff->switched(null, true, null));
        self::assertSame(['password', 'staff'], self::values($this->access->pools($client)));
    }

    public function testAnEnabledConnectionThatCannotWorkIsNotAvailableEvenWhenListed(): void
    {
        $client = $this->firstParty([ConnectionName::fromString('github')]);

        self::assertSame([], $this->access->available($client));
        self::assertFalse($this->access->allows($client, ConnectionName::fromString('github')));
    }

    public function testOnlyAWorkingExternalConnectionIsFoundAsOne(): void
    {
        $google = $this->access->external(ConnectionName::fromString('google'));
        self::assertSame('google', $google?->connection->name->value);
        self::assertNotNull($google?->provider);
        self::assertNull($this->access->external(ConnectionName::fromString('github')), 'Not configured.');
        self::assertNull($this->access->external(ConnectionName::defaultPool()), 'Not external.');
        self::assertNull($this->access->external(ConnectionName::fromString('gitlab')), 'Unknown.');

        $this->switchOff('google');
        self::assertNull($this->access->external(ConnectionName::fromString('google')), 'Switched off.');
    }

    /**
     * @param list<ConnectionName> $connections
     */
    private function firstParty(array $connections): Client
    {
        return Clients::public('spa')->withConnections($connections);
    }

    private function find(string $name): Connection
    {
        $connection = $this->connections->find(ConnectionName::fromString($name));
        self::assertNotNull($connection);

        return $connection;
    }

    private function switchOff(string $name): void
    {
        $this->connections->save($this->find($name)->switched(false, null, null));
    }

    /**
     * @param list<UsableConnection> $usable
     *
     * @return list<string>
     */
    private static function names(array $usable): array
    {
        return array_map(static fn (UsableConnection $one): string => $one->connection->name->value, $usable);
    }

    /**
     * @param list<ConnectionName> $names
     *
     * @return list<string>
     */
    private static function values(array $names): array
    {
        return array_map(static fn (ConnectionName $name): string => $name->value, $names);
    }
}
