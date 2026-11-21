<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\AssertedIdentity;
use Clavia\Domain\Identity\ExternalIdentity;
use Clavia\Domain\Identity\ExternalIdentityRepository;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\AlreadyExists;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see ExternalIdentityRepository} must do.
 */
trait ExternalIdentityRepositoryContract
{
    abstract protected function users(): UserRepository;

    abstract protected function identities(): ExternalIdentityRepository;

    #[Test]
    public function aLinkedIdentityIsFoundByProviderAndSubject(): void
    {
        $userId = $this->accountFor('ada@example.com');
        $this->identities()->add(ExternalIdentity::link(
            $this->asserted('google', 'g-123', 'ada@example.com'),
            $userId,
            new DateTimeImmutable('2026-01-15T10:00:00.123456Z'),
        ));

        $identity = $this->identities()->find(ConnectionName::fromString('google'), 'g-123');

        self::assertNotNull($identity);
        self::assertSame('google', $identity->provider->value);
        self::assertSame('g-123', $identity->subject);
        self::assertTrue($identity->userId->equals($userId));
        self::assertSame('ada@example.com', $identity->email);
        self::assertSame('2026-01-15T10:00:00.123456+00:00', $identity->linkedAt->format('Y-m-d\TH:i:s.uP'));
    }

    #[Test]
    public function theSubjectIsMatchedExactlyAndWithinItsProvider(): void
    {
        $this->identities()->add(ExternalIdentity::link(
            $this->asserted('google', 'g-123', null),
            $this->accountFor('ada@example.com'),
            new DateTimeImmutable(),
        ));

        self::assertNull($this->identities()->find(ConnectionName::fromString('github'), 'g-123'));
        self::assertNull($this->identities()->find(ConnectionName::fromString('google'), 'G-123'));
        self::assertNull($this->identities()->find(ConnectionName::fromString('google'), 'g-12'));
        self::assertNull($this->identities()->find(ConnectionName::fromString('google'), 'g-123')?->email);
    }

    #[Test]
    public function aSubjectIsLinkedToOneAccountOnly(): void
    {
        $this->identities()->add(ExternalIdentity::link(
            $this->asserted('google', 'g-123', null),
            $this->accountFor('ada@example.com'),
            new DateTimeImmutable(),
        ));

        $this->expectException(AlreadyExists::class);

        $this->identities()->add(ExternalIdentity::link(
            $this->asserted('google', 'g-123', null),
            $this->accountFor('bob@example.com'),
            new DateTimeImmutable(),
        ));
    }

    #[Test]
    public function anAccountMayHoldSeveralIdentities(): void
    {
        $userId = $this->accountFor('ada@example.com');
        foreach ([['google', 'g-1'], ['google', 'g-2'], ['github', '42']] as [$provider, $subject]) {
            $this->identities()->add(
                ExternalIdentity::link($this->asserted($provider, $subject, null), $userId, new DateTimeImmutable()),
            );
        }

        foreach ([['google', 'g-1'], ['google', 'g-2'], ['github', '42']] as [$provider, $subject]) {
            self::assertTrue(
                $this->identities()->find(ConnectionName::fromString($provider), $subject)?->userId->equals($userId),
            );
        }
    }

    #[Test]
    public function theIdentitiesOfAnAccountAreListedUnlinkedAndCountedByConnection(): void
    {
        $ada = $this->accountFor('ada@example.com');
        $bob = $this->accountFor('bob@example.com');
        $now = new DateTimeImmutable('2026-01-15T10:00:00Z');
        $links = [['google', 'g-2', $ada], ['github', '42', $ada], ['google', 'g-1', $ada], ['google', 'g-3', $bob]];
        foreach ($links as [$provider, $subject, $owner]) {
            $this->identities()->add(ExternalIdentity::link($this->asserted($provider, $subject, null), $owner, $now));
        }

        self::assertSame(
            ['github:42', 'google:g-1', 'google:g-2'],
            array_map(
                static fn (ExternalIdentity $identity): string => $identity->provider->value . ':' . $identity->subject,
                $this->identities()->ofUser($ada),
            ),
        );
        self::assertSame(3, $this->identities()->countThrough(ConnectionName::fromString('google')));

        self::assertSame(2, $this->identities()->unlink($ada, ConnectionName::fromString('google')));
        self::assertSame(0, $this->identities()->unlink($ada, ConnectionName::fromString('google')));

        self::assertCount(1, $this->identities()->ofUser($ada));
        self::assertNull($this->identities()->find(ConnectionName::fromString('google'), 'g-1'));
        self::assertNotNull($this->identities()->find(ConnectionName::fromString('google'), 'g-3'));
        self::assertSame(1, $this->identities()->countThrough(ConnectionName::fromString('google')));
        self::assertSame([], $this->identities()->ofUser(UserId::generate(new SeededRandomSource(5))));
    }

    private function asserted(string $provider, string $subject, ?string $email): AssertedIdentity
    {
        return AssertedIdentity::of(ConnectionName::fromString($provider), $subject, $email, true);
    }

    private function accountFor(string $email): UserId
    {
        $user = User::register(
            UserId::generate(new SeededRandomSource(crc32($email))),
            $email,
            null,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
        $this->users()->save($user);

        return $user->id;
    }
}
