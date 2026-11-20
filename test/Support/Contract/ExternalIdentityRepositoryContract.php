<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\Identity\AssertedIdentity;
use Clavia\Domain\Identity\ExternalIdentity;
use Clavia\Domain\Identity\ExternalIdentityRepository;
use Clavia\Domain\Identity\ProviderName;
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

        $identity = $this->identities()->find(ProviderName::fromString('google'), 'g-123');

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

        self::assertNull($this->identities()->find(ProviderName::fromString('github'), 'g-123'));
        self::assertNull($this->identities()->find(ProviderName::fromString('google'), 'G-123'));
        self::assertNull($this->identities()->find(ProviderName::fromString('google'), 'g-12'));
        self::assertNull($this->identities()->find(ProviderName::fromString('google'), 'g-123')?->email);
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
                $this->identities()->find(ProviderName::fromString($provider), $subject)?->userId->equals($userId),
            );
        }
    }

    private function asserted(string $provider, string $subject, ?string $email): AssertedIdentity
    {
        return AssertedIdentity::of(ProviderName::fromString($provider), $subject, $email, true);
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
