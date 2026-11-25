<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Authentication\External;

use Clavia\Application\Authentication\External\ExternalSignInFailure;
use Clavia\Application\Authentication\External\ResolveExternalAccount;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\AssertedIdentity;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryExternalIdentityRepository;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

/**
 * An address nothing vouches for (a SAML connection not trusted for them) still makes an account for
 * a new subject, unverified and linked to nothing; without that permission, as for OpenID Connect,
 * it signs nobody in.
 */
final class ResolveExternalAccountTest extends TestCase
{
    private InMemoryUserRepository $users;
    private InMemoryExternalIdentityRepository $identities;

    #[\Override]
    protected function setUp(): void
    {
        $this->users = new InMemoryUserRepository();
        $this->identities = new InMemoryExternalIdentityRepository();
    }

    public function testAnUnverifiedAddressIsRefusedUnlessTheCallerAllowsIt(): void
    {
        $asserted = AssertedIdentity::of(ConnectionName::fromString('acme'), 'subject-1', 'ada@acme.example', false);

        self::assertSame(ExternalSignInFailure::NoVerifiedEmail, ($this->resolve())($asserted, []));

        $user = ($this->resolve())($asserted, [], unverifiedAddress: true);
        self::assertInstanceOf(User::class, $user);
        self::assertFalse($user->isEmailVerified());
        self::assertSame('acme', $user->connection->value);
        $identity = $this->identities->find(ConnectionName::fromString('acme'), 'subject-1');
        self::assertTrue($identity?->userId->equals($user->id));
        $again = ($this->resolve())($asserted, [], unverifiedAddress: true);
        self::assertInstanceOf(User::class, $again, 'Signed in again by subject.');
    }

    public function testAnUnverifiedAddressNeverLinksToAnAccountThatHasIt(): void
    {
        $pool = ConnectionName::fromString('password');
        $id = UserId::generate(new SeededRandomSource(1));
        $this->users->save(User::register($id, 'ada@acme.example', null, new DateTimeImmutable(), $pool));
        $asserted = AssertedIdentity::of(ConnectionName::fromString('acme'), 'subject-1', 'ada@acme.example', false);

        $user = ($this->resolve(autoLink: true))($asserted, [$pool], unverifiedAddress: true);

        self::assertInstanceOf(User::class, $user);
        self::assertSame('acme', $user->connection->value, 'A new account, never the pool\'s.');
    }

    public function testWithNoAddressAtAllNobodySignsIn(): void
    {
        $asserted = AssertedIdentity::of(ConnectionName::fromString('acme'), 'subject-1', null, false);

        $refused = ($this->resolve())($asserted, [], unverifiedAddress: true);

        self::assertSame(ExternalSignInFailure::NoVerifiedEmail, $refused);
    }

    private function resolve(bool $autoLink = false): ResolveExternalAccount
    {
        return new ResolveExternalAccount(
            $this->users,
            $this->identities,
            new InMemoryTransactionManager(),
            new SeededRandomSource(2),
            new FrozenClock(),
            $autoLink,
        );
    }
}
