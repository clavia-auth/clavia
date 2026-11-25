<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Identity\Profile;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Provisioning\ProvisionedAccount;
use Clavia\Domain\Provisioning\ProvisionedAccountRepository;
use Clavia\Domain\Provisioning\ProvisioningTokenId;
use Clavia\Domain\Provisioning\ScimFilter;
use Clavia\Domain\Provisioning\ScimUser;
use Clavia\Domain\Shared\AlreadyExists;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see ProvisionedAccountRepository} must do, run against the double and PostgreSQL
 * (docs/design/scim-provisioning.md §4).
 */
trait ProvisionedAccountRepositoryContract
{
    abstract protected function provisionedAccounts(): ProvisionedAccountRepository;

    abstract protected function connections(): ConnectionRepository;

    abstract protected function users(): UserRepository;

    #[Test]
    public function aProvisionedAccountIsReadBackInItsConnectionOnly(): void
    {
        $ada = $this->provisioned('staff', 1, 'Ada.Lovelace', 'ext-1', 'ada@example.com');

        $stored = $this->provisionedAccounts()->find(ConnectionName::fromString('staff'), $ada->userId);

        self::assertSame('Ada.Lovelace', $stored?->userName);
        self::assertSame('ext-1', $stored?->externalId);
        self::assertTrue($stored?->provisionedBy->equals(self::token()));
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:00:01Z'), $stored?->createdAt);
        $this->connections()->add(
            Connection::pool(ConnectionName::fromString('other'), 'Other', true, false, new DateTimeImmutable()),
        );
        self::assertNull($this->provisionedAccounts()->find(ConnectionName::fromString('other'), $ada->userId));
    }

    #[Test]
    public function aUserNameIsTakenIgnoringCaseAndAnExternalIdExactly(): void
    {
        $this->provisioned('staff', 1, 'Ada', 'ext-1', 'ada@example.com');

        $attempts = [[2, 'ADA', 'ext-2', 'userName'], [3, 'grace', 'ext-1', 'externalId']];
        foreach ($attempts as [$seed, $name, $external, $taken]) {
            try {
                $this->provisioned('staff', $seed, $name, $external, 'person' . $seed . '@example.com');
                self::fail('Provisioned twice: ' . $taken);
            } catch (AlreadyExists $conflict) {
                self::assertStringContainsString($taken, $conflict->getMessage());
                self::assertStringNotContainsString($taken === 'userName' ? 'ADA' : 'ext-1', $conflict->getMessage());
            }
        }
        $this->provisioned('staff', 4, 'grace', 'EXT-1', 'person4@example.com');
        $this->provisioned('elsewhere', 5, 'ada', 'ext-1', 'ada@example.com');
    }

    #[Test]
    public function theConnectionsAccountsAreFilteredAndPagedOldestFirst(): void
    {
        $ada = $this->provisioned('staff', 1, 'Ada', 'ext-1', 'Ada@Example.com');
        $grace = $this->provisioned('staff', 2, 'Grace', 'ext-2', 'grace@example.com');
        $this->provisioned('elsewhere', 3, 'Ada', 'ext-1', 'ada@example.com');
        $staff = ConnectionName::fromString('staff');
        $names = fn (?string $filter, int $offset = 0, int $limit = 10): array => array_map(
            static fn (ProvisionedAccount $account): string => $account->userName,
            $this->provisionedAccounts()->matching(
                $staff,
                $filter === null ? null : ScimFilter::parse($filter),
                max(0, $offset),
                max(0, $limit),
            )['accounts'],
        );

        self::assertSame(['Ada', 'Grace'], $names(null));
        self::assertSame(['Grace'], $names(null, 1, 10));
        self::assertSame(['Ada'], $names('userName eq "ADA"'), 'Ignoring case.');
        self::assertSame([], $names('externalId eq "EXT-1"'), 'Exactly.');
        self::assertSame(['Grace'], $names('emails.value eq "GRACE@example.com"'));
        self::assertSame(['Ada'], $names('id eq "' . $ada->userId->value . '"'));
        self::assertSame([], $names('id eq "not-an-id"'));
        self::assertSame(['Grace'], $names('userName eq "grace" and externalId eq "ext-2"'));
        self::assertSame([], $names('userName eq "grace" and externalId eq "ext-1"'));
        self::assertSame(2, $this->provisionedAccounts()->matching($staff, null, 0, 0)['total']);
        self::assertSame([], $this->provisionedAccounts()->matching($staff, null, 0, 0)['accounts']);
        unset($grace);
    }

    #[Test]
    public function savingARecordChangesItsKeysUnderTheSameRules(): void
    {
        $ada = $this->provisioned('staff', 1, 'Ada', 'ext-1', 'ada@example.com');
        $this->provisioned('staff', 2, 'Grace', 'ext-2', 'grace@example.com');
        $later = new DateTimeImmutable('2026-02-01T10:00:00Z');

        $this->provisionedAccounts()->save($ada->changedTo(
            ScimUser::fromJson((object) ['userName' => 'ADA.L', 'externalId' => 'ext-1b']),
            $later,
        ));
        $stored = $this->provisionedAccounts()->find(ConnectionName::fromString('staff'), $ada->userId);
        self::assertSame('ADA.L', $stored?->userName);
        self::assertSame('ext-1b', $stored?->externalId);
        self::assertEquals($later, $stored?->updatedAt);
        self::assertNotNull($stored);
        $this->provisionedAccounts()->save($stored->changedTo(
            ScimUser::fromJson((object) ['userName' => 'ada.l', 'externalId' => 'ext-1b']),
            $later,
        ));

        $this->expectException(AlreadyExists::class);
        $this->provisionedAccounts()->save($ada->changedTo(
            ScimUser::fromJson((object) ['userName' => 'grace', 'externalId' => 'ext-1']),
            $later,
        ));
    }

    #[Test]
    public function deletingTheAccountDeletesItsRecord(): void
    {
        $ada = $this->provisioned('staff', 1, 'Ada', null, 'ada@example.com');

        $this->users()->delete($ada->userId);

        self::assertNull($this->provisionedAccounts()->find(ConnectionName::fromString('staff'), $ada->userId));
        $left = $this->provisionedAccounts()->matching(ConnectionName::fromString('staff'), null, 0, 10);
        self::assertSame(0, $left['total']);
    }

    private function provisioned(
        string $connection,
        int $seed,
        string $userName,
        ?string $externalId,
        string $email,
    ): ProvisionedAccount {
        $name = ConnectionName::fromString($connection);
        if ($this->connections()->find($name) === null) {
            $this->connections()->add(
                Connection::pool($name, ucfirst($connection), true, false, new DateTimeImmutable()),
            );
        }
        $now = new DateTimeImmutable(sprintf('2026-01-15T10:00:%02dZ', $seed));
        $id = UserId::generate(new SeededRandomSource($seed));
        $user = User::provision($id, $email, false, true, Profile::empty(), $name, $now);
        $this->users()->save($user);
        $account = ProvisionedAccount::provision(
            $user->id,
            $name,
            ScimUser::fromJson((object) ['userName' => $userName, 'externalId' => $externalId]),
            self::token(),
            $now,
        );
        $this->provisionedAccounts()->add($account);

        return $account;
    }

    private static function token(): ProvisioningTokenId
    {
        return ProvisioningTokenId::generate(new SeededRandomSource(42));
    }
}
