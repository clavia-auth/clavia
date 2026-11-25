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
use Clavia\Domain\Provisioning\ProvisioningTokenId;
use Clavia\Domain\Provisioning\ScimFilter;
use Clavia\Domain\Provisioning\ScimFilterAttribute;
use Clavia\Domain\Provisioning\ScimGroup;
use Clavia\Domain\Provisioning\ScimGroupId;
use Clavia\Domain\Provisioning\ScimGroupRepository;
use Clavia\Domain\Provisioning\ScimGroupResource;
use Clavia\Domain\Shared\AlreadyExists;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see ScimGroupRepository} must do, run against the double and PostgreSQL
 * (docs/design/scim-provisioning.md §5.5).
 */
trait ScimGroupRepositoryContract
{
    abstract protected function scimGroups(): ScimGroupRepository;

    abstract protected function connections(): ConnectionRepository;

    abstract protected function users(): UserRepository;

    #[Test]
    public function aGroupIsReadBackWithItsMembersInItsConnectionOnly(): void
    {
        [$ada, $grace] = [$this->member(1), $this->member(2)];
        $group = $this->group(10, 'Engineers', 'g-1', [$grace, $ada]);

        $stored = $this->scimGroups()->find(ConnectionName::fromString('staff'), $group->id);

        self::assertSame('Engineers', $stored?->displayName);
        self::assertSame('g-1', $stored?->externalId);
        self::assertEqualsCanonicalizing([$ada->value, $grace->value], self::ids($stored->members ?? []));
        $other = ConnectionName::fromString('other');
        $this->connections()->add(Connection::pool($other, 'Other', true, false, new DateTimeImmutable()));
        self::assertNull($this->scimGroups()->find($other, $group->id));
        $names = static fn (array $groups): array => array_map(
            static fn (ScimGroup $g): string => $g->displayName,
            $groups,
        );
        self::assertSame(['Engineers'], $names($this->scimGroups()->ofMember($ada)));
        self::assertSame(['Engineers'], $names($this->scimGroups()->named('Engineers')));
        self::assertSame([], $this->scimGroups()->named('engineers'), 'A role is named exactly.');
    }

    #[Test]
    public function aGroupsNameIsUniqueIgnoringCaseAndItsMembersAreWrittenWhole(): void
    {
        [$ada, $grace] = [$this->member(1), $this->member(2)];
        $group = $this->group(10, 'Engineers', 'g-1', [$ada]);

        try {
            $this->group(11, 'ENGINEERS', 'g-2', []);
            self::fail('Two groups of a name.');
        } catch (AlreadyExists $conflict) {
            self::assertSame(ScimGroupRepository::DISPLAY_NAME_TAKEN, $conflict->getMessage());
        }
        $this->scimGroups()->save($group->changedTo(
            ScimGroupResource::fromJson((object) ['displayName' => 'Engineering', 'externalId' => 'g-1']),
            [$grace],
            new DateTimeImmutable('2026-02-01T10:00:00Z'),
        ));

        $stored = $this->scimGroups()->find(ConnectionName::fromString('staff'), $group->id);
        self::assertSame('Engineering', $stored?->displayName);
        self::assertSame([$grace->value], self::ids($stored->members ?? []));
        self::assertSame([], $this->scimGroups()->ofMember($ada));
        $this->group(12, 'Engineers', null, []);
    }

    #[Test]
    public function theConnectionsGroupsAreFilteredAndADeletedAccountLeavesThem(): void
    {
        $ada = $this->member(1);
        $engineers = $this->group(10, 'Engineers', 'g-1', [$ada]);
        $this->group(11, 'Analysts', 'g-2', []);
        $staff = ConnectionName::fromString('staff');
        $names = fn (string $filter): array => array_map(
            static fn (ScimGroup $group): string => $group->displayName,
            $this->scimGroups()->matching(
                $staff,
                ScimFilter::parse($filter, ScimFilterAttribute::GROUPS),
                0,
                10,
            )['groups'],
        );

        self::assertSame(2, $this->scimGroups()->matching($staff, null, 0, 0)['total']);
        self::assertSame(['Engineers'], $names('displayName eq "ENGINEERS"'));
        self::assertSame(['Analysts'], $names('externalId eq "g-2"'));
        self::assertSame(['Engineers'], $names('id eq "' . $engineers->id->value . '"'));
        self::assertSame([], $names('id eq "nope"'));

        $this->users()->delete($ada);
        self::assertSame([], $this->scimGroups()->find($staff, $engineers->id)?->members);
        $this->scimGroups()->delete($engineers->id);
        self::assertNull($this->scimGroups()->find($staff, $engineers->id));
    }

    /**
     * @param list<UserId> $members
     *
     * @return list<string>
     */
    private static function ids(array $members): array
    {
        return array_map(static fn (UserId $id): string => $id->value, $members);
    }

    private function member(int $seed): UserId
    {
        $this->staff();
        $id = UserId::generate(new SeededRandomSource($seed));
        $this->users()->save(User::provision(
            $id,
            'person' . $seed . '@example.com',
            false,
            true,
            Profile::empty(),
            ConnectionName::fromString('staff'),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        ));

        return $id;
    }

    /** @param list<UserId> $members */
    private function group(int $seed, string $name, ?string $externalId, array $members): ScimGroup
    {
        $this->staff();
        $group = ScimGroup::provision(
            ScimGroupId::generate(new SeededRandomSource($seed)),
            ConnectionName::fromString('staff'),
            ScimGroupResource::fromJson((object) ['displayName' => $name, 'externalId' => $externalId]),
            $members,
            ProvisioningTokenId::generate(new SeededRandomSource(42)),
            new DateTimeImmutable(sprintf('2026-01-15T10:00:%02dZ', $seed)),
        );
        $this->scimGroups()->add($group);

        return $group;
    }

    private function staff(): void
    {
        $staff = ConnectionName::fromString('staff');
        if ($this->connections()->find($staff) === null) {
            $this->connections()->add(Connection::pool($staff, 'Staff', true, false, new DateTimeImmutable()));
        }
    }
}
