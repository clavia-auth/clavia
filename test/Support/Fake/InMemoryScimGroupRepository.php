<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Provisioning\ScimFilter;
use Clavia\Domain\Provisioning\ScimFilterAttribute;
use Clavia\Domain\Provisioning\ScimGroup;
use Clavia\Domain\Provisioning\ScimGroupId;
use Clavia\Domain\Provisioning\ScimGroupRepository;
use Clavia\Domain\Shared\AlreadyExists;

/**
 * SCIM groups in memory, with the storage's uniqueness rules; an account deleted from the users'
 * double leaves every group, as the cascade does.
 */
final class InMemoryScimGroupRepository implements ScimGroupRepository
{
    /** @var array<string, ScimGroup> By id. */
    private array $groups = [];

    public function __construct(private readonly UserRepository $users)
    {
    }

    #[\Override]
    public function add(ScimGroup $group): void
    {
        $this->refuseConflicts($group);
        $this->groups[$group->id->value] = $group;
    }

    #[\Override]
    public function save(ScimGroup $group): void
    {
        if (isset($this->groups[$group->id->value])) {
            $this->refuseConflicts($group);
            $this->groups[$group->id->value] = $group;
        }
    }

    #[\Override]
    public function find(ConnectionName $connection, ScimGroupId $id): ?ScimGroup
    {
        $group = $this->live($this->groups[$id->value] ?? null);

        return $group !== null && $group->connection->equals($connection) ? $group : null;
    }

    #[\Override]
    public function delete(ScimGroupId $id): void
    {
        unset($this->groups[$id->value]);
    }

    #[\Override]
    public function matching(ConnectionName $connection, ?ScimFilter $filter, int $offset, int $limit): array
    {
        $matching = [];
        foreach ($this->groups as $group) {
            $group = $this->live($group);
            if ($group !== null && $group->connection->equals($connection) && self::matches($group, $filter)) {
                $matching[] = $group;
            }
        }
        usort($matching, static fn (ScimGroup $a, ScimGroup $b): int
            => [$a->createdAt, $a->id->value] <=> [$b->createdAt, $b->id->value]);

        return ['total' => count($matching), 'groups' => array_slice($matching, $offset, $limit)];
    }

    #[\Override]
    public function ofMember(UserId $user): array
    {
        $groups = [];
        foreach ($this->groups as $group) {
            $group = $this->live($group);
            $members = $group === null ? [] : array_map(static fn (UserId $m): string => $m->value, $group->members);
            if ($group !== null && in_array($user->value, $members, true)) {
                $groups[] = $group;
            }
        }

        return $groups;
    }

    #[\Override]
    public function named(string $displayName): array
    {
        return array_values(array_filter(
            array_map($this->live(...), array_values($this->groups)),
            static fn (?ScimGroup $group): bool => $group !== null && $group->displayName === $displayName,
        ));
    }

    private function refuseConflicts(ScimGroup $group): void
    {
        foreach ($this->groups as $other) {
            if ($other->id->equals($group->id) || ! $other->connection->equals($group->connection)) {
                continue;
            }
            if ($other->displayNameKey() === $group->displayNameKey()) {
                throw new AlreadyExists(self::DISPLAY_NAME_TAKEN);
            }
            if ($group->externalId !== null && $other->externalId === $group->externalId) {
                throw new AlreadyExists(self::EXTERNAL_ID_TAKEN);
            }
        }
    }

    private static function matches(ScimGroup $group, ?ScimFilter $filter): bool
    {
        foreach ($filter->conditions ?? [] as [$attribute, $value]) {
            $holds = match ($attribute) {
                ScimFilterAttribute::DisplayName => $group->displayNameKey() === ScimGroup::keyOf($value),
                ScimFilterAttribute::ExternalId => $group->externalId === $value,
                ScimFilterAttribute::Id => strtolower($group->id->value) === strtolower($value),
                default => false,
            };
            if (! $holds) {
                return false;
            }
        }

        return true;
    }

    /** The group as storage would show it: without members whose account is gone. */
    private function live(?ScimGroup $group): ?ScimGroup
    {
        if ($group === null) {
            return null;
        }
        $members = array_values(array_filter(
            $group->members,
            fn (UserId $id): bool => $this->users->find($id) !== null,
        ));
        usort($members, static fn (UserId $a, UserId $b): int => $a->value <=> $b->value);

        return ScimGroup::reconstitute(
            $group->id,
            $group->connection,
            $group->displayName,
            $group->externalId,
            $members,
            $group->provisionedBy,
            $group->createdAt,
            $group->updatedAt,
        );
    }
}
