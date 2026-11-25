<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Provisioning\ProvisioningTokenId;
use Clavia\Domain\Provisioning\ScimFilter;
use Clavia\Domain\Provisioning\ScimFilterAttribute;
use Clavia\Domain\Provisioning\ScimGroup;
use Clavia\Domain\Provisioning\ScimGroupId;
use Clavia\Domain\Provisioning\ScimGroupRepository;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\InvalidValue;
use Throwable;

/**
 * SCIM groups in `scim_groups`, their members in `scim_group_members`. Members are written whole:
 * nothing points at a membership but the group, so replacing them is safe.
 *
 * @psalm-type GroupRow = array{id: string, connection: string, display_name: string,
 *                              external_id: string|null, provisioning_token_id: string,
 *                              created_at: string, updated_at: string}
 */
final readonly class PhpDbScimGroupRepository implements ScimGroupRepository
{
    private const string COLUMNS = 'g.id, g.connection, g.display_name, g.external_id, g.provisioning_token_id, '
        . 'g.created_at, g.updated_at';

    public function __construct(
        private Database $database,
        private TransactionManager $transactions,
    ) {
    }

    #[\Override]
    public function add(ScimGroup $group): void
    {
        $this->write($group, <<<'SQL'
            INSERT INTO scim_groups (
                id, connection, display_name, display_name_key, external_id, provisioning_token_id,
                created_at, updated_at
            ) VALUES (
                :id, :connection, :display_name, :display_name_key, :external_id, :provisioning_token_id,
                :created_at, :updated_at
            )
            SQL);
    }

    #[\Override]
    public function save(ScimGroup $group): void
    {
        $this->write($group, <<<'SQL'
            UPDATE scim_groups SET
                display_name = :display_name,
                display_name_key = :display_name_key,
                external_id = :external_id,
                updated_at = :updated_at
            WHERE id = :id AND connection = :connection
            SQL, ['provisioning_token_id', 'created_at']);
    }

    #[\Override]
    public function find(ConnectionName $connection, ScimGroupId $id): ?ScimGroup
    {
        /** @var GroupRow|null $row */
        $row = $this->database->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM scim_groups g WHERE g.connection = :connection AND g.id = :id',
            ['connection' => $connection->value, 'id' => $id->value],
        );

        return $row === null ? null : $this->hydrate($row);
    }

    #[\Override]
    public function delete(ScimGroupId $id): void
    {
        $this->database->execute('DELETE FROM scim_groups WHERE id = :id', ['id' => $id->value]);
    }

    #[\Override]
    public function matching(ConnectionName $connection, ?ScimFilter $filter, int $offset, int $limit): array
    {
        $conditions = ['g.connection = :connection'];
        $parameters = ['connection' => $connection->value];
        foreach ($filter->conditions ?? [] as $index => [$attribute, $value]) {
            $name = 'v' . $index;
            if ($attribute === ScimFilterAttribute::Id) {
                try {
                    $value = ScimGroupId::fromString($value)->value;
                } catch (InvalidValue) {
                    return ['total' => 0, 'groups' => []];
                }
            }
            $conditions[] = match ($attribute) {
                ScimFilterAttribute::DisplayName => 'g.display_name_key = :' . $name,
                ScimFilterAttribute::ExternalId => 'g.external_id = :' . $name,
                ScimFilterAttribute::Id => 'g.id = CAST(:' . $name . ' AS uuid)',
                default => 'false',
            };
            $parameters[$name] = $attribute === ScimFilterAttribute::DisplayName ? ScimGroup::keyOf($value) : $value;
        }
        $where = ' FROM scim_groups g WHERE ' . implode(' AND ', $conditions);
        /** @var int|string $total */
        $total = $this->database->fetchValue('SELECT count(*)' . $where, $parameters);
        if ($limit === 0) {
            return ['total' => max(0, (int) $total), 'groups' => []];
        }
        /** @var list<GroupRow> $rows */
        $rows = $this->database->fetchAll(
            'SELECT ' . self::COLUMNS . $where . ' ORDER BY g.created_at, g.id LIMIT :limit OFFSET :offset',
            $parameters + ['limit' => $limit, 'offset' => $offset],
        );

        return ['total' => max(0, (int) $total), 'groups' => array_map($this->hydrate(...), $rows)];
    }

    #[\Override]
    public function ofMember(UserId $user): array
    {
        /** @var list<GroupRow> $rows */
        $rows = $this->database->fetchAll(
            'SELECT ' . self::COLUMNS . ' FROM scim_groups g JOIN scim_group_members m ON m.group_id = g.id '
            . 'WHERE m.user_id = :user_id ORDER BY g.created_at, g.id',
            ['user_id' => $user->value],
        );

        return array_map($this->hydrate(...), $rows);
    }

    #[\Override]
    public function named(string $displayName): array
    {
        /** @var list<GroupRow> $rows */
        $rows = $this->database->fetchAll(
            'SELECT ' . self::COLUMNS . ' FROM scim_groups g WHERE g.display_name = :display_name ORDER BY g.id',
            ['display_name' => $displayName],
        );

        return array_map($this->hydrate(...), $rows);
    }

    /**
     * The group's row by the statement given, then its members, whole, in one transaction.
     *
     * @param list<string> $unbound Parameters the statement does not name.
     */
    private function write(ScimGroup $group, string $sql, array $unbound = []): void
    {
        try {
            $this->transactions->transactional(function () use ($group, $sql, $unbound): void {
                $this->database->execute($sql, array_diff_key([
                    'id' => $group->id->value,
                    'connection' => $group->connection->value,
                    'display_name' => $group->displayName,
                    'display_name_key' => $group->displayNameKey(),
                    'external_id' => $group->externalId,
                    'provisioning_token_id' => $group->provisionedBy->value,
                    'created_at' => Timestamp::toDatabase($group->createdAt),
                    'updated_at' => Timestamp::toDatabase($group->updatedAt),
                ], array_flip($unbound)));
                $this->database->execute(
                    'DELETE FROM scim_group_members WHERE group_id = :id',
                    ['id' => $group->id->value],
                );
                foreach ($group->members as $member) {
                    $this->database->execute(
                        'INSERT INTO scim_group_members (group_id, user_id) VALUES (:group_id, :user_id)',
                        ['group_id' => $group->id->value, 'user_id' => $member->value],
                    );
                }
            });
        } catch (Throwable $failure) {
            throw match (true) {
                Constraint::isUniqueViolation($failure, 'scim_groups_display_name_key')
                    => new AlreadyExists(self::DISPLAY_NAME_TAKEN, 0, $failure),
                Constraint::isUniqueViolation($failure, 'scim_groups_external_id_key')
                    => new AlreadyExists(self::EXTERNAL_ID_TAKEN, 0, $failure),
                default => $failure,
            };
        }
    }

    /** @param GroupRow $row */
    private function hydrate(array $row): ScimGroup
    {
        /** @var list<string> $members */
        $members = array_column($this->database->fetchAll(
            'SELECT user_id FROM scim_group_members WHERE group_id = :id ORDER BY user_id',
            ['id' => $row['id']],
        ), 'user_id');
        $displayName = $row['display_name'];
        $externalId = $row['external_id'];
        assert($displayName !== '' && $externalId !== '');

        return ScimGroup::reconstitute(
            ScimGroupId::fromString($row['id']),
            ConnectionName::fromString($row['connection']),
            $displayName,
            $externalId,
            array_map(UserId::fromString(...), $members),
            ProvisioningTokenId::fromString($row['provisioning_token_id']),
            Timestamp::fromDatabase($row['created_at']),
            Timestamp::fromDatabase($row['updated_at']),
        );
    }
}
