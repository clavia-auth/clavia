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
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Rbac\GrantedPermission;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;
use Clavia\Domain\Shared\Scope;
use Clavia\Domain\Shared\ScopeSet;
use DateTimeImmutable;
use Throwable;

/**
 * Roles in `roles`, what they grant in `role_permissions`, who holds them in
 * `user_roles`.
 *
 * Writes that touch several rows run in a transaction of their own (or of the caller's),
 * so a role is never seen with half its permissions, nor a person with half their roles.
 *
 * @psalm-type RoleRow = array{id: string, name: string, description: string, created_at: string}
 */
final readonly class PhpDbRoleRepository implements RoleRepository
{
    private const string COLUMNS = 'id, name, description, created_at';

    public function __construct(
        private Database $database,
        private TransactionManager $transactions,
    ) {
    }

    #[\Override]
    public function find(RoleId $id): ?Role
    {
        return $this->one('id = :key', $id->value);
    }

    #[\Override]
    public function findByName(string $name): ?Role
    {
        return $this->one('name = :key', $name);
    }

    #[\Override]
    public function save(Role $role): void
    {
        try {
            $this->transactions->transactional(fn () => $this->write($role));
        } catch (Throwable $failure) {
            throw Constraint::isUniqueViolation($failure, 'uq_roles_name')
                ? new AlreadyExists(sprintf("A role named '%s' already exists.", $role->name), 0, $failure)
                : $failure;
        }
    }

    #[\Override]
    public function delete(RoleId $id): void
    {
        $this->database->execute('DELETE FROM roles WHERE id = :id', ['id' => $id->value]);
    }

    #[\Override]
    public function page(PageRequest $request): Page
    {
        $search = Search::across($request, ['name', 'description']);
        /** @var int|string $total */
        $total = $this->database->fetchValue('SELECT count(*) FROM roles ' . $search->where, $search->parameters);
        /** @var list<RoleRow> $rows */
        $rows = $this->database->fetchAll(
            'SELECT ' . self::COLUMNS . ' FROM roles ' . $search->where
            . ' ORDER BY created_at DESC, id LIMIT :limit OFFSET :offset',
            $search->pageParameters($request),
        );

        return new Page(array_map($this->hydrate(...), $rows), max(0, (int) $total), $request);
    }

    #[\Override]
    public function all(): array
    {
        /** @var list<RoleRow> $rows */
        $rows = $this->database->fetchAll('SELECT ' . self::COLUMNS . ' FROM roles ORDER BY name');

        return array_map($this->hydrate(...), $rows);
    }

    #[\Override]
    public function assign(RoleId $role, UserId $user, DateTimeImmutable $at): void
    {
        $this->database->execute(
            <<<'SQL'
                INSERT INTO user_roles (user_id, role_id, assigned_at) VALUES (:user_id, :role_id, :assigned_at)
                ON CONFLICT (user_id, role_id) DO NOTHING
                SQL,
            ['user_id' => $user->value, 'role_id' => $role->value, 'assigned_at' => Timestamp::toDatabase($at)],
        );
    }

    #[\Override]
    public function unassign(RoleId $role, UserId $user): void
    {
        $this->database->execute(
            'DELETE FROM user_roles WHERE user_id = :user_id AND role_id = :role_id',
            ['user_id' => $user->value, 'role_id' => $role->value],
        );
    }

    #[\Override]
    public function replaceRolesOf(UserId $user, array $roles, DateTimeImmutable $at): void
    {
        $wanted = array_map(static fn (RoleId $role): string => $role->value, $roles);

        $this->transactions->transactional(function () use ($user, $roles, $wanted, $at): void {
            /** @var list<string> $held */
            $held = array_column($this->database->fetchAll(
                'SELECT role_id FROM user_roles WHERE user_id = :user_id FOR UPDATE',
                ['user_id' => $user->value],
            ), 'role_id');
            foreach (array_diff($held, $wanted) as $dropped) {
                $this->unassign(RoleId::fromString($dropped), $user);
            }
            foreach ($roles as $role) {
                $this->assign($role, $user, $at);
            }
        });
    }

    #[\Override]
    public function rolesOf(UserId $user): array
    {
        /** @var list<RoleRow> $rows */
        $rows = $this->database->fetchAll(
            <<<'SQL'
                SELECT roles.id, roles.name, roles.description, roles.created_at
                FROM roles JOIN user_roles ON user_roles.role_id = roles.id
                WHERE user_roles.user_id = :user_id
                ORDER BY roles.name
                SQL,
            ['user_id' => $user->value],
        );

        return array_map($this->hydrate(...), $rows);
    }

    #[\Override]
    public function holders(RoleId $role, PageRequest $request): Page
    {
        /** @var int|string $total */
        $total = $this->database->fetchValue(
            'SELECT count(*) FROM user_roles WHERE role_id = :role_id',
            ['role_id' => $role->value],
        );
        /** @var list<string> $ids */
        $ids = array_column($this->database->fetchAll(
            <<<'SQL'
                SELECT user_id FROM user_roles WHERE role_id = :role_id
                ORDER BY assigned_at DESC, user_id LIMIT :limit OFFSET :offset
                SQL,
            ['role_id' => $role->value, 'limit' => $request->perPage, 'offset' => $request->offset()],
        ), 'user_id');

        return new Page(
            array_map(static fn (string $id): UserId => UserId::fromString($id), $ids),
            max(0, (int) $total),
            $request,
        );
    }

    #[\Override]
    public function permissionsHeld(UserId $user, ResourceServerId $resourceServer): ScopeSet
    {
        /** @var list<string> $values */
        $values = array_column($this->database->fetchAll(
            <<<'SQL'
                SELECT DISTINCT role_permissions.value
                FROM user_roles JOIN role_permissions ON role_permissions.role_id = user_roles.role_id
                WHERE user_roles.user_id = :user_id AND role_permissions.resource_server_id = :resource_server_id
                SQL,
            ['user_id' => $user->value, 'resource_server_id' => $resourceServer->value],
        ), 'value');

        return ScopeSet::of(...array_map(static fn (string $value): Scope => Scope::fromString($value), $values));
    }

    private function write(Role $role): void
    {
        $this->database->execute(
            <<<'SQL'
                INSERT INTO roles (id, name, description, created_at) VALUES (:id, :name, :description, :created_at)
                ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description
                SQL,
            [
                'id' => $role->id->value,
                'name' => $role->name,
                'description' => $role->description,
                'created_at' => Timestamp::toDatabase($role->createdAt),
            ],
        );

        // Nothing points at a role's grants, so replacing them whole is safe.
        $this->database->execute('DELETE FROM role_permissions WHERE role_id = :id', ['id' => $role->id->value]);
        foreach ($role->permissions as $permission) {
            $this->database->execute(
                <<<'SQL'
                    INSERT INTO role_permissions (role_id, resource_server_id, value)
                    VALUES (:role_id, :resource_server_id, :value)
                    SQL,
                [
                    'role_id' => $role->id->value,
                    'resource_server_id' => $permission->resourceServerId->value,
                    'value' => $permission->value->value,
                ],
            );
        }
    }

    private function one(string $condition, string $key): ?Role
    {
        /** @var RoleRow|null $row */
        $row = $this->database->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM roles WHERE ' . $condition,
            ['key' => $key],
        );

        return $row === null ? null : $this->hydrate($row);
    }

    /**
     * @param RoleRow $row
     */
    private function hydrate(array $row): Role
    {
        /** @var list<array{resource_server_id: string, value: string}> $permissions */
        $permissions = $this->database->fetchAll(
            'SELECT resource_server_id, value FROM role_permissions WHERE role_id = :id',
            ['id' => $row['id']],
        );

        return Role::define(
            RoleId::fromString($row['id']),
            $row['name'],
            $row['description'],
            array_map(
                static fn (array $permission): GrantedPermission => new GrantedPermission(
                    ResourceServerId::fromString($permission['resource_server_id']),
                    Scope::fromString($permission['value']),
                ),
                $permissions,
            ),
            Timestamp::fromDatabase($row['created_at']),
        );
    }
}
