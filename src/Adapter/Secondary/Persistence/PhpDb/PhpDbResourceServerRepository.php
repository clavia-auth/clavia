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
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;
use LogicException;
use Throwable;

/**
 * APIs in `resource_servers`, their permissions in `permissions`.
 *
 * Saving replaces the permission rows as a whole, inside a transaction of its own (or
 * of the caller's), so an API is never seen with half its permissions.
 */
final readonly class PhpDbResourceServerRepository implements ResourceServerRepository
{
    private const string COLUMNS = 'id, identifier, name, is_system, created_at';

    public function __construct(
        private Database $database,
        private TransactionManager $transactions,
    ) {
    }

    #[\Override]
    public function find(ResourceServerId $id): ?ResourceServer
    {
        return $this->one('id = :key', $id->value);
    }

    #[\Override]
    public function findByIdentifier(Audience $identifier): ?ResourceServer
    {
        return $this->one('identifier = :key', $identifier->value);
    }

    #[\Override]
    public function save(ResourceServer $resourceServer): void
    {
        try {
            $this->transactions->transactional(fn () => $this->write($resourceServer));
        } catch (Throwable $failure) {
            throw Constraint::isUniqueViolation($failure, 'uq_resource_servers_identifier')
                ? new AlreadyExists(
                    sprintf("An API is already registered as '%s'.", $resourceServer->identifier->value),
                    0,
                    $failure,
                )
                : $failure;
        }
    }

    #[\Override]
    public function delete(ResourceServerId $id): void
    {
        $this->database->execute('DELETE FROM resource_servers WHERE id = :id', ['id' => $id->value]);
    }

    #[\Override]
    public function page(PageRequest $request): Page
    {
        $search = Search::across($request, ['identifier', 'name']);
        /** @var int|string $total */
        $total = $this->database->fetchValue(
            'SELECT count(*) FROM resource_servers ' . $search->where,
            $search->parameters,
        );
        /** @var list<array{id: string, identifier: string, name: string, is_system: bool, created_at: string}> $rows */
        $rows = $this->database->fetchAll(
            'SELECT ' . self::COLUMNS . ' FROM resource_servers ' . $search->where
            . ' ORDER BY created_at DESC, id LIMIT :limit OFFSET :offset',
            $search->pageParameters($request),
        );

        return new Page(array_map($this->hydrate(...), $rows), max(0, (int) $total), $request);
    }

    private function write(ResourceServer $resourceServer): void
    {
        /** @var mixed $stored */
        $stored = $this->database->fetchValue(
            <<<'SQL'
                INSERT INTO resource_servers (id, identifier, name, is_system, created_at)
                VALUES (:id, :identifier, :name, :is_system, :created_at)
                ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, is_system = EXCLUDED.is_system
                RETURNING identifier
                SQL,
            [
                'id' => $resourceServer->id->value,
                'identifier' => $resourceServer->identifier->value,
                'name' => $resourceServer->name,
                'is_system' => $resourceServer->isSystem,
                'created_at' => Timestamp::toDatabase($resourceServer->createdAt),
            ],
        );
        if ($stored !== $resourceServer->identifier->value) {
            // Immutable: tokens already issued carry the old one as their `aud`.
            throw new LogicException("An API's identifier cannot change.");
        }

        $this->database->execute(
            'DELETE FROM permissions WHERE resource_server_id = :id',
            ['id' => $resourceServer->id->value],
        );
        foreach ($resourceServer->permissions as $permission) {
            $this->database->execute(
                <<<'SQL'
                    INSERT INTO permissions (resource_server_id, value, description)
                    VALUES (:id, :value, :description)
                    SQL,
                [
                    'id' => $resourceServer->id->value,
                    'value' => $permission->value->value,
                    'description' => $permission->description,
                ],
            );
        }
    }

    private function one(string $condition, string $key): ?ResourceServer
    {
        /** @var array{id: string, identifier: string, name: string, is_system: bool, created_at: string}|null $row */
        $row = $this->database->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM resource_servers WHERE ' . $condition,
            ['key' => $key],
        );

        return $row === null ? null : $this->hydrate($row);
    }

    /**
     * @param array{id: string, identifier: string, name: string, is_system: bool, created_at: string} $row
     */
    private function hydrate(array $row): ResourceServer
    {
        /** @var list<array{value: string, description: string}> $permissions */
        $permissions = $this->database->fetchAll(
            'SELECT value, description FROM permissions WHERE resource_server_id = :id ORDER BY value',
            ['id' => $row['id']],
        );

        return ResourceServer::register(
            ResourceServerId::fromString($row['id']),
            Audience::fromString($row['identifier']),
            $row['name'],
            array_map(
                static fn (array $permission): Permission => Permission::of(
                    $permission['value'],
                    $permission['description'],
                ),
                $permissions,
            ),
            Timestamp::fromDatabase($row['created_at']),
            $row['is_system'],
        );
    }
}
