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
use Clavia\Domain\Shared\Audience;
use LogicException;

/**
 * APIs in `resource_servers`, their permissions in `permissions`.
 *
 * Saving replaces the permission rows as a whole, inside a transaction of its own (or
 * of the caller's), so an API is never seen with half its permissions.
 */
final readonly class PhpDbResourceServerRepository implements ResourceServerRepository
{
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
        $this->transactions->transactional(function () use ($resourceServer): void {
            /** @var mixed $stored */
            $stored = $this->database->fetchValue(
                <<<'SQL'
                    INSERT INTO resource_servers (id, identifier, name, created_at)
                    VALUES (:id, :identifier, :name, :created_at)
                    ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name
                    RETURNING identifier
                    SQL,
                [
                    'id' => $resourceServer->id->value,
                    'identifier' => $resourceServer->identifier->value,
                    'name' => $resourceServer->name,
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
        });
    }

    private function one(string $condition, string $key): ?ResourceServer
    {
        /** @var array{id: string, identifier: string, name: string, created_at: string}|null $row */
        $row = $this->database->fetchOne(
            'SELECT id, identifier, name, created_at FROM resource_servers WHERE ' . $condition,
            ['key' => $key],
        );
        if ($row === null) {
            return null;
        }

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
                static fn (array $row): Permission => Permission::of($row['value'], $row['description']),
                $permissions,
            ),
            Timestamp::fromDatabase($row['created_at']),
        );
    }
}
