<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\ResourceServer\ClientGrant;
use Clavia\Domain\ResourceServer\ClientGrantRepository;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\Scope;
use Clavia\Domain\Shared\ScopeSet;

/**
 * Client grants in `client_grants`, one row per client and API.
 */
final readonly class PhpDbClientGrantRepository implements ClientGrantRepository
{
    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function find(ClientId $client, ResourceServerId $resourceServer): ?ClientGrant
    {
        /** @var array{scopes: string, created_at: string}|null $row */
        $row = $this->database->fetchOne(
            <<<'SQL'
                SELECT scopes, created_at FROM client_grants
                WHERE client_id = :client_id AND resource_server_id = :resource_server_id
                SQL,
            ['client_id' => $client->value, 'resource_server_id' => $resourceServer->value],
        );

        return $row === null ? null : ClientGrant::reconstitute(
            $client,
            $resourceServer,
            ScopeSet::of(...array_map(Scope::fromString(...), Jsonb::decodeStrings($row['scopes']))),
            Timestamp::fromDatabase($row['created_at']),
        );
    }

    #[\Override]
    public function save(ClientGrant $grant): void
    {
        $this->database->execute(
            <<<'SQL'
                INSERT INTO client_grants (client_id, resource_server_id, scopes, created_at)
                VALUES (:client_id, :resource_server_id, CAST(:scopes AS jsonb), :created_at)
                ON CONFLICT (client_id, resource_server_id) DO UPDATE SET scopes = EXCLUDED.scopes
                SQL,
            [
                'client_id' => $grant->clientId->value,
                'resource_server_id' => $grant->resourceServerId->value,
                'scopes' => Jsonb::encode($grant->scopes->toList()),
                'created_at' => Timestamp::toDatabase($grant->createdAt),
            ],
        );
    }
}
