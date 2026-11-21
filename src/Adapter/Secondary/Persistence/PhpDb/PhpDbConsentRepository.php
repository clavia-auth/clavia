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
use Clavia\Domain\Consent\ConsentRepository;
use Clavia\Domain\Consent\UserConsent;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\ScopeSet;

/**
 * Consents in `user_consents`, one row per person, application and API — the API null
 * for a request that named none, kept to one row by `UNIQUE NULLS NOT DISTINCT`.
 *
 * @psalm-type ConsentRow = array{user_id: string, client_id: string, resource_server_id: string|null,
 *     scope: string, granted_at: string, updated_at: string}
 */
final readonly class PhpDbConsentRepository implements ConsentRepository
{
    private const string COLUMNS = 'user_id, client_id, resource_server_id, scope, granted_at, updated_at';

    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function find(UserId $userId, ClientId $clientId, ?ResourceServerId $resourceServerId): ?UserConsent
    {
        /** @var ConsentRow|null $row */
        $row = $this->database->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM user_consents'
            . ' WHERE user_id = :user_id AND client_id = :client_id'
            // `IS NOT DISTINCT FROM`, so that a null API matches the null API.
            . ' AND resource_server_id IS NOT DISTINCT FROM CAST(:resource_server_id AS varchar)',
            [
                'user_id' => $userId->value,
                'client_id' => $clientId->value,
                'resource_server_id' => $resourceServerId?->value,
            ],
        );

        return $row === null ? null : self::hydrate($row);
    }

    #[\Override]
    public function save(UserConsent $consent): void
    {
        $this->database->execute(
            <<<'SQL'
                INSERT INTO user_consents (user_id, client_id, resource_server_id, scope, granted_at, updated_at)
                VALUES (:user_id, :client_id, :resource_server_id, :scope, :granted_at, :updated_at)
                ON CONFLICT ON CONSTRAINT uq_user_consents DO UPDATE SET
                    scope = EXCLUDED.scope,
                    updated_at = EXCLUDED.updated_at
                SQL,
            [
                'user_id' => $consent->userId->value,
                'client_id' => $consent->clientId->value,
                'resource_server_id' => $consent->resourceServerId?->value,
                'scope' => $consent->scope->toString(),
                'granted_at' => Timestamp::toDatabase($consent->grantedAt),
                'updated_at' => Timestamp::toDatabase($consent->updatedAt),
            ],
        );
    }

    #[\Override]
    public function ofUser(UserId $userId): array
    {
        /** @var list<ConsentRow> $rows */
        $rows = $this->database->fetchAll(
            'SELECT ' . self::COLUMNS . ' FROM user_consents WHERE user_id = :user_id'
            . ' ORDER BY granted_at, client_id, resource_server_id NULLS FIRST',
            ['user_id' => $userId->value],
        );

        return array_map(self::hydrate(...), $rows);
    }

    #[\Override]
    public function withdraw(UserId $userId, ClientId $clientId): void
    {
        $this->database->execute(
            'DELETE FROM user_consents WHERE user_id = :user_id AND client_id = :client_id',
            ['user_id' => $userId->value, 'client_id' => $clientId->value],
        );
    }

    /**
     * @param ConsentRow $row
     */
    private static function hydrate(array $row): UserConsent
    {
        return UserConsent::reconstitute(
            UserId::fromString($row['user_id']),
            ClientId::fromString($row['client_id']),
            $row['resource_server_id'] === null ? null : ResourceServerId::fromString($row['resource_server_id']),
            ScopeSet::fromString($row['scope']),
            Timestamp::fromDatabase($row['granted_at']),
            Timestamp::fromDatabase($row['updated_at']),
        );
    }
}
