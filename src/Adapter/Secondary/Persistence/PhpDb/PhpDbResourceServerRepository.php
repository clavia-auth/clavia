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
use Clavia\Domain\Authentication\MfaPolicy;
use Clavia\Domain\Authorization\AuthorizationModel;
use Clavia\Domain\Authorization\AuthorizationModelId;
use Clavia\Domain\Authorization\AuthorizationSettings;
use Clavia\Domain\Authorization\StoreId;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Claims\ClaimMappings;
use Clavia\Domain\ResourceServer\AccessTokenFormat;
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
 * APIs in `resource_servers`, their permissions in `permissions`, the clients speaking for their
 * fine-grained authorization in `authorization_clients`.
 *
 * Saving reconciles the permission rows with the API's, inside a transaction of its own
 * (or of the caller's), so an API is never seen with half its permissions. Reconciles
 * rather than replaces: roles hold a permission by a foreign key onto its row, so a row
 * deleted and inserted again would have taken every role's grant of it along. The speaking clients
 * are replaced: nothing refers to their rows, and the table's key, the client, is what keeps a client
 * speaking for one API at most ({@see AlreadyExists}).
 *
 * @psalm-type ResourceServerRow = array{id: string, identifier: string, name: string, is_system: bool,
 *     enforce_policies: bool, allow_skipping_consent: bool, access_token_format: string,
 *     mfa_policy: string, created_at: string, claims: string, authorization_enabled: bool,
 *     fga_store_id: string|null, fga_model_id: string|null, authorization_model: string|null,
 *     authorization_denial_reasons: bool}
 */
final readonly class PhpDbResourceServerRepository implements ResourceServerRepository
{
    private const string COLUMNS = 'id, identifier, name, is_system, enforce_policies, allow_skipping_consent, '
        . 'access_token_format, mfa_policy, created_at, claims, authorization_enabled, fga_store_id, fga_model_id, '
        . 'authorization_model, authorization_denial_reasons';

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
            if (Constraint::isUniqueViolation($failure, 'uq_resource_servers_identifier')) {
                throw new AlreadyExists('An API is already registered with this identifier.', 0, $failure);
            }
            if (Constraint::isUniqueViolation($failure, 'authorization_clients_pkey')) {
                throw new AlreadyExists('A client already speaks for another API.', 0, $failure);
            }

            throw $failure;
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
        /** @var list<ResourceServerRow> $rows */
        $rows = $this->database->fetchAll(
            'SELECT ' . self::COLUMNS . ' FROM resource_servers ' . $search->where
            . ' ORDER BY created_at DESC, id LIMIT :limit OFFSET :offset',
            $search->pageParameters($request),
        );

        return new Page(array_map($this->hydrate(...), $rows), max(0, (int) $total), $request);
    }

    #[\Override]
    public function withAuthorization(): array
    {
        /** @var list<ResourceServerRow> $rows */
        $rows = $this->database->fetchAll(
            'SELECT ' . self::COLUMNS . ' FROM resource_servers WHERE fga_store_id IS NOT NULL ORDER BY created_at, id',
        );

        return array_map($this->hydrate(...), $rows);
    }

    private function write(ResourceServer $resourceServer): void
    {
        $authorization = $resourceServer->authorization;
        /** @var mixed $stored */
        $stored = $this->database->fetchValue(
            <<<'SQL'
                INSERT INTO resource_servers
                    (id, identifier, name, is_system, enforce_policies, allow_skipping_consent, access_token_format,
                    mfa_policy, created_at, claims, authorization_enabled, fga_store_id, fga_model_id,
                    authorization_model, authorization_denial_reasons)
                VALUES (:id, :identifier, :name, :is_system, :enforce_policies, :allow_skipping_consent,
                    :access_token_format, :mfa_policy, :created_at, CAST(:claims AS jsonb), :authorization_enabled,
                    :fga_store_id, :fga_model_id, :authorization_model, :authorization_denial_reasons)
                ON CONFLICT (id) DO UPDATE SET
                    name = EXCLUDED.name,
                    is_system = EXCLUDED.is_system,
                    enforce_policies = EXCLUDED.enforce_policies,
                    allow_skipping_consent = EXCLUDED.allow_skipping_consent,
                    access_token_format = EXCLUDED.access_token_format,
                    mfa_policy = EXCLUDED.mfa_policy,
                    claims = EXCLUDED.claims,
                    authorization_enabled = EXCLUDED.authorization_enabled,
                    fga_store_id = EXCLUDED.fga_store_id,
                    fga_model_id = EXCLUDED.fga_model_id,
                    authorization_model = EXCLUDED.authorization_model,
                    authorization_denial_reasons = EXCLUDED.authorization_denial_reasons
                RETURNING identifier
                SQL,
            [
                'id' => $resourceServer->id->value,
                'identifier' => $resourceServer->identifier->value,
                'name' => $resourceServer->name,
                'is_system' => $resourceServer->isSystem,
                'enforce_policies' => $resourceServer->enforcePolicies,
                'allow_skipping_consent' => $resourceServer->allowSkippingConsent,
                'access_token_format' => $resourceServer->accessTokenFormat->value,
                'mfa_policy' => $resourceServer->mfaPolicy->value,
                'created_at' => Timestamp::toDatabase($resourceServer->createdAt),
                'claims' => $resourceServer->claims->toJson(),
                'authorization_enabled' => $authorization?->enabled ?? false,
                'fga_store_id' => $authorization?->store->value,
                'fga_model_id' => $authorization?->modelId->value,
                'authorization_model' => $authorization?->model->json,
                'authorization_denial_reasons' => $authorization?->denialReasons ?? false,
            ],
        );
        if ($stored !== $resourceServer->identifier->value) {
            // Immutable: tokens already issued carry the old one as their `aud`.
            throw new LogicException("An API's identifier cannot change.");
        }

        $wanted = array_map(
            static fn (Permission $permission): string => $permission->value->value,
            $resourceServer->permissions,
        );
        /** @var list<string> $existing */
        $existing = array_column($this->database->fetchAll(
            'SELECT value FROM permissions WHERE resource_server_id = :id',
            ['id' => $resourceServer->id->value],
        ), 'value');
        foreach (array_diff($existing, $wanted) as $dropped) {
            // Cascades to every role that granted it.
            $this->database->execute(
                'DELETE FROM permissions WHERE resource_server_id = :id AND value = :value',
                ['id' => $resourceServer->id->value, 'value' => $dropped],
            );
        }
        foreach ($resourceServer->permissions as $permission) {
            $this->database->execute(
                <<<'SQL'
                    INSERT INTO permissions (resource_server_id, value, description)
                    VALUES (:id, :value, :description)
                    ON CONFLICT (resource_server_id, value) DO UPDATE SET description = EXCLUDED.description
                    SQL,
                [
                    'id' => $resourceServer->id->value,
                    'value' => $permission->value->value,
                    'description' => $permission->description,
                ],
            );
        }

        $this->database->execute(
            'DELETE FROM authorization_clients WHERE resource_server_id = :id',
            ['id' => $resourceServer->id->value],
        );
        foreach ($authorization->clients ?? [] as $position => $client) {
            $this->database->execute(
                'INSERT INTO authorization_clients (client_id, resource_server_id, position) '
                . 'VALUES (:client_id, :id, :position)',
                ['client_id' => $client->value, 'id' => $resourceServer->id->value, 'position' => $position],
            );
        }
    }

    private function one(string $condition, string $key): ?ResourceServer
    {
        /** @var ResourceServerRow|null $row */
        $row = $this->database->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM resource_servers WHERE ' . $condition,
            ['key' => $key],
        );

        return $row === null ? null : $this->hydrate($row);
    }

    /**
     * @param ResourceServerRow $row
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
            $row['enforce_policies'],
            $row['allow_skipping_consent'],
            AccessTokenFormat::from($row['access_token_format']),
            MfaPolicy::from($row['mfa_policy']),
            ClaimMappings::forApiFromJson($row['claims']),
            $this->authorization($row),
        );
    }

    /**
     * @param ResourceServerRow $row
     */
    private function authorization(array $row): ?AuthorizationSettings
    {
        if ($row['fga_store_id'] === null || $row['fga_model_id'] === null || $row['authorization_model'] === null) {
            return null;
        }
        /** @var list<string> $clients */
        $clients = array_column($this->database->fetchAll(
            'SELECT client_id FROM authorization_clients WHERE resource_server_id = :id ORDER BY position',
            ['id' => $row['id']],
        ), 'client_id');

        return AuthorizationSettings::of(
            $row['authorization_enabled'],
            StoreId::fromString($row['fga_store_id']),
            AuthorizationModelId::fromString($row['fga_model_id']),
            AuthorizationModel::fromJson($row['authorization_model']),
            array_map(ClientId::fromString(...), $clients),
            $row['authorization_denial_reasons'],
        );
    }
}
