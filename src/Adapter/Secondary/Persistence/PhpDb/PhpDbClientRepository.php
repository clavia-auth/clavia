<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Shared\Url;

/**
 * Clients in the `oauth2_clients` table. The three lists are `jsonb` arrays of strings.
 */
final readonly class PhpDbClientRepository implements ClientRepository
{
    private const string COLUMNS = 'client_id, client_secret_hash, name, client_type, redirect_uris, '
        . 'grant_types, response_types, token_endpoint_auth_method, created_at';

    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function find(ClientId $id): ?Client
    {
        $row = $this->database->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM oauth2_clients WHERE client_id = :client_id',
            ['client_id' => $id->value],
        );

        return $row === null ? null : $this->hydrate($row);
    }

    #[\Override]
    public function findByName(string $name): ?Client
    {
        $row = $this->database->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM oauth2_clients'
            . ' WHERE name = :name ORDER BY created_at, client_id LIMIT 1',
            ['name' => $name],
        );

        return $row === null ? null : $this->hydrate($row);
    }

    #[\Override]
    public function registersRedirectOrigin(string $origin): bool
    {
        // Origins are derived by the domain's own URL parsing rather than in SQL, so the
        // answer cannot differ from what Client::redirectOrigins() says for one client.
        foreach ($this->database->fetchAll('SELECT redirect_uris::text AS redirect_uris FROM oauth2_clients') as $row) {
            /** @var array{redirect_uris: string} $row */
            foreach ($this->decode($row['redirect_uris']) as $uri) {
                if (Url::fromString($uri)->origin() === $origin) {
                    return true;
                }
            }
        }

        return false;
    }

    #[\Override]
    public function save(Client $client): void
    {
        $this->database->execute(
            <<<'SQL'
                INSERT INTO oauth2_clients (
                    client_id, client_secret_hash, name, client_type, redirect_uris, grant_types,
                    response_types, token_endpoint_auth_method, created_at
                ) VALUES (
                    :client_id, :client_secret_hash, :name, :client_type, CAST(:redirect_uris AS jsonb),
                    CAST(:grant_types AS jsonb), CAST(:response_types AS jsonb), :auth_method, :created_at
                )
                ON CONFLICT (client_id) DO UPDATE SET
                    client_secret_hash = EXCLUDED.client_secret_hash,
                    name = EXCLUDED.name,
                    redirect_uris = EXCLUDED.redirect_uris,
                    grant_types = EXCLUDED.grant_types,
                    response_types = EXCLUDED.response_types,
                    token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method
                SQL,
            [
                'client_id' => $client->id->value,
                'client_secret_hash' => $client->secretHash(),
                'name' => $client->name,
                'client_type' => $client->type->value,
                'redirect_uris' => $this->encode(
                    array_map(static fn (Url $uri): string => $uri->value, $client->redirectUris),
                ),
                'grant_types' => $this->encode(
                    array_map(static fn (GrantType $grant): string => $grant->value, $client->grantTypes),
                ),
                'response_types' => $this->encode(
                    array_map(static fn (ResponseType $r): string => $r->value, $client->responseTypes),
                ),
                'auth_method' => $client->authMethod->value,
                'created_at' => Timestamp::toDatabase($client->createdAt),
            ],
        );
    }

    /**
     * @param array<string, mixed> $row
     */
    private function hydrate(array $row): Client
    {
        /**
         * @var array{client_id: string, client_secret_hash: string|null, name: string, client_type: string,
         *            redirect_uris: string, grant_types: string, response_types: string,
         *            token_endpoint_auth_method: string, created_at: string} $row
         */
        return Client::register(
            ClientId::fromString($row['client_id']),
            $row['name'],
            ClientType::from($row['client_type']),
            ClientAuthMethod::from($row['token_endpoint_auth_method']),
            $row['client_secret_hash'],
            array_map(Url::fromString(...), $this->decode($row['redirect_uris'])),
            array_map(GrantType::from(...), $this->decode($row['grant_types'])),
            array_map(ResponseType::from(...), $this->decode($row['response_types'])),
            Timestamp::fromDatabase($row['created_at']),
        );
    }

    /**
     * @param list<string> $values
     */
    private function encode(array $values): string
    {
        return json_encode($values, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * @return list<string>
     */
    private function decode(string $json): array
    {
        /** @var list<string> */
        return json_decode($json, true, flags: JSON_THROW_ON_ERROR);
    }
}
