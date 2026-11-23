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
use Clavia\Domain\Client\BackChannelLogout;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;
use Clavia\Domain\Shared\Url;

/**
 * Clients in the `oauth2_clients` table — the lists of URIs and types as `jsonb` arrays of
 * strings — and the connections each enables in `client_connections`, reconciled with
 * the client in one transaction.
 */
final readonly class PhpDbClientRepository implements ClientRepository
{
    private const string COLUMNS = 'client_id, client_secret_hash, name, client_type, redirect_uris, '
        . 'grant_types, response_types, token_endpoint_auth_method, created_at, post_logout_redirect_uris, '
        . 'backchannel_logout_uri, backchannel_logout_session_required, require_pkce, mfa_policy, '
        . 'require_pushed_authorization_requests';

    public function __construct(
        private Database $database,
        private TransactionManager $transactions,
    ) {
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
            foreach (Jsonb::decodeStrings($row['redirect_uris']) as $uri) {
                if (Url::fromString($uri)->origin() === $origin) {
                    return true;
                }
            }
        }

        return false;
    }

    #[\Override]
    public function delete(ClientId $id): void
    {
        $this->database->execute(
            'DELETE FROM oauth2_clients WHERE client_id = :client_id',
            ['client_id' => $id->value],
        );
    }

    #[\Override]
    public function page(PageRequest $request): Page
    {
        $search = Search::across($request, ['client_id', 'name']);
        /** @var int|string $total */
        $total = $this->database->fetchValue(
            'SELECT count(*) FROM oauth2_clients ' . $search->where,
            $search->parameters,
        );
        $rows = $this->database->fetchAll(
            'SELECT ' . self::COLUMNS . ' FROM oauth2_clients ' . $search->where
            . ' ORDER BY created_at DESC, client_id LIMIT :limit OFFSET :offset',
            $search->pageParameters($request),
        );

        return new Page(array_map($this->hydrate(...), $rows), max(0, (int) $total), $request);
    }

    #[\Override]
    public function save(Client $client): void
    {
        $this->transactions->transactional(function () use ($client): void {
            $this->write($client);
            $this->reconcileConnections($client);
        });
    }

    private function write(Client $client): void
    {
        $this->database->execute(
            <<<'SQL'
                INSERT INTO oauth2_clients (
                    client_id, client_secret_hash, name, client_type, redirect_uris, grant_types,
                    response_types, token_endpoint_auth_method, created_at, post_logout_redirect_uris,
                    backchannel_logout_uri, backchannel_logout_session_required, require_pkce, mfa_policy,
                    require_pushed_authorization_requests
                ) VALUES (
                    :client_id, :client_secret_hash, :name, :client_type, CAST(:redirect_uris AS jsonb),
                    CAST(:grant_types AS jsonb), CAST(:response_types AS jsonb), :auth_method, :created_at,
                    CAST(:post_logout_redirect_uris AS jsonb), :backchannel_logout_uri,
                    :backchannel_logout_session_required, :require_pkce, :mfa_policy,
                    :require_pushed_authorization_requests
                )
                ON CONFLICT (client_id) DO UPDATE SET
                    client_secret_hash = EXCLUDED.client_secret_hash,
                    name = EXCLUDED.name,
                    redirect_uris = EXCLUDED.redirect_uris,
                    grant_types = EXCLUDED.grant_types,
                    response_types = EXCLUDED.response_types,
                    token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method,
                    post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
                    backchannel_logout_uri = EXCLUDED.backchannel_logout_uri,
                    backchannel_logout_session_required = EXCLUDED.backchannel_logout_session_required,
                    require_pkce = EXCLUDED.require_pkce,
                    mfa_policy = EXCLUDED.mfa_policy,
                    require_pushed_authorization_requests = EXCLUDED.require_pushed_authorization_requests
                SQL,
            [
                'client_id' => $client->id->value,
                'client_secret_hash' => $client->secretHash(),
                'name' => $client->name,
                'client_type' => $client->type->value,
                'redirect_uris' => Jsonb::encode(
                    array_map(static fn (Url $uri): string => $uri->value, $client->redirectUris),
                ),
                'grant_types' => Jsonb::encode(
                    array_map(static fn (GrantType $grant): string => $grant->value, $client->grantTypes),
                ),
                'response_types' => Jsonb::encode(
                    array_map(static fn (ResponseType $r): string => $r->value, $client->responseTypes),
                ),
                'auth_method' => $client->authMethod->value,
                'created_at' => Timestamp::toDatabase($client->createdAt),
                'post_logout_redirect_uris' => Jsonb::encode(
                    array_map(static fn (Url $uri): string => $uri->value, $client->postLogoutRedirectUris),
                ),
                'backchannel_logout_uri' => $client->backChannelLogout?->uri->value,
                'backchannel_logout_session_required' => $client->backChannelLogout->sessionRequired ?? false,
                'require_pkce' => $client->requiresPkce,
                'mfa_policy' => $client->mfaPolicy->value,
                'require_pushed_authorization_requests' => $client->requiresPushedAuthorizationRequests,
            ],
        );
    }

    /** Delete what it no longer enables, insert what it newly does: one statement. */
    private function reconcileConnections(Client $client): void
    {
        $this->database->execute(
            <<<'SQL'
                WITH wanted AS (
                    SELECT jsonb_array_elements_text(CAST(:connections AS jsonb)) AS name
                ), dropped AS (
                    DELETE FROM client_connections
                    WHERE client_id = :client_id AND connection_name NOT IN (SELECT name FROM wanted)
                )
                INSERT INTO client_connections (client_id, connection_name)
                SELECT :client_id, name FROM wanted
                ON CONFLICT DO NOTHING
                SQL,
            [
                'client_id' => $client->id->value,
                'connections' => Jsonb::encode(array_map(
                    static fn (ConnectionName $connection): string => $connection->value,
                    $client->connections,
                )),
            ],
        );
    }

    /**
     * @return list<ConnectionName>
     */
    private function connectionsOf(string $clientId): array
    {
        /** @var list<array{connection_name: string}> $rows */
        $rows = $this->database->fetchAll(
            'SELECT connection_name FROM client_connections WHERE client_id = :client_id ORDER BY connection_name',
            ['client_id' => $clientId],
        );

        return array_map(
            static fn (array $row): ConnectionName => ConnectionName::fromString($row['connection_name']),
            $rows,
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
         *            token_endpoint_auth_method: string, created_at: string,
         *            post_logout_redirect_uris: string, backchannel_logout_uri: string|null,
         *            backchannel_logout_session_required: bool, require_pkce: bool, mfa_policy: string,
         *            require_pushed_authorization_requests: bool} $row
         */
        return Client::register(
            ClientId::fromString($row['client_id']),
            $row['name'],
            ClientType::from($row['client_type']),
            ClientAuthMethod::from($row['token_endpoint_auth_method']),
            $row['client_secret_hash'],
            array_map(Url::fromString(...), Jsonb::decodeStrings($row['redirect_uris'])),
            array_map(GrantType::from(...), Jsonb::decodeStrings($row['grant_types'])),
            array_map(ResponseType::from(...), Jsonb::decodeStrings($row['response_types'])),
            Timestamp::fromDatabase($row['created_at']),
            array_map(Url::fromString(...), Jsonb::decodeStrings($row['post_logout_redirect_uris'])),
            $this->connectionsOf($row['client_id']),
            $row['backchannel_logout_uri'] === null ? null : new BackChannelLogout(
                Url::fromString($row['backchannel_logout_uri']),
                $row['backchannel_logout_session_required'],
            ),
            $row['require_pkce'],
            MfaPolicy::from($row['mfa_policy']),
            $row['require_pushed_authorization_requests'],
        );
    }
}
