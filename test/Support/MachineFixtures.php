<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

use Clavia\Application\Port\PasswordHasher;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\ResourceServer\ClientGrant;
use Clavia\Domain\ResourceServer\ClientGrantRepository;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\ScopeSet;
use DateTimeImmutable;
use Psr\Http\Message\ResponseInterface;

/**
 * Machine-to-machine fixtures for acceptance tests: a confidential client registered for
 * the Client Credentials grant, an API, and a grant binding the two.
 *
 * Deliberately not OIDC scopes: a machine client names operations on an API; it has no
 * person to describe.
 */
trait MachineFixtures
{
    protected const string TEST_M2M_CLIENT_ID = 'test-m2m-client';
    protected const string TEST_M2M_SECRET = 'test-m2m-secret';
    protected const string TEST_M2M_AUDIENCE = 'https://machine.test/api/';
    protected const string TEST_M2M_SCOPE = 'api:read api:write';

    /**
     * A machine client: confidential, no redirect URI, no response type. HTTP Basic by
     * default, the method RFC 6749 §2.3.1 requires every server to support.
     */
    protected function m2mClient(ClientAuthMethod $authMethod = ClientAuthMethod::ClientSecretBasic): Client
    {
        $hasher = $this->container()->get(PasswordHasher::class);

        $client = Client::register(
            ClientId::fromString(self::TEST_M2M_CLIENT_ID),
            'Test machine client',
            ClientType::Confidential,
            $authMethod,
            $hasher->hash(self::TEST_M2M_SECRET),
            [],
            [GrantType::ClientCredentials],
            [],
            $this->container()->get(Clock::class)->now(),
        );
        $this->container()->get(ClientRepository::class)->save($client);

        return $client;
    }

    /**
     * An API, registered with the given permissions.
     *
     * @param list<string> $permissions
     */
    protected function anApi(string $identifier, array $permissions): ResourceServer
    {
        $api = ResourceServer::register(
            ResourceServerId::fromString('rs_' . substr(hash('sha256', $identifier), 0, 16)),
            Audience::fromString($identifier),
            'Machine API',
            array_map(static fn (string $value): Permission => Permission::of($value), $permissions),
            $this->container()->get(Clock::class)->now(),
        );
        $this->container()->get(ResourceServerRepository::class)->save($api);

        return $api;
    }

    /** Grant `$client` the space-separated `$scopes` of `$api`, as itself. */
    protected function grantClient(Client $client, ResourceServer $api, string $scopes): void
    {
        $this->container()->get(ClientGrantRepository::class)->save(ClientGrant::grant(
            $client->id,
            $api,
            ScopeSet::fromString($scopes),
            new DateTimeImmutable(),
        ));
    }

    /**
     * The machine client, and an API on which it holds every permission — the only way it
     * can get a token, since a client holds no scope of its own.
     */
    protected function machineApi(): ResourceServer
    {
        $client = $this->m2mClient();
        $api = $this->anApi(self::TEST_M2M_AUDIENCE, explode(' ', self::TEST_M2M_SCOPE));
        $this->grantClient($client, $api, self::TEST_M2M_SCOPE);

        return $api;
    }

    /**
     * Ask for a token with HTTP Basic credentials, as most client libraries do, naming the
     * machine API unless the form says otherwise (null removes a field).
     *
     * @param array<string, string|null> $form
     * @param array{string, string}|null $credentials
     */
    protected function requestMachineToken(array $form = [], ?array $credentials = null): ResponseInterface
    {
        $form = array_filter(
            $form + ['grant_type' => 'client_credentials', 'audience' => self::TEST_M2M_AUDIENCE],
            static fn (?string $value): bool => $value !== null,
        );

        return $this->post(
            '/oauth2/token',
            $form,
            basicAuth: $credentials ?? [self::TEST_M2M_CLIENT_ID, self::TEST_M2M_SECRET],
        );
    }
}
