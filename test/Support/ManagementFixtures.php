<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

use Clavia\Adapter\Primary\Http\Management\ManagementContract;
use Clavia\Application\Management\ManagementPermission;
use Clavia\Application\Management\Provisioning\RegisterManagementApi;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\ResourceServer\ResourceServer;
use Laminas\Diactoros\ServerRequest;
use Phayne\OpenAPI\Validator\Message\Exception\ValidationFailed;
use Psr\Http\Message\ResponseInterface;

/**
 * Fixtures for calling the Management API: its registration, a token for it, and
 * requests that check every response against `docs/openapi/management-api.yaml`.
 *
 * Uses {@see MachineFixtures}: the caller is the test machine client.
 */
trait ManagementFixtures
{
    protected const string MANAGEMENT_API = 'https://management.clavia.test/api/v1/';

    /** The token {@see self::api()} sends unless told otherwise. */
    private ?string $managementToken = null;

    /** The Management API, registered as `management-api:register` does. */
    protected function managementApi(): ResourceServer
    {
        return $this->container()->get(RegisterManagementApi::class)();
    }

    /**
     * Register the Management API and the machine client, grant it `$scopes` (every
     * management scope by default), and fetch a token: the one {@see self::api()} sends.
     *
     * @param list<string>|null $scopes
     */
    protected function adminToken(?array $scopes = null): string
    {
        $api = $this->managementApi();
        $client = $this->container()->get(ClientRepository::class)->find(ClientId::fromString(self::TEST_M2M_CLIENT_ID))
            ?? $this->m2mClient();
        $this->grantClient($client, $api, implode(' ', $scopes ?? array_map(
            static fn (ManagementPermission $permission): string => $permission->value,
            ManagementPermission::cases(),
        )));

        $response = $this->requestMachineToken(['audience' => self::MANAGEMENT_API]);
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        $token = self::json($response)['access_token'];
        self::assertIsString($token);

        return $this->managementToken = $token;
    }

    /**
     * Call the Management API on its host, with the admin token (or `$token`; `''`
     * for none) and a JSON body, and check the response against the contract.
     *
     * @param array<array-key, mixed>|null    $body
     * @param array<string, string>           $query
     * @param array<non-empty-string, string> $headers
     */
    protected function api(
        string $method,
        string $path,
        ?array $body = null,
        array $query = [],
        ?string $token = null,
        array $headers = [],
        ?string $rawBody = null,
    ): ResponseInterface {
        $token ??= $this->managementToken;
        if ($token !== null && $token !== '') {
            $headers += ['Authorization' => 'Bearer ' . $token];
        }
        if ($body !== null || $rawBody !== null) {
            $headers += ['Content-Type' => 'application/json'];
        }
        $queryString = http_build_query($query, '', '&', PHP_QUERY_RFC3986);
        $target = $path . ($queryString === '' ? '' : '?' . $queryString);

        $response = $this->request(
            $method,
            $target,
            $headers,
            self::MANAGEMENT_HOST,
            $rawBody ?? ($body === null ? '' : json_encode($body, JSON_THROW_ON_ERROR)),
        );
        $this->assertMatchesTheContract($method, $target, $response);

        return $response;
    }

    /**
     * A JSON document from the API: a resource, a page, a problem or a bearer error.
     *
     * @return array<array-key, mixed>
     */
    protected static function document(ResponseInterface $response): array
    {
        /** @var array<array-key, mixed> */
        return json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
    }

    private function assertMatchesTheContract(string $method, string $target, ResponseInterface $response): void
    {
        /** @var ManagementContract $contract */
        $contract = $this->container()->get(ManagementContract::class);
        $operation = $contract->operationFor(
            new ServerRequest(uri: 'https://' . self::MANAGEMENT_HOST . $target, method: $method),
        );
        if ($operation === null) {
            return;
        }

        try {
            $contract->validateResponse($operation, $response);
        } catch (ValidationFailed $failure) {
            $reasons = [];
            for ($cause = $failure; $cause !== null; $cause = $cause->getPrevious()) {
                $reasons[] = $cause->getMessage();
            }
            self::fail(sprintf(
                "%s %s answered what the contract does not describe:\n%s\n%s",
                $method,
                $target,
                implode("\n", $reasons),
                (string) $response->getBody(),
            ));
        }
    }
}
