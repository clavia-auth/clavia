<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

use Clavia\Adapter\Primary\Http\Access\AccessContract;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\ResponseDoesNotMatch;
use Clavia\Application\Port\DecisionEngine;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Domain\Authorization\AuthorizationModel;
use Clavia\Domain\Authorization\AuthorizationSettings;
use Clavia\Domain\Authorization\StoreId;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Clock;
use Fig\Http\Message\StatusCodeInterface;
use Laminas\Diactoros\ServerRequest;
use Psr\Http\Message\ResponseInterface;

/**
 * The Authorization API (`/access/v1/*`, docs/design/fine-grained-authorization.md) from an API's
 * side: an API with authorization on and its store, a machine client speaking for it with a token for
 * the Authorization API, and calls whose every answer is checked against
 * `docs/openapi/authorization-api.yaml`. The test registers the Authorization API first.
 */
trait AuthorizationApiFixtures
{
    use MachineFixtures;

    private const string SPEAKING_SECRET = 'speaking-client-secret';

    abstract protected function decisionEngine(): DecisionEngine;

    private function apiWithAuthorization(string $identifier, string $json, bool $denialReasons = false): ResourceServer
    {
        $model = AuthorizationModel::fromJson($json);
        $store = $this->decisionEngine()->createStore('clavia-test');
        $api = $this->anApi($identifier, ['read'])->withAuthorization(AuthorizationSettings::of(
            true,
            $store,
            $this->decisionEngine()->writeModel($store, $model),
            $model,
            [],
            $denialReasons,
        ));
        $this->container()->get(ResourceServerRepository::class)->save($api);

        return $api;
    }

    /** A first-party machine client speaking for the API, and a token it obtained for the Authorization API. */
    private function tokenSpeakingFor(
        ResourceServer $api,
        string $clientId,
        string $scope = 'write:relationships',
    ): string {
        $token = $this->clientWithAToken($clientId, $scope);
        $repository = $this->container()->get(ResourceServerRepository::class);
        $settings = $repository->find($api->id)?->authorization;
        self::assertNotNull($settings);
        $repository->save($api->withAuthorization(AuthorizationSettings::of(
            true,
            $settings->store,
            $settings->modelId,
            $settings->model,
            [ClientId::fromString($clientId)],
            $settings->denialReasons,
        )));

        return $token;
    }

    private function clientWithAToken(string $clientId, string $scope): string
    {
        $client = Client::register(
            ClientId::fromString($clientId),
            $clientId,
            ClientType::Confidential,
            ClientAuthMethod::ClientSecretBasic,
            $this->container()->get(PasswordHasher::class)->hash(self::SPEAKING_SECRET),
            [],
            [GrantType::ClientCredentials],
            [],
            $this->container()->get(Clock::class)->now(),
        );
        $this->container()->get(ClientRepository::class)->save($client);
        $authorizationApi = $this->container()->get(ResourceServerRepository::class)
            ->findByIdentifier(Audience::fromString('https://management.clavia.test/access'));
        self::assertNotNull($authorizationApi);
        $this->grantClient($client, $authorizationApi, $scope);

        $response = $this->requestMachineToken(
            ['audience' => $authorizationApi->identifier->value, 'scope' => $scope],
            [$clientId, self::SPEAKING_SECRET],
        );
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode(), (string) $response->getBody());
        $token = self::decoded($response)['access_token'] ?? null;
        self::assertIsString($token);

        return $token;
    }

    private function storeOf(ResourceServer $api): StoreId
    {
        $settings = $this->container()->get(ResourceServerRepository::class)->find($api->id)?->authorization;
        self::assertNotNull($settings);

        return $settings->store;
    }

    /**
     * A request to the management host, its answer checked against the Authorization API's contract.
     *
     * @param array<non-empty-string, string> $headers
     */
    private function sendAccess(
        string $method,
        string $target,
        ?string $token,
        string $body = '',
        array $headers = [],
    ): ResponseInterface {
        if ($token !== null) {
            $headers['Authorization'] = 'Bearer ' . $token;
        }
        if ($body !== '') {
            $headers['Content-Type'] = 'application/json';
        }
        $response = $this->request($method, $target, $headers, self::MANAGEMENT_HOST, $body);

        $contract = $this->container()->get(AccessContract::class);
        $operation = $contract->operationFor(
            new ServerRequest(uri: 'https://' . self::MANAGEMENT_HOST . $target, method: $method),
        );
        self::assertNotNull($operation);
        try {
            $contract->validateResponse($operation, $response);
        } catch (ResponseDoesNotMatch $mismatch) {
            self::fail($mismatch->getMessage() . "\n" . (string) $response->getBody());
        }

        return $response;
    }

    /**
     * Any JSON answer, a problem document included.
     *
     * @return array<array-key, mixed>
     */
    private static function decoded(ResponseInterface $response): array
    {
        /** @var array<array-key, mixed> */
        return json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
    }
}
