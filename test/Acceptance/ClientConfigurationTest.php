<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Application\Management\InitialAccessTokens\IssueInitialAccessToken;
use Clavia\Application\Management\InitialAccessTokens\NewInitialAccessToken;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use Psr\Http\Message\ResponseInterface;

/**
 * The client configuration endpoint (RFC 7592; docs/design/dynamic-client-registration.md,
 * slice 3): a self-registered client reads, replaces and deletes its registration with its
 * registration access token, rotated at each update — and nothing else.
 */
final class ClientConfigurationTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const array WEB_APP = [
        'client_name' => 'Acme Reports',
        'redirect_uris' => ['https://reports.acme.example/callback'],
    ];

    public function testAClientReadsItsConfigurationWithoutItsSecret(): void
    {
        $this->boot(['CLAVIA_CLIENT_REGISTRATION' => 'token']);
        $registered = $this->registered();

        $response = $this->configuration('GET', $registered);

        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        $document = self::json($response);
        self::assertSame($registered['client_id'], $document['client_id']);
        self::assertSame('Acme Reports', $document['client_name']);
        self::assertSame($registered['registration_client_uri'], $document['registration_client_uri']);
        self::assertArrayNotHasKey('client_secret', $document);
        self::assertArrayNotHasKey('registration_access_token', $document, 'Not rotated by a read.');
        self::assertSame(200, $this->configuration('GET', $registered)->getStatusCode(), 'The token still works.');
    }

    public function testAnUpdateReplacesTheMetadataAndRotatesTheToken(): void
    {
        $this->boot(['CLAVIA_CLIENT_REGISTRATION' => 'token']);
        $registered = $this->registered();

        $updated = $this->configuration('PUT', $registered, [
            'client_id' => $registered['client_id'],
            'client_secret' => $registered['client_secret'],
            'client_name' => 'Acme Reports 2',
            'token_endpoint_auth_method' => 'client_secret_post',
            'redirect_uris' => ['https://reports.acme.example/v2/callback'],
        ]);

        self::assertSame(200, $updated->getStatusCode(), (string) $updated->getBody());
        $document = self::json($updated);
        self::assertSame('Acme Reports 2', $document['client_name']);
        self::assertSame('client_secret_post', $document['token_endpoint_auth_method']);
        self::assertSame(['https://reports.acme.example/v2/callback'], $document['redirect_uris']);
        self::assertIsString($document['registration_access_token']);
        self::assertNotSame($registered['registration_access_token'], $document['registration_access_token']);
        self::assertSame(401, $this->configuration('GET', $registered)->getStatusCode(), 'The old token is spent.');
        self::assertSame(200, $this->configuration('GET', [
            'registration_access_token' => $document['registration_access_token'],
        ] + $registered)->getStatusCode());
        $client = $this->clientOf($registered);
        self::assertTrue($client->requiresPkce);
        self::assertFalse($client->isFirstParty());
        $changed = TestStorage::database()->fetchValue(
            'SELECT details::text FROM audit_events WHERE type = :type',
            ['type' => AuditEventType::ClientUpdated->value],
        );
        self::assertIsString($changed);
        self::assertStringContainsString('redirect_uris', $changed);
        self::assertStringNotContainsString('reports.acme.example', $changed, 'What changed, never to what.');
    }

    public function testAnUpdateThatOmitsAFieldTakesItsDefault(): void
    {
        $this->boot(['CLAVIA_CLIENT_REGISTRATION' => 'token']);
        $registered = $this->registered(['dpop_bound_access_tokens' => true]);

        $document = self::json($this->configuration('PUT', $registered, [
            'client_id' => $registered['client_id'],
        ] + self::WEB_APP));

        self::assertFalse($document['dpop_bound_access_tokens']);
    }

    /**
     * @param array<string, mixed> $change
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('refusedUpdates')]
    public function testWhatAnUpdateMayNotSayIsRefusedAndRotatesNothing(array $change): void
    {
        $this->boot(['CLAVIA_CLIENT_REGISTRATION' => 'token']);
        $registered = $this->registered();

        $response = $this->configuration('PUT', $registered, $change + [
            'client_id' => $registered['client_id'],
        ] + self::WEB_APP);

        self::assertSame(400, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame('invalid_client_metadata', self::json($response)['error']);
        self::assertSame(200, $this->configuration('GET', $registered)->getStatusCode());
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function refusedUpdates(): iterable
    {
        yield 'another client id' => [['client_id' => 'tpc_someoneelse']];
        yield 'a wrong secret' => [['client_secret' => 'not-the-secret']];
        yield 'its own token' => [['registration_access_token' => 'x']];
        yield 'its own uri' => [['registration_client_uri' => 'https://elsewhere.example/']];
        yield 'an issue date' => [['client_id_issued_at' => 0]];
        yield 'becoming public' => [['token_endpoint_auth_method' => 'none']];
        yield 'a machine grant' => [['grant_types' => ['client_credentials']]];
    }

    public function testAClientDeletesItself(): void
    {
        $this->boot(['CLAVIA_CLIENT_REGISTRATION' => 'token']);
        $registered = $this->registered();

        $deleted = $this->configuration('DELETE', $registered);

        self::assertSame(204, $deleted->getStatusCode());
        self::assertNull($this->container()->get(ClientRepository::class)->find(
            ClientId::fromString((string) $registered['client_id']),
        ));
        self::assertSame(401, $this->configuration('GET', $registered)->getStatusCode(), 'Its token went with it.');
        self::assertSame(1, (int) TestStorage::database()->fetchValue(
            "SELECT count(*) FROM audit_events WHERE type = :type AND actor_kind = 'application'",
            ['type' => AuditEventType::ClientDeleted->value],
        ));
    }

    public function testATokenAnswersForItsOwnClientOnly(): void
    {
        $this->boot(['CLAVIA_CLIENT_REGISTRATION' => 'token']);
        $this->publicClient();
        $first = $this->registered();
        $second = $this->registered();

        $another = $this->configuration('GET', ['client_id' => $second['client_id']] + $first);
        $operators = $this->configuration('GET', ['client_id' => self::TEST_CLIENT_ID] + $first);
        $unknown = $this->configuration('GET', ['registration_access_token' => 'nope'] + $first);
        $none = $this->configuration('DELETE', ['registration_access_token' => null] + $first);

        foreach ([$another, $operators, $unknown] as $response) {
            self::assertSame(401, $response->getStatusCode());
            self::assertSame('invalid_token', self::json($response)['error']);
        }
        self::assertSame(401, $none->getStatusCode());
        self::assertSame('Bearer realm="https://auth.clavia.test"', $none->getHeaderLine('WWW-Authenticate'));
        self::assertNotNull($this->container()->get(ClientRepository::class)->find(
            ClientId::fromString((string) $first['client_id']),
        ));
    }

    public function testOffThereIsNoConfigurationEndpoint(): void
    {
        $this->boot(['CLAVIA_CLIENT_REGISTRATION' => 'off']);

        self::assertSame(404, $this->request('GET', '/oauth2/register/tpc_anything')->getStatusCode());
    }

    public function testTheManagementApiShowsWhichTokenLetAClientIn(): void
    {
        $this->boot(['CLAVIA_CLIENT_REGISTRATION' => 'token']);
        $registered = $this->registered();
        $this->adminToken();
        $path = '/api/v1/clients/' . rawurlencode((string) $registered['client_id']);

        $self = self::document($this->api('GET', $path));
        $listed = self::document($this->api('GET', '/api/v1/clients'))['items'];
        $rotated = self::document($this->api('POST', $path . '/rotate-secret'));
        $operators = self::document($this->api('GET', '/api/v1/clients/' . self::TEST_M2M_CLIENT_ID));

        self::assertIsArray($self['registration']);
        self::assertIsString($self['registration']['initial_access_token_id']);
        self::assertIsString($self['registration']['registered_at']);
        self::assertIsArray($listed);
        $registrations = [];
        foreach ($listed as $item) {
            self::assertIsArray($item);
            self::assertIsString($item['client_id']);
            $registrations[$item['client_id']] = $item['registration'] !== null;
        }
        self::assertIsString($registered['client_id']);
        self::assertTrue($registrations[$registered['client_id']] ?? false);
        self::assertFalse($registrations[self::TEST_M2M_CLIENT_ID] ?? true);
        self::assertCount(2, $registrations);
        self::assertIsArray($rotated['registration']);
        self::assertNull($operators['registration']);
    }

    /**
     * Register a confidential client with a fresh initial access token.
     *
     * @param array<string, mixed> $extra
     *
     * @return array<array-key, mixed>
     */
    private function registered(array $extra = []): array
    {
        $token = $this->container()->get(IssueInitialAccessToken::class)(new NewInitialAccessToken('Acme'))->secret;
        $response = $this->request('POST', '/oauth2/register', [
            'Authorization' => 'Bearer ' . $token,
            'Content-Type' => 'application/json',
        ], body: (string) json_encode(self::WEB_APP + $extra));
        self::assertSame(201, $response->getStatusCode(), (string) $response->getBody());

        return self::json($response);
    }

    /**
     * @param array<array-key, mixed>   $registered What the registration answered.
     * @param array<string, mixed>|null $body
     */
    private function configuration(string $method, array $registered, ?array $body = null): ResponseInterface
    {
        $headers = ['Content-Type' => 'application/json'];
        /** @var mixed $token */
        $token = $registered['registration_access_token'] ?? null;
        if (is_string($token)) {
            $headers['Authorization'] = 'Bearer ' . $token;
        }

        return $this->request(
            $method,
            '/oauth2/register/' . rawurlencode((string) $registered['client_id']),
            $headers,
            body: $body === null ? '' : (string) json_encode($body),
        );
    }

    /** @param array<array-key, mixed> $registered */
    private function clientOf(array $registered): \Clavia\Domain\Client\Client
    {
        $client = $this->container()->get(ClientRepository::class)->find(
            ClientId::fromString((string) $registered['client_id']),
        );
        self::assertNotNull($client);

        return $client;
    }
}
