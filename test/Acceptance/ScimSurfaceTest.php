<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * The SCIM 2.0 surface (RFC 7644; docs/design/scim-provisioning.md §5.2, slice 1): a directory
 * reaches `/scim/v2` with its provisioning token and nothing else, every refusal of a token is
 * one `401`, failures are throttled per address, and the service provider describes itself.
 */
final class ScimSurfaceTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string CONFIG = '/scim/v2/ServiceProviderConfig';

    public function testADirectoryReadsTheServiceProviderConfiguration(): void
    {
        $token = $this->provisioningToken();

        $config = $this->scim('GET', self::CONFIG, $token);

        self::assertSame(StatusCodeInterface::STATUS_OK, $config->getStatusCode(), (string) $config->getBody());
        self::assertSame('application/scim+json', $config->getHeaderLine('Content-Type'));
        self::assertSame('no-store', $config->getHeaderLine('Cache-Control'));
        $document = self::document($config);
        self::assertSame(['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'], $document['schemas']);
        self::assertSame(['supported' => false], $document['patch'], 'Not until it is built.');
        self::assertSame(['supported' => true, 'maxResults' => 200], $document['filter']);
        self::assertSame(['supported' => false], $document['sort']);
        self::assertIsArray($document['bulk']);
        self::assertFalse($document['bulk']['supported']);
        self::assertIsArray($document['authenticationSchemes']);
        self::assertIsArray($document['authenticationSchemes'][0]);
        self::assertSame('oauthbearertoken', $document['authenticationSchemes'][0]['type']);
        self::assertIsArray($document['meta']);
        self::assertSame('https://management.clavia.test/scim/v2/ServiceProviderConfig', $document['meta']['location']);
    }

    public function testTheCataloguesListWhatExists(): void
    {
        $token = $this->provisioningToken();

        $types = self::document($this->scim('GET', '/scim/v2/ResourceTypes', $token));
        $schemas = self::document($this->scim('GET', '/scim/v2/Schemas', $token));
        $user = $this->scim('GET', '/scim/v2/ResourceTypes/User', $token);
        $schema = $this->scim('GET', '/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User', $token);

        self::assertSame(['urn:ietf:params:scim:api:messages:2.0:ListResponse'], $types['schemas']);
        self::assertSame(1, $types['totalResults'], 'Groups join with their slice.');
        self::assertSame(1, $schemas['totalResults']);
        self::assertSame(StatusCodeInterface::STATUS_OK, $user->getStatusCode());
        self::assertSame('/Users', self::document($user)['endpoint']);
        self::assertSame(StatusCodeInterface::STATUS_OK, $schema->getStatusCode());
        $attributes = self::document($schema)['attributes'];
        self::assertIsArray($attributes);
        self::assertContains('userName', array_column($attributes, 'name'));
        self::assertNotContains('password', array_column($attributes, 'name'), 'Never provisioned.');
        $group = $this->scim('GET', '/scim/v2/ResourceTypes/Group', $token);
        self::assertScimError(StatusCodeInterface::STATUS_NOT_FOUND, $group);
    }

    public function testBulkAndMeAreNotImplemented(): void
    {
        $token = $this->provisioningToken();

        $notImplemented = StatusCodeInterface::STATUS_NOT_IMPLEMENTED;
        self::assertScimError($notImplemented, $this->scim('POST', '/scim/v2/Bulk', $token));
        self::assertScimError($notImplemented, $this->scim('GET', '/scim/v2/Me', $token));
        self::assertScimError(StatusCodeInterface::STATUS_NOT_FOUND, $this->scim('GET', '/scim/v2/Nothing', $token));
    }

    public function testWithoutATokenNothingIsTold(): void
    {
        foreach ([self::CONFIG, '/scim/v2/Nothing', '/scim/v2/Bulk'] as $path) {
            $refused = $this->scim($path === '/scim/v2/Bulk' ? 'POST' : 'GET', $path, null);

            self::assertScimError(StatusCodeInterface::STATUS_UNAUTHORIZED, $refused);
            self::assertSame('Bearer realm="scim"', $refused->getHeaderLine('WWW-Authenticate'), 'RFC 6750 §3.1.');
        }
    }

    public function testEveryWrongTokenIsTheSameRefusal(): void
    {
        $clock = $this->freezeClock('2026-01-15T10:00:00Z');
        $this->adminToken();
        $expired = $this->provisioningToken(['expires_in' => 86_400]);
        $revoked = self::document($this->api('POST', '/api/v1/provisioning-tokens', [
            'connection' => 'password',
            'description' => 'Revoked',
        ]));
        self::assertIsString($revoked['id']);
        self::assertIsString($revoked['token']);
        $this->api('DELETE', '/api/v1/provisioning-tokens/' . $revoked['id']);
        $clock->advance(86_400);
        $management = $this->adminToken();

        $bodies = [];
        foreach (['not-a-real-token', $expired, $revoked['token'], $management] as $token) {
            $refused = $this->scim('GET', self::CONFIG, $token);
            self::assertScimError(StatusCodeInterface::STATUS_UNAUTHORIZED, $refused);
            self::assertSame('Bearer realm="scim", error="invalid_token"', $refused->getHeaderLine('WWW-Authenticate'));
            $bodies[] = (string) $refused->getBody();
        }
        foreach (['Basic ' . base64_encode('a:b'), 'DPoP abc', 'Bearer'] as $header) {
            $refused = $this->request('GET', self::CONFIG, ['Authorization' => $header], self::MANAGEMENT_HOST);
            self::assertScimError(StatusCodeInterface::STATUS_UNAUTHORIZED, $refused, $header);
            $bodies[] = (string) $refused->getBody();
        }

        self::assertCount(1, array_unique($bodies), 'One document, whatever was wrong.');
    }

    public function testFailedTokensAreThrottledPerAddress(): void
    {
        $this->boot(['CLAVIA_TOKEN_MAX_FAILURES' => '2', 'CLAVIA_TOKEN_FAILURE_WINDOW' => '600']);
        $token = $this->provisioningToken();
        $this->scim('GET', self::CONFIG, 'wrong-1');
        $this->scim('GET', self::CONFIG, 'wrong-2');

        $throttled = $this->scim('GET', self::CONFIG, $token);

        self::assertScimError(StatusCodeInterface::STATUS_TOO_MANY_REQUESTS, $throttled, 'Even the right token.');
        self::assertSame('600', $throttled->getHeaderLine('Retry-After'));
    }

    public function testARightTokenIsNeverThrottled(): void
    {
        $this->boot(['CLAVIA_TOKEN_MAX_FAILURES' => '2']);
        $token = $this->provisioningToken();

        foreach (range(1, 5) as $request) {
            self::assertSame(StatusCodeInterface::STATUS_OK, $this->scim('GET', self::CONFIG, $token)->getStatusCode());
        }
    }

    /** @param array<string, mixed> $options */
    private function provisioningToken(array $options = []): string
    {
        $this->adminToken();
        $issued = $this->api('POST', '/api/v1/provisioning-tokens', $options + [
            'connection' => 'password',
            'description' => 'Entra ID',
        ]);
        self::assertSame(StatusCodeInterface::STATUS_CREATED, $issued->getStatusCode(), (string) $issued->getBody());
        $token = self::document($issued)['token'];
        self::assertIsString($token);

        return $token;
    }

    private function scim(string $method, string $path, ?string $token): ResponseInterface
    {
        return $this->request(
            $method,
            $path,
            $token === null ? [] : ['Authorization' => 'Bearer ' . $token],
            self::MANAGEMENT_HOST,
        );
    }

    private static function assertScimError(int $status, ResponseInterface $response, string $message = ''): void
    {
        self::assertSame($status, $response->getStatusCode(), $message . ' ' . (string) $response->getBody());
        self::assertSame('application/scim+json', $response->getHeaderLine('Content-Type'));
        $document = self::document($response);
        self::assertSame(['urn:ietf:params:scim:api:messages:2.0:Error'], $document['schemas']);
        self::assertSame((string) $status, $document['status'], 'A string (RFC 7644 §3.12).');
        self::assertIsString($document['detail']);
    }
}
