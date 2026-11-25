<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Domain\Claims\ClaimMapping;
use Clavia\Domain\Claims\ClaimMappings;
use Clavia\Domain\Claims\ClaimName;
use Clavia\Domain\Claims\ClaimSource;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Domain\Identity\AppMetadata;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Rbac\GrantedPermission;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\AccessTokenFormat;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\Scope;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\SeededRandomSource;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\OidcFixtures;
use ClaviaTest\Support\TestStorage;
use DateTimeImmutable;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * An API's custom claims (#115, docs/design/custom-claims.md §5.2–§5.4): in its JWT access
 * tokens, recomputed at a refresh, in introspection for opaque tokens, constants only for a
 * machine, nothing for a third-party application, and defined through the Management API.
 */
final class ApiCustomClaimsTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use OidcFixtures;
    use ManagementFixtures;

    private const array MAPPINGS = [
        ['https://example.com/plan', 'app_metadata.plan'],
        ['tenant_id', 'app_metadata.tenant.id'],
        ['roles', 'roles'],
        ['https://example.com/email', 'email'],
        ['nick', 'profile.nickname'],
        ['absent', 'app_metadata.nothing'],
        ['deployment', 'constant', '"eu-1"'],
    ];

    public function testAJwtAccessTokenCarriesTheApisClaims(): void
    {
        $user = $this->loggedIn();
        $this->publicClient();
        $api = $this->claimingApi(AccessTokenFormat::Jwt);
        $this->setMetadata('{"plan":"pro","tenant":{"id":42}}');
        $this->giveRole('Report reader', $api);
        $this->giveRole('Elsewhere', $this->anApi('https://other.example/api/', ['other:read']));

        $claims = $this->verifiedJwt($this->userToken()['access_token'])['claims'];

        self::assertSame('pro', $claims['https://example.com/plan']);
        self::assertSame(42, $claims['tenant_id']);
        self::assertSame(['Report reader'], $claims['roles'], 'Only the roles holding a permission here.');
        self::assertSame(self::TEST_USER_EMAIL, $claims['https://example.com/email']);
        self::assertSame('eu-1', $claims['deployment']);
        self::assertArrayNotHasKey('nick', $claims, 'No value, no claim: never null.');
        self::assertArrayNotHasKey('absent', $claims);
        // The protocol's claims are what they always were.
        self::assertSame($user->id->value, $claims['sub']);
        self::assertSame(self::TEST_M2M_AUDIENCE, $claims['aud']);
    }

    public function testARefreshShowsWhatChanged(): void
    {
        $this->loggedIn();
        $this->refreshingClient();
        $api = $this->claimingApi(AccessTokenFormat::Jwt);
        $this->setMetadata('{"plan":"pro"}');
        $role = $this->giveRole('Report reader', $api);
        $first = $this->userToken();

        $this->setMetadata('{"plan":"free"}');
        $this->container()->get(RoleRepository::class)->unassign($role->id, $this->user()->id);
        $refreshed = $this->post('/oauth2/token', [
            'grant_type' => 'refresh_token',
            'client_id' => self::TEST_CLIENT_ID,
            'refresh_token' => (string) $first['refresh_token'],
        ]);

        $claims = $this->verifiedJwt((string) self::json($refreshed)['access_token'])['claims'];
        self::assertSame('free', $claims['https://example.com/plan']);
        self::assertArrayNotHasKey('roles', $claims, 'The role taken away is gone at once.');
    }

    public function testIntrospectionReportsThemForAnOpaqueTokenAsTheyAreNow(): void
    {
        $this->loggedIn();
        $this->publicClient();
        $this->claimingApi(AccessTokenFormat::Opaque);
        $this->setMetadata('{"plan":"pro"}');
        $token = $this->userToken()['access_token'];

        $answer = self::json($this->introspect($token));
        self::assertTrue($answer['active']);
        self::assertSame('pro', $answer['https://example.com/plan']);
        self::assertSame('eu-1', $answer['deployment']);

        $this->setMetadata('{"plan":"free"}');
        self::assertSame(
            'free',
            self::json($this->introspect($token))['https://example.com/plan'],
            'Worked out when asked.',
        );
    }

    public function testAMachineTokenCarriesTheConstantsOnly(): void
    {
        $this->claimingApi(AccessTokenFormat::Jwt);

        $claims = $this->verifiedJwt((string) self::json($this->requestMachineToken())['access_token'])['claims'];

        self::assertSame('eu-1', $claims['deployment']);
        self::assertArrayNotHasKey('https://example.com/plan', $claims);
        self::assertArrayNotHasKey('roles', $claims);
    }

    public function testAThirdPartyApplicationIsToldNothing(): void
    {
        $api = $this->claimingApi(AccessTokenFormat::Jwt);
        $partner = $this->thirdPartyMachine();
        $this->grantClient($partner, $api, 'api:read');

        $response = $this->requestMachineToken(credentials: [$partner->id->value, self::TEST_M2M_SECRET]);

        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode(), (string) $response->getBody());
        self::assertArrayNotHasKey(
            'deployment',
            $this->verifiedJwt((string) self::json($response)['access_token'])['claims'],
        );
    }

    public function testTooManyClaimsRefuseTheTokenAndRecordNothing(): void
    {
        $this->loggedIn();
        $this->publicClient();
        $rows = [['blob', 'app_metadata.blob']];
        foreach (range(1, 17) as $i) {
            $rows[] = ['c' . $i, 'constant', '"' . str_repeat('y', 1000) . '"'];
        }
        $this->claimingApi(AccessTokenFormat::Jwt, $rows);
        $this->setMetadata('{"blob":"' . str_repeat('x', 16_000) . '"}');

        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode(
            $challenge,
            ['scope' => 'openid api:read', 'audience' => self::TEST_M2M_AUDIENCE],
        );
        $response = $this->post('/oauth2/token', $this->tokenRequest($code, $verifier));

        self::assertSame(StatusCodeInterface::STATUS_INTERNAL_SERVER_ERROR, $response->getStatusCode());
        self::assertSame(0, TestStorage::database()->fetchValue('SELECT count(*) FROM oauth2_access_tokens'));
        self::assertNull(
            TestStorage::database()->fetchValue('SELECT used_at FROM oauth2_authorization_codes'),
            'Nothing spent.',
        );
    }

    public function testTheManagementApiDefinesThemAndRefusesWhatItMust(): void
    {
        $this->adminToken();
        $api = $this->machineApi();
        $path = '/api/v1/resource-servers/' . $api->id->value;

        $set = $this->api('PATCH', $path, ['claims' => [
            ['name' => 'https://example.com/plan', 'source' => 'app_metadata.plan'],
            ['name' => 'deployment', 'source' => 'constant', 'value' => ['region' => 'eu']],
        ]]);
        self::assertSame(StatusCodeInterface::STATUS_OK, $set->getStatusCode(), (string) $set->getBody());
        self::assertSame(
            [['name' => 'https://example.com/plan', 'source' => 'app_metadata.plan'],
                ['name' => 'deployment', 'source' => 'constant', 'value' => ['region' => 'eu']]],
            self::document($this->api('GET', $path))['claims'],
        );

        $entries = $this->api('PATCH', $path, ['claims' => [
            ['name' => 'sub', 'source' => 'email'],
            ['name' => 'fine', 'source' => 'email'],
            ['name' => 'unknown', 'source' => 'request.audience'],
            ['name' => 'nothing', 'source' => 'constant'],
        ]]);
        self::assertSame(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, $entries->getStatusCode());
        $pointers = array_column((array) self::document($entries)['errors'], 'pointer');
        self::assertSame(['/claims/0', '/claims/2', '/claims/3'], $pointers);

        $list = $this->api('PATCH', $path, ['claims' => [
            ['name' => 'tenant', 'source' => 'app_metadata.tenant'],
            ['name' => 'tenant_id', 'source' => 'app_metadata.tenant.id'],
        ]]);
        self::assertSame(['/claims'], array_column((array) self::document($list)['errors'], 'pointer'));
        self::assertCount(2, (array) self::document($this->api('GET', $path))['claims'], 'A refusal changes nothing.');

        $system = $this->api('PATCH', '/api/v1/resource-servers/' . $this->managementApi()->id->value, [
            'claims' => [['name' => 'plan', 'source' => 'app_metadata.plan']],
        ]);
        self::assertSame(StatusCodeInterface::STATUS_CONFLICT, $system->getStatusCode(), 'A system API takes none.');
    }

    /** @param list<array{0: string, 1: string, 2?: string}>|null $rows */
    private function claimingApi(AccessTokenFormat $format, ?array $rows = null): ResourceServer
    {
        $api = $this->machineApi()
            ->issuingAccessTokensAs($format)
            ->withClaims(ClaimMappings::of(array_map(
                static fn (array $row): ClaimMapping => ClaimMapping::forApi(
                    ClaimName::fromString($row[0], onAnApi: true),
                    ClaimSource::fromString($row[1], $row[2] ?? null),
                ),
                $rows ?? self::MAPPINGS,
            )));
        $this->container()->get(ResourceServerRepository::class)->save($api);

        return $api;
    }

    private function setMetadata(string $json): void
    {
        $users = $this->container()->get(UserRepository::class);
        $user = $this->user();
        $user->changeAppMetadata(AppMetadata::fromJson($json), new DateTimeImmutable());
        $users->save($user);
    }

    private function giveRole(string $name, ResourceServer $api): Role
    {
        $roles = $this->container()->get(RoleRepository::class);
        $role = Role::define(
            RoleId::generate(new SecretGenerator(new SeededRandomSource(crc32($name)))),
            $name,
            '',
            [new GrantedPermission($api->id, Scope::fromString($api->permissions[0]->value->value))],
            new DateTimeImmutable(),
        );
        $roles->save($role);
        $roles->assign($role->id, $this->user()->id, new DateTimeImmutable());

        return $role;
    }

    private function thirdPartyMachine(): Client
    {
        $client = Client::register(
            ClientId::fromString('tpc_test-machine'),
            'Partner machine',
            ClientType::Confidential,
            ClientAuthMethod::ClientSecretBasic,
            $this->container()->get(PasswordHasher::class)->hash(self::TEST_M2M_SECRET),
            [],
            [GrantType::ClientCredentials],
            [],
            $this->container()->get(Clock::class)->now(),
        );
        $this->container()->get(ClientRepository::class)->save($client);

        return $client;
    }

    /** @return array{access_token: string, refresh_token: string|null} */
    private function userToken(): array
    {
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode(
            $challenge,
            ['scope' => 'openid api:read', 'audience' => self::TEST_M2M_AUDIENCE],
        );
        $response = $this->post('/oauth2/token', $this->tokenRequest($code, $verifier));
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode(), (string) $response->getBody());
        $token = self::json($response);

        return [
            'access_token' => (string) $token['access_token'],
            'refresh_token' => isset($token['refresh_token']) ? (string) $token['refresh_token'] : null,
        ];
    }

    private function introspect(string $token): ResponseInterface
    {
        return $this->post(
            '/oauth2/introspect',
            ['token' => $token],
            basicAuth: [self::TEST_M2M_CLIENT_ID, self::TEST_M2M_SECRET],
        );
    }
}
