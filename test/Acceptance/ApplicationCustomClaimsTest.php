<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Domain\Claims\ClaimDestination;
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
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Identity\AppMetadata;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Rbac\GrantedPermission;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\Scope;
use Clavia\Domain\Shared\SecretGenerator;
use Clavia\Domain\Shared\Url;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\SeededRandomSource;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\OidcFixtures;
use DateTimeImmutable;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;

/**
 * An application's custom claims (#116, docs/design/custom-claims.md §5.3, §5.4): in its ID tokens
 * and userinfo answers, each where its mapping says, defined through the Management API, never
 * for a third-party application.
 */
final class ApplicationCustomClaimsTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use OidcFixtures;
    use ManagementFixtures;

    public function testTheIdTokenAndUserinfoEachCarryWhatIsMeantForThem(): void
    {
        $user = $this->loggedIn();
        $this->claimingClient();
        $users = $this->container()->get(UserRepository::class);
        $user->changeAppMetadata(AppMetadata::fromJson('{"plan":"pro","tenant":{"id":42}}'), new DateTimeImmutable());
        $users->save($user);
        $this->giveRole('Reports', $this->anApi('https://reports.example/api/', ['read:reports']));
        $this->giveRole('Billing', $this->anApi('https://billing.example/api/', ['read:invoices']));

        $tokens = $this->completeFlow('openid email');
        $idToken = $this->verifiedIdToken($tokens['id_token'])['claims'];
        $userinfo = self::json($this->request(RequestMethodInterface::METHOD_GET, '/oidc/userinfo', [
            'Authorization' => 'Bearer ' . (string) $tokens['access_token'],
        ]));

        self::assertSame(42, $idToken['tenant']);
        self::assertSame('eu-1', $idToken['deployment']);
        self::assertSame(
            ['Billing', 'Reports'],
            $idToken['https://example.com/roles'],
            'All of the roles, for an application.',
        );
        self::assertArrayNotHasKey('https://example.com/plan', $idToken, 'That one is for userinfo.');
        self::assertSame($user->id->value, $idToken['sub']);
        self::assertSame(self::TEST_CLIENT_ID, $idToken['aud']);

        self::assertSame('pro', $userinfo['https://example.com/plan']);
        self::assertSame(['Billing', 'Reports'], $userinfo['https://example.com/roles']);
        self::assertSame(self::TEST_USER_EMAIL, $userinfo['email'], 'What the scope releases is still there.');
        self::assertArrayNotHasKey('tenant', $userinfo, 'That one is for the ID token.');
    }

    public function testTheManagementApiDefinesThemAndRefusesWhatItMust(): void
    {
        $this->adminToken();
        $this->publicClient();
        $path = '/api/v1/clients/' . self::TEST_CLIENT_ID;

        $set = $this->api(RequestMethodInterface::METHOD_PATCH, $path, ['claims' => [
            ['name' => 'tenant', 'source' => 'app_metadata.tenant', 'in' => ['userinfo', 'id_token']],
        ]]);
        self::assertSame(StatusCodeInterface::STATUS_OK, $set->getStatusCode(), (string) $set->getBody());
        self::assertSame(
            [['name' => 'tenant', 'source' => 'app_metadata.tenant', 'in' => ['id_token', 'userinfo']]],
            self::document($this->api(RequestMethodInterface::METHOD_GET, $path))['claims'],
        );

        $entries = $this->api(RequestMethodInterface::METHOD_PATCH, $path, ['claims' => [
            ['name' => 'roles', 'source' => 'roles', 'in' => ['id_token']],
            ['name' => 'fine', 'source' => 'email', 'in' => ['id_token']],
            ['name' => 'email', 'source' => 'email', 'in' => ['userinfo']],
        ]]);
        self::assertSame(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, $entries->getStatusCode());
        $pointers = array_column((array) self::document($entries)['errors'], 'pointer');
        self::assertSame(['/claims/0', '/claims/2'], $pointers);

        $accessToken = $this->api(RequestMethodInterface::METHOD_PATCH, $path, ['claims' => [
            ['name' => 'plan', 'source' => 'email', 'in' => ['access_token']],
        ]]);
        self::assertSame(
            StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY,
            $accessToken->getStatusCode(),
            'The contract refuses it.',
        );

        $partner = $this->thirdPartyClient();
        $refused = $this->api(RequestMethodInterface::METHOD_PATCH, '/api/v1/clients/' . $partner->id->value, [
            'claims' => [['name' => 'plan', 'source' => 'app_metadata.plan', 'in' => ['id_token']]],
        ]);
        self::assertSame(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, $refused->getStatusCode());
        self::assertTrue($this->container()->get(ClientRepository::class)->find($partner->id)?->claims->isEmpty());
    }

    private function claimingClient(): void
    {
        /** @param list<ClaimDestination> $in */
        $mapping = static fn (string $name, string $source, array $in, ?string $value = null): ClaimMapping
            => ClaimMapping::forApplication(
                ClaimName::fromString($name, onAnApi: false),
                ClaimSource::fromString($source, $value),
                $in,
            );
        $client = $this->publicClient()->withClaims(ClaimMappings::of([
            $mapping('tenant', 'app_metadata.tenant.id', [ClaimDestination::IdToken]),
            $mapping('https://example.com/plan', 'app_metadata.plan', [ClaimDestination::UserInfo]),
            $mapping('https://example.com/roles', 'roles', [ClaimDestination::IdToken, ClaimDestination::UserInfo]),
            $mapping('deployment', 'constant', [ClaimDestination::IdToken], '"eu-1"'),
        ]));
        $this->container()->get(ClientRepository::class)->save($client);
    }

    private function giveRole(string $name, ResourceServer $api): void
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
    }

    private function thirdPartyClient(): Client
    {
        $client = Client::register(
            ClientId::fromString('tpc_partner'),
            'Partner',
            ClientType::Public,
            ClientAuthMethod::None,
            null,
            [Url::fromString('https://partner.example/cb')],
            [GrantType::AuthorizationCode],
            [ResponseType::Code],
            $this->container()->get(Clock::class)->now(),
        );
        $this->container()->get(ClientRepository::class)->save($client);

        return $client;
    }
}
