<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Management;

use Clavia\Application\Management\ManagementPermission;
use Clavia\Application\Management\NotFound;
use Clavia\Application\Management\Provisioning\GrantClientAccess;
use Clavia\Application\Management\Provisioning\RegisterManagementApi;
use Clavia\Application\Management\ResourceServers\DeleteResourceServer;
use Clavia\Application\Management\ResourceServers\NewResourceServer;
use Clavia\Application\Management\ResourceServers\PermissionDefinition;
use Clavia\Application\Management\ResourceServers\ReadResourceServers;
use Clavia\Application\Management\ResourceServers\RegisterResourceServer;
use Clavia\Application\Management\ResourceServers\UpdateResourceServer;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\SystemApiProtected;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\PageRequest;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\SecretGenerator;
use Clavia\Domain\Shared\Url;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryClientGrantRepository;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemoryResourceServerRepository;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * APIs through the Management API's use cases, and the two provisioning operations of
 * the shell: registering the Management API itself and granting a client access.
 */
final class ResourceServersTest extends TestCase
{
    private const string MANAGEMENT_API = 'https://management.clavia.test/api/v1/';

    private InMemoryClientGrantRepository $grants;
    private InMemoryResourceServerRepository $apis;
    private InMemoryClientRepository $clients;
    private FrozenClock $clock;
    private SecretGenerator $secrets;

    #[\Override]
    protected function setUp(): void
    {
        $this->grants = new InMemoryClientGrantRepository();
        $this->apis = new InMemoryResourceServerRepository($this->grants);
        $this->clients = new InMemoryClientRepository();
        $this->clock = new FrozenClock();
        $this->secrets = new SecretGenerator(new SeededRandomSource(1));
    }

    public function testARegisteredApiHasAGeneratedIdAndItsPermissions(): void
    {
        $api = $this->register(new NewResourceServer(
            'https://invoices.test/api/',
            'Invoices',
            [new PermissionDefinition('invoices:read', 'Read invoices')],
        ));

        self::assertMatchesRegularExpression('/^rs_[A-Za-z0-9]{16}$/D', $api->id->value);
        self::assertFalse($api->isSystem);
        self::assertSame('Read invoices', $api->permissions[0]->description);
        self::assertSame($api->name, $this->apis->find($api->id)?->name);
    }

    #[DataProvider('notAnIdentifier')]
    public function testAnIdentifierMustBeAnAbsoluteUriWithoutAFragment(string $identifier): void
    {
        $this->expectException(InvalidValue::class);

        $this->register(new NewResourceServer($identifier));
    }

    /** @return iterable<string, array{string}> */
    public static function notAnIdentifier(): iterable
    {
        yield 'a word' => ['invoices'];
        yield 'a relative path' => ['/api/'];
        yield 'a fragment' => ['https://x.test/#frag'];
    }

    public function testAPermissionMustBeAScopeTokenAndDefinedOnce(): void
    {
        $invalid = [
            [new PermissionDefinition('two words')],
            [new PermissionDefinition('a'), new PermissionDefinition('a')],
        ];
        foreach ($invalid as $permissions) {
            try {
                $this->register(new NewResourceServer('https://x.test/', permissions: $permissions));
                self::fail('The permissions were accepted.');
            } catch (InvalidValue) {
                self::assertSame(0, $this->apis->page(PageRequest::of())->total);
            }
        }
    }

    public function testAnIdentifierAlreadyRegisteredIsRefusedAsSuch(): void
    {
        $this->register(new NewResourceServer('https://x.test/'));

        $this->expectException(AlreadyExists::class);

        $this->register(new NewResourceServer('https://x.test/'));
    }

    public function testAnUpdateRenamesOrReplacesThePermissions(): void
    {
        $api = $this->register(new NewResourceServer('https://x.test/', 'X', [new PermissionDefinition('a')]));
        $update = new UpdateResourceServer($this->apis, new InMemoryDomainEvents());

        $renamed = $update($api->id, 'Y', null);
        self::assertSame('Y', $renamed->name);
        self::assertSame(['a'], $renamed->permissionScopes()->toList());

        $replaced = $update($api->id, null, [new PermissionDefinition('b'), new PermissionDefinition('c')]);
        self::assertSame('Y', $replaced->name);
        self::assertSame(['b', 'c'], $replaced->permissionScopes()->toList());
    }

    public function testDeletingAnApiTakesItsGrantsWithIt(): void
    {
        $api = $this->register(
            new NewResourceServer('https://x.test/', permissions: [new PermissionDefinition('a')]),
        );
        $client = $this->machineClient();
        $this->grant()($client->id, $api->identifier);

        new DeleteResourceServer($this->apis, new InMemoryDomainEvents())($api->id);

        self::assertNull($this->apis->find($api->id));
        self::assertNull($this->grants->find($client->id, $api->id));
    }

    public function testAnUnknownApiIsNotFound(): void
    {
        $this->expectException(NotFound::class);

        new ReadResourceServers($this->apis)->one(ResourceServerId::fromString('rs_0000000000000000'));
    }

    // ── The Management API ─────────────────────────────────────────────────────

    public function testTheManagementApiIsASystemApiDefiningEveryManagementPermission(): void
    {
        $api = $this->registerManagementApi()();

        self::assertTrue($api->isSystem);
        self::assertSame(RegisterManagementApi::NAME, $api->name);
        self::assertSame(self::MANAGEMENT_API, $api->identifier->value);
        self::assertEqualsCanonicalizing(
            array_map(
                static fn (ManagementPermission $permission): string => $permission->value,
                ManagementPermission::cases(),
            ),
            $api->permissionScopes()->toList(),
        );
    }

    public function testRegisteringAgainBringsThePermissionsUpToDateAndKeepsTheName(): void
    {
        // An API an older version registered: a permission since removed, one missing,
        // and a name the operator chose.
        $this->apis->save(ResourceServer::register(
            ResourceServerId::fromString('rs_aaaaaaaaaaaaaaaa'),
            Audience::fromString(self::MANAGEMENT_API),
            'Admin',
            [Permission::of('read:users'), Permission::of('read:everything')],
            $this->clock->now(),
        ));

        $api = $this->registerManagementApi()();

        self::assertSame('rs_aaaaaaaaaaaaaaaa', $api->id->value);
        self::assertSame('Admin', $api->name);
        self::assertTrue($api->isSystem);
        self::assertFalse($api->defines('read:everything'));
        self::assertTrue($api->defines('delete:resource_servers'));
    }

    public function testTheManagementApiCannotBeDeletedOrHaveItsPermissionsEdited(): void
    {
        $api = $this->registerManagementApi()();

        try {
            new DeleteResourceServer($this->apis, new InMemoryDomainEvents())($api->id);
            self::fail('The Management API was deleted.');
        } catch (SystemApiProtected) {
        }

        $this->expectException(SystemApiProtected::class);
        $update = new UpdateResourceServer($this->apis, new InMemoryDomainEvents());
        $update($api->id, null, [new PermissionDefinition('read:users')]);
    }

    // ── Grants ─────────────────────────────────────────────────────────────────

    public function testAGrantDefaultsToEveryPermissionAndReplacesThePreviousOne(): void
    {
        $api = $this->registerManagementApi()();
        $client = $this->machineClient();

        $grant = $this->grant()($client->id, $api->identifier);
        self::assertCount(count(ManagementPermission::cases()), $grant->scopes->toList());

        $this->grant()($client->id, $api->identifier, ScopeSet::fromString('read:users'));
        self::assertSame('read:users', $this->grants->find($client->id, $api->id)?->scopes->toString());
    }

    public function testAGrantNamingAnUndefinedScopeIsRefused(): void
    {
        $api = $this->registerManagementApi()();

        $this->expectException(InvalidValue::class);

        $this->grant()($this->machineClient()->id, $api->identifier, ScopeSet::fromString('read:everything'));
    }

    public function testOnlyAMachineClientCanBeGranted(): void
    {
        $api = $this->registerManagementApi()();
        $spa = Client::register(
            ClientId::fromString('spa'),
            'SPA',
            ClientType::Public,
            ClientAuthMethod::None,
            null,
            [Url::fromString('https://spa.test/cb')],
            [GrantType::AuthorizationCode],
            [ResponseType::Code],
            $this->clock->now(),
        );
        $this->clients->save($spa);

        $this->expectException(InvalidValue::class);

        $this->grant()($spa->id, $api->identifier);
    }

    public function testAThirdPartyMachineCanBeGrantedAnyApiButASystemOne(): void
    {
        $outsider = Client::register(
            ClientId::fromString('tpc_machine'),
            'Partner machine',
            ClientType::Confidential,
            ClientAuthMethod::ClientSecretBasic,
            '$hash$',
            [],
            [GrantType::ClientCredentials],
            [],
            $this->clock->now(),
        );
        $this->clients->save($outsider);
        $ordinary = $this->register(new NewResourceServer('https://x.test/', 'X', [new PermissionDefinition('a')]));
        $system = $this->registerManagementApi()();

        self::assertSame('a', $this->grant()($outsider->id, $ordinary->identifier)->scopes->toString());
        $this->expectException(InvalidValue::class);
        $this->expectExceptionMessage('third-party');
        $this->grant()($outsider->id, $system->identifier);
    }

    public function testAnUpdateDecidesWhetherFirstPartyApplicationsMaySkipConsent(): void
    {
        $api = $this->register(new NewResourceServer('https://x.test/', 'X', allowSkippingConsent: false));
        self::assertFalse($api->allowSkippingConsent);

        $update = new UpdateResourceServer($this->apis, new InMemoryDomainEvents());

        self::assertTrue($update($api->id, null, null, allowSkippingConsent: true)->allowSkippingConsent);
        self::assertTrue($update($api->id, 'Y', null)->allowSkippingConsent, 'Left alone when not named.');
    }

    public function testGrantingAnUnknownClientOrApiIsNotFound(): void
    {
        $api = $this->registerManagementApi()();

        try {
            $this->grant()(ClientId::fromString('nobody'), $api->identifier);
            self::fail('An unknown client was granted.');
        } catch (NotFound) {
        }

        $this->expectException(NotFound::class);
        $this->grant()($this->machineClient()->id, Audience::fromString('https://nothing.test/'));
    }

    private function register(NewResourceServer $new): ResourceServer
    {
        return new RegisterResourceServer($this->apis, $this->secrets, $this->clock, new InMemoryDomainEvents())($new);
    }

    private function registerManagementApi(): RegisterManagementApi
    {
        return new RegisterManagementApi(
            $this->apis,
            new InMemoryTransactionManager(),
            $this->secrets,
            $this->clock,
            Audience::fromString(self::MANAGEMENT_API),
            new InMemoryDomainEvents(),
        );
    }

    private function grant(): GrantClientAccess
    {
        return new GrantClientAccess(
            $this->clients,
            $this->apis,
            $this->grants,
            $this->clock,
            new InMemoryDomainEvents(),
        );
    }

    private function machineClient(): Client
    {
        $client = Client::register(
            ClientId::fromString('machine'),
            'Machine',
            ClientType::Confidential,
            ClientAuthMethod::ClientSecretBasic,
            'hash',
            [],
            [GrantType::ClientCredentials],
            [],
            $this->clock->now(),
        );
        $this->clients->save($client);

        return $client;
    }
}
