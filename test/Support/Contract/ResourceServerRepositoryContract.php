<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\Claims\ClaimMapping;
use Clavia\Domain\Claims\ClaimMappings;
use Clavia\Domain\Claims\ClaimName;
use Clavia\Domain\Claims\ClaimSource;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\ResourceServer\ClientGrant;
use Clavia\Domain\ResourceServer\ClientGrantRepository;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\PageRequest;
use Clavia\Domain\Shared\ScopeSet;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see ResourceServerRepository} and {@see ClientGrantRepository} does.
 */
trait ResourceServerRepositoryContract
{
    abstract protected function resourceServers(): ResourceServerRepository;

    abstract protected function clientGrants(): ClientGrantRepository;

    /** A client that exists in the storage under test, for a grant to belong to. */
    abstract protected function aClient(string $clientId): ClientId;

    #[Test]
    public function aSavedApiIsFoundByIdAndByIdentifierWithItsPermissions(): void
    {
        $api = $this->anApi('https://invoices.example/api/', ['invoices:write', 'invoices:read']);
        $this->resourceServers()->save($api);

        $byId = $this->resourceServers()->find($api->id);
        $byIdentifier = $this->resourceServers()->findByIdentifier(
            Audience::fromString('https://invoices.example/api/'),
        );

        self::assertNotNull($byId);
        self::assertNotNull($byIdentifier);
        self::assertTrue($byIdentifier->id->equals($api->id));
        self::assertSame('Invoices', $byId->name);
        self::assertSame('https://invoices.example/api/', $byId->identifier->value);
        self::assertSame('invoices:read invoices:write', $byId->permissionScopes()->toString());
        self::assertSame('Read invoices:read', $byId->permissions[0]->description);
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:00:00Z'), $byId->createdAt);
    }

    #[Test]
    public function itsCustomClaimsAreSavedAndReadBackWhole(): void
    {
        $api = $this->anApi('https://reports.example/api/', ['read:reports']);
        $this->resourceServers()->save($api);
        self::assertTrue($this->resourceServers()->find($api->id)?->claims->isEmpty());

        $claims = ClaimMappings::of([
            ClaimMapping::forApi(
                ClaimName::fromString('https://example.com/plan', onAnApi: true),
                ClaimSource::fromString('app_metadata.plan'),
            ),
            ClaimMapping::forApi(ClaimName::fromString('roles', onAnApi: true), ClaimSource::fromString('roles')),
            ClaimMapping::forApi(
                ClaimName::fromString('deployment', onAnApi: true),
                ClaimSource::fromString('constant', '{"region":"eu","n":2.5}'),
            ),
        ]);
        $this->resourceServers()->save($api->withClaims($claims));

        self::assertSame($claims->toJson(), $this->resourceServers()->find($api->id)?->claims->toJson());
        self::assertSame(
            $claims->toJson(),
            $this->resourceServers()->findByIdentifier(
                Audience::fromString('https://reports.example/api/'),
            )?->claims->toJson(),
        );
    }

    #[Test]
    public function identifiersAreMatchedExactly(): void
    {
        $this->resourceServers()->save($this->anApi('https://invoices.example/api/', []));

        foreach (['https://invoices.example/api', 'HTTPS://invoices.example/api/'] as $near) {
            self::assertNull($this->resourceServers()->findByIdentifier(Audience::fromString($near)));
        }
    }

    #[Test]
    public function savingAgainReplacesTheNameAndThePermissions(): void
    {
        $api = $this->anApi('https://invoices.example/api/', ['a', 'b']);
        $this->resourceServers()->save($api);

        $this->resourceServers()->save(ResourceServer::register(
            $api->id,
            $api->identifier,
            'Billing',
            [Permission::of('b'), Permission::of('c')],
            $api->createdAt,
        ));

        $stored = $this->resourceServers()->find($api->id);
        self::assertSame('Billing', $stored?->name);
        self::assertSame('b c', $stored?->permissionScopes()->toString());
    }

    #[Test]
    public function anUnknownApiIsNull(): void
    {
        self::assertNull($this->resourceServers()->find(ResourceServerId::fromString('rs_0000000000000000')));
        self::assertNull($this->resourceServers()->findByIdentifier(Audience::fromString('https://nowhere.example/')));
    }

    #[Test]
    public function aGrantIsFoundForItsClientAndApiAndSavingAgainReplacesIt(): void
    {
        $client = $this->aClient('m2m');
        $api = $this->anApi('https://invoices.example/api/', ['a', 'b', 'c']);
        $other = $this->anApi('https://other.example/api/', ['a']);
        $this->resourceServers()->save($api);
        $this->resourceServers()->save($other);

        $at = new DateTimeImmutable('2026-01-15T10:00:00Z');
        $this->clientGrants()->save(ClientGrant::grant($client, $api, ScopeSet::fromString('a b'), $at));
        self::assertSame('a b', $this->clientGrants()->find($client, $api->id)?->scopes->toString());
        self::assertNull($this->clientGrants()->find($client, $other->id));

        $this->clientGrants()->save(
            ClientGrant::grant($client, $api, ScopeSet::fromString('c'), $at->modify('+1 day')),
        );

        $stored = $this->clientGrants()->find($client, $api->id);
        self::assertSame('c', $stored?->scopes->toString());
        self::assertEquals($at, $stored?->createdAt);
    }

    #[Test]
    public function aGrantMayHoldNothing(): void
    {
        $client = $this->aClient('m2m');
        $api = $this->anApi('https://invoices.example/api/', ['a']);
        $this->resourceServers()->save($api);

        $this->clientGrants()->save(
            ClientGrant::grant($client, $api, ScopeSet::empty(), new DateTimeImmutable('2026-01-15T10:00:00Z')),
        );

        self::assertTrue($this->clientGrants()->find($client, $api->id)?->scopes->isEmpty());
    }

    #[Test]
    public function anIdentifierAlreadyRegisteredIsRefusedAsSuch(): void
    {
        $this->resourceServers()->save($this->anApi('https://invoices.example/api/', []));

        $this->expectException(AlreadyExists::class);

        $this->resourceServers()->save(ResourceServer::register(
            ResourceServerId::fromString('rs_zzzzzzzzzzzzzzzz'),
            Audience::fromString('https://invoices.example/api/'),
            'Duplicate',
            [],
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        ));
    }

    #[Test]
    public function aSystemApiIsReadBackAsOne(): void
    {
        $api = $this->anApi('https://management.example/api/v1/', ['read:users']);
        $this->resourceServers()->save($api->asSystem('Management', $api->permissions));

        self::assertTrue($this->resourceServers()->find($api->id)?->isSystem);
        self::assertTrue($this->resourceServers()->find($api->id)?->enforcePolicies);
        self::assertTrue($this->resourceServers()->page(PageRequest::of())->items[0]->isSystem);
    }

    #[Test]
    public function whetherAnApiEnforcesRolesIsKept(): void
    {
        $api = $this->anApi('https://invoices.example/api/', ['a']);
        $this->resourceServers()->save($api);
        self::assertFalse($this->resourceServers()->find($api->id)?->enforcePolicies);

        $this->resourceServers()->save($api->enforcingPolicies(true));

        self::assertTrue($this->resourceServers()->find($api->id)?->enforcePolicies);
    }

    #[Test]
    public function apisArePagedAndSearchedByIdentifierAndName(): void
    {
        $this->resourceServers()->save($this->anApi('https://invoices.example/api/', ['a']));
        $this->resourceServers()->save($this->anApi('https://reports.example/api/', ['b']));

        $all = $this->resourceServers()->page(PageRequest::of());
        self::assertSame(2, $all->total);
        self::assertSame(1, $this->resourceServers()->page(PageRequest::of(search: 'REPORTS'))->total);
        self::assertSame(2, $this->resourceServers()->page(PageRequest::of(search: 'invoices'))->total);
        self::assertSame(['a'], $this->resourceServers()->page(
            PageRequest::of(search: 'invoices.example'),
        )->items[0]->permissionScopes()->toList());
    }

    #[Test]
    public function aDeletedApiTakesItsGrantsWithIt(): void
    {
        $client = $this->aClient('m2m');
        $api = $this->anApi('https://invoices.example/api/', ['a']);
        $this->resourceServers()->save($api);
        $this->clientGrants()->save(
            ClientGrant::grant($client, $api, ScopeSet::fromString('a'), new DateTimeImmutable()),
        );

        $this->resourceServers()->delete($api->id);

        self::assertNull($this->resourceServers()->find($api->id));
        self::assertNull($this->clientGrants()->find($client, $api->id));
    }

    /**
     * @param list<string> $permissions
     */
    private function anApi(string $identifier, array $permissions): ResourceServer
    {
        return ResourceServer::register(
            ResourceServerId::fromString('rs_' . substr(hash('sha256', $identifier), 0, 16)),
            Audience::fromString($identifier),
            'Invoices',
            array_map(static fn (string $value): Permission => Permission::of($value, 'Read ' . $value), $permissions),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
    }
}
