<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\OAuth2;

use Clavia\Application\OAuth2\Token\ApiClaims;
use Clavia\Domain\Claims\ClaimMapping;
use Clavia\Domain\Claims\ClaimMappings;
use Clavia\Domain\Claims\ClaimName;
use Clavia\Domain\Claims\ClaimSource;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\OAuth2\AccessToken;
use Clavia\Domain\OAuth2\AccessTokenId;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Fake\InMemoryRoleRepository;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

/** Which tokens an API's custom claims reach (docs/design/custom-claims.md §2). */
final class ApiClaimsTest extends TestCase
{
    public function testAFirstPartyMachineTokenTakesTheConstants(): void
    {
        self::assertSame(
            ['deployment' => 'eu-1'],
            $this->claims()->for(self::api(), self::machineToken('reports-job')),
        );
    }

    public function testAThirdPartyApplicationsTokenTakesNothing(): void
    {
        self::assertSame([], $this->claims()->for(self::api(), self::machineToken('tpc_partner')));
    }

    public function testAnApiWithoutMappingsAddsNothing(): void
    {
        self::assertSame([], $this->claims()->for(self::api(ClaimMappings::none()), self::machineToken('reports-job')));
    }

    private function claims(): ApiClaims
    {
        return new ApiClaims(new InMemoryUserRepository(), new InMemoryRoleRepository());
    }

    private static function api(?ClaimMappings $claims = null): ResourceServer
    {
        return ResourceServer::register(
            ResourceServerId::fromString('rs_aaaaaaaaaaaaaaaa'),
            Audience::fromString('https://reports.example/api/'),
            'Reports',
            [Permission::of('read:reports')],
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            claims: $claims ?? ClaimMappings::of([
                ClaimMapping::forApi(
                    ClaimName::fromString('deployment', onAnApi: true),
                    ClaimSource::fromString('constant', '"eu-1"'),
                ),
                ClaimMapping::forApi(
                    ClaimName::fromString('plan', onAnApi: true),
                    ClaimSource::fromString('app_metadata.plan'),
                ),
            ]),
        );
    }

    private static function machineToken(string $client): AccessToken
    {
        return AccessToken::issueToClient(
            AccessTokenId::generate(new SeededRandomSource(1)),
            Digest::of('token'),
            ClientId::fromString($client),
            Audience::fromString('https://reports.example/api/'),
            ScopeSet::fromString('read:reports'),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            300,
        );
    }
}
