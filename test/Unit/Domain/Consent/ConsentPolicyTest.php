<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Consent;

use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Consent\ConsentPolicy;
use Clavia\Domain\Consent\UserConsent;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\Prompt;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Clients;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ConsentPolicyTest extends TestCase
{
    private const string SCOPE = 'openid invoices:read';

    /**
     * The decision table, row by row.
     */
    #[DataProvider('decisions')]
    public function testWhoIsAsked(
        string $clientId,
        ?bool $apiAllowsSkipping,
        ?string $prompt,
        ?string $given,
        bool $asked,
    ): void {
        $api = $apiAllowsSkipping === null ? null : self::api($apiAllowsSkipping);

        self::assertSame($asked, ConsentPolicy::mustAsk(
            self::client($clientId),
            $api,
            Prompt::fromParameter($prompt),
            ScopeSet::fromString(self::SCOPE),
            $given === null ? null : self::consent($clientId, $given),
        ));
    }

    /** @return iterable<string, array{string, bool|null, string|null, string|null, bool}> */
    public static function decisions(): iterable
    {
        yield 'first-party, no API: signing in is the consent' => ['spa', null, null, null, false];
        yield 'first-party, an API that allows skipping' => ['spa', true, null, null, false];
        yield 'first-party, an API that insists' => ['spa', false, null, null, true];
        yield 'first-party, an API that insists, agreed before' => ['spa', false, null, self::SCOPE, false];
        yield 'first-party, prompt=consent' => ['spa', null, 'consent', null, true];
        yield 'third-party, nothing agreed' => ['tpc_partner', true, null, null, true];
        yield 'third-party, no API, nothing agreed' => ['tpc_partner', null, null, null, true];
        yield 'third-party, all of it agreed' => ['tpc_partner', true, null, self::SCOPE, false];
        yield 'third-party, more than agreed' => ['tpc_partner', true, null, 'openid', true];
        yield 'third-party, agreed before but prompt=consent' => ['tpc_partner', true, 'consent', self::SCOPE, true];
        yield 'third-party, prompt=none: still has to be asked' => ['tpc_partner', true, 'none', null, true];
    }

    private static function client(string $id): Client
    {
        return Clients::public($id);
    }

    private static function api(bool $allowSkipping): ResourceServer
    {
        return ResourceServer::register(
            ResourceServerId::fromString('rs_aaaaaaaaaaaaaaaa'),
            Audience::fromString('https://invoices.example/'),
            'Invoices',
            [],
            new DateTimeImmutable('2026-01-15T09:00:00Z'),
            allowSkippingConsent: $allowSkipping,
        );
    }

    private static function consent(string $clientId, string $scope): UserConsent
    {
        return UserConsent::give(
            UserId::fromString('00000000-0000-4000-8000-000000000001'),
            ClientId::fromString($clientId),
            null,
            ScopeSet::fromString($scope),
            new DateTimeImmutable('2026-01-15T09:30:00Z'),
        );
    }
}
