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
 * A `409` for something already taken names the kind of thing, never the value at fault (#167): no
 * error repeats a value the caller sent, an address least of all.
 */
final class ConflictsTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    public function testATakenRoleNameIsNotRepeated(): void
    {
        $this->adminToken();
        $role = ['name' => 'Zebra auditors', 'description' => 'Reads the trail.'];
        $this->api('POST', '/api/v1/roles', $role);

        self::assertConflictWithout('Zebra auditors', $this->api('POST', '/api/v1/roles', $role));
    }

    public function testATakenConnectionNameIsNotRepeated(): void
    {
        $this->adminToken();
        $pool = ['name' => 'zebra-pool', 'display_name' => 'Zebras', 'strategy' => 'database'];
        $this->api('POST', '/api/v1/connections', $pool);

        self::assertConflictWithout('zebra-pool', $this->api('POST', '/api/v1/connections', $pool));
    }

    public function testATakenApiIdentifierIsNotRepeated(): void
    {
        $this->adminToken();
        $api = ['name' => 'Zebras', 'identifier' => 'https://zebras.example/api'];
        $this->api('POST', '/api/v1/resource-servers', $api);

        self::assertConflictWithout('zebras.example', $this->api('POST', '/api/v1/resource-servers', $api));
    }

    public function testATakenAddressIsNotRepeated(): void
    {
        $this->adminToken();
        $account = ['email' => 'zebra@example.com', 'password' => 'a-good-password'];
        $this->api('POST', '/api/v1/users', $account);

        $response = $this->api('POST', '/api/v1/users', $account);

        self::assertConflictWithout('zebra@example.com', $response);
        self::assertStringNotContainsString(
            'password',
            (string) (self::document($response)['detail'] ?? ''),
            'Nor the connection.',
        );
    }

    private static function assertConflictWithout(string $value, ResponseInterface $response): void
    {
        $body = (string) $response->getBody();
        self::assertSame(StatusCodeInterface::STATUS_CONFLICT, $response->getStatusCode(), $body);
        self::assertStringNotContainsString($value, $body);
    }
}
