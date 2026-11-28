<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Primary\Cli\RunJobsCommand;
use Clavia\Application\Management\Users\Export\ExportUsers;
use Clavia\Domain\Identity\UserRepository;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use stdClass;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * Application metadata on accounts (#114, docs/design/custom-claims.md §5.1): written by an operator
 * holding `update:users_app_metadata` beside `update:users`, replaced whole, read with
 * `read:users`, recorded by field name only, exported, ignored by imports.
 */
final class ManagementUserAppMetadataTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    public function testAnOperatorWithItsScopeSetsItAndEveryoneReadsItBack(): void
    {
        $this->adminToken(['read:users', 'update:users', 'update:users_app_metadata']);
        $path = '/api/v1/users/' . $this->user()->id->value;

        $set = $this->api(RequestMethodInterface::METHOD_PATCH, $path, [
            'app_metadata' => ['tenant' => ['region' => 'eu', 'id' => 42], 'plan' => 'pro'],
        ]);

        self::assertSame(StatusCodeInterface::STATUS_OK, $set->getStatusCode(), (string) $set->getBody());
        $sorted = ['plan' => 'pro', 'tenant' => ['id' => 42, 'region' => 'eu']];
        self::assertSame($sorted, self::document($set)['app_metadata']);
        self::assertStringContainsString(
            '"app_metadata":{"plan":"pro","tenant":{"id":42,"region":"eu"}}',
            (string) $this->api(RequestMethodInterface::METHOD_GET, $path)->getBody(),
        );

        // Replaced whole: a key left out is gone; an empty object clears it.
        $this->api(RequestMethodInterface::METHOD_PATCH, $path, ['app_metadata' => ['plan' => 'free']]);
        self::assertSame(
            ['plan' => 'free'],
            self::document($this->api(RequestMethodInterface::METHOD_GET, $path))['app_metadata'],
        );
        $cleared = $this->api(RequestMethodInterface::METHOD_PATCH, $path, ['app_metadata' => new stdClass()]);
        self::assertStringContainsString('"app_metadata":{}', (string) $cleared->getBody());

        // The trail names the field, never a value.
        $details = (string) TestStorage::database()->fetchValue(
            "SELECT details::text FROM audit_events WHERE type = 'user.updated' ORDER BY occurred_at LIMIT 1",
        );
        self::assertStringContainsString('app_metadata', $details);
        self::assertStringNotContainsString('pro', $details);
    }

    public function testWithoutItsScopeNothingChanges(): void
    {
        $this->adminToken(['read:users', 'update:users']);
        $user = $this->user();
        $path = '/api/v1/users/' . $user->id->value;

        $refused = $this->api(
            RequestMethodInterface::METHOD_PATCH,
            $path,
            ['name' => 'Ada King', 'app_metadata' => ['plan' => 'pro']],
        );

        self::assertSame(StatusCodeInterface::STATUS_FORBIDDEN, $refused->getStatusCode());
        self::assertStringContainsString('insufficient_scope', $refused->getHeaderLine('WWW-Authenticate'));
        $stored = $this->container()->get(UserRepository::class)->find($user->id);
        self::assertNotNull($stored);
        self::assertTrue($stored->appMetadata()->isEmpty());
        self::assertNull($stored->profile()->name, 'Nothing of the request was applied.');

        // The rest of the operation needs only its own scope.
        $named = $this->api(RequestMethodInterface::METHOD_PATCH, $path, ['name' => 'Ada King']);
        self::assertSame(StatusCodeInterface::STATUS_OK, $named->getStatusCode());
    }

    public function testItsBoundsAreRefusedAtTheirPointer(): void
    {
        $this->adminToken(['read:users', 'update:users', 'update:users_app_metadata']);
        $path = '/api/v1/users/' . $this->user()->id->value;

        $tooDeep = $this->api(
            RequestMethodInterface::METHOD_PATCH,
            $path,
            ['app_metadata' => ['a' => ['b' => ['c' => ['d' => ['e' => [1]]]]]]],
        );
        $badKey = $this->api(RequestMethodInterface::METHOD_PATCH, $path, ['app_metadata' => ['the plan' => 'pro']]);
        $notAnObject = $this->api(RequestMethodInterface::METHOD_PATCH, $path, ['app_metadata' => ['pro']]);

        // Its bounds are a rule of the domain (422); not being an object, the contract's (400).
        foreach (
            [
                [$tooDeep, StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY],
                [$badKey, StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY],
                [$notAnObject, StatusCodeInterface::STATUS_BAD_REQUEST],
            ] as [$response, $status]
        ) {
            self::assertSame($status, $response->getStatusCode());
            self::assertStringContainsString('"pointer":"/app_metadata', (string) $response->getBody());
        }
        self::assertStringNotContainsString('the plan', (string) $badKey->getBody(), 'Never the value at fault.');
    }

    public function testAnExportWritesItAndAnImportIgnoresIt(): void
    {
        $this->adminToken(['read:users', 'create:users', 'update:users', 'update:users_app_metadata']);
        $user = $this->user();
        $this->api(
            RequestMethodInterface::METHOD_PATCH,
            '/api/v1/users/' . $user->id->value,
            ['app_metadata' => ['plan' => 'pro']],
        );
        $stored = $this->container()->get(UserRepository::class)->find($user->id);
        self::assertNotNull($stored);

        $line = (string) json_encode(ExportUsers::line($stored));
        self::assertStringContainsString('"app_metadata":{"plan":"pro"}', $line);

        $import = self::document($this->api(
            RequestMethodInterface::METHOD_POST,
            '/api/v1/jobs/users-imports',
            headers: ['Content-Type' => 'application/x-ndjson'],
            rawBody: str_replace(self::TEST_USER_EMAIL, 'grace@example.com', $line) . "\n",
        ));
        $this->runJobs();
        $report = self::document(
            $this->api(RequestMethodInterface::METHOD_GET, '/api/v1/jobs/' . (string) $import['id']),
        );
        self::assertSame(['total' => 1, 'created' => 1, 'failed' => 0], $report['summary'], 'Ignored, not refused.');
    }

    private function runJobs(): void
    {
        $tester = new CommandTester($this->container()->get(RunJobsCommand::class));
        $tester->execute([]);
    }
}
