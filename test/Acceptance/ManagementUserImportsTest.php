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
use Clavia\Application\Port\PasswordHasher;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\UserRepository;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * Bulk import of users (#19): NDJSON queued through the Management API, run by `clavia jobs:run`,
 * each line taken or refused by number in the job's report.
 */
final class ManagementUserImportsTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string IMPORTS = '/api/v1/jobs/users-imports';
    private const string BCRYPT = '$2y$12$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW';

    public function testAnImportTakesTheGoodLinesAndReportsTheOthers(): void
    {
        $this->adminToken();
        $this->user();
        $hash = $this->container()->get(PasswordHasher::class)->hash('graces-password');
        $lines = [
            [
                'email' => 'grace@example.com',
                'email_verified' => true,
                'name' => 'Grace Hopper',
                'password_hash' => $hash,
            ],
            ['email' => 'alan@example.com', 'locale' => 'en-GB'],
            'not json at all',
            ['email' => self::TEST_USER_EMAIL],
            ['email' => 'ada@example.com', 'role' => 'admin'],
            ['email' => 'bob@example.com', 'password_hash' => self::BCRYPT],
            ['email' => 'eve@example.com', 'password' => 'plaintext-password'],
            ['email' => 'not an address'],
        ];

        $queued = $this->import(self::ndjson($lines));

        self::assertSame(StatusCodeInterface::STATUS_ACCEPTED, $queued->getStatusCode(), (string) $queued->getBody());
        $job = self::document($queued);
        self::assertSame('queued', $job['status']);
        self::assertIsString($job['id']);
        self::assertSame('/api/v1/jobs/' . $job['id'], $queued->getHeaderLine('Location'));

        self::assertSame("Ran 1 job; 0 stalled jobs failed; 0 finished jobs purged.\n", $this->runJobs());

        $done = self::document($this->api('GET', '/api/v1/jobs/' . $job['id']));
        self::assertSame('completed', $done['status']);
        self::assertSame(['total' => 8, 'created' => 2, 'failed' => 6], $done['summary']);
        self::assertSame(
            [
                [3, 'invalid_json'],
                [4, 'already_exists'],
                [5, 'invalid_field'],
                [6, 'unsupported_hash'],
                [7, 'invalid_field'],
                [8, 'invalid_field'],
            ],
            array_map(static fn (array $e): array => [$e['line'], $e['error']], (array) $done['errors']),
        );
        // A report never repeats what a line held.
        self::assertStringNotContainsString('bob@example.com', (string) json_encode($done));
        self::assertStringNotContainsString('plaintext-password', (string) json_encode($done));

        $users = $this->container()->get(UserRepository::class);
        $grace = $users->findByEmail(ConnectionName::defaultPool(), 'grace@example.com');
        self::assertNotNull($grace);
        self::assertSame($hash, $grace->passwordHash(), 'The hash is kept as it was.');
        self::assertTrue($grace->isEmailVerified());
        self::assertSame('Grace Hopper', $grace->profile()->name);
        self::assertNull($users->findByEmail(ConnectionName::defaultPool(), 'alan@example.com')?->passwordHash());
        self::assertNull($users->findByEmail(ConnectionName::defaultPool(), 'bob@example.com'));
        self::assertSame(2, (int) TestStorage::database()->fetchValue(
            "SELECT count(*) FROM audit_events WHERE type = :type AND actor_kind = 'application'",
            ['type' => AuditEventType::UserCreated->value],
        ), 'Recorded as the work of the caller who queued it.');
        self::assertNull(
            TestStorage::database()->fetchValue('SELECT input FROM user_jobs'),
            'The input, hashes included, is let go.',
        );
    }

    public function testOnlyAPoolTakesAnImport(): void
    {
        $this->adminToken();

        self::assertSame(
            StatusCodeInterface::STATUS_NOT_FOUND,
            $this->import('{"email":"a@example.com"}', 'nowhere')->getStatusCode(),
        );
        self::assertSame(
            StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY,
            $this->import('{"email":"a@example.com"}', 'google')->getStatusCode(),
        );
        self::assertSame(
            StatusCodeInterface::STATUS_UNSUPPORTED_MEDIA_TYPE,
            $this->api('POST', self::IMPORTS, rawBody: '{"email":"a@example.com"}')->getStatusCode(),
        );
        self::assertSame(0, (int) TestStorage::database()->fetchValue('SELECT count(*) FROM user_jobs'));
    }

    public function testAnImportPastItsLimitsIsRefusedWhole(): void
    {
        $this->adminToken();

        $tooMany = $this->import(str_repeat("{\"email\":\"a@example.com\"}\n", 10_001));
        $empty = $this->import("\n\n");

        self::assertSame(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, $tooMany->getStatusCode());
        self::assertSame(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, $empty->getStatusCode());
    }

    public function testEachOperationNeedsItsScope(): void
    {
        $this->adminToken(['read:users']);

        self::assertSame(
            StatusCodeInterface::STATUS_FORBIDDEN,
            $this->import('{"email":"a@example.com"}')->getStatusCode(),
        );
        self::assertSame(
            StatusCodeInterface::STATUS_NOT_FOUND,
            $this->api('GET', '/api/v1/jobs/0b0f5a3e-8f2c-4d1a-9b7e-3c2d1e0f9a8b')->getStatusCode(),
        );
    }

    private function import(string $ndjson, ?string $connection = null): ResponseInterface
    {
        return $this->api(
            'POST',
            self::IMPORTS,
            query: $connection === null ? [] : ['connection' => $connection],
            headers: ['Content-Type' => 'application/x-ndjson'],
            rawBody: $ndjson,
        );
    }

    private function runJobs(): string
    {
        $tester = new CommandTester($this->container()->get(RunJobsCommand::class));
        $tester->execute([]);

        return $tester->getDisplay(true);
    }

    /** @param list<array<string, mixed>|string> $lines */
    private static function ndjson(array $lines): string
    {
        return implode("\n", array_map(
            static fn (array|string $line): string => is_string($line) ? $line : (string) json_encode($line),
            $lines,
        )) . "\n";
    }
}
