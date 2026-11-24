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
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\SeededRandomSource;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use DateTimeImmutable;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * Bulk export of users (#19): queued through the Management API, written by `clavia jobs:run`,
 * downloaded as NDJSON, never with a password hash.
 */
final class ManagementUserExportsTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string EXPORTS = '/api/v1/jobs/users-exports';

    public function testAnExportWritesThePoolWithoutHashesAndIsRecorded(): void
    {
        $this->adminToken(['read:users', 'create:users']);
        $this->user();
        $this->container()->get(UserRepository::class)->save(User::registerFromProvider(
            UserId::generate(new SeededRandomSource(31)),
            'grace@example.com',
            ConnectionName::fromString('google'),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        ));

        $queued = $this->api('POST', self::EXPORTS);
        self::assertSame(StatusCodeInterface::STATUS_ACCEPTED, $queued->getStatusCode(), (string) $queued->getBody());
        $job = self::document($queued);
        self::assertIsString($job['id']);
        self::assertSame('users_export', $job['type']);
        self::assertSame('/api/v1/jobs/' . $job['id'], $queued->getHeaderLine('Location'));
        self::assertSame(
            StatusCodeInterface::STATUS_CONFLICT,
            $this->download($job['id'])->getStatusCode(),
            'Not before it is written.',
        );

        self::assertSame("Ran 1 job; 0 stalled jobs failed; 0 finished jobs purged.\n", $this->runJobs());

        $done = self::document($this->api('GET', '/api/v1/jobs/' . $job['id']));
        self::assertSame('completed', $done['status']);
        self::assertSame(['total' => 1, 'created' => 0, 'failed' => 0], $done['summary']);

        $output = $this->download($job['id']);
        self::assertSame(StatusCodeInterface::STATUS_OK, $output->getStatusCode());
        self::assertSame('application/x-ndjson', $output->getHeaderLine('Content-Type'));
        self::assertStringStartsWith('attachment;', $output->getHeaderLine('Content-Disposition'));
        self::assertSame('no-store', $output->getHeaderLine('Cache-Control'));
        $lines = array_values(array_filter(explode("\n", (string) $output->getBody())));
        self::assertCount(1, $lines, 'Only the pool asked for.');
        /** @var array<string, mixed> $line */
        $line = json_decode($lines[0], true, 8, JSON_THROW_ON_ERROR);
        self::assertSame(self::TEST_USER_EMAIL, $line['email']);
        self::assertSame('password', $line['connection']);
        self::assertArrayNotHasKey('password_hash', $line);
        self::assertStringNotContainsString('pbkdf2', (string) $output->getBody(), 'Never a hash.');

        $recorded = TestStorage::database()->fetchOne(
            "SELECT actor_kind, target_type, target_id FROM audit_events WHERE type = 'user.exported'",
        );
        self::assertSame(
            ['actor_kind' => 'application', 'target_type' => 'connection', 'target_id' => 'password'],
            $recorded,
        );

        // An export imports as it is: the line is refused only because the account is there.
        $import = self::document($this->api(
            'POST',
            '/api/v1/jobs/users-imports',
            headers: ['Content-Type' => 'application/x-ndjson'],
            rawBody: (string) $output->getBody(),
        ));
        $this->runJobs();
        $report = self::document($this->api('GET', '/api/v1/jobs/' . (string) $import['id']));
        self::assertSame(
            [['line' => 1, 'error' => 'already_exists', 'detail' => 'An account in this pool has that address.']],
            $report['errors'],
        );
    }

    public function testAnyConnectionCanBeExportedAndAnUnknownOneIsNot(): void
    {
        $this->adminToken(['read:users']);

        self::assertSame(
            StatusCodeInterface::STATUS_ACCEPTED,
            $this->api('POST', self::EXPORTS, query: ['connection' => 'google'])->getStatusCode(),
        );
        self::assertSame(
            StatusCodeInterface::STATUS_NOT_FOUND,
            $this->api('POST', self::EXPORTS, query: ['connection' => 'nowhere'])->getStatusCode(),
        );
    }

    public function testAnImportHasNoOutput(): void
    {
        $this->adminToken(['read:users', 'create:users']);
        $import = self::document($this->api(
            'POST',
            '/api/v1/jobs/users-imports',
            headers: ['Content-Type' => 'application/x-ndjson'],
            rawBody: "{\"email\":\"ada@example.com\"}\n",
        ));
        $this->runJobs();

        self::assertSame(
            StatusCodeInterface::STATUS_NOT_FOUND,
            $this->download((string) $import['id'])->getStatusCode(),
        );
    }

    public function testExportingNeedsReadUsers(): void
    {
        $this->adminToken(['create:users']);

        self::assertSame(StatusCodeInterface::STATUS_FORBIDDEN, $this->api('POST', self::EXPORTS)->getStatusCode());
        self::assertSame(0, (int) TestStorage::database()->fetchValue('SELECT count(*) FROM user_jobs'));
    }

    private function download(string $jobId): ResponseInterface
    {
        return $this->api('GET', '/api/v1/jobs/' . $jobId . '/output');
    }

    private function runJobs(): string
    {
        $tester = new CommandTester($this->container()->get(RunJobsCommand::class));
        $tester->execute([]);

        return $tester->getDisplay(true);
    }
}
