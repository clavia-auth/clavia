<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Primary\Cli\ImportUsersFromSqsCommand;
use Clavia\Application\Management\Users\Import\UserImport;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\UserRepository;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\FakeQueueMessages;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use Psr\Log\LoggerInterface;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * `clavia users:import-sqs` (#108): one account per SQS message, through the same import port as an
 * import job, against the real container and database; the queue is a double.
 */
final class ImportUsersFromSqsTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;

    private const string QUEUE = 'https://sqs.eu-west-1.amazonaws.com/123456789012/clavia-imports';

    public function testEachMessageIsImportedOrRefusedAndEveryOneIsDeleted(): void
    {
        $this->user();
        $queue = new FakeQueueMessages(
            FakeQueueMessages::message('m-1', '{"email":"grace@example.com","name":"Grace Hopper"}'),
            FakeQueueMessages::message('m-2', '{"email":"alan@example.com"}', 'password'),
            FakeQueueMessages::message('m-3', '{"email":"' . self::TEST_USER_EMAIL . '"}'),
            FakeQueueMessages::message('m-4', 'not json'),
            FakeQueueMessages::message('m-5', '{"email":"eve@example.com"}', 'google'),
            FakeQueueMessages::message('m-6', '{"email":"bob@example.com"}', 'Not A Name'),
        );

        $display = $this->listen($queue, ['--idle-exit' => true]);

        self::assertSame("Imported 2, refused 4, left 0 for a retry.\n", $display);
        self::assertSame([self::QUEUE], $queue->opened);
        self::assertSame(['m-1', 'm-2', 'm-3', 'm-4', 'm-5', 'm-6'], $queue->deleted, 'Final either way.');
        $users = $this->container()->get(UserRepository::class);
        $grace = $users->findByEmail(ConnectionName::defaultPool(), 'grace@example.com');
        self::assertSame('Grace Hopper', $grace?->profile()->name);
        self::assertNotNull($users->findByEmail(ConnectionName::defaultPool(), 'alan@example.com'));
        self::assertNull($users->findByEmail(ConnectionName::defaultPool(), 'eve@example.com'));
        self::assertSame(2, (int) TestStorage::database()->fetchValue(
            "SELECT count(*) FROM audit_events WHERE type = :type AND actor_kind = 'system'",
            ['type' => AuditEventType::UserCreated->value],
        ));
        // Refusals are logged by message and code, never by body.
        $log = (string) json_encode($this->logger->records);
        self::assertStringContainsString('already_exists', $log);
        self::assertStringContainsString('invalid_connection', $log);
        self::assertStringNotContainsString('eve@example.com', $log);
    }

    public function testItStopsAfterMaxMessages(): void
    {
        $queue = new FakeQueueMessages(
            FakeQueueMessages::message('m-1', '{"email":"one@example.com"}'),
            FakeQueueMessages::message('m-2', '{"email":"two@example.com"}'),
            FakeQueueMessages::message('m-3', '{"email":"three@example.com"}'),
        );

        $display = $this->listen($queue, ['--max-messages' => '2']);

        self::assertSame("Imported 2, refused 0, left 0 for a retry.\n", $display);
        self::assertSame(['m-1', 'm-2'], $queue->deleted);
    }

    public function testAMessageThatFailsUnexpectedlyIsLeftForARetry(): void
    {
        $queue = new FakeQueueMessages(FakeQueueMessages::message('m-1', '{"email":"grace@example.com"}'));
        $failing = new class implements UserImport {
            #[\Override]
            public function import(string $line, ConnectionName $pool): never
            {
                throw new \RuntimeException('The database is down.');
            }
        };
        $logger = $this->container()->get(LoggerInterface::class);
        $tester = new CommandTester(new ImportUsersFromSqsCommand($queue, $failing, $logger));

        $tester->execute(['queue-url' => self::QUEUE, '--idle-exit' => true]);

        self::assertSame("Imported 0, refused 0, left 1 for a retry.\n", $tester->getDisplay(true));
        self::assertSame([], $queue->deleted, 'It comes back, and reaches the dead-letter queue if it keeps failing.');
    }

    /** @param array<string, string|bool> $options */
    private function listen(FakeQueueMessages $queue, array $options): string
    {
        $tester = new CommandTester(new ImportUsersFromSqsCommand(
            $queue,
            $this->container()->get(UserImport::class),
            $this->container()->get(LoggerInterface::class),
        ));
        $tester->execute(['queue-url' => self::QUEUE] + $options);

        return $tester->getDisplay(true);
    }
}
