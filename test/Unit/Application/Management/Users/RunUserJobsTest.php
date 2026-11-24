<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Management\Users;

use Clavia\Application\Audit\AuditContext;
use Clavia\Application\Management\Users\Export\ExportUsers;
use Clavia\Application\Management\Users\Import\ImportLine;
use Clavia\Application\Management\Users\Import\ImportUser;
use Clavia\Application\Management\Users\Jobs\RunUserJobs;
use Clavia\Domain\Audit\Actor;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\Event\UsersExported;
use Clavia\Domain\Identity\Jobs\UserJob;
use Clavia\Domain\Identity\Jobs\UserJobId;
use Clavia\Domain\Identity\Jobs\UserJobStatus;
use ClaviaTest\Support\Fake\FakePasswordHasher;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryConnectionRepository;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\InMemoryUserJobRepository;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use PHPUnit\Framework\TestCase;

final class RunUserJobsTest extends TestCase
{
    private InMemoryUserJobRepository $jobs;
    private InMemoryUserRepository $users;
    private InMemoryDomainEvents $events;
    private FrozenClock $clock;

    #[\Override]
    protected function setUp(): void
    {
        $this->jobs = new InMemoryUserJobRepository();
        $this->users = new InMemoryUserRepository();
        $this->events = new InMemoryDomainEvents();
        $this->clock = new FrozenClock('2026-01-15T10:00:00Z');
    }

    public function testAJobWhoseWorkerStoppedIsFailedAndItsInputLetGo(): void
    {
        $stalled = $this->queue(1);
        $this->jobs->claimNext($this->clock->now());
        $this->clock->advance(RunUserJobs::STALL_AFTER_SECONDS + 1);

        $run = $this->worker()();

        $job = $this->jobs->find($stalled->id);
        self::assertSame(1, $run->stalled);
        self::assertNotNull($job);
        self::assertSame(UserJobStatus::Failed, $job->status());
        self::assertNull($job->input());
        self::assertNotNull($job->failure());
    }

    public function testAFinishedJobIsPurgedAfterItsRetention(): void
    {
        $old = $this->queue(1);
        self::assertSame(1, $this->worker()()->completed);

        $this->clock->advance(RunUserJobs::RETENTION_DAYS * 86_400 - 60);
        self::assertSame(0, $this->worker()()->purged, 'Still within its retention.');
        $this->clock->advance(120);
        self::assertSame(1, $this->worker()()->purged);
        self::assertNull($this->jobs->find($old->id));
    }

    public function testAnExportWritesThePoolOutAndIsRecorded(): void
    {
        $this->users->save(User::register(
            UserId::generate(new SeededRandomSource(11)),
            'ada@example.com',
            '$fake$hash$',
            $this->clock->now(),
        ));
        $this->users->save(User::registerFromProvider(
            UserId::generate(new SeededRandomSource(12)),
            'grace@example.com',
            ConnectionName::fromString('google'),
            $this->clock->now(),
        ));
        $export = UserJob::queueExport(
            UserJobId::generate(new SeededRandomSource(13)),
            ConnectionName::defaultPool(),
            Actor::system(),
            $this->clock->now(),
        );
        $this->jobs->add($export);

        self::assertSame(1, $this->worker()()->completed);

        $done = $this->jobs->find($export->id);
        self::assertNotNull($done);
        self::assertSame(UserJobStatus::Completed, $done->status());
        self::assertSame(1, $done->total());
        $output = (string) $this->jobs->output($export->id);
        self::assertStringContainsString('"email":"ada@example.com"', $output);
        self::assertStringNotContainsString('grace@example.com', $output, 'Only its connection.');
        self::assertStringNotContainsString('$fake$hash$', $output, 'Never a hash.');
        $exported = $this->events->ofType(UsersExported::class);
        self::assertCount(1, $exported);
        self::assertSame(1, $exported[0]->count);
    }

    private function queue(int $seed): UserJob
    {
        $job = UserJob::queueImport(
            UserJobId::generate(new SeededRandomSource($seed)),
            ConnectionName::defaultPool(),
            "{\"email\":\"ada@example.com\"}\n",
            Actor::system(),
            $this->clock->now(),
        );
        $this->jobs->add($job);

        return $job;
    }

    private function worker(): RunUserJobs
    {
        return new RunUserJobs(
            $this->jobs,
            new ImportUser(
                new ImportLine(new FakePasswordHasher()),
                $this->users,
                new InMemoryConnectionRepository(),
                new InMemoryTransactionManager(),
                new SeededRandomSource(5),
                $this->clock,
                $this->events,
            ),
            new ExportUsers($this->users),
            new InMemoryTransactionManager(),
            new AuditContext(),
            $this->clock,
            $this->events,
        );
    }
}
