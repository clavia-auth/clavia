<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\Audit\Actor;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\Jobs\LineError;
use Clavia\Domain\Identity\Jobs\UserJob;
use Clavia\Domain\Identity\Jobs\UserJobId;
use Clavia\Domain\Identity\Jobs\UserJobRepository;
use Clavia\Domain\Identity\Jobs\UserJobStatus;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see UserJobRepository} must do, run against the double and PostgreSQL.
 */
trait UserJobRepositoryContract
{
    abstract protected function userJobs(): UserJobRepository;

    #[Test]
    public function aQueuedImportIsReadBackWhole(): void
    {
        $job = $this->aJob(1, '2026-01-15T10:00:00Z');
        $this->userJobs()->add($job);

        $stored = $this->userJobs()->find($job->id);

        self::assertNotNull($stored);
        self::assertSame(UserJobStatus::Queued, $stored->status());
        self::assertSame('password', $stored->connection->value);
        self::assertTrue($stored->requestedBy->clientId?->equals(ClientId::fromString('operator-app')));
        self::assertSame("{\"email\":\"ada@example.com\"}\n", $stored->input());
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:00:00Z'), $stored->createdAt);
        self::assertNull($this->userJobs()->find(UserJobId::generate(new SeededRandomSource(99))));
    }

    #[Test]
    public function theOldestQueuedJobIsClaimedOnce(): void
    {
        $newer = $this->aJob(1, '2026-01-15T10:05:00Z');
        $older = $this->aJob(2, '2026-01-15T10:00:00Z');
        $this->userJobs()->add($newer);
        $this->userJobs()->add($older);
        $now = new DateTimeImmutable('2026-01-15T11:00:00Z');

        $first = $this->userJobs()->claimNext($now);
        $second = $this->userJobs()->claimNext($now);
        $third = $this->userJobs()->claimNext($now);

        self::assertNotNull($first);
        self::assertTrue($first->id->equals($older->id));
        self::assertSame(UserJobStatus::Running, $first->status());
        self::assertEquals($now, $first->startedAt());
        self::assertTrue($second?->id->equals($newer->id));
        self::assertNull($third, 'Nothing is queued any more.');
        self::assertSame(UserJobStatus::Running, $this->userJobs()->find($older->id)?->status());
    }

    #[Test]
    public function aFinishedJobKeepsItsReportAndNotItsInput(): void
    {
        $job = $this->aJob(1, '2026-01-15T10:00:00Z');
        $this->userJobs()->add($job);
        $claimed = $this->userJobs()->claimNext(new DateTimeImmutable('2026-01-15T10:01:00Z'));
        self::assertNotNull($claimed);

        $claimed->recordCreated();
        $claimed->recordRefused(new LineError(2, 'already_exists', 'An account in this pool has that address.'));
        $claimed->complete(new DateTimeImmutable('2026-01-15T10:02:00Z'));
        $this->userJobs()->save($claimed);

        $stored = $this->userJobs()->find($job->id);
        self::assertNotNull($stored);
        self::assertSame(UserJobStatus::Completed, $stored->status());
        self::assertNull($stored->input());
        self::assertSame([2, 1, 1], [$stored->total(), $stored->created(), $stored->failed()]);
        $refused = new LineError(2, 'already_exists', 'An account in this pool has that address.');
        self::assertEquals([$refused], $stored->errors());
    }

    #[Test]
    public function stalledJobsAreFoundAndFinishedOnesPurged(): void
    {
        $stalled = $this->aJob(1, '2026-01-15T08:00:00Z');
        $done = $this->aJob(2, '2026-01-15T08:30:00Z');
        $waiting = $this->aJob(3, '2026-01-15T09:00:00Z');
        foreach ([$stalled, $done, $waiting] as $job) {
            $this->userJobs()->add($job);
        }
        $this->userJobs()->claimNext(new DateTimeImmutable('2026-01-15T08:00:00Z'));
        $finishing = $this->userJobs()->claimNext(new DateTimeImmutable('2026-01-15T08:40:00Z'));
        self::assertNotNull($finishing);
        $finishing->complete(new DateTimeImmutable('2026-01-15T08:41:00Z'));
        $this->userJobs()->save($finishing);

        $running = $this->userJobs()->runningSince(new DateTimeImmutable('2026-01-15T08:30:00Z'));
        $purged = $this->userJobs()->purgeFinishedBefore(new DateTimeImmutable('2026-01-16T00:00:00Z'));

        self::assertCount(1, $running);
        self::assertTrue($running[0]->id->equals($stalled->id));
        self::assertSame(1, $purged);
        self::assertNull($this->userJobs()->find($done->id));
        self::assertNotNull($this->userJobs()->find($stalled->id), 'A running job is never purged.');
        self::assertNotNull($this->userJobs()->find($waiting->id));
    }

    private function aJob(int $seed, string $at): UserJob
    {
        return UserJob::queueImport(
            UserJobId::generate(new SeededRandomSource($seed)),
            ConnectionName::defaultPool(),
            "{\"email\":\"ada@example.com\"}\n",
            Actor::application(ClientId::fromString('operator-app')),
            new DateTimeImmutable($at),
        );
    }
}
