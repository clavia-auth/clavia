<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use Clavia\Domain\Audit\Actor;
use Clavia\Domain\Audit\ActorKind;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\Jobs\LineError;
use Clavia\Domain\Identity\Jobs\UserJob;
use Clavia\Domain\Identity\Jobs\UserJobId;
use Clavia\Domain\Identity\Jobs\UserJobKind;
use Clavia\Domain\Identity\Jobs\UserJobRepository;
use Clavia\Domain\Identity\Jobs\UserJobStatus;
use Clavia\Domain\Identity\UserId;
use DateTimeImmutable;

/**
 * Bulk jobs in `user_jobs`. The queue is the table itself: a worker claims the oldest queued row
 * with `FOR UPDATE SKIP LOCKED`, so workers never wait on, nor share, a job.
 *
 * @psalm-type JobRow = array{id: string, kind: string, status: string, connection: string,
 *     requested_by_kind: string, requested_by_user_id: string|null, requested_by_client_id: string|null,
 *     created_at: string, started_at: string|null, finished_at: string|null, input: string|null,
 *     total: int, created: int, failed: int, errors: string, failure: string|null}
 */
final readonly class PhpDbUserJobRepository implements UserJobRepository
{
    private const string COLUMNS = 'id, kind, status, connection, requested_by_kind, requested_by_user_id, '
        . 'requested_by_client_id, created_at, started_at, finished_at, input, total, created, failed, errors, '
        . 'failure';

    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function add(UserJob $job): void
    {
        $this->database->execute(
            'INSERT INTO user_jobs (' . self::COLUMNS . ') VALUES (:id, :kind, :status, :connection, '
            . ':requested_by_kind, :requested_by_user_id, :requested_by_client_id, :created_at, :started_at, '
            . ':finished_at, :input, :total, :created, :failed, CAST(:errors AS jsonb), :failure)',
            self::row($job),
        );
    }

    #[\Override]
    public function find(UserJobId $id): ?UserJob
    {
        /** @var JobRow|null $row */
        $row = $this->database->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM user_jobs WHERE id = :id',
            ['id' => $id->value],
        );

        return $row === null ? null : self::hydrate($row);
    }

    #[\Override]
    public function save(UserJob $job): void
    {
        $row = self::row($job);
        unset(
            $row['kind'],
            $row['connection'],
            $row['requested_by_kind'],
            $row['requested_by_user_id'],
            $row['requested_by_client_id'],
            $row['created_at']
        );
        $this->database->execute(
            'UPDATE user_jobs SET status = :status, started_at = :started_at, finished_at = :finished_at, '
            . 'input = :input, total = :total, created = :created, failed = :failed, '
            . 'errors = CAST(:errors AS jsonb), failure = :failure WHERE id = :id',
            $row,
        );
    }

    #[\Override]
    public function claimNext(DateTimeImmutable $now): ?UserJob
    {
        /** @var JobRow|null $row */
        $row = $this->database->fetchOne(
            <<<'SQL'
                UPDATE user_jobs SET status = 'running', started_at = :now
                WHERE id = (
                    SELECT id FROM user_jobs WHERE status = 'queued'
                    ORDER BY created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED
                )
                RETURNING
                SQL . ' ' . self::COLUMNS,
            ['now' => Timestamp::toDatabase($now)],
        );

        return $row === null ? null : self::hydrate($row);
    }

    #[\Override]
    public function runningSince(DateTimeImmutable $startedBefore): array
    {
        /** @var list<JobRow> $rows */
        $rows = $this->database->fetchAll(
            'SELECT ' . self::COLUMNS . " FROM user_jobs WHERE status = 'running' AND started_at < :before "
            . 'ORDER BY started_at, id',
            ['before' => Timestamp::toDatabase($startedBefore)],
        );

        return array_map(self::hydrate(...), $rows);
    }

    #[\Override]
    public function purgeFinishedBefore(DateTimeImmutable $before): int
    {
        return max(0, $this->database->execute(
            "DELETE FROM user_jobs WHERE status IN ('completed', 'failed') AND finished_at < :before",
            ['before' => Timestamp::toDatabase($before)],
        ));
    }

    #[\Override]
    public function writeOutput(UserJobId $id, string $content): void
    {
        $this->database->execute(
            'INSERT INTO user_job_outputs (job_id, content) VALUES (:id, :content) '
            . 'ON CONFLICT (job_id) DO UPDATE SET content = EXCLUDED.content',
            ['id' => $id->value, 'content' => $content],
        );
    }

    #[\Override]
    public function output(UserJobId $id): ?string
    {
        /** @var string|null $content */
        $content = $this->database->fetchValue(
            'SELECT content FROM user_job_outputs WHERE job_id = :id',
            ['id' => $id->value],
        );

        return $content;
    }

    /** @return array<string, string|int|null> */
    private static function row(UserJob $job): array
    {
        $instant = static fn (?DateTimeImmutable $at): ?string => $at === null ? null : Timestamp::toDatabase($at);

        return [
            'id' => $job->id->value,
            'kind' => $job->kind->value,
            'status' => $job->status()->value,
            'connection' => $job->connection->value,
            'requested_by_kind' => $job->requestedBy->kind->value,
            'requested_by_user_id' => $job->requestedBy->userId?->value,
            'requested_by_client_id' => $job->requestedBy->clientId?->value,
            'created_at' => Timestamp::toDatabase($job->createdAt),
            'started_at' => $instant($job->startedAt()),
            'finished_at' => $instant($job->finishedAt()),
            'input' => $job->input(),
            'total' => $job->total(),
            'created' => $job->created(),
            'failed' => $job->failed(),
            'errors' => Jsonb::encode(array_map(
                static fn (LineError $error): array => [
                    'line' => $error->line,
                    'error' => $error->error,
                    'detail' => $error->detail,
                ],
                $job->errors(),
            )),
            'failure' => $job->failure(),
        ];
    }

    /** @param JobRow $row */
    private static function hydrate(array $row): UserJob
    {
        /** @var list<array{line: positive-int, error: non-empty-string, detail: non-empty-string}> $errors */
        $errors = json_decode($row['errors'], true, 8, JSON_THROW_ON_ERROR);
        $instant = static fn (?string $at): ?DateTimeImmutable => $at === null ? null : Timestamp::fromDatabase($at);

        return UserJob::reconstitute(
            UserJobId::fromString($row['id']),
            UserJobKind::from($row['kind']),
            UserJobStatus::from($row['status']),
            ConnectionName::fromString($row['connection']),
            Actor::reconstitute(
                ActorKind::from($row['requested_by_kind']),
                $row['requested_by_user_id'] === null ? null : UserId::fromString($row['requested_by_user_id']),
                $row['requested_by_client_id'] === null ? null : ClientId::fromString($row['requested_by_client_id']),
            ),
            Timestamp::fromDatabase($row['created_at']),
            $instant($row['started_at']),
            $instant($row['finished_at']),
            $row['input'],
            $row['total'],
            $row['created'],
            $row['failed'],
            array_map(static fn (array $e): LineError => new LineError($e['line'], $e['error'], $e['detail']), $errors),
            $row['failure'],
        );
    }
}
