<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity\Jobs;

use Clavia\Domain\Audit\Actor;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Shared\InvalidValue;
use DateTimeImmutable;

/**
 * A bulk job on the users, queued by the Management API and run by `clavia jobs:run`, outside any
 * request: an import of accounts into one pool from NDJSON.
 *
 * It keeps its input only until it finishes: an import's lines carry password hashes, which must
 * not outlive the job that reads them. What remains is the report — how many lines, how many
 * accounts made, and each refused line by number and reason, never by content.
 */
final class UserJob
{
    /** The refused lines a report lists; past them, only the count grows. */
    public const int MAX_REPORTED_ERRORS = 1000;

    /** The most lines one import takes. */
    public const int MAX_LINES = 10_000;

    /** The largest input one import takes: under PHP's default `post_max_size` (8 MB). */
    public const int MAX_INPUT_BYTES = 5_242_880;

    /**
     * @param list<LineError> $errors
     */
    private function __construct(
        public readonly UserJobId $id,
        public readonly UserJobKind $kind,
        private UserJobStatus $status,
        public readonly ConnectionName $connection,
        public readonly Actor $requestedBy,
        public readonly DateTimeImmutable $createdAt,
        private ?DateTimeImmutable $startedAt,
        private ?DateTimeImmutable $finishedAt,
        private ?string $input,
        private int $total,
        private int $created,
        private int $failed,
        private array $errors,
        private ?string $failure,
    ) {
    }

    /**
     * An import of `$input`, NDJSON, into `$connection`, waiting for a worker.
     *
     * @throws InvalidValue When the input is empty or larger than an import takes.
     */
    public static function queueImport(
        UserJobId $id,
        ConnectionName $connection,
        #[\SensitiveParameter] string $input,
        Actor $requestedBy,
        DateTimeImmutable $now,
    ): self {
        if (trim($input) === '') {
            throw new InvalidValue('An import needs at least one line.');
        }
        if (strlen($input) > self::MAX_INPUT_BYTES) {
            throw new InvalidValue(
                sprintf('An import is at most %d bytes; split it into several.', self::MAX_INPUT_BYTES),
            );
        }

        return new self(
            $id,
            UserJobKind::Import,
            UserJobStatus::Queued,
            $connection,
            $requestedBy,
            $now,
            null,
            null,
            $input,
            0,
            0,
            0,
            [],
            null,
        );
    }

    /**
     * A job as storage holds it.
     *
     * @param list<LineError> $errors
     */
    public static function reconstitute(
        UserJobId $id,
        UserJobKind $kind,
        UserJobStatus $status,
        ConnectionName $connection,
        Actor $requestedBy,
        DateTimeImmutable $createdAt,
        ?DateTimeImmutable $startedAt,
        ?DateTimeImmutable $finishedAt,
        #[\SensitiveParameter] ?string $input,
        int $total,
        int $created,
        int $failed,
        array $errors,
        ?string $failure,
    ): self {
        return new self(
            $id,
            $kind,
            $status,
            $connection,
            $requestedBy,
            $createdAt,
            $startedAt,
            $finishedAt,
            $input,
            $total,
            $created,
            $failed,
            $errors,
            $failure,
        );
    }

    public function status(): UserJobStatus
    {
        return $this->status;
    }

    public function startedAt(): ?DateTimeImmutable
    {
        return $this->startedAt;
    }

    public function finishedAt(): ?DateTimeImmutable
    {
        return $this->finishedAt;
    }

    /** The input still to process; null once the job has finished. */
    public function input(): ?string
    {
        return $this->input;
    }

    /** Lines read, accounts made, lines refused. */
    public function total(): int
    {
        return $this->total;
    }

    public function created(): int
    {
        return $this->created;
    }

    public function failed(): int
    {
        return $this->failed;
    }

    /** @return list<LineError> The first {@see MAX_REPORTED_ERRORS} refused lines. */
    public function errors(): array
    {
        return $this->errors;
    }

    /** Why the job stopped as a whole, when it did. */
    public function failure(): ?string
    {
        return $this->failure;
    }

    public function isFinished(): bool
    {
        return $this->status === UserJobStatus::Completed || $this->status === UserJobStatus::Failed;
    }

    /** A worker took it: what storage records when it claims the job ({@see UserJobRepository::claimNext()}). */
    public function start(DateTimeImmutable $now): void
    {
        $this->status = UserJobStatus::Running;
        $this->startedAt = $now;
    }

    public function recordCreated(): void
    {
        ++$this->total;
        ++$this->created;
    }

    public function recordRefused(LineError $error): void
    {
        ++$this->total;
        ++$this->failed;
        if (count($this->errors) < self::MAX_REPORTED_ERRORS) {
            $this->errors[] = $error;
        }
    }

    /** Every line was read: the report is final, and the input (hashes included) is let go. */
    public function complete(DateTimeImmutable $now): void
    {
        $this->status = UserJobStatus::Completed;
        $this->finishedAt = $now;
        $this->input = null;
    }

    /** Stopped as a whole: the input is let go all the same. */
    public function fail(string $reason, DateTimeImmutable $now): void
    {
        $this->status = UserJobStatus::Failed;
        $this->finishedAt = $now;
        $this->failure = $reason;
        $this->input = null;
    }
}
