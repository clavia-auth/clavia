<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Identity\Jobs;

use Clavia\Domain\Audit\Actor;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\Jobs\LineError;
use Clavia\Domain\Identity\Jobs\UserJob;
use Clavia\Domain\Identity\Jobs\UserJobId;
use Clavia\Domain\Identity\Jobs\UserJobStatus;
use Clavia\Domain\Shared\InvalidValue;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class UserJobTest extends TestCase
{
    public function testTheReportListsTheFirstThousandRefusalsAndCountsThemAll(): void
    {
        $job = self::job("{}\n");

        for ($line = 1; $line <= UserJob::MAX_REPORTED_ERRORS + 5; ++$line) {
            $job->recordRefused(new LineError($line, 'invalid_json', 'The line is not valid JSON.'));
        }
        $job->recordCreated();

        self::assertCount(UserJob::MAX_REPORTED_ERRORS, $job->errors());
        self::assertSame(UserJob::MAX_REPORTED_ERRORS + 5, $job->failed());
        self::assertSame(UserJob::MAX_REPORTED_ERRORS + 6, $job->total());
    }

    public function testAFinishedJobKeepsNoInput(): void
    {
        $completed = self::job("{}\n");
        $failed = self::job("{}\n");

        $completed->complete(new DateTimeImmutable('2026-01-15T10:01:00Z'));
        $failed->fail('The worker stopped.', new DateTimeImmutable('2026-01-15T10:01:00Z'));

        self::assertSame(UserJobStatus::Completed, $completed->status());
        self::assertNull($completed->input());
        self::assertSame(UserJobStatus::Failed, $failed->status());
        self::assertNull($failed->input());
        self::assertSame('The worker stopped.', $failed->failure());
    }

    public function testAnEmptyOrOversizedInputIsRefused(): void
    {
        foreach (["\n \n", str_repeat('a', UserJob::MAX_INPUT_BYTES + 1)] as $input) {
            try {
                self::job($input);
                self::fail('The input was queued.');
            } catch (InvalidValue $refusal) {
                self::assertNotSame('', $refusal->getMessage());
            }
        }
    }

    private static function job(string $input): UserJob
    {
        return UserJob::queueImport(
            UserJobId::generate(new SeededRandomSource(1)),
            ConnectionName::defaultPool(),
            $input,
            Actor::system(),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
    }
}
