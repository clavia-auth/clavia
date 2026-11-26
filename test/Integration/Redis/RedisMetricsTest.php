<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Integration\Redis;

use Clavia\Adapter\Secondary\Redis\RedisConnection;
use Clavia\Adapter\Secondary\Redis\RedisMetrics;
use Clavia\Application\Metrics\Metric;
use Clavia\Application\Port\Metrics;
use Closure;
use ClaviaTest\Support\Contract\MetricsContract;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\RecordingLogger;
use ClaviaTest\Support\TestEnvironment;

final class RedisMetricsTest extends IntegrationTestCase
{
    use MetricsContract;

    private ?RedisMetrics $metrics = null;

    #[\Override]
    protected function metrics(): Metrics
    {
        return $this->metrics ??= new RedisMetrics(
            new RedisConnection(TestEnvironment::redisUrl()),
            new RecordingLogger(),
            static function (Closure $flush): void {
                // Held back: the test flushes when it means to, as the entry point would.
            },
        );
    }

    #[\Override]
    protected function flushMetrics(): void
    {
        $this->metrics?->flush();
    }

    public function testAFlushIsAskedForWheneverSamplesWaitAgain(): void
    {
        $scheduled = [];
        $metrics = new RedisMetrics(
            new RedisConnection(TestEnvironment::redisUrl()),
            new RecordingLogger(),
            static function (Closure $flush) use (&$scheduled): void {
                $scheduled[] = $flush;
            },
        );

        $metrics->count(Metric::Mail, ['outcome' => 'sent']);
        $metrics->count(Metric::Mail, ['outcome' => 'sent']);
        self::assertCount(1, $scheduled, 'Once for both.');
        $scheduled[0]();
        $metrics->count(Metric::Mail, ['outcome' => 'failed']);

        self::assertCount(2, $scheduled, 'Again once the first was written.');
    }

    public function testNothingIsWrittenUntilTheRequestEnds(): void
    {
        $this->metrics()->count(Metric::Mail, ['outcome' => 'sent']);

        self::assertSame([], $this->metrics()->samples(), 'Buffered.');
        $this->flushMetrics();
        self::assertCount(1, $this->metrics()->samples());
    }

    public function testEveryProcessAddsToTheSameSeries(): void
    {
        foreach ([1, 2] as $process) {
            $metrics = new RedisMetrics(new RedisConnection(TestEnvironment::redisUrl()), new RecordingLogger());
            $metrics->count(Metric::Mail, ['outcome' => 'sent']);
            $metrics->flush();
        }

        self::assertSame(2.0, $this->metrics()->samples()[0]->value);
    }

    public function testAStoreThatCannotBeReachedDropsTheSamplesAndSaysSo(): void
    {
        $logger = new RecordingLogger();
        $metrics = new RedisMetrics(new RedisConnection('redis://127.0.0.1:1/1'), $logger);
        $metrics->count(Metric::Mail, ['outcome' => 'sent']);

        $metrics->flush();

        self::assertTrue($logger->hasRecordContaining('Metrics could not be written'));
    }
}
