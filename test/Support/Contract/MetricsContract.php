<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Metrics\Metric;
use Clavia\Application\Metrics\MetricSample;
use Clavia\Application\Port\Metrics;
use Fig\Http\Message\RequestMethodInterface;
use PHPUnit\Framework\Attributes\Test;

/** What every {@see Metrics} must do, run against the double and Redis. */
trait MetricsContract
{
    abstract protected function metrics(): Metrics;

    /** Whatever the store holds back until a request ends is written now. */
    abstract protected function flushMetrics(): void;

    #[Test]
    public function aCounterSumsItsOccurrencesBySeries(): void
    {
        $this->metrics()->count(Metric::TokensIssued, ['grant_type' => 'authorization_code']);
        $this->metrics()->count(Metric::TokensIssued, ['grant_type' => 'authorization_code']);
        $this->metrics()->count(Metric::TokensIssued, ['grant_type' => 'client_credentials']);
        $this->flushMetrics();

        $values = [];
        foreach ($this->metrics()->samples() as $sample) {
            if ($sample->metric === Metric::TokensIssued) {
                $values[$sample->labels['grant_type']] = $sample->value;
            }
        }
        ksort($values);

        self::assertSame(['authorization_code' => 2.0, 'client_credentials' => 1.0], $values);
    }

    #[Test]
    public function aHistogramKeepsCumulativeBucketsItsSumAndItsCount(): void
    {
        $labels = ['route' => 'oauth2.token', 'method' => RequestMethodInterface::METHOD_POST, 'status' => '200'];
        $this->metrics()->observe(Metric::RequestDuration, 0.004, $labels);
        $this->metrics()->observe(Metric::RequestDuration, 0.3, $labels);
        $this->metrics()->observe(Metric::RequestDuration, 30.0, $labels);
        $this->flushMetrics();

        $sample = self::only($this->metrics()->samples(), Metric::RequestDuration);

        self::assertSame($labels, $sample->labels);
        self::assertSame(3, $sample->count);
        self::assertEqualsWithDelta(30.304, $sample->value, 0.0001);
        self::assertSame([
            ['0.005', 1], ['0.01', 1], ['0.025', 1], ['0.05', 1], ['0.1', 1], ['0.25', 1],
            ['0.5', 2], ['1', 2], ['2.5', 2], ['5', 2], ['10', 2], ['+Inf', 3],
        ], $sample->buckets, 'Cumulative, +Inf last.');
    }

    #[Test]
    public function aLabelValueCannotBreakTheFormat(): void
    {
        $this->metrics()->count(Metric::OAuthErrors, ['endpoint' => 'token', 'error' => "a\"b,c=d|e\n"]);
        $this->flushMetrics();

        $sample = self::only($this->metrics()->samples(), Metric::OAuthErrors);

        self::assertSame(['endpoint' => 'token', 'error' => 'a_b_c_d_e_'], $sample->labels);
    }

    /** @param list<MetricSample> $samples */
    private static function only(array $samples, Metric $metric): MetricSample
    {
        $found = array_values(array_filter($samples, static fn (MetricSample $s): bool => $s->metric === $metric));
        self::assertCount(1, $found);

        return $found[0];
    }
}
