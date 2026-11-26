<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Metrics\LabelValue;
use Clavia\Application\Metrics\Metric;
use Clavia\Application\Metrics\MetricSample;
use Clavia\Application\Port\Metrics;

/** Metrics in memory: each series by its labels, as the Redis store keeps them. */
final class InMemoryMetrics implements Metrics
{
    /** @var array<string, MetricSample> By metric and labels. */
    private array $series = [];

    #[\Override]
    public function count(Metric $metric, array $labels): void
    {
        $current = $this->current($metric, $labels);
        $this->series[self::key($metric, $current->labels)] = new MetricSample(
            $metric,
            $current->labels,
            $current->value + 1.0,
        );
    }

    #[\Override]
    public function observe(Metric $metric, float $seconds, array $labels): void
    {
        $current = $this->current($metric, $labels);
        $buckets = [];
        foreach ($current->buckets as [$bound, $count]) {
            $within = $bound === '+Inf' || $seconds <= (float) $bound;
            $buckets[] = [$bound, $count + ($within ? 1 : 0)];
        }
        $this->series[self::key($metric, $current->labels)] = new MetricSample(
            $metric,
            $current->labels,
            $current->value + $seconds,
            $buckets,
            $current->count + 1,
        );
    }

    #[\Override]
    public function samples(): array
    {
        return array_values($this->series);
    }

    /**
     * The value of one counter series, 0 when it was never counted: for tests.
     *
     * @param array<non-empty-string, string> $labels
     */
    public function valueOf(Metric $metric, array $labels): float
    {
        return ($this->series[self::key($metric, self::normal($metric, $labels))] ?? null)?->value ?? 0.0;
    }

    /** @param array<non-empty-string, string> $labels */
    private function current(Metric $metric, array $labels): MetricSample
    {
        $normal = self::normal($metric, $labels);
        $buckets = [];
        foreach ($metric->buckets() as $bound) {
            $buckets[] = [rtrim(rtrim(sprintf('%.3f', $bound), '0'), '.'), 0];
        }

        return $this->series[self::key($metric, $normal)]
            ?? new MetricSample($metric, $normal, 0.0, $metric->isHistogram() ? [...$buckets, ['+Inf', 0]] : []);
    }

    /** @param array<non-empty-string, string> $labels */
    private static function key(Metric $metric, array $labels): string
    {
        return $metric->name() . '|' . json_encode($labels, JSON_THROW_ON_ERROR);
    }

    /**
     * @param array<non-empty-string, string> $labels
     *
     * @return array<non-empty-string, string>
     */
    private static function normal(Metric $metric, array $labels): array
    {
        $normal = [];
        foreach ($metric->labels() as $name) {
            $normal[$name] = LabelValue::of($labels[$name] ?? '');
        }

        return $normal;
    }
}
