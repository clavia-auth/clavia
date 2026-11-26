<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Metrics;

/**
 * One series of a metric as recorded: a counter's value, or a histogram's cumulative buckets, sum
 * and count.
 */
final readonly class MetricSample
{
    /**
     * @param array<non-empty-string, string> $labels
     * @param list<array{string, int}>        $buckets A histogram's bounds and cumulative counts, `+Inf` last.
     */
    public function __construct(
        public Metric $metric,
        public array $labels,
        public float $value,
        public array $buckets = [],
        public int $count = 0,
    ) {
    }
}
